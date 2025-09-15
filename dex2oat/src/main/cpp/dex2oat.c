/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

//
// Created by Nullptr on 2022/4/1.
//

#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "logging.h"

#if defined(__LP64__)
#define LP_SELECT(lp32, lp64) lp64
#else
#define LP_SELECT(lp32, lp64) lp32
#endif

#define ID_VEC(is64, is_debug) (((is64) << 1) | (is_debug))

const char kSockName[] = "5291374ceda0aef7c5d86cd2a4f6a3ac\0";

static ssize_t xrecvmsg(int sockfd, struct msghdr *msg, int flags) {
    int rec = recvmsg(sockfd, msg, flags);
    if (rec < 0) {
        PLOGE("recvmsg");
    }
    return rec;
}

static void *recv_fds(int sockfd, char *cmsgbuf, size_t bufsz, int cnt) {
    struct iovec iov = {
        .iov_base = &cnt,
        .iov_len = sizeof(cnt),
    };
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cmsgbuf, .msg_controllen = bufsz};

    xrecvmsg(sockfd, &msg, MSG_WAITALL);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (msg.msg_controllen != bufsz || cmsg == NULL ||
        cmsg->cmsg_len != CMSG_LEN(sizeof(int) * cnt) || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS) {
        return NULL;
    }

    return CMSG_DATA(cmsg);
}

static int recv_fd(int sockfd) {
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    void *data = recv_fds(sockfd, cmsgbuf, sizeof(cmsgbuf), 1);
    if (data == NULL) return -1;

    int result;
    memcpy(&result, data, sizeof(int));
    return result;
}

static int read_int(int fd) {
    int val;
    ssize_t read_bytes = 0;
    while (read_bytes < sizeof(val)) {
        ssize_t ret = TEMP_FAILURE_RETRY(read(fd, ((char *)&val) + read_bytes, sizeof(val) - read_bytes));
        if (ret < 0) {
            PLOGE("read failed");

            return -1;
        }

        read_bytes += ret;
    }

    return val;
}

static void write_int(int fd, int val) {
    ssize_t written_bytes = 0;
    while (written_bytes < sizeof(val)) {
        ssize_t ret = TEMP_FAILURE_RETRY(write(fd, ((char *)&val) + written_bytes, sizeof(val) - written_bytes));
        if (ret < 0) {
            PLOGE("write failed");

            return;
        }

        written_bytes += ret;
    }
}

static void write_string(int fd, const char *str, size_t len) {
    write_int(fd, (int)len);
    if (len > 0) write(fd, str, len);
}

int main(int argc, char **argv) {
    LOGD("dex2oat wrapper ppid=%d, uid=%d", getppid(), getuid());

    if (getenv("LD_LIBRARY_PATH") == NULL) {
        char const *libenv = LP_SELECT(
            "LD_LIBRARY_PATH=/apex/com.android.art/lib:/apex/com.android.os.statsd/lib",
            "LD_LIBRARY_PATH=/apex/com.android.art/lib64:/apex/com.android.os.statsd/lib64");
        putenv((char *)libenv);
    }

    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        PLOGE("failed to create socket");

        return 1;
    }

    struct sockaddr_un sock = {
        .sun_family = AF_UNIX,
        .sun_path = { 0 },
    };
    strlcpy(sock.sun_path + 1, kSockName, sizeof(sock.sun_path) - 1);

    size_t len = sizeof(sa_family_t) + strlen(sock.sun_path + 1) + 1;
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(sock_fd, (struct sockaddr *)&sock, len)) {
        PLOGE("failed to connect to %s", sock.sun_path + 1);

        return 1;
    }

    write_int(sock_fd, 1); /* INFO: liboat_hook fd retrieval op */
    write_int(sock_fd, ID_VEC(LP_SELECT(0, 1), strstr(argv[0], "dex2oatd") != NULL));

    int stock_fd = recv_fd(sock_fd);
    if (stock_fd == -1) {
        PLOGE("failed to read stock dex2oat");

        close(sock_fd);

        return 1;
    }

    LOGI("stock dex2oat fd: %d", stock_fd);

    close(sock_fd);

    const char* prefix = "--classpath-dir=";
    size_t prefix_len = strlen(prefix);
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], prefix, prefix_len) != 0) continue;

        const char* classpath_dir = argv[i] + prefix_len;
        size_t dir_len = strlen(classpath_dir);

        sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(sock_fd, (struct sockaddr *)&sock, len)) {
            PLOGE("failed to connect to %s", sock.sun_path + 1);

            return 1;
        }

        write_int(sock_fd, 2); /* INFO: denylist check op */
        write_string(sock_fd, classpath_dir, dir_len);

        int is_in_denylist = read_int(sock_fd);
        close(sock_fd);

        if (is_in_denylist) {
            LOGD("App is in denylist, exiting");

            fexecve(stock_fd, (char **)argv, environ);

            LOGE("fexecve failed");

            close(stock_fd);

            return 2;
        }

        LOGD("App is not in denylist, continuing");
        break;
    }

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(sock_fd, (struct sockaddr *)&sock, len)) {
        PLOGE("failed to connect to %s", sock.sun_path + 1);

        close(stock_fd);

        return 1;
    }

    write_int(sock_fd, 1); /* INFO: liboat_hook fd retrieval op */
    write_int(sock_fd, LP_SELECT(4, 5));

    int hooker_fd = recv_fd(sock_fd);
    if (hooker_fd == -1) {
        PLOGE("failed to read liboat_hook.so");

        close(sock_fd);

        close(stock_fd);
    }

    close(sock_fd);

    LOGD("sock: %s %d", sock.sun_path + 1, stock_fd);

    const char *new_argv[argc + 2];
    for (int i = 0; i < argc; i++) new_argv[i] = argv[i];
    new_argv[argc] = "--inline-max-code-units=0";
    new_argv[argc + 1] = NULL;

    char liboat_fd_path[64];
    snprintf(liboat_fd_path, sizeof(liboat_fd_path), "/proc/%d/fd/%d", getpid(), hooker_fd);

    setenv("LD_PRELOAD", liboat_fd_path, 1);
    LOGD("Set env LD_PRELOAD=%s", liboat_fd_path);

    fexecve(stock_fd, (char **)new_argv, environ);

    PLOGE("fexecve failed");

    close(stock_fd);

    return 2;
}
