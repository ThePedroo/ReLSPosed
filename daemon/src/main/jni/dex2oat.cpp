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
 * Copyright (C) 2023 LSPosed Contributors
 */
#include <fcntl.h>
#include <jni.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "logging.h"
#include <errno.h>

extern "C" JNIEXPORT void JNICALL Java_org_lsposed_lspd_service_Dex2OatService_doMountNative(
    JNIEnv *env, jobject, jboolean enabled, jstring r32, jstring d32, jstring r64, jstring d64) {
    char dex2oat32[PATH_MAX], dex2oat64[PATH_MAX];
    realpath("bin/dex2oat32", dex2oat32);
    realpath("bin/dex2oat64", dex2oat64);

    if (pid_t pid = fork(); pid > 0) {  // parent
        waitpid(pid, nullptr, 0);
    } else {  // child
        int ns = open("/proc/1/ns/mnt", O_RDONLY);
        setns(ns, CLONE_NEWNS);
        close(ns);

        const char *r32p, *d32p, *r64p, *d64p;
        if (r32) r32p = env->GetStringUTFChars(r32, nullptr);
        if (d32) d32p = env->GetStringUTFChars(d32, nullptr);
        if (r64) r64p = env->GetStringUTFChars(r64, nullptr);
        if (d64) d64p = env->GetStringUTFChars(d64, nullptr);

        if (enabled) {
            LOGI("Enable dex2oat wrapper");
            if (r32) {
                mount(dex2oat32, r32p, nullptr, MS_BIND, nullptr);
                mount(nullptr, r32p, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
            }
            if (d32) {
                mount(dex2oat32, d32p, nullptr, MS_BIND, nullptr);
                mount(nullptr, d32p, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
            }
            if (r64) {
                mount(dex2oat64, r64p, nullptr, MS_BIND, nullptr);
                mount(nullptr, r64p, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
            }
            if (d64) {
                mount(dex2oat64, d64p, nullptr, MS_BIND, nullptr);
                mount(nullptr, d64p, nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr);
            }
        } else {
            LOGI("Disable dex2oat wrapper");
            if (r32) umount(r32p);
            if (d32) umount(d32p);
            if (r64) umount(r64p);
            if (d64) umount(d64p);
        }

        PLOGE("Failed to resetprop");
        exit(1);
    }
}

static int setsockcreatecon_raw(const char *context) {
    std::string path = "/proc/self/task/" + std::to_string(gettid()) + "/attr/sockcreate";
    int fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    int ret;
    if (context) {
        do {
            ret = write(fd, context, strlen(context) + 1);
        } while (ret < 0 && errno == EINTR);
    } else {
        do {
            ret = write(fd, nullptr, 0);  // clear
        } while (ret < 0 && errno == EINTR);
    }
    close(fd);
    return ret < 0 ? -1 : 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_lsposed_lspd_service_Dex2OatService_setSockCreateContext(JNIEnv *env, jclass,
                                                                  jstring contextStr) {
    const char *context = env->GetStringUTFChars(contextStr, nullptr);
    int ret = setsockcreatecon_raw(context);
    env->ReleaseStringUTFChars(contextStr, context);
    return ret == 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_lsposed_lspd_service_Dex2OatService_getSockPath(JNIEnv *env, jobject) {
    return env->NewStringUTF("5291374ceda0aef7c5d86cd2a4f6a3ac\0");
}

// ------------------------------------------------------------------------------------------------------------------------------------------------
/* INFO: Code below contains parts of the code of the ReZygisk's Daemon. It is protected by its AGPL 3.0.0 license by The PerformanC Organization.
           See https://github.com/PerformanC/ReZygisk repository for more details. */
// ------------------------------------------------------------------------------------------------------------------------------------------------

bool exec_command(char *buf, size_t len, const char *file, const char *argv[]) {
    int link[2];
    pid_t pid;

    if (pipe(link) == -1) {
        LOGE("pipe: %s\n", strerror(errno));

        return false;
    }

    if ((pid = fork()) == -1) {
        LOGE("fork: %s\n", strerror(errno));

        close(link[0]);
        close(link[1]);

        return false;
    }

    if (pid == 0) {
        dup2(link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);

        execv(file, (char *const *)argv);

        LOGE("execv failed: %s\n", strerror(errno));
        _exit(1);
    } else {
        close(link[1]);

        ssize_t nbytes = read(link[0], buf, len);
        if (nbytes > 0) buf[nbytes - 1] = '\0';
        /* INFO: If something went wrong, at least we must ensure it is NULL-terminated */
        else buf[0] = '\0';

        wait(NULL);

        close(link[0]);
    }

    return true;
}

#define KERNEL_SU_OPTION (int)0xdeadbeef
#define KERNELSU_CMD_GET_VERSION 2
#define KERNELSU_CMD_UID_SHOULD_UMOUNT 13

static int root_impl = -1;
static bool ksu_get_existence() {
    int version = 0;
    int reply_ok = 0;

    prctl((signed int)KERNEL_SU_OPTION, KERNELSU_CMD_GET_VERSION, &version, 0, &reply_ok);

    if (version != 0) {
        LOGD("KernelSU version: %d", version);
        root_impl = 1;

        return true;
    }

    return false;
}

static bool ksu_is_in_denylist(uid_t app_uid) {
    bool umount = false;

    int reply_ok = 0;
    prctl((signed int)KERNEL_SU_OPTION, KERNELSU_CMD_UID_SHOULD_UMOUNT, app_uid, &umount, &reply_ok);

    return umount;
}

#if (defined(__LP64__) || defined(_LP64))
  #define lp_select(a, b) b
#else
  #define lp_select(a, b) a
#endif

#define SBIN_MAGISK lp_select("/sbin/magisk32", "/sbin/magisk64")
#define BITLESS_SBIN_MAGISK "/sbin/magisk"
#define DEBUG_RAMDISK_MAGISK lp_select("/debug_ramdisk/magisk32", "/debug_ramdisk/magisk64")
#define BITLESS_DEBUG_RAMDISK_MAGISK "/debug_ramdisk/magisk"


static char path_to_magisk[sizeof(DEBUG_RAMDISK_MAGISK)] = { 0 };
bool is_using_sulist = false;

static bool magisk_get_existence() {
    const char *magisk_files[] = {
        SBIN_MAGISK,
        BITLESS_SBIN_MAGISK,
        DEBUG_RAMDISK_MAGISK,
        BITLESS_DEBUG_RAMDISK_MAGISK
    };

    for (size_t i = 0; i < sizeof(magisk_files) / sizeof(magisk_files[0]); i++) {
        if (access(magisk_files[i], F_OK) != 0) {
            if (errno != ENOENT) {
                LOGE("Failed to access Magisk binary: %s\n", strerror(errno));
            }
            errno = 0;

            continue;
        }

        strcpy(path_to_magisk, magisk_files[i]);

        break;
    }

    if (path_to_magisk[0] == '\0')
        return false;

    const char *argv[] = { "magisk", "-V", NULL };

    char magisk_version[32];
    if (!exec_command(magisk_version, sizeof(magisk_version), (const char *)path_to_magisk, argv)) {
        LOGE("Failed to execute magisk binary: %s\n", strerror(errno));
        errno = 0;

        return false;
    }

    /* INFO: Magisk Kitsune has a feature called SuList, which is a whitelist of
                which processes are allowed to see root. Although only Kitsune has
                this option, there are Kitsune forks without "-kitsune" suffix, so
                to avoid excluding them from taking advantage of that feature, we
                will not check the variant.
    */
    const char *argv_sulist[] = { "magisk", "--sqlite", "select value from settings where key = 'sulist' limit 1", NULL };

    char sulist_enabled[32];
    if (!exec_command(sulist_enabled, sizeof(sulist_enabled), (const char *)path_to_magisk, argv_sulist)) {
        LOGE("Failed to execute magisk binary: %s\n", strerror(errno));
        errno = 0;

        return false;
    }

    root_impl = 2;

    return true;
}

bool magisk_is_in_denylist(const char *const process) {
    #define PROCESS_NAME_MAX_LEN 256 + 1
    char sqlite_cmd[51 + PROCESS_NAME_MAX_LEN];
    if (is_using_sulist)
      snprintf(sqlite_cmd, sizeof(sqlite_cmd), "SELECT 1 FROM sulist WHERE process=\"%s\" LIMIT 1", process);
    else
      snprintf(sqlite_cmd, sizeof(sqlite_cmd), "SELECT 1 FROM denylist WHERE process=\"%s\" LIMIT 1", process);

    const char *argv[] = { "magisk", "--sqlite", sqlite_cmd, NULL };

    char result[sizeof("1=1")];
    if (!exec_command(result, sizeof(result), (const char *)path_to_magisk, argv)) {
      LOGE("Failed to execute magisk binary: %s\n", strerror(errno));
      errno = 0;

      return false;
    }

    if (is_using_sulist) return result[0] == '\0';
    else return result[0] != '\0';
}


bool apatch_get_existence() {
    struct stat s;
    if (stat("/data/adb/apd", &s) != 0) {
        errno = 0;

        return false;
    }

    char apatch_version[32];
    const char *argv[] = { "apd", "-V", NULL };

    if (!exec_command(apatch_version, sizeof(apatch_version), "/data/adb/apd", argv)) {
        LOGE("Failed to execute apd binary: %s\n", strerror(errno));

        errno = 0;

        return false;
    }

    int version = atoi(apatch_version + strlen("apd "));

    if (version >= 10655 && version <= 999999) {
        root_impl = 3;

        return true;
    }

    LOGE("Unsupported APatch version: %d", version);

    return false;
}

struct package_config {
    char *process;
    uid_t uid;
    bool root_granted;
    bool umount_needed;
};

struct packages_config {
    struct package_config *configs;
    size_t size;
};

void _apatch_free_package_config(struct packages_config *config) {
    for (size_t i = 0; i < config->size; i++) {
        free(config->configs[i].process);
    }

    free(config->configs);
}

bool _apatch_get_package_config(struct packages_config *config) {
    config->configs = NULL;
    config->size = 0;

    FILE *fp = fopen("/data/adb/ap/package_config", "r");
    if (fp == NULL) {
        LOGE("Failed to open APatch's package_config: %s\n", strerror(errno));

        return false;
    }

    char line[1048];
    /* INFO: Skip the CSV header */
    if (fgets(line, sizeof(line), fp) == NULL) {
        LOGE("Failed to read APatch's package_config header: %s\n", strerror(errno));

        fclose(fp);

        return false;
    }

    while (fgets(line, sizeof(line), fp) != NULL) { 
        struct package_config *tmp_configs = (struct package_config *)realloc(config->configs, (config->size + 1) * sizeof(struct package_config));
        if (tmp_configs == NULL) {
            LOGE("Failed to realloc APatch config struct: %s\n", strerror(errno));

            _apatch_free_package_config(config);
            fclose(fp);

            return false;
        }
        config->configs = tmp_configs;

        config->configs[config->size].process = strdup(strtok(line, ","));

        char *exclude_str = strtok(NULL, ",");
        if (exclude_str == NULL) continue;

        char *allow_str = strtok(NULL, ",");
        if (allow_str == NULL) continue;

        char *uid_str = strtok(NULL, ",");
        if (uid_str == NULL) continue;

        config->configs[config->size].uid = (uid_t)atoi(uid_str);
        config->configs[config->size].root_granted = strcmp(allow_str, "1") == 0;
        config->configs[config->size].umount_needed = strcmp(exclude_str, "1") == 0;

        config->size++;
    }

    fclose(fp);

    return true;
}

bool apatch_uid_should_umount(const char *const process) {
    struct packages_config config;
    if (!_apatch_get_package_config(&config)) return false;

    size_t targeted_process_length = strlen(process);

    for (size_t i = 0; i < config.size; i++) {
        size_t config_process_length = strlen(config.configs[i].process);
        size_t smallest_process_length = targeted_process_length < config_process_length ? targeted_process_length : config_process_length;

        if (strncmp(config.configs[i].process, process, smallest_process_length) != 0) continue;

        /* INFO: This allow us to copy the information to avoid use-after-free */
        bool umount_needed = config.configs[i].umount_needed;

        _apatch_free_package_config(&config);

        return umount_needed;
    }

    _apatch_free_package_config(&config);

    return false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_lsposed_lspd_service_Dex2OatService_isInDenylist(JNIEnv *env, jobject, jstring appName) {
    const char *app_name = env->GetStringUTFChars(appName, nullptr);
    if (app_name == nullptr) {
        LOGE("Failed to get app name string");

        return JNI_FALSE;
    }

    char app_data_dir[PATH_MAX];
    snprintf(app_data_dir, sizeof(app_data_dir), "/data/data/%s", app_name);

    struct stat st;
    if (stat(app_data_dir, &st) == -1) {
        PLOGE("Failed to stat %s", app_data_dir);

        goto app_not_in_denylist;
    }

    if (root_impl == -1 && !ksu_get_existence() && !magisk_get_existence() && !apatch_get_existence()) {
        LOGE("No supported root implementation found, skipping denylist check");

        goto app_not_in_denylist;
    }

    if (root_impl == 1) {
        if (ksu_is_in_denylist(st.st_uid)) {
            LOGI("App %s is in KernelSU denylist", app_name);

            goto app_in_denylist;
        }

        goto app_not_in_denylist;
    }

    if (root_impl == 2) {
        if (magisk_is_in_denylist(app_name)) {
            LOGI("App %s is in Magisk denylist", app_name);

            goto app_in_denylist;
        }

        goto app_not_in_denylist;
    }

    if (root_impl == 3) {
        if (apatch_uid_should_umount(app_name)) {
            LOGI("App %s is in APatch denylist", app_name);

            goto app_in_denylist;
        }

        goto app_not_in_denylist;
    }

    env->ReleaseStringUTFChars(appName, app_name);

    LOGE("No supported root implementation found, skipping denylist check");

    app_in_denylist:
        env->ReleaseStringUTFChars(appName, app_name);

        return JNI_TRUE;
    app_not_in_denylist:
        env->ReleaseStringUTFChars(appName, app_name);

        return JNI_FALSE;
}
