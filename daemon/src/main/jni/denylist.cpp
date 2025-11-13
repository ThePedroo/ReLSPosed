/*
 * This file is part of ReLSPosed.
 *
 * ReLSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ReLSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ReLSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2023 The PerformanC Organization Contributors
 */
// ------------------------------------------------------------------------------------------------------------------------------------------------
/* INFO: Code below contains parts of the code of the ReZygisk's Daemon. It is protected by its AGPL 3.0.0 license by The PerformanC Organization.
           See https://github.com/PerformanC/ReZygisk repository for more details. */
// ------------------------------------------------------------------------------------------------------------------------------------------------

#include <fcntl.h>
#include <jni.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>

#include "ksu.h"
#include "logging.h"
#include "packagename.h"

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

/*
 * Root implementation indicator
 *
 * -1 - None
 *  1 - KernelSU
 *  2 - Magisk
 *  3 - APatch
 */
static int root_impl = -1;

static int ksu_fd = -1;

static bool prepare_ksu_fd() {
    if (ksu_fd >= 0) goto ksu_fd_return_success;

    LOGD("Prepare KSU fd: Trying to send ksu option");

    syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, (void*)&ksu_fd);

    LOGD("Prepare KSU fd: %x", ksu_fd);

    return ksu_fd >= 0;

    ksu_fd_return_success:
    return true;
}

static void ksu_close_fd() {
    if (ksu_fd >= 0) {
        close(ksu_fd);
        ksu_fd = -1;
    }
}

static bool ksu_get_existence() {
    int version = 0;
    int reply_ok = 0;

    if (prepare_ksu_fd()) {
        struct ksu_get_info_cmd g_version {};

        syscall(SYS_ioctl, ksu_fd, KSU_IOCTL_GET_INFO, &g_version);

        if (g_version.version > 0) {
            LOGD("KernelSU version: %d (IOCTL)", g_version.version);

            root_impl = 1;

            goto ksu_exist_return_success;
        } else {
            ksu_close_fd();
        }
    }

    prctl((signed int)KERNEL_SU_OPTION, KERNELSU_CMD_GET_VERSION, &version, 0, &reply_ok);

    if (version != 0) {
        LOGD("KernelSU version: %d (PRCTL)", version);

        root_impl = 1;

        goto ksu_exist_return_success;
    }

    return false;

    ksu_exist_return_success:
    return true;
}

static bool ksu_is_in_denylist(uid_t app_uid) {
    bool umount = false;
    int reply_ok = 0;

    if (prepare_ksu_fd()) {
        struct ksu_uid_should_umount_cmd cmd = { app_uid };

        syscall(SYS_ioctl, ksu_fd, KSU_IOCTL_UID_SHOULD_UMOUNT, &cmd);

        umount = !!cmd.should_umount;
        goto ksu_return_umount;
    }

    prctl((signed int)KERNEL_SU_OPTION, KERNELSU_CMD_UID_SHOULD_UMOUNT, app_uid, &umount, &reply_ok);

    ksu_return_umount:
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
Java_org_lsposed_lspd_service_DenylistManager_isInDenylist(JNIEnv *env, jclass, jstring appName) {
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

extern "C" JNIEXPORT jboolean JNICALL
Java_org_lsposed_lspd_service_DenylistManager_isInDenylistFromClasspathDir(JNIEnv *env, jclass, jstring classpathDirArg) {
    const char *classpath_dir_arg = env->GetStringUTFChars(classpathDirArg, nullptr);

    if (classpath_dir_arg == nullptr) {
        LOGE("Failed to get classpathdir string");
        return JNI_FALSE;
    }

    int app_name_len = 0;
    char app_name[256] = { 0 };
    app_name_len = get_pkg_from_classpath_arg(classpath_dir_arg, app_name, sizeof(app_name));
    
    if(app_name_len == -1)
    {
        LOGE("Unknown classpath dir: %s", classpath_dir_arg);
        return JNI_FALSE;
    }
    env->ReleaseStringUTFChars(classpathDirArg, classpath_dir_arg);

    char app_data_dir[1024] = {0};
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

    LOGE("No supported root implementation found, skipping denylist check");
    
    app_not_in_denylist:
        return JNI_FALSE;

    app_in_denylist:
        return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_org_lsposed_lspd_service_DenylistManager_clearFd(JNIEnv *env, jclass) {
    ksu_close_fd();
}
