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
 * Copyright (C) 2021 - 2022 LSPosed Contributors
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "config_impl.h"
#include "magisk_loader.h"
#include "zygisk.hpp"

namespace lspd {

int allow_unload = 0;
int *allowUnload = &allow_unload;
bool should_ignore = false;

class ZygiskModule : public zygisk::ModuleBase {
    JNIEnv *env_;
    zygisk::Api *api_;

    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        env_ = env;
        api_ = api;
        MagiskLoader::Init();
        ConfigImpl::Init();
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        int cfd = api_->connectCompanion();
        if (cfd < 0) {
            LOGE("Failed to connect to companion: %s", strerror(errno));
            return;
        }

        uint8_t injection_hardening_disabled = 0;
        if (read(cfd, &injection_hardening_disabled, sizeof(injection_hardening_disabled)) < 0) {
            LOGE("Failed to read from companion socket: %s", strerror(errno));
        }

        close(cfd);

        if (!injection_hardening_disabled) {
            uint32_t flags = api_->getFlags();
            if ((flags & zygisk::PROCESS_ON_DENYLIST) == 0) goto bypass_denylist;

            const char *shell_name = "com.android.shell";
            const char *lsp_manager = "org.lsposed.manager";
            const char *name = env_->GetStringUTFChars(args->nice_name, nullptr);
            if (!name) {
                LOGE("Failed to get process name");
                should_ignore = true;
                return;
            }

            bool isShell = strcmp(name, shell_name) == 0;
            bool isLspManager = strcmp(name, lsp_manager) == 0;
            if (isShell || isLspManager) {
                LOGD("Process is com.android.shell or org.lsposed.manager, bypassing denylist check");
                env_->ReleaseStringUTFChars(args->nice_name, name);
                goto bypass_denylist;
            }

            LOGE("Process {} is on denylist, cannot specialize", name);
            env_->ReleaseStringUTFChars(args->nice_name, name);
            should_ignore = true;
            return;
        } else {
            LOGD("Injection hardening is disabled");
        }

        bypass_denylist:
            MagiskLoader::GetInstance()->OnNativeForkAndSpecializePre(
                env_, args->uid, args->gids, args->nice_name,
                args->is_child_zygote ? *args->is_child_zygote : false, args->app_data_dir);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (should_ignore) {
            LOGD("Ignoring postAppSpecialize due to injection hardening being enabled");
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        MagiskLoader::GetInstance()->OnNativeForkAndSpecializePost(env_, args->nice_name,
                                                                   args->app_data_dir);
        if (*allowUnload) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void preServerSpecialize([[maybe_unused]] zygisk::ServerSpecializeArgs *args) override {
        MagiskLoader::GetInstance()->OnNativeForkSystemServerPre(env_);
    }

    void postServerSpecialize([[maybe_unused]] const zygisk::ServerSpecializeArgs *args) override {
        if (__system_property_find("ro.vendor.product.ztename")) {
            auto *process = env_->FindClass("android/os/Process");
            auto *set_argv0 = env_->GetStaticMethodID(process, "setArgV0", "(Ljava/lang/String;)V");
            auto *name = env_->NewStringUTF("system_server");
            env_->CallStaticVoidMethod(process, set_argv0, name);
            env_->DeleteLocalRef(name);
            env_->DeleteLocalRef(process);
        }
        MagiskLoader::GetInstance()->OnNativeForkSystemServerPost(env_);
        if (*allowUnload) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
};
}  // namespace lspd

void relsposed_companion(int lib_fd) {
    /* INFO: The only current task we do in companion now is to check if
               /data/adb/disable_injection_hardening file exists. */
    uint8_t file_exists = 0;
    if (access("/data/adb/disable_injection_hardening", F_OK) == 0) {
        LOGD("Found /data/adb/disable_injection_hardening, disabling injection hardening");

        file_exists = 1;
    }

    if (write(lib_fd, &file_exists, sizeof(file_exists)) < 0) {
        LOGE("Failed to write to companion socket: %s", strerror(errno));
    }

    close(lib_fd);
}

REGISTER_ZYGISK_MODULE(lspd::ZygiskModule);
REGISTER_ZYGISK_COMPANION(relsposed_companion);
