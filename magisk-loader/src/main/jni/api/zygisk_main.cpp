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
#include <sstream>

#include "config_impl.h"
#include "magisk_loader.h"
#include "zygisk.hpp"

#define SKIP_TARGET_LIST_PATH "/data/adb/lspd/skip_list.txt"

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
        const char *pkgName = env_->GetStringUTFChars(args->nice_name, nullptr);

        long targetSize = 0;
        int cfd = api_->connectCompanion();
        std::string_view process(pkgName);

        // Send package name to companion
        std::string processStr(process);
        long processSize = processStr.size();
        write(cfd, &processSize, sizeof(long));
        write(cfd, processStr.data(), processSize);

        read(cfd, &targetSize, sizeof(long));
        targetVector.resize(targetSize);
        read(cfd, targetVector.data(), targetSize);

        close(cfd);

        parseTargetVector();

        if (isTargetPackage(pkgName)) {
            LOGD("Process {} is on hardening skip_list.txt, cannot specialize", pkgName);
            env_->ReleaseStringUTFChars(args->nice_name, pkgName);
            should_ignore = true;
            return;
        }

        env_->ReleaseStringUTFChars(args->nice_name, pkgName);

        MagiskLoader::GetInstance()->OnNativeForkAndSpecializePre(
            env_, args->uid, args->gids, args->nice_name,
            args->is_child_zygote ? *args->is_child_zygote : false, args->app_data_dir);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (should_ignore) {
            LOGD("Ignoring postAppSpecialize for {} due to injection hardening", args->nice_name);
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        targetVector.clear();
        targetPackages.clear();

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

private:
    std::vector<char> targetVector;
    std::vector<std::string> targetPackages;

    void parseTargetVector() {
        if (targetVector.empty()) {
            return;
        }
        std::string content(targetVector.begin(), targetVector.end());
        std::stringstream ss(content);
        std::string line;
        while (std::getline(ss, line)) {
            std::string trimmedLine = "";
            for (char c : line) {
                if (!std::isspace(c)) {
                    trimmedLine += c;
                }
            }
            if (!trimmedLine.empty() && trimmedLine[0] != '#') {
                std::string finalTrimmedLine = "";
                int lastNonSpace = trimmedLine.length() - 1;
                while (lastNonSpace >= 0 && std::isspace(trimmedLine[lastNonSpace])) {
                    lastNonSpace--;
                }
                if (lastNonSpace >= 0) {
                    finalTrimmedLine = trimmedLine.substr(0, lastNonSpace + 1);
                } else {
                    finalTrimmedLine = trimmedLine;
                }
                targetPackages.push_back(finalTrimmedLine);
            }
        }
    }

    bool isTargetPackage(std::string_view pkgName) {

        //Don't process this shell
        if (pkgName == "com.android.shell") return false;

        std::string pkgStr(pkgName);
        for (const auto &pkg : targetPackages) {
            if (pkg == pkgStr) {
                return true;
            }
        }
        return false;
    }
};
}  // namespace lspd

void relsposed_companion(int lib_fd) {
    long targetSize = 0;
    std::vector<char> targetVector;

    FILE *target = fopen(SKIP_TARGET_LIST_PATH, "r");
    if (target) {
        fseek(target, 0, SEEK_END);
        targetSize = ftell(target);
        fseek(target, 0, SEEK_SET);

        targetVector.resize(targetSize);
        fread(targetVector.data(), 1, targetSize, target);

        fclose(target);
    }

    write(lib_fd, &targetSize, sizeof(long));
    write(lib_fd, targetVector.data(), targetSize);
}

REGISTER_ZYGISK_MODULE(lspd::ZygiskModule);
REGISTER_ZYGISK_COMPANION(relsposed_companion);
