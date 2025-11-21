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
// -------------------------------------------------------------------------------------------------------------
/* INFO: Code below contains parts of the code of the KernelSU's Daemon. It is protected by its GPL-3.0 license.
           See https://github.com/tiann/KernelSU repository for more details. */
// -------------------------------------------------------------------------------------------------------------


#ifndef RELSPOSED_KSU_H
#define RELSPOSED_KSU_H

#include <stdint.h>
#include <sys/ioctl.h>

struct ksu_get_info_cmd {
    uint32_t version;
    uint32_t flags;
    uint32_t features;
};

struct ksu_uid_should_umount_cmd {
    uint32_t uid;
    uint8_t should_umount;
};

#define KERNEL_SU_OPTION (int)0xdeadbeef
#define KERNELSU_CMD_GET_VERSION 2
#define KERNELSU_CMD_UID_SHOULD_UMOUNT 13

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

#define KSU_IOCTL_GET_INFO _IOC(_IOC_READ, 'K', 2, 0)
#define KSU_IOCTL_UID_SHOULD_UMOUNT _IOC(_IOC_READ | _IOC_WRITE, 'K', 9, 0)

#endif //RELSPOSED_KSU_H
