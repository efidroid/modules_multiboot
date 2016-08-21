/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <lib/fs_mgr.h>
#include <lib/uevent.h>
#include <lib/mounts.h>

#include <common.h>
#include <util.h>
#include <lib/list.h>

#define LOG_TAG "BOOT_RECOVERY"
#include <lib/log.h>

int boot_recovery(void) {
    int rc;

    util_setup_partition_replacements();

    // run and trace init
    rc = run_init(true);
    if(rc) {
        MBABORT("Can't trace init: %s\n", strerror(errno));
    }

    MBABORT_RET("init returned\n");
}
