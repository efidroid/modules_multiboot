/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include <limits.h>
#include <util.h>

#include "fs_mgr_priv.h"

struct fstab_rec *fs_mgr_esp(struct fstab *fstab)
{
    int i = 0;

    if (!fstab) {
        return NULL;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (fstab->recs[i].esp)
            return &fstab->recs[i];
    }

    return NULL;
}

struct fstab_rec *fs_mgr_nvvars(struct fstab *fstab)
{
    int i = 0;

    if (!fstab) {
        return NULL;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (fs_mgr_is_nvvars(&fstab->recs[i]))
            return &fstab->recs[i];
    }

    return NULL;
}

struct fstab_rec *fs_mgr_get_by_ueventblock(struct fstab *fstab, uevent_block_t *block)
{
    int i = 0;
    char buf[PATH_MAX];
    char *fstype = NULL;
    struct fstab_rec *ret = NULL;
    int rc;

    if (!fstab) {
        return NULL;
    }

    // build dev name
    rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/%s", block->devname);
    if (rc<0 || (size_t)rc>=sizeof(buf)) {
        return NULL;
    }

    // get fstype
    fstype = util_get_fstype(buf);

    for (i = 0; i < fstab->num_entries; i++) {
        uevent_block_t *fstab_block = get_blockinfo_for_path(multiboot_get_data()->blockinfo, fstab->recs[i].blk_device);
        if (!fstab_block)
            continue;

        // assume that we only have one global blockinfo list
        if (fstab_block==block) {
            ret = &fstab->recs[i];
            break;
        }
    }

    free(fstype);
    return ret;
}

struct fstab_rec *fs_mgr_get_by_mountpoint(struct fstab *fstab, const char *mount_point)
{
    int i = 0;

    if (!fstab) {
        return NULL;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (!strcmp(fstab->recs[i].mount_point, mount_point))
            return &fstab->recs[i];
    }

    return NULL;
}

struct fstab_rec *fs_mgr_get_by_name(struct fstab *fstab, const char *name)
{
    int i = 0;

    if (!fstab) {
        return NULL;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (!strcmp(fstab->recs[i].mount_point+1, name))
            return &fstab->recs[i];
    }

    return NULL;
}
