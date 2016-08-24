/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <lib/mntentex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <limits.h>

#include <lib/mounts.h>
#include <common.h>

static inline void
free_volume_internals(const mounted_volume_t *volume)
{
    free((char *)volume->device);
    free((char *)volume->mount_root);
    free((char *)volume->mount_point);
    free((char *)volume->filesystem);
    free((char *)volume->flags);
    free((mounted_volume_t *)volume);
}

void free_mounts_state(mounts_state_t *mounts_state)
{
    while (!list_is_empty(mounts_state)) {
        mounted_volume_t *volume = list_remove_tail_type(mounts_state, mounted_volume_t, node);
        free_volume_internals(volume);
    }
}

#define PROC_MOUNTS_FILENAME   MBPATH_PROC"/1/mountinfo"

int
scan_mounted_volumes(mounts_state_t *mounts_state)
{
    FILE *fp;
    mntentex_t *mentry;
    mntentex_t buf_mntent;
    char buf_mntstr[PATH_MAX];

    /* Free the old volume state.
     */
    free_mounts_state(mounts_state);

    /* Open and read mount table entries. */
    fp = setmntentex(PROC_MOUNTS_FILENAME, "r");
    if (fp == NULL) {
        return -1;
    }
    while ((mentry = getmntentex(fp, &buf_mntent, buf_mntstr, sizeof(buf_mntstr))) != NULL) {
        mounted_volume_t *v = safe_calloc(1, sizeof(mounted_volume_t));
        v->id = mentry->mnt_id;
        v->parentid = mentry->mnt_pid;
        v->major = mentry->mnt_major;
        v->minor = mentry->mnt_minor;
        v->device = safe_strdup(mentry->mnt_fsname);
        v->mount_root = safe_strdup(mentry->mnt_root);
        v->mount_point = safe_strdup(mentry->mnt_dir);
        v->filesystem = safe_strdup(mentry->mnt_type);
        v->flags = safe_strdup(mentry->mnt_opts);

        list_add_tail(mounts_state, &v->node);
    }
    endmntentex(fp);
    return 0;
}

const mounted_volume_t *
find_mounted_volume_by_device(mounts_state_t *mounts_state, const char *device)
{
    mounted_volume_t *v;
    list_for_every_entry(mounts_state, v, mounted_volume_t, node) {
        /* May be null if it was unmounted and we haven't rescanned.
         */
        if (v->device != NULL) {
            if (strcmp(v->device, device) == 0) {
                return v;
            }
        }
    }

    return NULL;
}

const mounted_volume_t *
find_mounted_volume_by_mount_point(mounts_state_t *mounts_state, const char *mount_point)
{
    mounted_volume_t *v;
    list_for_every_entry(mounts_state, v, mounted_volume_t, node) {
        /* May be null if it was unmounted and we haven't rescanned.
         */
        if (v->mount_point != NULL) {
            if (strcmp(v->mount_point, mount_point) == 0) {
                return v;
            }
        }
    }
    return NULL;
}

const mounted_volume_t *
find_mounted_volume_by_majmin(mounts_state_t *mounts_state, unsigned major, unsigned minor, int with_bindmounts)
{
    mounted_volume_t *v;
    list_for_every_entry(mounts_state, v, mounted_volume_t, node) {
        if (v->major == major && v->minor == minor) {
            if (with_bindmounts || !strcmp(v->mount_root, "/"))
                return v;
        }
    }
    return NULL;
}

int
unmount_mounted_volume(const mounted_volume_t *volume)
{
    /* Intentionally pass NULL to umount if the caller tries
     * to unmount a volume they already unmounted using this
     * function.
     */
    int ret = umount(volume->mount_point);
    if (ret == 0) {
        list_delete((list_node_t *)&volume->node);
        free_volume_internals(volume);
        return 0;
    }
    return ret;
}

int
remount_read_only(const mounted_volume_t *volume)
{
    return mount(volume->device, volume->mount_point, volume->filesystem,
                 MS_NOATIME | MS_NODEV | MS_NODIRATIME |
                 MS_RDONLY | MS_REMOUNT, 0);
}
