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

#ifndef MTDUTILS_MOUNTS_H_
#define MTDUTILS_MOUNTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <lib/list.h>

typedef struct {
    list_node_t node;

    int id;
    int parentid;
    unsigned major;
    unsigned minor;
    const char *device;
    const char *mount_root;
    const char *mount_point;
    const char *filesystem;
    const char *flags;
} mounted_volume_t;

typedef list_node_t mounts_state_t;

void free_mounts_state(mounts_state_t *mounts_state);

int scan_mounted_volumes(mounts_state_t *mounts_state);

const mounted_volume_t *find_mounted_volume_by_device(mounts_state_t *mounts_state, const char *device);

const mounted_volume_t *
find_mounted_volume_by_mount_point(mounts_state_t *mounts_state, const char *mount_point);
const mounted_volume_t *
find_mounted_volume_by_majmin(mounts_state_t *mounts_states, unsigned major, unsigned minor, int with_bindmounts);

int unmount_mounted_volume(const mounted_volume_t *volume);

int remount_read_only(const mounted_volume_t *volume);

#ifdef __cplusplus
}
#endif

#endif  // MTDUTILS_MOUNTS_H_
