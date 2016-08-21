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

typedef struct {
    int id;
    int parentid;
    unsigned major;
    unsigned minor;
    const char *mount_root;
    const char *mount_point;
    const char *flags;
    const char *filesystem;
    const char *device;
    const char *fsflags;
} mounted_volume_t;

typedef struct {
    mounted_volume_t *volumes;
    int volumes_allocd;
    int volume_count;
} mounts_state_t;

void free_mounts_state(mounts_state_t* mounts_states);

int scan_mounted_volumes(mounts_state_t* mounts_states);
void dump_mounted_volumes(mounts_state_t* mounts_states);

const mounted_volume_t *find_mounted_volume_by_device(mounts_state_t* mounts_states, const char *device, int with_bindmounts);
const mounted_volume_t *
find_mounted_volume_by_mount_point(mounts_state_t* mounts_states, const char *mount_point);
const mounted_volume_t *
find_mounted_volume_by_majmin(mounts_state_t* mounts_states, unsigned major, unsigned minor, int with_bindmounts);

int unmount_mounted_volume(const mounted_volume_t *volume);
int unmount_mounted_volume_detach(const mounted_volume_t *volume);
int remount_read_only(const mounted_volume_t* volume);

#ifdef __cplusplus
}
#endif

#endif  // MTDUTILS_MOUNTS_H_
