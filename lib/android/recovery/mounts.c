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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <unistd.h>
#include <limits.h>

#include <lib/mounts.h>

#define LOG_TAG "MOUNTS"
#include <lib/log.h>

typedef struct {
    mounted_volume_t *volumes;
    int volumes_allocd;
    int volume_count;
} mounts_state_t;

static mounts_state_t g_mounts_state = {
    NULL,   // volumes
    0,      // volumes_allocd
    0       // volume_count
};

static inline void
free_volume_internals(const mounted_volume_t *volume, int zero)
{
    free((char *)volume->mount_root);
    free((char *)volume->mount_point);
    free((char *)volume->flags);
    free((char *)volume->filesystem);
    free((char *)volume->device);
    free((char *)volume->fsflags);
    if (zero) {
        memset((void *)volume, 0, sizeof(*volume));
    }
}

#define PROC_MOUNTS_FILENAME   "/proc/1/mountinfo"
#define PROC_MOUNTS_BUFSIZE 4096
int
scan_mounted_volumes(void)
{
    char *buf = NULL;
    const char *bufp;
    int fd;
    ssize_t nbytes;

    if (g_mounts_state.volumes == NULL) {
        const int numv = 32;
        mounted_volume_t *volumes = malloc(numv * sizeof(*volumes));
        if (volumes == NULL) {
            errno = ENOMEM;
            return -1;
        }
        g_mounts_state.volumes = volumes;
        g_mounts_state.volumes_allocd = numv;
        memset(volumes, 0, numv * sizeof(*volumes));
    } else {
        /* Free the old volume strings.
         */
        int i;
        for (i = 0; i < g_mounts_state.volume_count; i++) {
            free_volume_internals(&g_mounts_state.volumes[i], 1);
        }
    }
    g_mounts_state.volume_count = 0;

    buf = calloc(PROC_MOUNTS_BUFSIZE, 1);
    if(!buf) {
        goto bail;
    }

    /* Open and read the file contents.
     */
    fd = open(PROC_MOUNTS_FILENAME, O_RDONLY);
    if (fd < 0) {
        goto bail;
    }
    nbytes = read(fd, buf, PROC_MOUNTS_BUFSIZE - 1);
    close(fd);
    if (nbytes < 0) {
        goto bail;
    }
    buf[nbytes] = '\0';

    /* Parse the contents of the file, which looks like:
     *
     *     # cat /proc/1/mountinfo
     *     1 1 0:1 / / rw - rootfs rootfs rw,seclabel
     *     12 11 0:9 / /dev/pts rw,relatime - devpts devpts rw,seclabel,mode=600
     *     13 1 0:3 / /proc rw,relatime - proc proc rw
     *     14 1 0:12 / /sys rw,relatime - sysfs sysfs rw,seclabel
     *     22 1 179:23 / /system rw,relatime - ext4 /dev/block/mmcblk0p23 rw,seclabel,data=ordered
     *     18 1 179:26 / /data rw,relatime - ext4 /dev/block/mmcblk0p26 rw,seclabel,data=ordered
     *     21 1 179:27 / /sdcard rw,relatime - ext4 /dev/block/mmcblk0p27 rw,seclabel,data=ordered
     */
    bufp = buf;
    while (nbytes > 0) {
        int id, parentid;
        unsigned major, minor;
        char* mount_root = NULL;
        char* mount_point = NULL;
        char* flags = NULL;
        char* filesystem = NULL;
        char* device = NULL;
        char* fsflags = NULL;
        int matches;

        /* %ms is a gnu extension that malloc()s a string for each field.
         */
        matches = sscanf(bufp, "%i %i %u:%u %ms %ms %ms",
                &id, &parentid, &major, &minor, &mount_root, &mount_point, &flags);

        if (matches != 7) {
            LOGW("matches was %d on <<%.40s>>\n", matches, bufp);
            goto ERR;
        }

        const char* bufp2 = strstr(bufp, " - ");
        if(!bufp2) {
            LOGW("' - ' not found in <<%.40s>>\n", bufp);
            goto ERR;
        }

        matches = sscanf(bufp2, " - %ms %ms %ms", &filesystem, &device, &fsflags);
        if (matches != 3) {
            LOGW("matches was %d on <<%.40s>>\n", matches, bufp2);
            goto ERR;
        }

        mounted_volume_t *v =
                &g_mounts_state.volumes[g_mounts_state.volume_count++];
        v->id = id;
        v->parentid = parentid;
        v->major = major;
        v->minor = minor;
        v->mount_root = mount_root;
        v->mount_point = mount_point;
        v->flags = flags;
        v->filesystem = filesystem;
        v->device = device;
        v->fsflags = fsflags;
        goto NEXT;

ERR:
        free(mount_root);
        free(mount_point);
        free(flags);
        free(filesystem);
        free(device);
        free(fsflags);

NEXT:
        /* Eat the line.
         */
        while (nbytes > 0 && *bufp != '\n') {
            bufp++;
            nbytes--;
        }
        if (nbytes > 0) {
            bufp++;
            nbytes--;
        }
    }

    return 0;

bail:
    free(buf);

//TODO: free the strings we've allocated.
    g_mounts_state.volume_count = 0;
    return -1;
}

void
dump_mounted_volumes(void)
{
    if (g_mounts_state.volumes != NULL) {
        int i;
        for (i = 0; i < g_mounts_state.volume_count; i++) {
            mounted_volume_t *v = &g_mounts_state.volumes[i];
            LOGI("%i %i %u:%u %s %s %s - %s %s %s\n",
                v->id, v->parentid, v->major, v->minor, v->mount_root, v->mount_point, v->flags, v->filesystem, v->device, v->fsflags);
        }
    }
}


const mounted_volume_t *
find_mounted_volume_by_device(const char *device)
{
    if (g_mounts_state.volumes != NULL) {
        int i;
        for (i = 0; i < g_mounts_state.volume_count; i++) {
            mounted_volume_t *v = &g_mounts_state.volumes[i];
            /* May be null if it was unmounted and we haven't rescanned.
             */
            if (v->device != NULL) {
                if (strcmp(v->device, device) == 0) {
                    return v;
                }
            }
        }
    }
    return NULL;
}

const mounted_volume_t *
find_mounted_volume_by_mount_point(const char *mount_point)
{
    if (g_mounts_state.volumes != NULL) {
        int i;
        for (i = 0; i < g_mounts_state.volume_count; i++) {
            mounted_volume_t *v = &g_mounts_state.volumes[i];
            /* May be null if it was unmounted and we haven't rescanned.
             */
            if (v->mount_point != NULL) {
                if (strcmp(v->mount_point, mount_point) == 0) {
                    return v;
                }
            }
        }
    }
    return NULL;
}

const mounted_volume_t *
find_mounted_volume_by_majmin(unsigned major, unsigned minor)
{
    if (g_mounts_state.volumes != NULL) {
        int i;
        for (i = 0; i < g_mounts_state.volume_count; i++) {
            mounted_volume_t *v = &g_mounts_state.volumes[i];
            /* May be null if it was unmounted and we haven't rescanned.
             */
            if (v->major == major && v->minor == minor) {
                return v;
            }
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
        free_volume_internals(volume, 1);
        return 0;
    }
    return ret;
}

int
unmount_mounted_volume_detach(const mounted_volume_t *volume)
{
    /* Intentionally pass NULL to umount if the caller tries
     * to unmount a volume they already unmounted using this
     * function.
     */
    int ret = umount2(volume->mount_point, MNT_DETACH);
    if (ret == 0) {
        free_volume_internals(volume, 1);
        return 0;
    }
    return ret;
}

int
remount_read_only(const mounted_volume_t* volume)
{
    return mount(volume->device, volume->mount_point, volume->filesystem,
                 MS_NOATIME | MS_NODEV | MS_NODIRATIME |
                 MS_RDONLY | MS_REMOUNT, 0);
}

