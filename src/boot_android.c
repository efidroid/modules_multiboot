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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

#include <lib/mounts.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "BOOT_ANDROID"
#include <lib/log.h>

static multiboot_data_t* multiboot_data = NULL;

static volatile sig_atomic_t mbinit_usr_interrupt = 0;
static void mbinit_usr_handler(UNUSED int sig, siginfo_t* info, UNUSED void* vp) {
    int rc;
    int i;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    char buf3[PATH_MAX];
    char* name = NULL;
    char* esp_mountpoint = NULL;

    // ignore further signals
    if(mbinit_usr_interrupt)
        return;

    // stop waiting for signals
    mbinit_usr_interrupt = 1;

    // scan mounted volumes
    rc = scan_mounted_volumes();
    if(rc) {
        LOGE("Can't scan mounted volumes: %s\n", strerror(errno));
        goto finish;
    }

    // find ESP volume
    const mounted_volume_t* volume = find_mounted_volume_by_majmin(multiboot_data->espdev->major, multiboot_data->espdev->minor, 0);
    if(!volume) {
        LOGE("ESP is not yet mounted\n");
        goto finish;
    }

    // get espdir
    esp_mountpoint = util_get_espdir(volume->mount_point);
    if(!esp_mountpoint) {
        LOGE("Can't get ESP directory: %s\n", strerror(errno));
        goto finish;
    }

    // create UEFIESP directory
    if(!util_exists(esp_mountpoint, true)) {
        rc = util_mkdir(esp_mountpoint);
        if(rc) {
            LOGE("Can't create directory at %s\n", esp_mountpoint);
            goto finish;
        }
    }

    for(i=0; i<multiboot_data->mbfstab->num_entries; i++) {
        struct fstab_rec *rec;

        // skip non-uefi partitions
        rec = &multiboot_data->mbfstab->recs[i];
        if(!fs_mgr_is_uefi(rec)) continue;

        // build devicenode path
        name = util_basename(rec->mount_point);
        if(!name) {
            LOGE("Can't get basename of %s\n", rec->mount_point);
            rc = -1;
            goto finish;
        }

        // resolve symlinks for device node
        char* blk_device = realpath(rec->blk_device, buf);
        if(!blk_device) {
            LOGE("Can't get real path for %s\n", rec->blk_device);
            rc = -errno;
            goto finish;
        }

        // stat original device
        struct stat sb;
        rc = stat(blk_device, &sb);
        if(rc) {
            LOGE("Can't stat device at %s\n", blk_device);
            goto finish;
        }

        // create path for backup node
        rc = snprintf(buf3, sizeof(buf3), "%s/replacement_backup_%s", MBPATH_DEV, name);
        if(SNPRINTF_ERROR(rc, sizeof(buf3))) {
            LOGE("Can't build name for partition image\n");
            goto finish;
        }

        // create backup node
        rc = mknod(buf3, S_IRUSR | S_IWUSR | S_IFBLK, makedev(major(sb.st_rdev), minor(sb.st_rdev)));
        if (rc) {
            LOGE("Can't create backup node for device %s\n", buf3);
            goto finish;
        }

        // get number of blocks
        unsigned long num_blocks = 0;
        util_block_num(blk_device, &num_blocks);

        // create path for loop image
        rc = snprintf(buf2, sizeof(buf2), "%s/partition_%s.img", esp_mountpoint, name);
        if(SNPRINTF_ERROR(rc, sizeof(buf2))) {
            LOGE("Can't build name for partition image\n");
            goto finish;
        }

        // create raw image if it doesn't exists yet
        // or if it's size doesn't match the original partition
        if(!util_exists(buf2, false) || util_filesize(buf2, false)!=num_blocks*512llu) {
            rc = util_dd(blk_device, buf2, 0);
            if(rc) {
                LOGE("Can't copy %s to %s\n", blk_device, buf2);
                goto finish;
            }
        }

        // delete original node
        if(util_exists(blk_device, false)) {
            rc = unlink(blk_device);
            if(rc) {
                LOGE("Can't delete %s\n", blk_device);
                goto finish;
            }
        }

        // create new node
        rc = util_make_loop(blk_device);
        if(rc) {
            LOGE("Can't create loop device at %s\n", blk_device);
            goto finish;
        }

        // setup loop device
        rc = util_losetup(blk_device, buf2, false);
        if(rc) {
            LOGE("Can't setup loop device at %s for %s\n", blk_device, buf2);
            goto finish;
        }

        // cleanup
        free(name);
        name = NULL;
    }

finish:
    free(name);
    free(esp_mountpoint);

    // continue trigger-postfs
    kill(info->si_pid, SIGUSR1);
}

static volatile sig_atomic_t init_usr_interrupt = 0;
static void init_usr_handler(UNUSED int sig, UNUSED siginfo_t* info, UNUSED void* vp) {
    // stop waiting for signals
    init_usr_interrupt = 1;
}

#define CHECK_WRITE(fd, str) \
        len = strlen(str); \
        bytes_written = write(fd, str, len); \
        if(bytes_written!=(size_t)len) { \
            MBABORT("Can't write\n"); \
        }

static int fstab_append(int fd, const char* blk_device, const char* mount_point, const char* fs_type, const char* mnt_flags, const char* fs_mgr_flags) {
    size_t bytes_written;
    size_t len;

    // allocate line buffer
    size_t linelen = strlen(blk_device) + strlen(mount_point) + strlen(fs_type) + strlen(mnt_flags) + strlen(fs_mgr_flags) + 6;
    char* line = safe_malloc(linelen);

    // build line
    SAFE_SNPRINTF_RET(MBABORT, -1, line, linelen, "%s %s %s %s %s\n", blk_device, mount_point, fs_type, mnt_flags, fs_mgr_flags);

    // write line
    CHECK_WRITE(fd, line);

    // free line
    free(line);

    return 0;
}

int boot_android(void) {
    multiboot_data = multiboot_get_data();

    int rc;
    int i;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    // multiboot setup
    if(multiboot_data->is_multiboot) {
        // get directory of multiboot.ini
        char* basedir = util_dirname(multiboot_data->path);
        if(!basedir) {
            MBABORT("Can't get base dir for multiboot path\n");
        }

        // open fstab for writing
        int fd = open(multiboot_data->romfstabpath, O_WRONLY|O_TRUNC);
        if(fd<0) {
            MBABORT("Can't open init.rc for writing\n");
        }

        // write entries
        int processed_data = 0;
        for(i=0; i<multiboot_data->romfstab->num_entries; i++) {
            struct fstab_rec *rec;
            rec = &multiboot_data->romfstab->recs[i];
            int is_data = !strcmp(rec->mount_point, "/data");

            // this is a workaround for /data having two entries: for ext4 and f2fs
            // while double-mounting it doesn't seem to break sth. it doesn't looks good either
            if(is_data && processed_data)
                continue;

            // get multiboot part
            // TODO: use blkdevice
            multiboot_partition_t* part = util_mbpart_by_name(rec->mount_point+1);
            if(part) {
                const char* blk_device;
                const char* mnt_flags = rec->mnt_flags_orig;

                // build path
                SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BOOTDEV"%s/%s", basedir, part->path);

                if(part->type==MBPART_TYPE_BIND) {
                    blk_device = buf;
                    mnt_flags = "bind";
                }
                else {
                    // build loop path
                    SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), MBPATH_DEV"/block/mbloop_%s", part->name);

                    // create new node
                    rc = util_make_loop(buf2);
                    if(rc) {
                        MBABORT("Can't create loop device at %s\n", buf2);
                    }

                    // setup loop device
                    rc = util_losetup(buf2, buf, false);
                    if(rc) {
                        MBABORT("Can't setup loop device at %s for %s\n", buf2, buf);
                    }

                    blk_device = buf2;
                }

                fstab_append(fd, blk_device, rec->mount_point, rec->fs_type, mnt_flags, rec->fs_mgr_flags_orig);

                // bind mount datamedia
                if(part->type==MBPART_TYPE_BIND && is_data) {
                    // create /media on the main data partition
                    if(!util_exists(MBPATH_DATA"/media", false)) {
                        rc = util_mkdir(MBPATH_DATA"/media");
                        if(rc) {
                            MBABORT("Can't create datamedia on source: %s\n", strerror(rc));
                        }
                    }

                    // create /media on the ROM's data partition
                    SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BOOTDEV"/%s/%s", basedir, part->path);
                    if(!util_exists(buf, false)) {
                        rc = util_mkdir(buf);
                        if(rc) {
                            MBABORT("Can't create datamedia on target: %s\n", strerror(rc));
                        }
                    }

                    fstab_append(fd, MBPATH_DATA"/media", "/data/media", rec->fs_type, "bind", "defaults");
                }

                if(is_data)
                    processed_data = 1;
            }

            else {
                // write unmodified entry
                fstab_append(fd, rec->blk_device, rec->mount_point, rec->fs_type, rec->mnt_flags_orig, rec->fs_mgr_flags_orig);
            }
        }

        // close file
        close(fd);
    }

    LOGI("Booting Android\n");
    pid_t pid = safe_fork();

    // parent
    if(pid) {
        // install usr handler
        util_setsighandler(SIGUSR1, init_usr_handler);

        // wait for mbinit to finish
        WAIT_FOR_SIGNAL(SIGUSR1, !init_usr_interrupt);

        return run_init(0);
    }

    // child
    else {
        // add post-fs-data event
        SAFE_SNPRINTF_RET(LOGE, -1, buf, PATH_MAX, "\n\n"
                 "on post-fs-data\n"
                 "    start mbpostfs\n"
                 "    wait "POSTFS_NOTIFICATION_FILE"\n"
                 "\n"
                 "service mbpostfs "MBPATH_TRIGGER_POSTFS_DATA" %u\n"
                 "    disabled\n"
                 "    oneshot\n"
                 "\n",

                 getpid()
                );
        rc = util_append_string_to_file("/init.rc", buf);
        if(rc) return rc;

        // install postfs handler
        util_setsighandler(SIGUSR1, mbinit_usr_handler);

        // continue init
        kill(getppid(), SIGUSR1);

        // wait for postfs
        WAIT_FOR_SIGNAL(SIGUSR1, !mbinit_usr_interrupt);

        // we are not allowed to return
        exit(0);
    }
}
