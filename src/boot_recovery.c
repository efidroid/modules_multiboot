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

static multiboot_data_t* multiboot_data = NULL;

int boot_recovery(void) {
    multiboot_data = multiboot_get_data();

    int rc;
    int i;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    // multiboot
    if(multiboot_data->is_multiboot) {
        // get directory of multiboot.ini
        char* basedir = util_dirname(multiboot_data->path);
        if(!basedir) {
            MBABORT("Can't get base dir for multiboot path\n");
        }

        // make sure we have /dev/fuse
        if(!util_exists("/dev", false)) {
            rc = util_mkdir("/dev");
            if(rc) {
                MBABORT("Can't create /dev directory\n");
            }
        }
        mknod("/dev/fuse", S_IFCHR | 0600, makedev(10, 229));

        // setup multiboot partitions
        for(i=0; i<multiboot_data->mbfstab->num_entries; i++) {
            struct fstab_rec *rec;

            // skip non-multiboot partitions
            rec = &multiboot_data->mbfstab->recs[i];
            if(!fs_mgr_is_multiboot(rec)) continue;

            // get multiboot part
            multiboot_partition_t* part = util_mbpart_by_name(rec->mount_point+1);
            if(!part) {
                MBABORT("Partition '%s' wasn't found in multiboot.ini\n", rec->mount_point+1);
            }

            // get blockinfo
            uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, rec->blk_device);
            if(!bi) {
                MBABORT("Can't get blockinfo for '%s'\n", rec->blk_device);
            }

            // path to multiboot rom dir
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BOOTDEV"%s/%s", basedir, part->path);
            char* partpath = safe_strdup(buf);

            // path to loop device
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%s", part->name);
            char* loopdevice = safe_strdup(buf);

            // stat path
            struct stat sb;
            rc = lstat(partpath, &sb);
            if(rc) rc = -errno;
            if(rc && rc!=-ENOENT) {
                MBABORT("Can't stat '%s'\n", partpath);
            }

            // check node type
            if(!rc && (
                        (part->type==MBPART_TYPE_BIND && !S_ISDIR(sb.st_mode)) ||
                        (part->type!=MBPART_TYPE_BIND && !S_ISREG(sb.st_mode))
                    )
              ) {
                MBABORT("path '%s'(type=%d) has invalid mode: %x\n", partpath, part->type, sb.st_mode);
            }

            // get real device
            char* device = util_device_from_mbname(part->name);
            if(!device) {
                MBABORT("Can't get device for '%s'\n", part->name);
            }

            if(part->type==MBPART_TYPE_BIND) {
                // create directory
                if(rc==-ENOENT) {
                    rc = util_mkdir(partpath);
                    if(rc) {
                        MBABORT("Can't create directory '%s'\n", partpath);
                    }
                }

                // get size of original partition
                unsigned long num_blocks = 0;
                rc = util_block_num(device, &num_blocks);
                if(rc || num_blocks==0) {
                    MBABORT("Can't get size of device %s\n", rec->blk_device);
                }

                // mkfs needs much time for large filesystems, so just use max 200MB
                num_blocks = MIN(num_blocks, (200*1024*1024)/512llu);

                // path to dynfilefs mountpopint
                SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), MBPATH_ROOT"/dynmount:%s", part->name);

                // path to dynfilefs storage file
                SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_ROOT"/dynstorage:%s", part->name);

                // mount dynfilefs
                rc = util_dynfilefs(buf, buf2, num_blocks*512llu);
                if(rc) {
                    MBABORT("can't mount dynfilefs\n");
                }

                // path to stub partition backup (in dynfs mountpoint)
                SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s/loop.fs", buf2);

                // create new loop node
                rc = util_make_loop(loopdevice);
                if(rc) {
                    MBABORT("Can't create loop device at %s\n", loopdevice);
                }

                // setup loop device
                rc = util_losetup(loopdevice, buf, false);
                if(rc) {
                    MBABORT("Can't setup loop device at %s for %s\n", loopdevice, buf);
                }

                // get fstype
                const char* fstype = "ext4";

                // create filesystem on loop device
                rc = util_mkfs(loopdevice, fstype);
                if(rc) {
                    MBABORT("Can't create '%s' filesystem on %s\n", fstype, loopdevice);
                }

                // mount loop device
                SAFE_MOUNT(loopdevice, MBPATH_STUB, fstype, 0, NULL);

                // create id file
                int fd = open(MBPATH_STUB_IDFILE, O_RDWR|O_CREAT);
                if(fd<0) {
                    MBABORT("Can't create ID file\n");
                }
                close(fd);

                // unmount loop device
                SAFE_UMOUNT(MBPATH_STUB);
            }

            else if(part->type==MBPART_TYPE_LOOP) {
                // create new node
                rc = util_make_loop(loopdevice);
                if(rc) {
                    MBABORT("Can't create loop device at %s\n", loopdevice);
                }

                // setup loop device
                rc = util_losetup(loopdevice, partpath, false);
                if(rc) {
                    MBABORT("Can't setup loop device at %s for %s\n", loopdevice, partpath);
                }
            }

            else {
                LOGF("invalid partition type: %d\n", part->type);
            }

            part_replacement_t* pdata = safe_calloc(sizeof(part_replacement_t), 1);
            if(!pdata) {
                MBABORT("Can't allocate hook device\n");
            }

            pthread_mutex_init(&pdata->lock, NULL);
            pdata->major = bi->major;
            pdata->minor = bi->minor;
            pdata->loopdevice = loopdevice;
            pdata->u.multiboot.part = part;
            pdata->u.multiboot.partpath = partpath;

            list_add_tail(&multiboot_data->replacements, &pdata->node);
        }

        // TODO: check for optional replacement partitions

        free(basedir);
    }

    else {
        // mount ESP
        util_mount_esp();

        // get espdir
        char* espdir = util_get_espdir(MBPATH_ESP);
        if(!espdir) {
            MBABORT("Can't get ESP directory: %s\n", strerror(errno));
        }

        // copy path
        SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s", espdir);

        // create UEFIESP directory
        if(!util_exists(buf, true)) {
            rc = util_mkdir(buf);
            if(rc) {
                MBABORT("Can't create directory at %s\n", buf);
            }
        }

        for(i=0; i<multiboot_data->mbfstab->num_entries; i++) {
            struct fstab_rec *rec;

            // skip non-uefi partitions
            rec = &multiboot_data->mbfstab->recs[i];
            if(!fs_mgr_is_uefi(rec)) continue;

            // get blockinfo
            uevent_block_t* bi = get_blockinfo_for_path(multiboot_data->blockinfo, rec->blk_device);
            if(!bi) {
                MBABORT("Can't get blockinfo\n");
            }

            // get ESP filename
            char* espfilename = util_get_esp_path_for_partition(MBPATH_ESP, rec);
            if(!espfilename) {
                MBABORT("Can't get filename\n");
            }

            // get real device in MBPATH_DEV
            char* mbpathdevice = util_getmbpath_from_device(rec->blk_device);
            if(!mbpathdevice) {
                MBABORT("Can't get mbpath device\n");
            }

            // create partition image on ESP (in case it doesn't exist)
            rc = util_create_partition_backup(mbpathdevice, espfilename);
            if(rc) {
                MBABORT("Can't create partition image\n");
            }

            // path to loop device
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%u:%u", bi->major, bi->minor);

            // path to temporary partition backup
            SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), MBPATH_ROOT"/loopfile:%u:%u", bi->major, bi->minor);

            // create temporary partition backup
            rc = util_cp(espfilename, buf2);
            if(rc) {
                MBABORT("Can't copy partition from esp to temp\n");
            }

            // create new loop node
            rc = util_make_loop(buf);
            if(rc) {
                MBABORT("Can't create loop device at %s\n", buf);
            }

            // setup loop device
            rc = util_losetup(buf, buf2, false);
            if(rc) {
                MBABORT("Can't setup loop device at %s for %s\n", buf, buf2);
            }

            part_replacement_t* pdata = safe_calloc(sizeof(part_replacement_t), 1);
            if(!pdata) {
                MBABORT("Can't allocate hook device\n");
            }

            pthread_mutex_init(&pdata->lock, NULL);
            pdata->major = bi->major;
            pdata->minor = bi->minor;
            pdata->loopdevice = safe_strdup(buf);
            pdata->u.native.rec = rec;

            list_add_tail(&multiboot_data->replacements, &pdata->node);

            // cleanup
            free(mbpathdevice);
            free(espfilename);
        }

        // unmount ESP
        SAFE_UMOUNT(MBPATH_ESP);
    }

    // run and trace init
    rc = run_init(true);
    if(rc) {
        MBABORT("Can't trace init: %s\n", strerror(errno));
    }

    MBABORT_RET("init returned\n");
}
