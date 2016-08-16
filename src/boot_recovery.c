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

#include <lib/efivars.h>
#include <lib/fs_mgr.h>
#include <lib/uevent.h>
#include <lib/mounts.h>
#include <lib/dynfilefs.h>

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
            return EFIVARS_LOG_TRACE(-1, "Can't get base dir for multiboot path\n");
        }

        // make sure we have /dev/fuse
        if(!util_exists("/dev", false)) {
            rc = util_mkdir("/dev");
            if(rc) {
                return EFIVARS_LOG_TRACE(rc, "Can't create /dev directory\n");
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
                return EFIVARS_LOG_TRACE(-ENOENT, "Partition '%s' wasn't found in multiboot.ini\n", rec->mount_point+1);
            }

            // get blockinfo
            uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, rec->blk_device);
            if(!bi) {
                return EFIVARS_LOG_TRACE(-1, "Can't get blockinfo for '%s'\n", rec->blk_device);
            }

            // build path
            rc = snprintf(buf, sizeof(buf), MBPATH_BOOTDEV"%s/%s", basedir, part->path);
            if(rc<0 || (size_t)rc>=sizeof(buf)) {
                return EFIVARS_LOG_TRACE(-1, "Can't build path for partition '%s'\n", part->name);
            }

            char* partpath = strdup(buf);
            if(!partpath) {
                return EFIVARS_LOG_TRACE(-1, "Can't duplicate path for partition '%s'\n", part->name);
            }

            // stat path
            struct stat sb;
            rc = lstat(partpath, &sb);
            if(rc) rc = -errno;
            if(rc && rc!=-ENOENT) {
                return EFIVARS_LOG_TRACE(-1, "Can't stat '%s'\n", partpath);
            }

            // check node type
            if(!rc && (
                        (part->type==MBPART_TYPE_BIND && !S_ISDIR(sb.st_mode)) ||
                        (part->type!=MBPART_TYPE_BIND && !S_ISREG(sb.st_mode))
                    )
              ) {
                return EFIVARS_LOG_TRACE(-1, "path '%s'(type=%d) has invalid mode: %x\n", partpath, part->type, sb.st_mode);
            }

            // get real device
            char* loopdevice = NULL;
            char* device = util_device_from_mbname(part->name);
            if(!device) {
                return EFIVARS_LOG_TRACE(-1, "Can't get device for '%s'\n", part->name);
            }

            if(part->type==MBPART_TYPE_BIND) {
                // create directory
                if(rc==-ENOENT) {
                    rc = util_mkdir(partpath);
                    if(rc) {
                        return EFIVARS_LOG_TRACE(-1, "Can't create directory '%s'\n", partpath);
                    }
                }

                // build path for loop device
                rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%s", part->name);
                if(rc<0 || (size_t)rc>=sizeof(buf)) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
                }
                loopdevice = strdup(buf);
                if(!loopdevice) {
                    return EFIVARS_LOG_TRACE(rc, "Can't duplicate path for loop device\n");
                }

                // get partition size
                unsigned long num_blocks = 0;
                rc = util_block_num(device, &num_blocks);
                if(rc || num_blocks==0) {
                    return EFIVARS_LOG_TRACE(rc, "Can't get size of device %s\n", rec->blk_device);
                }

                // mkfs needs much time for large filesystems, so just use max 1GB
                num_blocks = MIN(num_blocks, (200*1024*1024)/512llu);

                // build path for dynfilefs mountpopint
                rc = snprintf(buf2, sizeof(buf2), MBPATH_ROOT"/dynmount:%s", part->name);
                if(rc<0 || (size_t)rc>=sizeof(buf2)) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build dynfilefs partition path\n");
                }

                // build path for dynfilefs storage file
                rc = snprintf(buf, sizeof(buf), MBPATH_ROOT"/dynstorage:%s", part->name);
                if(rc<0 || (size_t)rc>=sizeof(buf)) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build dynfilefs storage path\n");
                }

                // mount dynfilefs
                rc = dynfilefs_mount(buf, num_blocks, buf2);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "can't mount dynfilefs\n");
                }

                // build path for stub partition backup
                rc = snprintf(buf, sizeof(buf), "%s/loop.fs", buf2);
                if(rc<0 || (size_t)rc>=sizeof(buf)) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
                }

                // create new loop node
                rc = util_make_loop(loopdevice);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't create loop device at %s\n", loopdevice);
                }

                // setup loop device
                rc = util_losetup(loopdevice, buf, false);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't setup loop device at %s for %s\n", loopdevice, buf);
                }

                // get fstype
                const char* fstype = "ext4";

                // create filesystem on loop device
                rc = util_mkfs(loopdevice, fstype);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't create '%s' filesystem on %s\n", fstype, loopdevice);
                }

                // mount loop device
                rc = util_mount(loopdevice, MBPATH_STUB, fstype, 0, NULL);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't mount %s on %s: %s\n", loopdevice, MBPATH_STUB, strerror(errno));
                }

                // create id file
                int fd = open(MBPATH_STUB_IDFILE, O_RDWR|O_CREAT);
                if(fd<0) {
                    return EFIVARS_LOG_TRACE(rc, "Can't create ID file\n");
                }
                close(fd);

                // unmount loop device
                rc = umount(MBPATH_STUB);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't unmount %s: %s\n", MBPATH_STUB, strerror(errno));
                }
            }

            else {
                // create partition image
                rc = util_create_partition_backup(device, partpath);
                if(rc) {
                    return EFIVARS_LOG_TRACE(-1, "Can't create file '%s'\n", partpath);
                }

                // build loop path
                rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/mbloop_%s", part->name);
                if(rc<0 || (size_t)rc>=sizeof(buf)) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build path for loop device\n");
                }
                loopdevice = strdup(buf);
                if(!loopdevice) {
                    return EFIVARS_LOG_TRACE(rc, "Can't duplicate path for loop device\n");
                }

                // create new node
                rc = util_make_loop(loopdevice);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't create loop device at %s\n", loopdevice);
                }

                // setup loop device
                rc = util_losetup(loopdevice, partpath, false);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't setup loop device at %s for %s\n", loopdevice, partpath);
                }
            }

            part_replacement_t* pdata = calloc(sizeof(part_replacement_t), 1);
            if(!pdata) {
                return EFIVARS_LOG_TRACE(-errno, "Can't allocate hook device\n");
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
        unsigned long mountflags = 0;
        const void* data = NULL;

        // find ESP in the rom's fstab
        struct fstab_rec* esprec = fs_mgr_get_by_ueventblock(multiboot_data->romfstab, multiboot_data->espdev);
        if(esprec) {
            // use the ROM's mount options for this partition
            mountflags = esprec->flags;
            data = (void*)esprec->fs_options;
            LOGD("use ROM mountflags for ESP, flags:%lu, data:%s\n", mountflags, (const char*)data);
        }

        // mount ESP
        rc = uevent_mount(multiboot_data->espdev, MBPATH_ESP, NULL, mountflags, data);
        if(rc) {
            // mount without flags
            LOGI("mount ESP without flags\n");
            mountflags = 0;
            data = NULL;
            rc = uevent_mount(multiboot_data->espdev, MBPATH_ESP, NULL, mountflags, data);
            if(rc)
                return EFIVARS_LOG_TRACE(rc, "Can't mount ESP: %s\n", strerror(errno));
        }

        // get espdir
        char* espdir = util_get_espdir(MBPATH_ESP);
        if(!espdir) {
            return EFIVARS_LOG_TRACE(-1, "Can't get ESP directory: %s\n", strerror(errno));
        }

        // copy path
        rc = snprintf(buf, sizeof(buf), "%s", espdir);
        free(espdir);
        if(rc<0 || (size_t)rc>=sizeof(buf)) {
            return EFIVARS_LOG_TRACE(rc, "Can't copy ESP dir path: %s\n", espdir);
        }

        // create UEFIESP directory
        if(!util_exists(buf, true)) {
            rc = util_mkdir(buf);
            if(rc) {
                return EFIVARS_LOG_TRACE(rc, "Can't create directory at %s\n", buf);
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
                return EFIVARS_LOG_TRACE(-1, "Can't get blockinfo\n");
            }

            // get ESP filename
            char* espfilename = util_get_esp_path_for_partition(MBPATH_ESP, rec);
            if(!espfilename) {
                return EFIVARS_LOG_TRACE(-1, "Can't get filename\n");
            }

            // get real device in MBPATH_DEV
            char* mbpathdevice = util_getmbpath_from_device(rec->blk_device);
            if(!mbpathdevice) {
                return EFIVARS_LOG_TRACE(-1, "Can't get mbpath device\n");
            }

            // create partition image on ESP (in case it doesn't exist)
            rc = util_create_partition_backup(mbpathdevice, espfilename);
            if(rc) {
                return EFIVARS_LOG_TRACE(rc, "Can't create partition image\n");
            }

            // build path for loop device
            rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%u:%u", bi->major, bi->minor);
            if(rc<0 || (size_t)rc>=sizeof(buf)) {
                return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
            }

            // build path for temporary partition backup
            rc = snprintf(buf2, sizeof(buf2), MBPATH_ROOT"/loopfile:%u:%u", bi->major, bi->minor);
            if(rc<0 || (size_t)rc>=sizeof(buf2)) {
                return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
            }

            // create temporary partition backup
            rc = util_cp(espfilename, buf2);
            if(rc) {
                return EFIVARS_LOG_TRACE(rc, "Can't copy partition from esp to temp\n");
            }

            // create new loop node
            rc = util_make_loop(buf);
            if(rc) {
                return EFIVARS_LOG_TRACE(rc, "Can't create loop device at %s\n", buf);
            }

            // setup loop device
            rc = util_losetup(buf, buf2, false);
            if(rc) {
                return EFIVARS_LOG_TRACE(rc, "Can't setup loop device at %s for %s\n", buf, buf2);
            }

            part_replacement_t* pdata = calloc(sizeof(part_replacement_t), 1);
            if(!pdata) {
                return EFIVARS_LOG_TRACE(-errno, "Can't allocate hook device\n");
            }

            pthread_mutex_init(&pdata->lock, NULL);
            pdata->major = bi->major;
            pdata->minor = bi->minor;
            pdata->loopdevice = strdup(buf);
            pdata->u.native.rec = rec;

            list_add_tail(&multiboot_data->replacements, &pdata->node);

            // cleanup
            free(mbpathdevice);
            free(espfilename);
        }

        // unmount ESP
        rc = umount(MBPATH_ESP);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't unmount ESP: %s\n", strerror(errno));
        }
    }

    // run and trace init
    rc = run_init(true);
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't trace init: %s\n", strerror(errno));
    }

    return EFIVARS_LOG_TRACE(-1, "tracy returned\n");
}
