#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <lib/efivars.h>
#include <lib/fs_mgr.h>
#include <lib/hookmgr.h>
#include <lib/uevent.h>
#include <lib/mounts.h>
#include <tracy.h>

#include <common.h>
#include <util.h>

#define LOG_TAG "BOOT_RECOVERY"
#include <lib/log.h>

multiboot_data_t* multiboot_data = NULL;

typedef struct {
    hookmgr_device_t dev;
    char* loopdevice;
    struct fstab_rec* rec;
} hookdev_pdata_t;

static void dev_open(hookmgr_device_t* dev, hookmgr_open_event_t* event) {
    hookdev_pdata_t* pdata = (hookdev_pdata_t*)dev;

    // use loop device
    event->set_pathname(event, pdata->loopdevice);
}

static void dev_close_post(hookmgr_device_t* dev, unused hookmgr_close_event_t* event) {
    hookdev_pdata_t* pdata = (hookdev_pdata_t*)dev;
    int rc;
    const char* mountpoint = NULL;

    if(!(event->flags & O_WRONLY) && !(event->flags & O_RDWR)) {
        return;
    }

    // scan mounted volumes
    rc = scan_mounted_volumes();
    if(rc) {
        EFIVARS_LOG_FATAL(rc, "Can't scan mounted volumes: %s\n", strerror(errno));
        return;
    }

    // find esp
    const mounted_volume_t* volume = find_mounted_volume_by_majmin(multiboot_data->espdev->major, multiboot_data->espdev->minor, 0);
    if(volume) {
        mountpoint = volume->mount_point;
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
        }

        // mount ESP
        rc = uevent_mount(multiboot_data->espdev, MBPATH_ESP, NULL, mountflags, data);
        if(rc) {
            EFIVARS_LOG_FATAL(rc, "Can't mount ESP: %s\n", strerror(errno));
            return;
        }

        mountpoint = MBPATH_ESP;
    }

    // get espdir
    char* espdir = util_get_espdir(mountpoint, NULL);
    if(!espdir) {
        EFIVARS_LOG_FATAL(-1, "Can't get ESP directory: %s\n", strerror(errno));
        return;
    }

    // get ESP filename
    char* espfilename = util_get_esp_path_for_partition(mountpoint, pdata->rec);
    if(!espfilename) {
        EFIVARS_LOG_FATAL(-1, "Can't get filename\n");
        return;
    }

    // copy loop to esp
    rc = util_dd(pdata->loopdevice, espfilename, 0);
    if(rc) {
        EFIVARS_LOG_FATAL(rc, "Can't create partition image\n");
        return;
    }

    if(!volume) {
        // unmount ESP
        rc = umount(MBPATH_ESP);
        if(rc) {
            EFIVARS_LOG_FATAL(rc, "Can't unmount ESP: %s\n", strerror(errno));
            return;
        }
    }

    free(espfilename);
    free(espdir);
}

typedef struct {
    hookmgr_device_t dev;
    multiboot_partition_t* part;
    char* partpath;
    char* loopdevice;
    char* previous_fstype;
} hookdev_mb_pdata_t;

static void dev_mb_mount(hookmgr_device_t* dev, unused hookmgr_mount_event_t* event) {
    hookdev_mb_pdata_t* pdata = (hookdev_mb_pdata_t*)dev;
    int rc;

    if(pdata->part->is_bind) {
        rc = mount(pdata->partpath, event->target, NULL, MS_BIND, NULL);
        event->abort(event, rc);
    }

    else {
        // use loop device
        event->set_source(event, pdata->loopdevice);
    }
}

static void dev_mb_open(hookmgr_device_t* dev, hookmgr_open_event_t* event) {
    hookdev_mb_pdata_t* pdata = (hookdev_mb_pdata_t*)dev;

    // use loop device
    event->set_pathname(event, pdata->loopdevice);
}

static void dev_mb_close_post(hookmgr_device_t* dev, unused hookmgr_close_event_t* event) {
    hookdev_mb_pdata_t* pdata = (hookdev_mb_pdata_t*)dev;
    int rc;
    char buf[PATH_MAX];

    if(!(event->flags & O_WRONLY) && !(event->flags & O_RDWR)) {
        return;
    }

    if(pdata->part->is_bind) {
        char* fstype = util_get_fstype(pdata->loopdevice);

        // mount loop
        rc = util_mount(pdata->loopdevice, MBPATH_STUB, fstype, 0, NULL);
        if(rc) {
            EFIVARS_LOG_FATAL(rc, "Can't mount %s on %s using %s: %s\n", pdata->loopdevice, MBPATH_STUB, fstype, strerror(errno));
            return;
        }

        // create id file
        if(fstype!=pdata->previous_fstype || !util_exists(MBPATH_STUB_IDFILE, false)) {
            LOGI("%s got formatted!\n", pdata->loopdevice);

            // create id file
            int fd = open(MBPATH_STUB_IDFILE, O_RDWR|O_CREAT);
            if(fd<0) {
                EFIVARS_LOG_FATAL(rc, "Can't create ID file\n");
                return;
            }
            close(fd);

            // build format command
            rc = snprintf(buf, sizeof(buf), MBPATH_BUSYBOX" rm -Rf %s/*", pdata->partpath);
            if((size_t)rc >= sizeof(buf)) {
                EFIVARS_LOG_FATAL(-1, "Can't build format command\n");
                return;
            }

            // format bind source
            rc = util_shell(buf);
            if(rc) {
                EFIVARS_LOG_FATAL(rc, "Can't format bind source at %s\n", pdata->partpath);
                return;
            }

            free(pdata->previous_fstype);
            pdata->previous_fstype = fstype;
        }

        // unmount loop device
        rc = umount(MBPATH_STUB);
        if(rc) {
            EFIVARS_LOG_FATAL(rc, "Can't unmount %s: %s\n", MBPATH_STUB, strerror(errno));
            return;
        }
    }
}

int boot_recovery(void) {
    multiboot_data = multiboot_get_data();

    int rc;
    int i;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    struct tracy *tracy;
	long tracy_opt = 0;

    // initialize tracy
    tracy_opt |= TRACY_TRACE_CHILDREN;
    tracy_opt |= TRACY_WORKAROUND_ARM_7475_1;
    tracy = tracy_init(tracy_opt);

    // init hookmgr
    hookmgr_t* hookmgr = hookmgr_init(tracy);
    if(!hookmgr) {
        return EFIVARS_LOG_TRACE(-1, "Can't initialize hookmgr\n");
    }

    // multiboot
    if(multiboot_data->is_multiboot) {
        // get directory of multiboot.ini
        char* basedir = util_dirname(multiboot_data->path);
        if(!basedir) {
            return EFIVARS_LOG_TRACE(-1, "Can't get base dir for multiboot path\n");
        }

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

            // build path
            rc = snprintf(buf, sizeof(buf), MBPATH_BOOTDEV"%s/%s", basedir, part->path);
            if(rc<0) {
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
                (part->is_bind && !S_ISDIR(sb.st_mode)) || 
                (!part->is_bind && !S_ISREG(sb.st_mode))
                )
            ) {
                return EFIVARS_LOG_TRACE(-1, "path '%s' has invalid type\n", partpath);
            }

            // get real device
            char* loopdevice = NULL;
            char* device = util_device_from_mbname(part->name);
            char* previous_fstype = NULL;
            if(!device) {
                return EFIVARS_LOG_TRACE(-1, "Can't get device for '%s'\n", part->name);
            }

            if(part->is_bind) {
                // create directory
                if(rc==-ENOENT) {
                    rc = util_mkdir(partpath);
                    if(rc) {
                        return EFIVARS_LOG_TRACE(-1, "Can't create directory '%s'\n", partpath);
                    }
                }

                // build path for loop device
                rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%s", part->name);
                if(rc<0) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
                }
                loopdevice = strdup(buf);
                if(!loopdevice) {
                    return EFIVARS_LOG_TRACE(rc, "Can't duplicate path for loop device\n");
                }

                // build path for stub partition backup
                rc = snprintf(buf, sizeof(buf), MBPATH_ROOT"/loopfile:%s", part->name);
                if(rc<0) {
                    return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
                }

                // create stub partition backup
                rc = util_create_partition_backup_ex(MBPATH_DEV"/zero", buf, (5*1024*1024)/512llu, true);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't create stub partition backup\n");
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
                char* fstype = util_get_fstype(device);
                if(!fstype)
                    fstype = strdup("ext4");
                previous_fstype = fstype;


                // create filesystem on loop device
                rc = util_mkfs(loopdevice, fstype);
                if(rc) {
                    return EFIVARS_LOG_TRACE(rc, "Can't create filesystem on %s\n", loopdevice);
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
                if(rc<0) {
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

            // get blockinfo
            uevent_block_t* bi = get_blockinfo_for_path(multiboot_data->blockinfo, device);
            if(!bi) {
                return EFIVARS_LOG_TRACE(-1, "Can't get blockinfo for %s\n", device);
            }

            hookdev_mb_pdata_t* pdata = calloc(sizeof(hookdev_mb_pdata_t), 1);
            if(!pdata) {
                return EFIVARS_LOG_TRACE(-errno, "Can't allocate hook device\n");
            }

            pdata->dev.major = bi->major;
            pdata->dev.minor = bi->minor;
            pdata->dev.mount = dev_mb_mount;
            pdata->dev.open = dev_mb_open;
            pdata->dev.close_post = dev_mb_close_post;
            pdata->part = part;
            pdata->loopdevice = loopdevice;
            pdata->partpath = partpath;
            pdata->previous_fstype = previous_fstype;

            hookmgr_redirect_device(hookmgr, &pdata->dev);
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
        }

        // mount ESP
        rc = uevent_mount(multiboot_data->espdev, MBPATH_ESP, NULL, mountflags, data);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't mount ESP: %s\n", strerror(errno));
        }

        // get espdir
        char* espdir = util_get_espdir(MBPATH_ESP, buf);
        if(!espdir) {
            return EFIVARS_LOG_TRACE(-1, "Can't get ESP directory: %s\n", strerror(errno));
        }

        // create UEFIESP directory
        if(!util_exists(espdir, true)) {
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
            if(rc<0) {
                return EFIVARS_LOG_TRACE(rc, "Can't build temp partition path\n");
            }

            // build path for temporary partition backup
            rc = snprintf(buf2, sizeof(buf2), MBPATH_ROOT"/loopfile:%u:%u", bi->major, bi->minor);
            if(rc<0) {
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

            hookdev_pdata_t* pdata = calloc(sizeof(hookdev_pdata_t), 1);
            if(!pdata) {
                return EFIVARS_LOG_TRACE(-errno, "Can't allocate hook device\n");
            }

            pdata->dev.major = bi->major;
            pdata->dev.minor = bi->minor;
            pdata->dev.open = dev_open;
            pdata->dev.close_post = dev_close_post;
            pdata->loopdevice = strdup(buf);
            pdata->rec = rec;

            hookmgr_redirect_device(hookmgr, &pdata->dev);

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
    rc = run_init(tracy);
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't trace init: %s\n", strerror(errno));
    }

	// main event-loop
	tracy_main(tracy);

	// cleanup
	tracy_free(tracy);

    return EFIVARS_LOG_TRACE(-1, "tracy returned\n");
}
