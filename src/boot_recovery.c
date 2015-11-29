#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/mount.h>

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
    rc = util_create_partition_backup(pdata->loopdevice, espfilename);
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

int boot_recovery(void) {
    multiboot_data = multiboot_get_data();

    int rc;
    int i;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    struct tracy *tracy;
	long tracy_opt = 0;

	// mount private dev fs
	rc = util_mount("tmpfs", MBPATH_DEV, "tmpfs", MS_NOSUID, "mode=0755");
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't mount tmpfs for dev: %s\n", strerror(errno));
    }

    // build private dev fs
    rc = uevent_create_nodes(multiboot_data->blockinfo, MBPATH_DEV);
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't mount proc: %s\n", strerror(errno));
    }

    unsigned long mountflags = 0;
    const void* data = NULL;

    // find ESP in the rom's fstab
    struct fstab_rec* esprec = fs_mgr_get_by_ueventblock(multiboot_data->romfstab, multiboot_data->espdev);
    if(esprec) {
        // use the ROM's mount options for this partition
        mountflags = esprec->flags;
        data = (void*)esprec->fs_options;
    }

    // initialize tracy
    tracy_opt |= TRACY_TRACE_CHILDREN;
    tracy_opt |= TRACY_WORKAROUND_ARM_7475_1;
    tracy = tracy_init(tracy_opt);

    // init hookmgr
    hookmgr_t* hookmgr = hookmgr_init(tracy);
    if(!hookmgr) {
        return EFIVARS_LOG_TRACE(-1, "Can't initialize hookmgr\n");
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
