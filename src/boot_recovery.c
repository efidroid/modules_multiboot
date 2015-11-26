#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>

#include <lib/efivars.h>
#include <lib/fs_mgr.h>
#include <lib/hookmgr.h>
#include <lib/uevent.h>
#include <tracy.h>

#include <common.h>
#include <util.h>

#define LOG_TAG "BOOT_RECOVERY"
#include <lib/log.h>

multiboot_data_t* multiboot_data = NULL;

int boot_recovery(void) {
    multiboot_data = multiboot_get_data();

    int rc;
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

#if 0
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
        EFIVARS_LOG_RETURN(rc, "Can't mount ESP: %s\n", strerror(errno));
    }
#endif

    // initialize tracy
    //tracy_opt |= TRACY_MEMORY_FALLBACK;
    tracy_opt |= TRACY_TRACE_CHILDREN;
    tracy_opt |= TRACY_WORKAROUND_ARM_7475_1;
    tracy = tracy_init(tracy_opt);

    // init hookmgr
    hookmgr_t* hookmgr = hookmgr_init(tracy);
    if(!hookmgr) {
        return EFIVARS_LOG_TRACE(-1, "Can't initialize hookmgr\n");
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
