#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mount.h>

#include <lib/cmdline.h>
#include <lib/mounts.h>
#include <lib/efivars.h>
#include <lib/fs_mgr.h>
#include <blkid.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "INIT"
#include <lib/log.h>

PAYLOAD_IMPORT(fstab_multiboot);
PAYLOAD_IMPORT(busybox);
static multiboot_data_t multiboot_data;

multiboot_data_t* multiboot_get_data(void) {
    return &multiboot_data;
}

static void import_kernel_nv(char *name)
{
	char *value = strchr(name, '=');
	int name_len = strlen(name);
	int rc;

	if (value == 0)
		return;
	*value++ = 0;
	if (name_len == 0)
		return;

	if (!strcmp(name, "multibootpath")) {
		char type[4];
        char guid[37];
        char *path = NULL;

        // check type
        const char* format = NULL;
        if(!strncmp(value, "GPT", 3))
            format = "%3s,%36s,%ms";
        else if(!strncmp(value, "MBR", 3))
            format = "%3s,%11s,%ms";
        else {
            LOGE("invalid format\n");
            return;
        }

        // read values
		if ((rc=sscanf(value, format, type, guid, &path)) != 3) {
            LOGE("%d\n", rc);
			return;
		}

        multiboot_data.guid = strdup(guid);
        multiboot_data.path = path;
	}

	else if (!strcmp(name, "androidboot.hardware")) {
        multiboot_data.hwname = strdup(value);
    }
}

static int device_matches(const char* path, const char* guid) {
    int rc = 0;
	blkid_tag_iterate iter;
	const char *type, *value;
	blkid_cache cache = NULL;

    // get dev
	blkid_get_cache(&cache, NULL);
	blkid_dev dev = blkid_get_dev(cache, path, BLKID_DEV_NORMAL);
	if(!dev) {
		LOGV("Device %s not found\n", path);
		return 0;
	}

    // get part uuid
	iter = blkid_tag_iterate_begin(dev);
	while (blkid_tag_next(iter, &type, &value) == 0) {
        if(!strcmp(type, "PARTUUID") && !strcasecmp(value, guid)) {
            rc = 1;
            break;
        }
	}
	blkid_tag_iterate_end(iter);

	return rc;
}

int run_init(struct tracy *tracy)
{
	char *par[2];
	int i = 0, ret = 0;

	// build args
	par[i++] = "/init";
	par[i++] = (char *)0;

	// RUN
    if (tracy)
		ret = !tracy_exec(tracy, par);
	else
    	ret = execve(par[0], par, NULL);

	// error check
	if (ret) {
		LOGE("Can't start %s: %s\n", par[0], strerror(errno));
		return ret;
	}

	return 0;
}

#if 0
int wait_for_partition(void)
{
    int rc;

    // create epoll event
    int efd = epoll_create1(0);
    if(efd<0) {
        LOGE("Can't create epoll: %s\n", strerror(errno));
        return efd;
    }

    // mount procfs
	mkdir(MBPATH_PROC, 0755);
    rc = mount("proc", MBPATH_PROC, "proc", 0, NULL);
	if(rc) {
        LOGE("Can't mount procfs: %s\n", strerror(errno));
        return rc;
    }

    // open mounts
    int mountsfd = open(MBPATH_PROC"/1/mountinfo", O_RDONLY);
    if(mountsfd<0) {
        LOGE("Can't open mountinfo: %s\n", strerror(errno));
        return mountsfd;
    }

    // add FD to epoll
    struct epoll_event event;
    event.data.fd = mountsfd;
    event.events = EPOLLIN | EPOLLET;
    rc = epoll_ctl(efd, EPOLL_CTL_ADD, mountsfd, &event);
    if(rc<0) {
        LOGE("Can't setup epoll: %s\n", strerror(errno));
        return rc;
    }

    // poll changes
    struct epoll_event events;
    while (epoll_wait(efd, &events, 1, -1)>=0) {
        LOGI("CHANGE\n");

        scan_mounted_volumes();
        dump_mounted_volumes();
    }

    return 0;
}
#endif

static int selinux_fixup(void) {
    int rc = 0;

    // we ignore errors on purpose here because selinux might not be needed or supported by the system

    // these two are a side effect of running /init with execve
    // { execmem } for  uid=0 pid=160 comm="init" scontext=u:r:init:s0 tcontext=u:r:init:s0 tclass=process
    util_sepolicy_inject("init", "init", "process", "execmem");
    // { execute } for  uid=0 pid=166 comm="e2fsck" path="/dev/__properties__" dev="tmpfs" ino=5017 scontext=u:r:init:s0 tcontext=u:object_r:properties_device:s0 tclass=file
    util_sepolicy_inject("init", "properties_device", "file", "execute");

    // for sending SIGUSR1 from trigger-postfs to init.multiboot
    // { signal } for  uid=0 pid=209 comm="trigger-postfs-" scontext=u:r:init:s0 tcontext=u:r:kernel:s0 tclass=process
    util_sepolicy_inject("init", "kernel", "process", "signal");
    // for sending SIGUSR1 from init.multiboot to trigger-postfs
    // { signal } for  uid=0 pid=156 comm="init.multiboot" scontext=u:r:kernel:s0 tcontext=u:r:init:s0 tclass=process
    util_sepolicy_inject("kernel", "init", "process", "signal");
    // for creating POSTFS_NOTIFICATION_FILE
    // { write } for  uid=0 pid=156 comm="init.multiboot" path=2F6465762F5F5F6B6D73675F5F202864656C6574656429 dev="rootfs" ino=5004 scontext=u:r:kernel:s0 tcontext=u:object_r:rootfs:s0 tclass=chr_file
    util_sepolicy_inject("kernel", "rootfs", "chr_file", "write");

    // the following rules are needed for setting up UEFI partition replacements
    // { execute } for  uid=0 pid=210 comm="init.multiboot" name="busybox" dev="tmpfs" ino=4985 scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=file
    // { execute_no_trans } for  uid=0 pid=210 comm="init.multiboot" path="/multiboot/bin/busybox" dev="tmpfs" ino=4985 scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=file
    util_sepolicy_inject("kernel", "tmpfs", "file", "execute,execute_no_trans");
    // { execmem } for  uid=0 pid=210 comm="busybox" scontext=u:r:kernel:s0 tcontext=u:r:kernel:s0 tclass=process
    util_sepolicy_inject("kernel", "kernel", "process", "execmem");
    // { unlink } for  uid=0 pid=157 comm="init.multiboot" name="mmcblk0p31" dev="tmpfs" ino=6980 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=blk_file
    util_sepolicy_inject("kernel", "block_device", "blk_file", "unlink");
    // { mknod } for  uid=0 pid=157 comm="init.multiboot" capability=27  scontext=u:r:kernel:s0 tcontext=u:r:kernel:s0 tclass=capability
    util_sepolicy_inject("kernel", "kernel", "capability", "mknod");
    // { create } for  uid=0 pid=157 comm="init.multiboot" name="mmcblk0p31" scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=blk_file
    // { write } for  uid=0 pid=211 comm="busybox" name="mmcblk0p31" dev="tmpfs" ino=7264 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=blk_file
    util_sepolicy_inject("kernel", "block_device", "blk_file", "create,write");

    // give our files some selinux context
    util_append_string_to_file("/file_contexts", "\n\n"
        "/multiboot(/.*)?             u:object_r:rootfs:s0\n"
        "/multiboot/bin(/.*)?         u:object_r:rootfs:s0\n"

        // prevent restorecon_recursive on multiboot directories
        "/data/media/multiboot(/.*)?          <<none>>\n"
        "/data/media/0/multiboot(/.*)?        <<none>>\n"
        "/realdata/media/multiboot(/.*)?      <<none>>\n"
        "/realdata/media/0/multiboot(/.*)?    <<none>>\n"
    );

    return rc;
}

static volatile sig_atomic_t mbinit_usr_interrupt = 0;
static void mbinit_usr_handler(int sig, siginfo_t* info, void* vp) {
    (void)(sig);
    (void)(vp);
    int rc;
    int i;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
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
    const mounted_volume_t* volume = find_mounted_volume_by_majmin(multiboot_data.espdev->major, multiboot_data.espdev->minor, 0);
    if(!volume) {
        LOGE("ESP is not yet mounted\n");
        goto finish;
    }

    // get esp directory
    const char* espdir = NULL;
    if(multiboot_data.esp->esp[0]=='/')
        espdir = multiboot_data.esp->esp+1;
    else if(!strcmp(multiboot_data.esp->esp, "datamedia"))
        espdir = "media";
    else {
        LOGE("Invalid ESP path %s\n", multiboot_data.esp->esp);
        rc = -EINVAL;
        goto finish;
    }
    
    // build UEFIESP mountpoint
    rc = snprintf(buf, PATH_MAX, "%s/%s/UEFIESP", volume->mount_point, espdir);
    if(rc<0) {
        LOGE("Can't build name for UEFIESP\n");
        goto finish;
    }

    // duplicate UEFIESP mountpoint
    esp_mountpoint = strdup(buf);
    if(!esp_mountpoint) {
        LOGE("Can't alloc mem for UEFIESP\n");
        rc = -ENOMEM;
        goto finish;
    }

    // create UEFIESP directory
    if(!util_exists(buf, true)) {
        rc = util_mkdir(buf);
        if(rc) {
            LOGE("Can't create directory at %s\n", buf);
            goto finish;
        }
    }
    
    for(i=0; i<multiboot_data.mbfstab->num_entries; i++) {
        struct fstab_rec *rec;

        // skip non-uefi partitions
        rec = &multiboot_data.mbfstab->recs[i];
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

        // get number of blocks
        unsigned long num_blocks = 0;
        util_block_num(blk_device, &num_blocks);

        // create path for loop image
        rc = snprintf(buf2, PATH_MAX, "%s/partition_%s.img", esp_mountpoint, name);
        if(rc<0) {
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

    if(rc) {
        LOGE("Error in %s: %s\n", __func__, strerror(-rc));
    }

    // continue trigger-postfs
    kill(info->si_pid, SIGUSR1);
}

static volatile sig_atomic_t init_usr_interrupt = 0;
static void init_usr_handler(int sig, siginfo_t* info, void* vp) {
    (void)(sig);
    (void)(info);
    (void)(vp);

    // stop waiting for signals
    init_usr_interrupt = 1;
}

int multiboot_main(int argc, char** argv) {
    (void)(argc);
    (void)(argv);
    (void)(device_matches);

    int rc = 0;
    char buf[PATH_MAX];

    // init logging
    log_init();

    // mount tmpfs to MBPATH_ROOT so we'll be able to write once init mounted rootfs as RO
    rc = util_mount("tmpfs", MBPATH_ROOT, "tmpfs", MS_NOSUID, "mode=0755");
    if(rc) {
        LOGE("Can't mount tmpfs: %s\n", strerror(errno));
        return rc;
    }

    // mount sysfs
    rc = util_mount("sysfs", MBPATH_SYS, "sysfs", 0, NULL);
	if(rc) {
        LOGE("Can't mount sysfs: %s\n", strerror(errno));
        return rc;
    }

    // mount proc
    rc = util_mount("proc", MBPATH_PROC, "proc", 0, NULL);
	if(rc) {
        LOGE("Can't mount sysfs: %s\n", strerror(errno));
        return rc;
    }

    // parse cmdline
    import_kernel_cmdline(import_kernel_nv);

    // parse /sys/block
    multiboot_data.blockinfo = get_block_devices();
    if(!multiboot_data.blockinfo) {
        LOGE("Can't retrieve blockinfo: %s\n", strerror(errno));
        return -errno;
    }

    // check for hwname
    if(!multiboot_data.hwname) {
        return EFIVARS_LOG_TRACE(-ENOENT, "cmdline didn't contain a valid 'androidboot.hardware': %s\n", strerror(ENOENT));
    }

    // create directories
    rc = util_mkdir(MBPATH_BIN);
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't create directory '"MBPATH_BIN"': %s\n", strerror(errno));
    }

    // extract fstab.multiboot
    rc = util_buf2file(PAYLOAD_PTR(fstab_multiboot), MBPATH_FSTAB, PAYLOAD_SIZE(fstab_multiboot));
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't extract fstab to "MBPATH_FSTAB": %s\n", strerror(errno));
    }

    // extract busybox
    rc = util_extractbin(PAYLOAD_PTR(busybox), MBPATH_BUSYBOX, PAYLOAD_SIZE(busybox));
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't extract busybox to "MBPATH_BUSYBOX": %s\n", strerror(errno));
    }

    // create symlinks
    if(util_exists(MBPATH_TRIGGER_POSTFS_DATA, false)) {
        rc = unlink(MBPATH_TRIGGER_POSTFS_DATA);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Error deleting "MBPATH_TRIGGER_POSTFS_DATA": %s\n", strerror(errno));
        }
    }
    rc = symlink(argv[0], MBPATH_TRIGGER_POSTFS_DATA);
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't create symlink "MBPATH_TRIGGER_POSTFS_DATA": %s\n", strerror(errno));
    }

    // parse multiboot fstab
    multiboot_data.mbfstab = fs_mgr_read_fstab(MBPATH_FSTAB);
    if(!multiboot_data.mbfstab) {
        return EFIVARS_LOG_TRACE(rc, "Can't parse multiboot fstab: %s\n", strerror(errno));
    }

    // build fstab name
    rc = snprintf(buf, sizeof(buf), "/fstab.%s", multiboot_data.hwname);
    if(rc<0) {
        return EFIVARS_LOG_TRACE(rc, "Can't build fstab name: %s\n", strerror(errno));
    }

    // parse ROM fstab
    multiboot_data.romfstab = fs_mgr_read_fstab(buf);
    if(!multiboot_data.romfstab) {
        return EFIVARS_LOG_TRACE(rc, "Can't parse %s: %s\n", buf, strerror(errno));
    }

    // get ESP partition
    multiboot_data.esp = fs_mgr_esp(multiboot_data.mbfstab);
    if(!multiboot_data.esp) {
        return EFIVARS_LOG_TRACE(-ENOENT, "ESP partition not found\n");
    }
    multiboot_data.espdev = get_blockinfo_for_path(multiboot_data.blockinfo, multiboot_data.esp->blk_device);

    // grant ourselves some selinux permissions :)
    selinux_fixup();

    // boot recovery
    if(util_exists("/sbin/recovery", true)) {
        return boot_recovery();
    }

    // boot main system
    if(multiboot_data.guid==NULL && multiboot_data.path==NULL) {
        LOGI("Booting main system\n");

        pid_t pid = fork();
        if(pid<0) {
            return EFIVARS_LOG_TRACE(pid, "Can't fork current process\n");
        }

        // parent
        if(pid) {
            // install usr handler
            util_setsighandler(SIGUSR1, init_usr_handler);

            // wait for mbinit to finish
            WAIT_FOR_SIGNAL(SIGUSR1, !init_usr_interrupt);

            return run_init(NULL);
        }

        // child
        else {
            // add post-fs-data event
            snprintf(buf, PATH_MAX, "\n\n"
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
        }
    }

    // TODO: boot multiboot system
    else {
        LOGE("UNSUPPORTED\n");
        return -1;
    }

    return 0;



#if 0
    LOGI("Booting from {%s}%s\n", multiboot_data.guid,multiboot_data.path);

    // parse /sys/block
    uevent_block_info_t* blockinfo = get_block_devices();

    // get boot device
    int i;
    char buf[PATH_MAX+1];
	for (i = 0; i < blockinfo->num_entries; i++) {
		uevent_block_t *event = &blockinfo->entries[i];

        snprintf(buf, sizeof(buf), "/dev/block/%s", event->devname);
        if(device_matches(buf, multiboot_data.guid)) {
            multiboot_data.bootdev = event;
            break;
        }
	}
    if(!multiboot_data.bootdev) {
        LOGE("Boot device not found!");
        return -EINVAL;
    }

    LOGI("Boot device: %s\n", multiboot_data.bootdev->devname);
    scan_mounted_volumes();
    dump_mounted_volumes();

    const mounted_volume_t* volume = find_mounted_volume_by_majmin(multiboot_data.bootdev->major, multiboot_data.bootdev->minor);
    if(volume) {
        LOGI("bootdev mounted at %s\n", volume->mount_point);
    }
#endif

    return rc;
}
