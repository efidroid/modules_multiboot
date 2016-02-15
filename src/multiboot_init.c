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
#include <ini.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "INIT"
#include <lib/log.h>

PAYLOAD_IMPORT(fstab_multiboot);
PAYLOAD_IMPORT(busybox);
PAYLOAD_IMPORT(mke2fs);
PAYLOAD_IMPORT(mkfs_f2fs);
static multiboot_data_t multiboot_data = {0};

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
            EFIVARS_LOG_FATAL(-1, "invalid format\n");
            return;
        }

        // read values
        if ((rc=sscanf(value, format, type, guid, &path)) != 3) {
            EFIVARS_LOG_FATAL(rc, "invalid format\n");
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
    pid_t pid;

    // libblkid uses hardcoded paths for /sys and /dev
    // to make it work with our custom environmont (without modifying the libblkid code)
    // we have to chroot to /multiboot
    pid = fork();
    if (!pid) {
        chroot("/multiboot");

        // get dev
        blkid_get_cache(&cache, NULL);
        blkid_dev dev = blkid_get_dev(cache, path, BLKID_DEV_NORMAL);
        if(!dev) {
            LOGV("Device %s not found\n", path);
            exit(0);
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
        exit(rc);
    } else {
        waitpid(pid, &rc, 0);
    }

    return rc;
}

int run_init(struct tracy *tracy)
{
    char *par[2];
    int i = 0, ret = 0;

    // build args
    par[i++] = "/init";
    par[i++] = (char *)0;

    // close all file handles
    int fd;
    for(fd=0; fd<10; fd++)
        close(fd);

    // RUN
    if (tracy)
        ret = !tracy_exec(tracy, par);
    else {
        ret = execve(par[0], par, NULL);
    }

    // error check
    if (ret) {
        LOGE("Can't start %s: %s\n", par[0], strerror(errno));
        return ret;
    }

    return 0;
}

static int selinux_fixup(void) {
    int rc = 0;

    // we ignore errors on purpose here because selinux might not be needed or supported by the system

    // these two are a side effect of running /init with execve
    // { execmem } for  uid=0 pid=160 comm="init" scontext=u:r:init:s0 tcontext=u:r:init:s0 tclass=process
    util_sepolicy_inject("init", "init", "process", "execmem");
    // { execute } for  uid=0 pid=166 comm="e2fsck" path="/dev/__properties__" dev="tmpfs" ino=5017 scontext=u:r:init:s0 tcontext=u:object_r:properties_device:s0 tclass=file
    util_sepolicy_inject("init", "properties_device", "file", "execute");

    // Android M needs these to run /init
    // { execute } for  uid=0 pid=1 comm="init" path="/file_contexts" dev="rootfs" ino=4541 scontext=u:r:kernel:s0 tcontext=u:object_r:rootfs:s0 tclass=file permissive=0
    // { execute } for  uid=0 pid=1 comm="init" name="init" dev="rootfs" ino=4543 scontext=u:r:kernel:s0 tcontext=u:object_r:rootfs:s0 tclass=file permissive=0
    util_sepolicy_inject("kernel", "rootfs", "file", "execute");

    // for sending SIGUSR1 from trigger-postfs to init.multiboot
    // { signal } for  uid=0 pid=209 comm="trigger-postfs-" scontext=u:r:init:s0 tcontext=u:r:kernel:s0 tclass=process
    util_sepolicy_inject("init", "kernel", "process", "signal");
    // for sending SIGUSR1 from init.multiboot to trigger-postfs
    // { signal } for  uid=0 pid=156 comm="init.multiboot" scontext=u:r:kernel:s0 tcontext=u:r:init:s0 tclass=process
    util_sepolicy_inject("kernel", "init", "process", "signal");
    // for creating POSTFS_NOTIFICATION_FILE
    // { write } for  uid=0 pid=156 comm="init.multiboot" path=2F6465762F5F5F6B6D73675F5F202864656C6574656429 dev="rootfs" ino=5004 scontext=u:r:kernel:s0 tcontext=u:object_r:rootfs:s0 tclass=chr_file
    util_sepolicy_inject("kernel", "rootfs", "chr_file", "write");
    // Android M
    // { execute_no_trans } for uid=0 pid=188 comm="init" path="/init.multiboot" dev="rootfs" ino=4575 scontext=u:r:init:s0 tcontext=u:object_r:rootfs:s0 tclass=file permissive=0
    util_sepolicy_inject("init", "rootfs", "file", "execute_no_trans");
    // { search } for uid=0 pid=153 comm="init.multiboot" name="1" dev="proc" ino=5311 scontext=u:r:kernel:s0 tcontext=u:r:init:s0 tclass=dir permissive=0
    util_sepolicy_inject("kernel", "init", "dir", "search");
    // { read } for uid=0 pid=153 comm="init.multiboot" name="mountinfo" dev="proc" ino=6119 scontext=u:r:kernel:s0 tcontext=u:r:init:s0 tclass=file permissive=0
    // { open } for uid=0 pid=152 comm="init.multiboot" name="mountinfo" dev="proc" ino=7086 scontext=u:r:kernel:s0 tcontext=u:r:init:s0 tclass=file permissive=0
    util_sepolicy_inject("kernel", "init", "file", "read,open");
    // { search } for uid=0 pid=153 comm="init.multiboot" name="media" dev="mmcblk0p36" ino=106 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=dir permissive=0
    // { getattr } for uid=0 pid=153 comm="init.multiboot" path="/data/media" dev="mmcblk0p36" ino=106 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=dir permissive=0
    // { write } for uid=0 pid=209 comm="busybox" name="UEFIESP" dev="mmcblk0p36" ino=38022 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=dir permissive=1
    util_sepolicy_inject("kernel", "media_rw_data_file", "dir", "search,getattr,write");
    // { getattr } for uid=0 pid=153 comm="init.multiboot" path="/dev/block/mmcblk0p32" dev="tmpfs" ino=6864 scontext=u:r:kernel:s0 tcontext=u:object_r:recovery_block_device:s0 tclass=blk_file permissive=0
    // { read } for uid=0 pid=152 comm="init.multiboot" name="mmcblk0p32" dev="tmpfs" ino=7050 scontext=u:r:kernel:s0 tcontext=u:object_r:recovery_block_device:s0 tclass=blk_file permissive=0
    // { ioctl } for uid=0 pid=151 comm="init.multiboot" path="/dev/block/mmcblk0p32" dev="tmpfs" ino=6424 ioctlcmd=1260 scontext=u:r:kernel:s0 tcontext=u:object_r:recovery_block_device:s0 tclass=blk_file permissive=1
    // { open } for uid=0 pid=153 comm="init.multiboot" name="mmcblk0p32" dev="tmpfs" ino=6182 scontext=u:r:kernel:s0 tcontext=u:object_r:recovery_block_device:s0 tclass=blk_file permissive=0
    util_sepolicy_inject("kernel", "recovery_block_device", "blk_file", "getattr,read,ioctl,open");
    // { write } for uid=0 pid=151 comm="init.multiboot" name="block" dev="tmpfs" ino=6217 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=dir permissive=1
    // { remove_name } for uid=0 pid=151 comm="init.multiboot" name="mmcblk0p32" dev="tmpfs" ino=6424 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=dir permissive=1
    // { add_name } for uid=0 pid=151 comm="init.multiboot" name="mmcblk0p32" scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=dir permissive=1
    util_sepolicy_inject("kernel", "block_device", "dir", "write,remove_name,add_name");
    // { create } for uid=0 pid=209 comm="busybox" name="partition_recovery.img" scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=1
    // { write open } for uid=0 pid=209 comm="busybox" name="partition_recovery.img" dev="mmcblk0p36" ino=55728 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=1
    // { read } for uid=0 pid=210 comm="busybox" name="partition_recovery.img" dev="mmcblk0p36" ino=55728 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=1
    // { getattr } for uid=0 pid=152 comm="init.multiboot" path="/data/media/UEFIESP/partition_recovery.img" dev="mmcblk0p36" ino=55728 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=0
    util_sepolicy_inject("kernel", "media_rw_data_file", "file", "create,write,read,open,getattr");

    // the following rules are needed for setting up UEFI partition replacements
    // { execute } for  uid=0 pid=210 comm="init.multiboot" name="busybox" dev="tmpfs" ino=4985 scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=file
    // { execute_no_trans } for  uid=0 pid=210 comm="init.multiboot" path="/multiboot/bin/busybox" dev="tmpfs" ino=4985 scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=file
    // { open } for uid=0 pid=209 comm="init.multiboot" name="busybox" dev="tmpfs" ino=5507 scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=file permissive=1
    util_sepolicy_inject("kernel", "tmpfs", "file", "execute,execute_no_trans,open");
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

static int mbini_count_handler(unused void* user, const char* section, unused const char* name, unused const char* value) {
    // we're interested in partitions only
    if(strcmp(section, "partitions"))
        return 1;

    multiboot_data.num_mbparts++;

    return 1;
}

static int mbini_handler(unused void* user, const char* section, const char* name, const char* value) {
    uint32_t* index = user;

    if((*index)>=multiboot_data.num_mbparts) {
        EFIVARS_LOG_TRACE(-ENOMEM, "Too many partitions\n");
    }

    // we're interested in partitions only
    if(strcmp(section, "partitions"))
        return 1;

    // validate args
    if(!name || !value) {
        EFIVARS_LOG_TRACE(-EINVAL, "Invalid argument\n");
        return 1;
    }

    // setup partition
    multiboot_partition_t* part = &multiboot_data.mbparts[(*index)++];
    part->name = strdup(name);
    part->path = strdup(value);
    part->is_bind = 1;

    // validate duplicated strings
    if(!part->name || !part->path) {
        EFIVARS_LOG_TRACE(-ENOMEM, "Can't duplicate strings\n");
        return 1;
    }

    // check if it's a bind mount
    int pathlen = strlen(part->path);
    if(pathlen>=4 && !strcmp(part->path+pathlen-4, ".img"))
        part->is_bind = 0;

    // inih defines 1 as OK
    return 1;
}

multiboot_partition_t* multiboot_part_by_name(const char* name) {
    uint32_t i;

    if(!multiboot_data.mbparts)
        return NULL;

    for(i=0; i<multiboot_data.num_mbparts; i++) {
        multiboot_partition_t* part = &multiboot_data.mbparts[i];

        if(!strcmp(part->name, name))
            return part;
    }

    return NULL;
}

int multiboot_main(unused int argc, char** argv) {
    int rc = 0;
    int i;
    char buf[PATH_MAX];

    // init logging
    log_init();

    // mount tmpfs to MBPATH_ROOT so we'll be able to write once init mounted rootfs as RO
    rc = util_mount("tmpfs", MBPATH_ROOT, "tmpfs", MS_NOSUID, "mode=0755");
    if(rc) {
        LOGE("Can't mount tmpfs: %s\n", strerror(errno));
        return rc;
    }

    // mount private sysfs
    rc = util_mount("sysfs", MBPATH_SYS, "sysfs", 0, NULL);
    if(rc) {
        LOGE("Can't mount sysfs: %s\n", strerror(errno));
        return rc;
    }

    // mount private proc
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

    // mount private dev fs
    rc = util_mount("tmpfs", MBPATH_DEV, "tmpfs", MS_NOSUID, "mode=0755");
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't mount tmpfs for dev: %s\n", strerror(errno));
    }

    // build private dev fs
    rc = uevent_create_nodes(multiboot_data.blockinfo, MBPATH_DEV);
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't mount dev: %s\n", strerror(errno));
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

    // extract mke2fs
    rc = util_extractbin(PAYLOAD_PTR(mke2fs), MBPATH_MKE2FS, PAYLOAD_SIZE(mke2fs));
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't extract busybox to "MBPATH_MKE2FS": %s\n", strerror(errno));
    }

    // extract mke2fs
    rc = util_extractbin(PAYLOAD_PTR(mkfs_f2fs), MBPATH_MKFS_F2FS, PAYLOAD_SIZE(mkfs_f2fs));
    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "Can't extract busybox to "MBPATH_MKE2FS": %s\n", strerror(errno));
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
    multiboot_data.romfstabpath = strdup(buf);

    // parse ROM fstab
    multiboot_data.romfstab = fs_mgr_read_fstab(buf);
    if(!multiboot_data.romfstab) {
        // for Android, this fstab is mandatory
        if(!util_exists("/sbin/recovery", true))
            return EFIVARS_LOG_TRACE(rc, "Can't parse %s: %s\n", buf, strerror(errno));

        // try /etc/twrp.fstab
        multiboot_data.romfstab = fs_mgr_read_fstab("/etc/twrp.fstab");
        if(multiboot_data.romfstab) {
            multiboot_data.romfstabpath = strdup("/etc/twrp.fstab");
        }
    }

    // get ESP partition
    multiboot_data.esp = fs_mgr_esp(multiboot_data.mbfstab);
    if(!multiboot_data.esp) {
        return EFIVARS_LOG_TRACE(-ENOENT, "ESP partition not found\n");
    }
    multiboot_data.espdev = get_blockinfo_for_path(multiboot_data.blockinfo, multiboot_data.esp->blk_device);

    // grant ourselves some selinux permissions :)
    selinux_fixup();

    // common multiboot initialization
    if(multiboot_data.guid!=NULL && multiboot_data.path!=NULL) {
        multiboot_data.is_multiboot = 1;
        LOGI("Booting from {%s}%s\n", multiboot_data.guid, multiboot_data.path);

        // get boot device
        for(i=0; i<multiboot_data.blockinfo->num_entries; i++) {
            uevent_block_t *event = &multiboot_data.blockinfo->entries[i];

            snprintf(buf, sizeof(buf), "/dev/block/%s", event->devname);
            if(device_matches(buf, multiboot_data.guid)) {
                multiboot_data.bootdev = event;
                break;
            }
        }

        if(!multiboot_data.bootdev) {
            return EFIVARS_LOG_TRACE(-EINVAL, "Boot device not found");
        }
        LOGI("Boot device: %s\n", multiboot_data.bootdev->devname);

        // try to use the ROM's mountflags
        unsigned long mountflags = 0;
        const void* data = NULL;
        struct fstab_rec* bootdevrec = fs_mgr_get_by_ueventblock(multiboot_data.romfstab, multiboot_data.bootdev);
        if(bootdevrec) {
            // use the ROM's mount options for this partition
            mountflags = bootdevrec->flags;
            data = (void*)bootdevrec->fs_options;
        }

        // mount bootdev
        rc = uevent_mount(multiboot_data.bootdev, MBPATH_BOOTDEV, NULL, mountflags, data);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't mount boot device: %s\n", strerror(errno));
        }

        // get rec for /data
        struct fstab_rec* datarecmb = fs_mgr_get_by_mountpoint(multiboot_data.mbfstab, "/data");
        if(!datarecmb) {
            return EFIVARS_LOG_TRACE(-ENOENT, "Can't get rec for /data\n");
        }

        // get blockinfo for /data
        uevent_block_t* datablock = get_blockinfo_for_path(multiboot_data.blockinfo, datarecmb->blk_device);
        if(!datablock) {
            return EFIVARS_LOG_TRACE(-ENOENT, "Can't get blockinfo for %s\n", datarecmb->blk_device);
        }

        // get the ROM's mount flags for /data
        mountflags = 0;
        data = NULL;
        struct fstab_rec* datarec = fs_mgr_get_by_ueventblock(multiboot_data.romfstab, datablock);
        if(datarec) {
            mountflags = datarec->flags;
            data = (void*)datarec->fs_options;
        }

        // mount data
        rc = uevent_mount(datablock, MBPATH_DATA, NULL, mountflags, data);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't mount data: %s\n", strerror(errno));
        }

        // check for bind-mount support
        rc = scan_mounted_volumes();
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't scan mounted volumes: %s\n", strerror(errno));
        }
        const mounted_volume_t* volume = find_mounted_volume_by_majmin(multiboot_data.bootdev->major, multiboot_data.bootdev->minor, 0);
        if(!volume) {
            return EFIVARS_LOG_TRACE(rc, "boot device not mounted (DAFUQ?)\n");
        }
        if(util_fs_supports_multiboot_bind(volume->filesystem)) {
            multiboot_data.bootdev_supports_bindmount = 1;
        }

        // build multiboot.ini filename
        rc = snprintf(buf, sizeof(buf), MBPATH_BOOTDEV"%s", multiboot_data.path);
        if(rc<0) {
            return EFIVARS_LOG_TRACE(rc, "Can't build multiboot.ini path: %s\n", strerror(errno));
        }

        // count partitions in multiboot.ini
        rc = ini_parse(buf, mbini_count_handler, NULL);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't count partitions in '%s': %s\n", buf, strerror(errno));
        }

        // allocate mbparts array
        multiboot_data.mbparts = calloc(sizeof(multiboot_partition_t), multiboot_data.num_mbparts);
        if(!multiboot_data.mbparts) {
            return EFIVARS_LOG_TRACE(-errno, "Can't allocate multiboot partitions array: %s\n", strerror(errno));
        }

        // parse multiboot.ini
        uint32_t index = 0;
        rc = ini_parse(buf, mbini_handler, &index);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't parse '%s': %s\n", buf, strerror(errno));
        }

        // verify multiboot partitions
        for(i=0; i<multiboot_data.mbfstab->num_entries; i++) {
            struct fstab_rec *rec;

            // skip non-multiboot partitions
            rec = &multiboot_data.mbfstab->recs[i];
            if(!fs_mgr_is_multiboot(rec)) continue;

            // get multiboot partition
            multiboot_partition_t* part = multiboot_part_by_name(rec->mount_point+1);
            if(!part) {
                return EFIVARS_LOG_TRACE(-ENOENT, "Can't find multiboot partition for '%s': %s\n", rec->mount_point, strerror(errno));
            }

            // check if bind support is needed
            if(part->is_bind && !multiboot_data.bootdev_supports_bindmount) {
                return EFIVARS_LOG_TRACE(-1, "Boot device doesn't support bind mounts\n");
            }

            // check if bind support is needed
            if(part->is_bind && !strcmp(rec->fs_type, "emmc")) {
                return EFIVARS_LOG_TRACE(-1, "raw device %s doesn't support bind mounts\n", rec->blk_device);
            }
        }
    }

    // boot recovery
    if(util_exists("/sbin/recovery", true)) {
        LOGI("Booting recovery\n");
        return boot_recovery();
    }

    // boot android
    else {
        LOGI("Booting android\n");
        return boot_android();
    }

    return rc;
}
