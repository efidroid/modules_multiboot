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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <lib/cmdline.h>
#include <lib/mounts.h>
#include <lib/fs_mgr.h>
#include <blkid/blkid.h>
#include <ini.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "INIT"
#include <lib/log.h>

PAYLOAD_IMPORT(fstab_multiboot);
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
            MBABORT("invalid multibootpath: %s\n", value);
            return;
        }

        // read values
        if ((rc=sscanf(value, format, type, guid, &path)) != 3) {
            MBABORT("invalid multibootpath: %s\n", value);
            return;
        }

        multiboot_data.guid = safe_strdup(guid);
        multiboot_data.path = path;
    }

    if (!strcmp(name, "multiboot.debug")) {
        uint32_t val;
        if (sscanf(value, "%u", &val) != 1) {
            LOGE("invalid value for %s: %s\n", name, value);
            return;
        }

        log_set_level(val);
    }

    else if (!strcmp(name, "androidboot.hardware")) {
        multiboot_data.hwname = safe_strdup(value);
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
    pid = safe_fork();
    if (!pid) {
        rc = chroot("/multiboot");
        if(rc<0) {
            MBABORT("chroot error: %s\n", strerror(errno));
        }

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

int run_init(int trace)
{
    char *par[2];
    int i = 0, ret = 0;

    // build args
    par[i++] = "/init";
    par[i++] = (char *)0;

    // RUN
    if (trace){
        ret = multiboot_exec_tracee(par);
    }
    else {
        // close all file handles
        int fd;
        for(fd=0; fd<10; fd++)
            close(fd);
        ret = execve(par[0], par, NULL);
    }

    // error check
    if (ret) {
        MBABORT("Can't start %s: %s\n", par[0], strerror(errno));
        return -1;
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
    // { unlink } for uid=0 pid=152 comm="init.multiboot" name="mmcblk0p32" dev="tmpfs" ino=6322 scontext=u:r:kernel:s0 tcontext=u:object_r:recovery_block_device:s0 tclass=blk_file permissive=0
    util_sepolicy_inject("kernel", "recovery_block_device", "blk_file", "getattr,read,ioctl,open,unlink");
    // { write } for uid=0 pid=151 comm="init.multiboot" name="block" dev="tmpfs" ino=6217 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=dir permissive=1
    // { remove_name } for uid=0 pid=151 comm="init.multiboot" name="mmcblk0p32" dev="tmpfs" ino=6424 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=dir permissive=1
    // { add_name } for uid=0 pid=151 comm="init.multiboot" name="mmcblk0p32" scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=dir permissive=1
    util_sepolicy_inject("kernel", "block_device", "dir", "write,remove_name,add_name");
    // { create } for uid=0 pid=209 comm="busybox" name="partition_recovery.img" scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=1
    // { write open } for uid=0 pid=209 comm="busybox" name="partition_recovery.img" dev="mmcblk0p36" ino=55728 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=1
    // { read } for uid=0 pid=210 comm="busybox" name="partition_recovery.img" dev="mmcblk0p36" ino=55728 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=1
    // { getattr } for uid=0 pid=152 comm="init.multiboot" path="/data/media/UEFIESP/partition_recovery.img" dev="mmcblk0p36" ino=55728 scontext=u:r:kernel:s0 tcontext=u:object_r:media_rw_data_file:s0 tclass=file permissive=0
    util_sepolicy_inject("kernel", "media_rw_data_file", "file", "create,write,read,open,getattr");
    // { ioctl } for uid=0 pid=152 comm="init.multiboot" path="/dev/block/mmcblk0p31" dev="tmpfs" ino=6412 ioctlcmd=1260 scontext=u:r:kernel:s0 tcontext=u:object_r:boot_block_device:s0 tclass=blk_file permissive=1
    // { read } for uid=0 pid=152 comm="init.multiboot" name="mmcblk0p31" dev="tmpfs" ino=6412 scontext=u:r:kernel:s0 tcontext=u:object_r:boot_block_device:s0 tclass=blk_file permissive=1
    // { open } for uid=0 pid=152 comm="init.multiboot" name="mmcblk0p31" dev="tmpfs" ino=6412 scontext=u:r:kernel:s0 tcontext=u:object_r:boot_block_device:s0 tclass=blk_file permissive=1
    // { getattr } for uid=0 pid=153 comm="init.multiboot" path="/dev/block/mmcblk0p31" dev="tmpfs" ino=6705 scontext=u:r:kernel:s0 tcontext=u:object_r:boot_block_device:s0 tclass=blk_file permissive=0
    util_sepolicy_inject("kernel", "boot_block_device", "blk_file", "ioctl,read,open,getattr");

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
    // { write } for uid=0 pid=152 comm="init.multiboot" name="/" dev="tmpfs" ino=5328 scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=dir permissive=0
    util_sepolicy_inject("kernel", "tmpfs", "dir", "write");
    // { create } for uid=0 pid=153 comm="init.multiboot" name="replacement_backup_boot" scontext=u:r:kernel:s0 tcontext=u:object_r:tmpfs:s0 tclass=blk_file permissive=0
    util_sepolicy_inject("kernel", "tmpfs", "blk_file", "create");

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

static int mbini_count_handler(UNUSED void* user, const char* section, UNUSED const char* name, UNUSED const char* value) {
    // we're interested in partitions only
    if(strcmp(section, "partitions"))
        return 1;

    multiboot_data.num_mbparts++;

    return 1;
}

static int mbini_handler(UNUSED void* user, const char* section, const char* name, const char* value) {
    uint32_t* index = user;

    // we're interested in partitions only
    if(strcmp(section, "partitions"))
        return 1;

    if((*index)>=multiboot_data.num_mbparts) {
        MBABORT("Too many partitions: %d>=%d\n", (*index), multiboot_data.num_mbparts);
        return 0;
    }

    // validate args
    if(!name || !value) {
        MBABORT("Invalid name/value in multiboot.ini\n");
        return 1;
    }

    // setup partition
    multiboot_partition_t* part = &multiboot_data.mbparts[(*index)++];
    part->name = safe_strdup(name);
    part->path = safe_strdup(value);
    part->type = MBPART_TYPE_BIND;

    // determine partition type
    int pathlen = strlen(part->path);
    if(pathlen>=4) {
        const char* ext = part->path+pathlen-4;
        if(!strcmp(ext, ".img"))
            part->type = MBPART_TYPE_LOOP;
        else if(!strcmp(ext, ".dyn"))
            part->type = MBPART_TYPE_DYN;
    }

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

int multiboot_main(UNUSED int argc, char** argv) {
    int rc = 0;
    int i;
    char buf[PATH_MAX];

    // basic multiboot_data init
    list_initialize(&multiboot_data.replacements);

    // init logging
    log_init();

    // mount tmpfs to MBPATH_ROOT so we'll be able to write once init mounted rootfs as RO
    SAFE_MOUNT("tmpfs", MBPATH_ROOT, "tmpfs", MS_NOSUID, "mode=0755");

    // mount private sysfs
    SAFE_MOUNT("sysfs", MBPATH_SYS, "sysfs", 0, NULL);

    // mount private proc
    SAFE_MOUNT("proc", MBPATH_PROC, "proc", 0, NULL);

    // parse cmdline
    LOGD("parse cmdline\n");
    import_kernel_cmdline(import_kernel_nv);

    // parse /sys/block
    LOGD("parse /sys/block\n");
    multiboot_data.blockinfo = get_block_devices();
    if(!multiboot_data.blockinfo) {
        LOGE("Can't retrieve blockinfo: %s\n", strerror(errno));
        return -errno;
    }

    // mount private dev fs
    LOGD("mount %s\n", MBPATH_DEV);
    SAFE_MOUNT("tmpfs", MBPATH_DEV, "tmpfs", MS_NOSUID, "mode=0755");

    // build private dev fs
    LOGD("build dev fs\n");
    rc = uevent_create_nodes(multiboot_data.blockinfo, MBPATH_DEV);
    if(rc) {
        MBABORT("Can't mount dev: %s\n", strerror(errno));
    }

    // check for hwname
    LOGV("verify hw name\n");
    if(!multiboot_data.hwname) {
        MBABORT("cmdline didn't contain a valid 'androidboot.hardware': %s\n", strerror(ENOENT));
    }

    // create directories
    LOGV("create %s\n", MBPATH_BIN);
    rc = util_mkdir(MBPATH_BIN);
    if(rc) {
        MBABORT("Can't create directory '"MBPATH_BIN"': %s\n", strerror(errno));
    }

    // extract fstab.multiboot
    LOGD("extract %s\n", MBPATH_FSTAB);
    rc = util_buf2file(PAYLOAD_PTR(fstab_multiboot), MBPATH_FSTAB, PAYLOAD_SIZE(fstab_multiboot));
    if(rc) {
        MBABORT("Can't extract fstab to "MBPATH_FSTAB": %s\n", strerror(errno));
    }

    // create symlinks
    LOGV("create symlink %s->%s\n", MBPATH_TRIGGER_POSTFS_DATA, argv[0]);
    rc = symlink(argv[0], MBPATH_TRIGGER_POSTFS_DATA);
    if(rc) {
        MBABORT("Can't create symlink "MBPATH_TRIGGER_POSTFS_DATA": %s\n", strerror(errno));
    }

    LOGV("create symlink %s->%s\n", MBPATH_BUSYBOX, argv[0]);
    rc = symlink(argv[0], MBPATH_BUSYBOX);
    if(rc) {
        MBABORT("Can't create symlink "MBPATH_BUSYBOX": %s\n", strerror(errno));
    }

    LOGV("create symlink %s->%s\n", MBPATH_MKE2FS, argv[0]);
    rc = symlink(argv[0], MBPATH_MKE2FS);
    if(rc) {
        MBABORT("Can't create symlink "MBPATH_MKE2FS": %s\n", strerror(errno));
    }

    // parse multiboot fstab
    LOGD("parse %s\n", MBPATH_FSTAB);
    multiboot_data.mbfstab = fs_mgr_read_fstab(MBPATH_FSTAB);
    if(!multiboot_data.mbfstab) {
        MBABORT("Can't parse multiboot fstab: %s\n", strerror(errno));
    }

    // build fstab name
    SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "/fstab.%s", multiboot_data.hwname);
    multiboot_data.romfstabpath = safe_strdup(buf);

    // parse ROM fstab
    LOGD("parse ROM fstab: %s\n", buf);
    multiboot_data.romfstab = fs_mgr_read_fstab(buf);
    if(!multiboot_data.romfstab) {
        // for Android, this fstab is mandatory
        if(!util_exists("/sbin/recovery", true))
            MBABORT("Can't parse %s: %s\n", buf, strerror(errno));

        // try /etc/twrp.fstab
        LOGD("parse /etc/twrp.fstab\n");
        multiboot_data.romfstab = fs_mgr_read_fstab("/etc/twrp.fstab");
        if(multiboot_data.romfstab) {
            multiboot_data.romfstabpath = safe_strdup("/etc/twrp.fstab");
        }
    }

    // get ESP partition
    LOGV("get ESP from fs_mgr\n");
    multiboot_data.esp = fs_mgr_esp(multiboot_data.mbfstab);
    if(!multiboot_data.esp) {
        MBABORT("ESP partition not found\n");
    }
    LOGV("get blockinfo for ESP\n");
    multiboot_data.espdev = get_blockinfo_for_path(multiboot_data.blockinfo, multiboot_data.esp->blk_device);
    if(!multiboot_data.espdev) {
        MBABORT("can't get blockinfo for ESP\n");
    }

    // grant ourselves some selinux permissions :)
    LOGD("patch sepolicy\n");
    selinux_fixup();

    // common multiboot initialization
    if(multiboot_data.guid!=NULL && multiboot_data.path!=NULL) {
        multiboot_data.is_multiboot = 1;
        LOGI("Booting from {%s}%s\n", multiboot_data.guid, multiboot_data.path);

        // get boot device
        LOGD("search for boot device\n");
        for(i=0; i<multiboot_data.blockinfo->num_entries; i++) {
            uevent_block_t *event = &multiboot_data.blockinfo->entries[i];

            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "/dev/block/%s", event->devname);
            if(device_matches(buf, multiboot_data.guid)) {
                multiboot_data.bootdev = event;
                break;
            }
        }

        if(!multiboot_data.bootdev) {
            MBABORT("Boot device not found\n");
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

            LOGD("use ROM mountflags for bootdev, flags:%lu, data:%s\n", mountflags, (const char*)data);
        }

        // mount bootdev
        LOGD("mount boot device\n");
        rc = uevent_mount(multiboot_data.bootdev, MBPATH_BOOTDEV, NULL, mountflags, data);
        if(rc) {
            // mount without flags
            LOGI("mount bootdev without flags\n");
            mountflags = 0;
            data = NULL;
            rc = uevent_mount(multiboot_data.bootdev, MBPATH_BOOTDEV, NULL, mountflags, data);
            if(rc)
                MBABORT("Can't mount boot device: %s\n", strerror(errno));
        }

        // get rec for /data
        LOGV("search for /data\n");
        struct fstab_rec* datarecmb = fs_mgr_get_by_mountpoint(multiboot_data.mbfstab, "/data");
        if(!datarecmb) {
            MBABORT("Can't get rec for /data\n");
        }

        // get blockinfo for /data
        LOGV("get blockinfo for /data\n");
        uevent_block_t* datablock = get_blockinfo_for_path(multiboot_data.blockinfo, datarecmb->blk_device);
        if(!datablock) {
            MBABORT("Can't get blockinfo for %s\n", datarecmb->blk_device);
        }

        // get the ROM's mount flags for /data
        mountflags = 0;
        data = NULL;
        struct fstab_rec* datarec = fs_mgr_get_by_ueventblock(multiboot_data.romfstab, datablock);
        if(datarec) {
            mountflags = datarec->flags;
            data = (void*)datarec->fs_options;
            LOGD("use ROM mountflags for /data, flags:%lu, data:%s\n", mountflags, (const char*)data);
        }

        // mount data
        LOGD("mount /data\n");
        rc = uevent_mount(datablock, MBPATH_DATA, NULL, mountflags, data);
        if(rc) {
            // mount without flags
            LOGI("mount /data without flags\n");
            mountflags = 0;
            data = NULL;
            rc = uevent_mount(datablock, MBPATH_DATA, NULL, mountflags, data);
            if(rc)
                MBABORT("Can't mount data: %s\n", strerror(errno));
        }

        // check for bind-mount support
        LOGV("scan mounted volumes\n");
        rc = scan_mounted_volumes();
        if(rc) {
            MBABORT("Can't scan mounted volumes: %s\n", strerror(errno));
        }
        LOGV("search mounted bootdev\n");
        const mounted_volume_t* volume = find_mounted_volume_by_majmin(multiboot_data.bootdev->major, multiboot_data.bootdev->minor, 0);
        if(!volume) {
            MBABORT("boot device not mounted (DAFUQ?)\n");
        }
        if(util_fs_supports_multiboot_bind(volume->filesystem)) {
            LOGD("bootdev has bind mount support\n");
            multiboot_data.bootdev_supports_bindmount = 1;
        }

        // build multiboot.ini filename
        SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BOOTDEV"%s", multiboot_data.path);

        // count partitions in multiboot.ini
        LOGD("parse %s using mbini_count_handler\n", buf);
        rc = ini_parse(buf, mbini_count_handler, NULL);
        if(rc) {
            MBABORT("Can't count partitions in '%s': %s\n", buf, strerror(errno));
        }

        // allocate mbparts array
        multiboot_data.mbparts = safe_calloc(sizeof(multiboot_partition_t), multiboot_data.num_mbparts);
        if(!multiboot_data.mbparts) {
            MBABORT("Can't allocate multiboot partitions array: %s\n", strerror(errno));
        }

        // parse multiboot.ini
        uint32_t index = 0;
        LOGD("parse %s using mbini_handler\n", buf);
        rc = ini_parse(buf, mbini_handler, &index);
        if(rc) {
            MBABORT("Can't parse '%s': %s\n", buf, strerror(errno));
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
                MBABORT("Can't find multiboot partition for '%s': %s\n", rec->mount_point, strerror(errno));
            }

            if(part->type==MBPART_TYPE_BIND) {
                // check if bootdev supports bind mounts
                if(!multiboot_data.bootdev_supports_bindmount)
                    MBABORT("Boot device doesn't support bind mounts\n");

                // check if this should be a raw partition
                if(!strcmp(rec->fs_type, "emmc")) {
                    MBABORT("raw device %s doesn't support bind mounts\n", rec->blk_device);
                }
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
