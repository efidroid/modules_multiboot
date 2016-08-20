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
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/netlink.h>

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
        char guid[37];
        char *path = NULL;

        // check type
        const char* format = NULL;
        if(!strncmp(value, "GPT", 3))
            format = "GPT,%36s,%ms";
        else if(!strncmp(value, "MBR", 3))
            format = "MBR,%11s,%ms";
        else {
            MBABORT("invalid multibootpath: %s\n", value);
            return;
        }

        // read values
        if ((rc=sscanf(value, format, guid, &path)) != 2) {
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

static uevent_block_t* get_blockinfo_for_guid(const char* guid) {
    int rc = 0;
    blkid_tag_iterate iter;
    const char *type, *value;
    blkid_cache cache = NULL;
    pid_t pid;
    char path[PATH_MAX];

    // allocate shared memory
    uevent_block_t** result = mmap(NULL, sizeof(void*), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if(!result)  {
        MBABORT("mmap failed: %s\n", strerror(errno));
    }
    *result = NULL;

    // libblkid uses hardcoded paths for /sys and /dev
    // to make it work with our custom environmont (without modifying the libblkid code)
    // we have to chroot to /multiboot
    pid = safe_fork();
    if (!pid) {
        // chroot
        rc = chroot("/multiboot");
        if(rc<0) {
            MBABORT("chroot error: %s\n", strerror(errno));
        }

        uevent_block_t *event;
        list_for_every_entry(multiboot_data.blockinfo, event, uevent_block_t, node) {
            rc = snprintf(path, sizeof(path), "/dev/block/%s", event->devname);
            if(SNPRINTF_ERROR(rc, sizeof(path))) {
                MBABORT("snprintf error\n");
            }

            // get dev
            blkid_get_cache(&cache, NULL);
            blkid_dev dev = blkid_get_dev(cache, path, BLKID_DEV_NORMAL);
            if(!dev) {
                LOGV("Device %s not found\n", path);
                continue;
            }

            // get part uuid
            iter = blkid_tag_iterate_begin(dev);
            while (blkid_tag_next(iter, &type, &value) == 0) {
                if(!strcmp(type, "PARTUUID")) {
                    if(!strcasecmp(value, guid)) {
                        // we have a match

                        // this assignment works because both we and our parent use the same address
                        // so while the actual memory is (or may be) different, the address is the same
                        *result = event;
                        exit(0);
                    }
                }
            }

            blkid_tag_iterate_end(iter);
        }

        // not found
        exit(1);
    } else {
        waitpid(pid, &rc, 0);
    }

    // get result
    uevent_block_t* ret = NULL;
    if(rc==0)
        ret = *result;

    // cleanup
    munmap(result, sizeof(void*));

    return ret;
}

int run_init(int trace)
{
    char *par[2];
    int i = 0, ret = 0;

    // cancel watchdog timer
    alarm(0);

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

    // don't apply patches in recovery mode
    if(util_exists("/sbin/recovery", true))
        return 0;

    util_sepolicy_inject("init_multiboot", "rootfs", "filesystem", "associate");
    util_sepolicy_inject("init", "init_multiboot", "file", "relabelto,getattr,execute,read,execute_no_trans,open");
    util_sepolicy_inject("kernel", "rootfs", "file", "execute");
    util_sepolicy_inject("rootfs", "tmpfs", "filesystem", "associate");

    // let init run postfs trigger
    util_sepolicy_inject("init", "init", "process", "execmem");
    util_sepolicy_inject("init", "kernel", "process", "signal");

    // let init.multiboot do it's postfs work
    util_sepolicy_inject("kernel", "kernel", "capability", "mknod");
    util_sepolicy_inject("kernel", "rootfs", "chr_file", "write");
    util_sepolicy_inject("kernel", "init", "dir", "search");
    util_sepolicy_inject("kernel", "init", "file", "read,open");
    util_sepolicy_inject("kernel", "init", "process", "signal");
    util_sepolicy_inject("kernel", "boot_block_device", "blk_file", "getattr,read,open,ioctl,unlink");
    util_sepolicy_inject("kernel", "block_device", "dir", "write,remove_name,add_name");
    util_sepolicy_inject("kernel", "block_device", "blk_file", "create");
    util_sepolicy_inject("kernel", "device", "dir", "write,add_name");
    util_sepolicy_inject("kernel", "device", "blk_file", "create");
    util_sepolicy_inject("kernel", "media_rw_data_file", "dir", "getattr");
    util_sepolicy_inject("kernel", "media_rw_data_file", "file", "getattr,read,write,open");
    util_sepolicy_inject("kernel", "recovery_block_device", "blk_file", "getattr,read,open,ioctl,unlink");

    // for our restorecon injections
    util_sepolicy_inject("init", "rootfs", "dir", "relabelto");
    util_sepolicy_inject("init", "tmpfs", "chr_file", "relabelfrom");
    util_sepolicy_inject("init", "null_device", "chr_file", "relabelto");
    util_sepolicy_inject("init", "zero_device", "chr_file", "relabelto");
    util_sepolicy_inject("init", "block_device", "blk_file", "relabelto");
    util_sepolicy_inject("init", "block_device", "dir", "relabelto");
    util_sepolicy_inject("init", "tmpfs", "blk_file", "getattr");
    util_sepolicy_inject("init", "tmpfs", "blk_file", "relabelfrom");

    // give our files selinux contexts
    util_append_string_to_file("/file_contexts", "\n\n"
                               "/multiboot(/.*)?               u:object_r:rootfs:s0\n"
                               "/multiboot/dev(/.*)?           u:object_r:device:s0\n"
                               "/multiboot/dev/null            u:object_r:null_device:s0\n"
                               "/multiboot/dev/zero            u:object_r:zero_device:s0\n"
                               "/multiboot/dev/block(/.*)?     u:object_r:block_device:s0\n"
                               "/init\\.multiboot              u:object_r:init_multiboot:s0\n"

                               // prevent restorecon_recursive on multiboot directories
                               "/data/media/multiboot(/.*)?          <<none>>\n"
                               "/data/media/0/multiboot(/.*)?        <<none>>\n"
                               "/realdata/media/multiboot(/.*)?      <<none>>\n"
                               "/realdata/media/0/multiboot(/.*)?    <<none>>\n"
                              );

    // we need to manually restore these contexts
    util_append_string_to_file("/init.rc", "\n\n"
                               "on early-init\n"
                               "    restorecon /init.multiboot\n"
                               "    restorecon /multiboot\n"
                               "    restorecon_recursive /multiboot/dev\n"
                               "\n"
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

static void find_bootdev(int update) {
    int rc;

    if(update) {
        // rescan
        add_new_block_devices(multiboot_data.blockinfo);

        // update devfs
        rc = uevent_create_nodes(multiboot_data.blockinfo, MBPATH_DEV);
        if(rc) {
            MBABORT("Can't build devfs: %s\n", strerror(errno));
        }
    }

    multiboot_data.bootdev = get_blockinfo_for_guid(multiboot_data.guid);
}

static void wait_for_bootdev(void) {
    struct sockaddr_nl nls;
    struct pollfd pfd;
    char buf[512];

    // initialize memory
    memset(&nls,0,sizeof(struct sockaddr_nl));
    nls.nl_family = AF_NETLINK;
    nls.nl_pid = getpid();
    nls.nl_groups = -1;

    // create socket
    pfd.events = POLLIN;
    pfd.fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (pfd.fd==-1)
        LOGF("cant create socket: %s\n", strerror(errno));

    // bind to socket
    if (bind(pfd.fd, (void *)&nls, sizeof(struct sockaddr_nl)))
        LOGF("can't bind: %s\n", strerror(errno));

    // we do this because the device could have become available between
    // us searching for the first time and setting up the socket
    find_bootdev(1);
    if(multiboot_data.bootdev) {
        goto close_socket;
    }

    // poll for changes
    while (poll(&pfd, 1, -1) != -1) {
        int len = recv(pfd.fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len==-1)  {
            LOGF("recv error: %s\n", strerror(errno));
        }

        // we don't check the event type here and just rescan the block devices everytime

        // search for bootdev
        find_bootdev(1);
        if(multiboot_data.bootdev) {
            goto close_socket;
        }
        LOGE("Boot device still not found. continue waiting.\n");
    }

close_socket:
    close(pfd.fd);
}

static void alarm_signal(UNUSED int sig, UNUSED siginfo_t* info, UNUSED void* vp) {
    LOGF("watchdog timeout\n");
}

int multiboot_main(UNUSED int argc, char** argv) {
    int rc = 0;
    int i;
    char buf[PATH_MAX];

    // basic multiboot_data init
    list_initialize(&multiboot_data.replacements);

    // init logging
    log_init();

    // set watchdog timer
    util_setsighandler(SIGALRM, alarm_signal);
    alarm(15);

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
        MBABORT("Can't build devfs: %s\n", strerror(errno));
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

    // common multiboot initialization
    if(multiboot_data.guid!=NULL && multiboot_data.path!=NULL) {
        multiboot_data.is_multiboot = 1;
        LOGI("Booting from {%s}%s\n", multiboot_data.guid, multiboot_data.path);

        // get boot device
        LOGD("search for boot device\n");

        find_bootdev(0);
        if(!multiboot_data.bootdev) {
            LOGE("Boot device not found. waiting for changes.\n");
        }

        // wait until we found it
        wait_for_bootdev();

        // just to make sure we really found it
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

    // grant ourselves some selinux permissions :)
    LOGD("patch sepolicy\n");
    selinux_fixup();

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
