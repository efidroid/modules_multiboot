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
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <linux/netlink.h>

#include <lib/cmdline.h>
#include <lib/mounts.h>
#include <lib/fs_mgr.h>
#include <lib/sefbinparser.h>
#include <lib/sefsrcparser.h>
#include <lib/dmcrypt.h>
#include <blkid/blkid.h>
#include <ini.h>
#include <sepolicy_inject.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "INIT"
#include <lib/log.h>

PAYLOAD_IMPORT(fstab_multiboot);
PAYLOAD_IMPORT(file_contexts);
PAYLOAD_IMPORT(file_contexts_bin);
static multiboot_data_t multiboot_data = {0};

multiboot_data_t *multiboot_get_data(void)
{
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
        char *pttype = NULL;

        // check type
        const char *format = NULL;
        if (!strncmp(value, "GPT", 3)){
            pttype = strdup("gpt");
            format = "GPT,%36s,%ms";
        }
        else if (!strncmp(value, "MBR", 3)) {
            pttype = strdup("dos");
            format = "MBR,%11s,%ms";
        }
        else {
            MBABORT("invalid multibootpath: %s\n", value);
            return;
        }

        // read values
        if ((rc=sscanf(value, format, guid, &path)) != 2) {
            MBABORT("invalid multibootpath: %s\n", value);
            return;
        }

        multiboot_data.pttype = pttype;
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

    else if (!strcmp(name, "androidboot.slot_suffix")) {
        multiboot_data.slot_suffix = safe_strdup(value);
    }
}

static uevent_block_t *get_blockinfo_for_guid(const char *pttype, const char *guid)
{
    int rc = 0;
    blkid_tag_iterate iter;
    const char *type, *value;
    blkid_cache cache = NULL;
    pid_t pid;
    char path[PATH_MAX];

    // allocate shared memory
    uevent_block_t **result = mmap(NULL, sizeof(void *), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (!result)  {
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
        if (rc<0) {
            MBABORT("chroot error: %s\n", strerror(errno));
        }

        int is_zerombr = (!strcmp(pttype, "dos") && strlen(guid)==11 && !strncmp(guid, "00000000", 8));

        uevent_block_t *event;
        list_for_every_entry(multiboot_data.blockinfo, event, uevent_block_t, node) {
            rc = snprintf(path, sizeof(path), "/dev/block/%s", event->devname);
            if (SNPRINTF_ERROR(rc, sizeof(path))) {
                MBABORT("snprintf error\n");
            }

            // get dev
            blkid_get_cache(&cache, NULL);
            blkid_dev dev = blkid_get_dev(cache, path, BLKID_DEV_NORMAL);
            if (!dev) {
                LOGV("Device %s not found\n", path);
                continue;
            }

            // get part uuid
            iter = blkid_tag_iterate_begin(dev);
            while (blkid_tag_next(iter, &type, &value) == 0) {
                if (!strcmp(type, "PARTUUID")) {
                    if (!strcasecmp(value, guid)) {
                        // we have a match

                        // this assignment works because both we and our parent use the same address
                        // so while the actual memory is (or may be) different, the address is the same
                        *result = event;
                        exit(0);
                    }
                }

                else if(is_zerombr && !strcmp(type, "PTTYPE")){
                    if (!strcasecmp(value, "dos")) {
                        unsigned long ptnumber = strtoul (&guid[9], NULL, 10);
                        rc = snprintf(path, sizeof(path), "%sp%"PRIuPTR, event->devname, (unsigned int)ptnumber);
                        if (SNPRINTF_ERROR(rc, sizeof(path))) {
                            MBABORT("snprintf error\n");
                        }

                        uevent_block_t *dospart_block = get_blockinfo_for_devname(multiboot_data.blockinfo, path);
                        if (dospart_block) {
                            *result = dospart_block;
                            exit(0);
                        }
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
    uevent_block_t *ret = NULL;
    if (rc==0)
        ret = *result;

    // cleanup
    munmap(result, sizeof(void *));

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
    if (trace) {
        ret = multiboot_exec_tracee(par);
    } else {
        // close all file handles
        int fd;
        for (fd=0; fd<10; fd++)
            close(fd);
        ret = execvp(par[0], par);
    }

    // error check
    if (ret) {
        MBABORT("Can't start %s: %s\n", par[0], strerror(errno));
        return -1;
    }

    return 0;
}

static int selinux_fixup(void)
{
    int rc = 0;

    // we ignore errors on purpose here because selinux might not be needed or supported by the system

    // this makes sure /dev got published before starting any services
    util_append_string_to_file("/init.rc", "\n\n"
                               "on early-init\n"
                               // wait for coldboot
                               // together with init's wait we're waiting 10s for this file
                               "    wait /dev/.coldboot_done\n"
                               "\n");

    // recovery
    if (multiboot_data.is_recovery) {
        return 0;
    }

    void *handle = sepolicy_inject_open("/sepolicy");
    if (handle) {
        // init_multiboot is free to do anything it wants :)
        // also, this has to be first so our context gets created
        sepolicy_inject_set_permissive(handle, "init_multiboot", 1);

        // for some reason our binary needs execmem
        sepolicy_inject_add_rule(handle, "init", "init", "process", "execmem");
        sepolicy_inject_add_rule(handle, "kernel", "kernel", "process", "execmem");

        // init has to change our label
        sepolicy_inject_add_rule(handle, "init", "init_multiboot", "file", "relabelto");

        // init wants to exec /file_contexts for some reason
        sepolicy_inject_add_rule(handle, "kernel", "rootfs", "file", "execute");

        // init seems to use logging after giving us our context
        sepolicy_inject_add_rule(handle, "logd", "init_multiboot", "dir", "search");
        sepolicy_inject_add_rule(handle, "logd", "init_multiboot", "file", "read,open,getattr");

        // for our restorecon injections
        sepolicy_inject_add_rule(handle, "init", "rootfs", "dir", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "tmpfs", "chr_file", "relabelfrom");
        sepolicy_inject_add_rule(handle, "init", "tmpfs", "blk_file", "getattr,relabelfrom");
        sepolicy_inject_add_rule(handle, "init", "null_device", "chr_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "zero_device", "chr_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "block_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "block_device", "dir", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "device", "dir", "relabelto");

        // let init run our trigger
        sepolicy_inject_add_rule(handle, "init", "rootfs", "file", "create,write,unlink");
        sepolicy_inject_add_rule(handle, "init", "init_multiboot", "file", "getattr,execute,read,open");
        sepolicy_inject_add_rule(handle, "init", "init_multiboot", "process", "transition,rlimitinh,siginh,noatsecure");
        sepolicy_inject_add_rule(handle, "rootfs", "tmpfs", "filesystem", "associate");

        // we still try to solve all the denials to keep dmesg clean
        sepolicy_inject_add_rule(handle, "init_multiboot", "rootfs", "filesystem", "associate");
        sepolicy_inject_add_rule(handle, "init_multiboot", "rootfs", "file", "read,open,getattr,unlink,create,write,entrypoint");
        sepolicy_inject_add_rule(handle, "init_multiboot", "rootfs", "dir", "write,remove_name,add_name");
        sepolicy_inject_add_rule(handle, "init_multiboot", "device", "chr_file", "create,write,open,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "device", "dir", "write,add_name,remove_name");
        sepolicy_inject_add_rule(handle, "init_multiboot", "device", "blk_file", "create");
        sepolicy_inject_add_rule(handle, "init_multiboot", "tmpfs", "file", "read,open,create,write");
        sepolicy_inject_add_rule(handle, "init_multiboot", "tmpfs", "dir", "getattr,mounton,write,remove_name,add_name");
        sepolicy_inject_add_rule(handle, "init_multiboot", "tmpfs", "blk_file", "getattr,create,read,open,ioctl,write");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init", "dir", "search");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init", "file", "read,open,getattr");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init", "process", "sigchld");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init_tmpfs", "file", "read,open,getattr,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init_multiboot", "process", "fork,sigchld");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init_multiboot", "capability", "dac_override,mknod");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init_multiboot", "file", "entrypoint");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init_multiboot", "dir", "search");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init_multiboot", "lnk_file", "read");
        sepolicy_inject_add_rule(handle, "init_multiboot", "media_rw_data_file", "dir", "search");
        sepolicy_inject_add_rule(handle, "init_multiboot", "media_rw_data_file", "file", "read,open,write");
        sepolicy_inject_add_rule(handle, "init_multiboot", "boot_block_device", "blk_file", "getattr,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "recovery_block_device", "blk_file", "getattr,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "cache_block_device", "blk_file", "getattr,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "userdata_block_device", "blk_file", "getattr,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "block_device", "blk_file", "read,open,ioctl,write,getattr,create,unlink");
        sepolicy_inject_add_rule(handle, "init_multiboot", "block_device", "dir", "write,remove_name,add_name");
        sepolicy_inject_add_rule(handle, "init_multiboot", "debugfs", "dir", "search");
        sepolicy_inject_add_rule(handle, "init_multiboot", "init", "fd", "use");
        sepolicy_inject_add_rule(handle, "init_multiboot", "null_device", "chr_file", "read,write");
        sepolicy_inject_add_rule(handle, "init_multiboot", "properties_device", "file", "read");
        sepolicy_inject_add_rule(handle, "init_multiboot", "proc", "dir", "search");
        sepolicy_inject_add_rule(handle, "init_multiboot", "proc", "lnk_file", "read");

        // relabel rules for /multiboot/dev
        sepolicy_inject_add_rule(handle, "init", "ram_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "loop_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "swap_block_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "sd_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "dm_device", "chr_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "frp_block_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "oem_block_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "root_block_device", "blk_file", "relabelto");
        sepolicy_inject_add_rule(handle, "init", "rpmb_device", "blk_file", "relabelto");

        // the kernel thread for loop images is checked by selinux too
        sepolicy_inject_add_rule(handle, "kernel", "unlabeled", "file", "read");
        sepolicy_inject_add_rule(handle, "kernel", "media_rw_data_file", "file", "read");

        if (multiboot_data.is_multiboot) {
            // this is for the datamedia bind-mount
            sepolicy_inject_add_rule(handle, "init", "media_rw_data_file", "dir", "mounton");
        }

        // write new policy
        sepolicy_inject_write(handle, "/sepolicy");
        sepolicy_inject_close(handle);
    }

    if (multiboot_data.is_multiboot) {
        // just in case we changed/created it
        util_append_string_to_file("/init.rc", "\n\n"
                                   "on post-fs-data\n"
                                   "    restorecon /data/.layout_version\n"
                                   "\n"
                                  );
    }

    if (util_exists("/file_contexts.bin", 1)) {
        sefbin_file_t *seffile = sefbin_parse("/file_contexts.bin", 1);
        if (seffile) {
            sefbin_file_t *seffile_mb = sefbin_parse(MBPATH_FILE_CONTEXTS_BIN, 0);
            sefbin_append(seffile, seffile_mb);
            sefbin_append_multiboot_rules(seffile);
            sefbin_write(seffile, "/file_contexts.bin");
        }

        else {
            util_append_buffer_to_file("/file_contexts.bin", PAYLOAD_PTR(file_contexts), PAYLOAD_SIZE(file_contexts));
            sefsrc_append_multiboot_rules("/file_contexts.bin");
        }
    }

    if (util_exists("/file_contexts", 1)) {
        util_append_buffer_to_file("/file_contexts", PAYLOAD_PTR(file_contexts), PAYLOAD_SIZE(file_contexts));
        sefsrc_append_multiboot_rules("/file_contexts");
    }

    // we need to manually restore these contexts
    util_append_string_to_file("/init.rc", "\n\n"
                               "on early-init\n"
                               "    restorecon /multiboot_init\n"
                               "    restorecon_recursive /multiboot/dev\n"
                               "\n"
                              );

    // flush stdlib messages so they don't appear between the other logs
    fflush(stderr);
    fflush(stdout);

    return rc;
}

static int mbini_count_handler(UNUSED void *user, const char *section, UNUSED const char *name, UNUSED const char *value)
{
    // we're interested in partitions only
    if (strcmp(section, "partitions"))
        return 1;

    multiboot_data.num_mbparts++;

    return 1;
}

static int mbini_handler(UNUSED void *user, const char *section, const char *name, const char *value)
{
    uint32_t *index = user;

    // we're interested in partitions only
    if (strcmp(section, "partitions"))
        return 1;

    if ((*index)>=multiboot_data.num_mbparts) {
        MBABORT("Too many partitions: %d>=%d\n", (*index), multiboot_data.num_mbparts);
        return 0;
    }

    // validate args
    if (!name || !value) {
        MBABORT("Invalid name/value in multiboot.ini\n");
        return 1;
    }

    // setup partition
    multiboot_partition_t *part = &multiboot_data.mbparts[(*index)++];
    part->name = safe_strdup(name);
    part->path = safe_strdup(value);
    part->type = MBPART_TYPE_BIND;

    // determine partition type
    int pathlen = strlen(part->path);
    if (pathlen>=4) {
        const char *ext = part->path+pathlen-4;
        if (!strcmp(ext, ".img"))
            part->type = MBPART_TYPE_LOOP;
    }

    // check if bootdev supports bind mounts
    if (part->type==MBPART_TYPE_BIND) {
        if (!multiboot_data.bootdev_supports_bindmount)
            MBABORT("Boot device doesn't support bind mounts\n");
    }

    // get uevent block for this partition
    struct fstab_rec *rec = fs_mgr_get_by_name(multiboot_data.mbfstab, part->name);
    if (rec) {
        // fail if this is a UEFI partition which isn't marked as multiboot
        if (fs_mgr_is_uefi(rec) && !fs_mgr_is_multiboot(rec)) {
            MBABORT("You can't replace pure UEFI partitions from a multiboot.ini (%s)\n", part->name);
        }

        // check if this should be a raw partition
        if (part->type==MBPART_TYPE_BIND && !strcmp(rec->fs_type, "emmc")) {
            MBABORT("raw device %s doesn't support bind mounts\n", rec->blk_device);
        }

        // treat as name from fstab.multiboot
        part->uevent_block = get_blockinfo_for_path(multiboot_data.blockinfo, rec->blk_device);
    }
    if (!part->uevent_block) {
        // treat as GPT partition name
        part->uevent_block = get_blockinfo_for_partname(multiboot_data.blockinfo, part->name);
    }
    if (!part->uevent_block) {
        // treat as device name(mmcblk*)
        part->uevent_block = get_blockinfo_for_devname(multiboot_data.blockinfo, part->name);
    }

    if (!part->uevent_block) {
        MBABORT("Can't find uevent block for partition %s\n", part->name);
    }

    // inih defines 1 as OK
    return 1;
}

static multiboot_partition_t *multiboot_part_by_name(const char *name)
{
    uint32_t i;

    if (!multiboot_data.mbparts)
        return NULL;

    for (i=0; i<multiboot_data.num_mbparts; i++) {
        multiboot_partition_t *part = &multiboot_data.mbparts[i];

        if (!strcmp(part->name, name))
            return part;
    }

    return NULL;
}

static int find_bootdev(int update)
{
    int rc;

    if (update) {
        // rescan
        add_new_block_devices(multiboot_data.blockinfo);

        // update devfs
        rc = uevent_create_nodes(multiboot_data.blockinfo, MBPATH_DEV);
        if (rc) {
            MBABORT("Can't build devfs: %s\n", strerror(errno));
        }
    }

    multiboot_data.bootdev = get_blockinfo_for_guid(multiboot_data.pttype, multiboot_data.guid);
    if (!multiboot_data.bootdev)
        return -1;

    return 0;
}

static int find_espdev(int update)
{
    int rc;

    if (update) {
        // rescan
        add_new_block_devices(multiboot_data.blockinfo);

        // update devfs
        rc = uevent_create_nodes(multiboot_data.blockinfo, MBPATH_DEV);
        if (rc) {
            MBABORT("Can't build devfs: %s\n", strerror(errno));
        }
    }

    multiboot_data.espdev = get_blockinfo_for_path(multiboot_data.blockinfo, multiboot_data.esp->blk_device);
    if (!multiboot_data.espdev)
        return -1;

    return 0;
}

static void wait_for_device(int (*find_device)(int update))
{
    struct sockaddr_nl nls;
    struct pollfd pfd;
    char buf[512];
    int rc;

    // check if the device is already available
    rc = find_device(0);
    if (rc==0) {
        return;
    }

    LOGE("Device not found. waiting for changes.\n");

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
    rc = find_device(1);
    if (rc==0) {
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
        rc = find_device(1);
        if (rc==0) {
            goto close_socket;
        }
        LOGE("Boot device still not found. continue waiting.\n");
    }

close_socket:
    close(pfd.fd);
}

static void alarm_signal(UNUSED int sig, UNUSED siginfo_t *info, UNUSED void *vp)
{
    LOGF("watchdog timeout\n");
}

static uint32_t get_mb_sdk_version(void)
{
    const char *systempath;
    char buf[PATH_MAX];
    ssize_t bytecount;
    int rc;

    part_replacement_t *replacement = util_get_replacement_by_mbfstabname("system");
    if (!replacement) {
        MBABORT("Can't find replacement partition for system\n");
    }

    if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_LOOP) {
        // mount system
        rc = util_mount(replacement->loopdevice, MBPATH_MB_SYSTEM, NULL, 0, NULL);
        if (rc) {
            MBABORT("Can't mount system: %s\n", strerror(errno));
        }

        systempath = MBPATH_MB_SYSTEM;
    } else {
        systempath = replacement->bindsource;
    }

    // read sdk version
    SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "%s/build.prop", systempath);
    char *prop = util_get_property(buf, "ro.build.version.sdk");
    if (!prop) {
        MBABORT("Can't read property from %s: %s\n", buf, strerror(errno));
    }

    // convert sdk version to int
    uint32_t sdk_version;
    bytecount = sscanf(prop, "%u", &sdk_version);
    free(prop);
    if (bytecount != 1) {
        MBABORT("Can't convert\n");
    }

    // unmount system
    if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_LOOP) {
        SAFE_UMOUNT(MBPATH_MB_SYSTEM);
    }

    return sdk_version;
}

static void prepare_multiboot_data(void)
{
    int rc;
    uint32_t sdk_version;
    const char *datapath;
    char buf[PATH_MAX];

    // get sdk version
    sdk_version = get_mb_sdk_version();
    LOGI("SDK version: %u\n", sdk_version);

    // determine required layout version
    uint32_t layout_version_needed;
    if (sdk_version<17)
        layout_version_needed = 0;
    else if (sdk_version<20)
        layout_version_needed = 2;
    else
        layout_version_needed = 3;

    // get data replacement
    part_replacement_t *replacement = util_get_replacement_by_mbfstabname("data");
    if (!replacement) {
        MBABORT("Can't find replacement partition for data\n");
    }

    // mount data partition
    if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_LOOP) {
        // mount system
        rc = util_mount(replacement->loopdevice, MBPATH_MB_DATA, NULL, 0, NULL);
        if (rc) {
            MBABORT("Can't mount data: %s\n", strerror(errno));
        }

        datapath = MBPATH_MB_DATA;
    } else {
        datapath = replacement->bindsource;
    }

    // get layout version
    uint32_t layout_version;
    SAFE_SNPRINTF_RET(LOGE, , buf, sizeof(buf), "%s/.layout_version", datapath);
    rc = util_read_int(buf, &layout_version);
    if (rc) {
        layout_version = 0;
    }
    LOGI("MB layout_version: %u\n", layout_version);

    // determine bind-mount mapping
    const char *datamedia_source = NULL;
    const char *datamedia_target = NULL;
    if (ANYEQ_2(multiboot_data.native_data_layout_version, 0, 1))
        datamedia_source = MBPATH_DATA"/media";
    else if (ANYEQ_2(multiboot_data.native_data_layout_version, 2, 3))
        datamedia_source = MBPATH_DATA"/media/0";
    if (ANYEQ_2(layout_version_needed, 0, 1))
        datamedia_target = "/media";
    else if (ANYEQ_2(layout_version_needed, 2, 3))
        datamedia_target = "/media/0";

    // verify results
    if (datamedia_source==NULL || datamedia_target==NULL) {
        MBABORT("datamedia_source=%s datamedia_target=%s\n", datamedia_source?:"(null)", datamedia_target?:"(null)");
    }

    // upgrade/downgrade target layout version
    if (layout_version_needed>0 && layout_version!=layout_version_needed) {
        rc = util_write_int(buf, layout_version_needed);
        if (rc) {
            MBABORT("can't set layout version to %u\n", layout_version_needed);
        }
    }

    // create mount source directory
    if (!util_exists(datamedia_source, false)) {
        rc = util_mkdir(datamedia_source);
        if (rc) {
            MBABORT("Can't create datamedia on source: %s\n", strerror(rc));
        }
    }

    // create mount target directory
    SAFE_SNPRINTF_RET(LOGE, , buf, sizeof(buf), MBPATH_MB_DATA"%s", datamedia_target);
    if (!util_exists(buf, false)) {
        rc = util_mkdir(buf);
        if (rc) {
            MBABORT("Can't create datamedia on target: %s\n", strerror(rc));
        }
    }

    multiboot_data.datamedia_target = datamedia_target;
    multiboot_data.datamedia_source = datamedia_source;

    if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_LOOP) {
        SAFE_UMOUNT(MBPATH_MB_DATA);
    }
}

static int setup_partition_replacements(void)
{
    int rc;
    int i;
    uint32_t iu;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    // multiboot
    if (multiboot_data.is_multiboot) {
        // get directory of multiboot.ini
        char *basedir = util_dirname(multiboot_data.path);
        if (!basedir) {
            MBABORT("Can't get base dir for multiboot path\n");
        }

        // make sure we have /dev/fuse
        if (!util_exists("/dev", false)) {
            rc = util_mkdir("/dev");
            if (rc) {
                MBABORT("Can't create /dev directory\n");
            }
        }
        if (!util_exists("/dev/fuse", true)) {
            rc = mknod("/dev/fuse", S_IFCHR | 0600, makedev(10, 229));
            if (rc) {
                MBABORT("Can't create /dev/fuse: %s\n", strerror(errno));
            }
        }

        // setup multiboot partitions
        for (iu=0; iu<multiboot_data.num_mbparts; iu++) {
            multiboot_partition_t *part = &multiboot_data.mbparts[iu];

            // path to multiboot rom dir
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BOOTDEV"%s/%s", basedir, part->path);
            char *partpath = safe_strdup(buf);

            // path to loop device
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%s", part->name);
            char *loopdevice = safe_strdup(buf);

            // stat path
            struct stat sb;
            rc = lstat(partpath, &sb);
            if (rc) rc = -errno;
            if (rc && rc!=-ENOENT) {
                MBABORT("Can't stat '%s'\n", partpath);
            }

            // check node type
            if (!rc && (
                        (part->type==MBPART_TYPE_BIND && !S_ISDIR(sb.st_mode)) ||
                        (part->type!=MBPART_TYPE_BIND && !S_ISREG(sb.st_mode))
                    )
               ) {
                MBABORT("path '%s'(type=%d) has invalid mode: %x\n", partpath, part->type, sb.st_mode);
            }

            char *loopfile = NULL;
            if (part->type==MBPART_TYPE_BIND) {
                // create directory
                // TODO: don't do that
                if (rc==-ENOENT) {
                    rc = util_mkdir(partpath);
                    if (rc) {
                        MBABORT("Can't create directory '%s'\n", partpath);
                    }
                }

                // get real device
                SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_DEV"/block/%s", part->uevent_block->devname);

                // get size of original partition
                unsigned long num_blocks = 0;
                rc = util_block_num(buf, &num_blocks);
                if (rc || num_blocks==0) {
                    MBABORT("Can't get size of device %s\n", buf);
                }

                // mkfs needs much time for large filesystems, so just use max 200MB
                num_blocks = MIN(num_blocks, (200*1024*1024)/512llu);

                // path to dynfilefs mountpopint
                SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), MBPATH_ROOT"/dynmount:%s", part->name);

                // path to dynfilefs storage file
                SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_ROOT"/dynstorage:%s", part->name);

                // mount dynfilefs
                rc = util_dynfilefs(buf, buf2, num_blocks*512llu);
                if (rc) {
                    MBABORT("can't mount dynfilefs\n");
                }

                // path to stub partition backup (in dynfs mountpoint)
                SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s/loop.fs", buf2);

                // create new loop node
                rc = util_make_loop(loopdevice);
                if (rc) {
                    MBABORT("Can't create loop device at %s\n", loopdevice);
                }

                // setup loop device
                rc = util_losetup(loopdevice, buf, false);
                if (rc) {
                    MBABORT("Can't setup loop device at %s for %s\n", loopdevice, buf);
                }

                // get fstype
                const char *fstype = "ext4";

                // create filesystem on loop device
                rc = util_mkfs(loopdevice, fstype);
                if (rc) {
                    MBABORT("Can't create '%s' filesystem on %s\n", fstype, loopdevice);
                }

                // mount loop device
                SAFE_MOUNT(loopdevice, MBPATH_STUB, fstype, 0, NULL);

                // create id file
                int fd = open(MBPATH_STUB_IDFILE, O_RDWR|O_CREAT);
                if (fd<0) {
                    MBABORT("Can't create ID file\n");
                }
                close(fd);

                // unmount loop device
                SAFE_UMOUNT(MBPATH_STUB);
            }

            else if (part->type==MBPART_TYPE_LOOP) {
                // create new node
                rc = util_make_loop(loopdevice);
                if (rc) {
                    MBABORT("Can't create loop device at %s\n", loopdevice);
                }

                // setup loop device
                loopfile = safe_strdup(partpath);
                rc = util_losetup(loopdevice, loopfile, false);
                if (rc) {
                    MBABORT("Can't setup loop device at %s for %s\n", loopdevice, loopfile);
                }
            }

            else {
                LOGF("invalid partition type: %d\n", part->type);
            }

            part_replacement_t *replacement = safe_calloc(sizeof(part_replacement_t), 1);
            pthread_mutex_init(&replacement->lock, NULL);
            replacement->uevent_block = part->uevent_block;
            if (part->type==MBPART_TYPE_BIND)
                replacement->mountmode = PART_REPLACEMENT_MOUNTMODE_BIND;
            else if (part->type==MBPART_TYPE_LOOP)
                replacement->mountmode = PART_REPLACEMENT_MOUNTMODE_LOOP;
            else
                MBABORT("invalid mbpart type %d\n", part->type);
            replacement->iomode = PART_REPLACEMENT_IOMODE_REDIRECT;
            if (part->type==MBPART_TYPE_BIND)
                replacement->bindsource = partpath;
            replacement->losetup_done = 1;
            replacement->loopdevice = loopdevice;
            replacement->loopfile = loopfile;


            list_add_tail(&multiboot_data.replacements, &replacement->node);
        }

        free(basedir);

        // prepare datamedia setup
        if (!multiboot_data.is_recovery) {
            prepare_multiboot_data();
        }

        // bootdev is already mounted, so redirect it to a bind mount
        int found_replacement = 1;
        part_replacement_t *replacement = util_get_replacement_by_ueventblock(multiboot_data.bootdev);
        if (!replacement) {
            found_replacement = 0;
            replacement = safe_calloc(sizeof(part_replacement_t), 1);
            pthread_mutex_init(&replacement->lock, NULL);
            replacement->uevent_block = multiboot_data.bootdev;
        }

        if (!found_replacement || replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_ALLOW) {
            replacement->mountmode = PART_REPLACEMENT_MOUNTMODE_BIND;
            replacement->bindsource = safe_strdup(MBPATH_BOOTDEV);
        }

        if (!found_replacement || replacement->iomode==PART_REPLACEMENT_IOMODE_ALLOW) {
            replacement->iomode = PART_REPLACEMENT_IOMODE_DENY;
        }

        // check if this is adoptable storage
        if (multiboot_data.bootdev->partname && !strcmp(multiboot_data.bootdev->partname, "android_expand")) {
            uevent_block_t *bi_meta = get_blockinfo_for_sisterpart(multiboot_data.blockinfo, multiboot_data.bootdev, 1);
            if (!bi_meta)
                MBABORT("can't find meta partition of adoptable storage");

            // create denial-redirection for android_expand
            part_replacement_t *replacementmeta = safe_calloc(sizeof(part_replacement_t), 1);
            pthread_mutex_init(&replacementmeta->lock, NULL);
            replacementmeta->uevent_block = replacement->uevent_block;
            replacementmeta->mountmode = PART_REPLACEMENT_MOUNTMODE_DENY;
            replacementmeta->iomode = PART_REPLACEMENT_IOMODE_DENY;
            list_add_tail(&multiboot_data.replacements, &replacementmeta->node);

            // redirect android_meta instead
            replacement->uevent_block = bi_meta;
        }

        if (!found_replacement) {
            list_add_tail(&multiboot_data.replacements, &replacement->node);
        }
    }

    // internal system

    // mount ESP
    util_mount_esp(1);

    // get espdir
    char *espdir = util_get_espdir(MBPATH_ESP);
    if (!espdir) {
        MBABORT("Can't get ESP directory: %s\n", strerror(errno));
    }

    // copy path
    SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s", espdir);

    // create UEFIESP directory
    if (!util_exists(buf, true)) {
        rc = util_mkdir(buf);
        if (rc) {
            MBABORT("Can't create directory at %s\n", buf);
        }
    }

    // setup uefi partition redirections
    for (i=0; i<multiboot_data.mbfstab->num_entries; i++) {
        struct fstab_rec *rec = &multiboot_data.mbfstab->recs[i];

        // skip non-uefi partitions
        if (!fs_mgr_is_uefi(rec)) continue;

        // get blockinfo
        uevent_block_t *bi = get_blockinfo_for_path(multiboot_data.blockinfo, rec->blk_device);
        if (!bi) {
            MBABORT("Can't get blockinfo\n");
        }

        // this partition got replaced by multiboot aready
        if (util_get_replacement(bi->major, bi->minor)) continue;

        // get ESP filename
        char *espfilename = util_get_esp_path_for_partition(MBPATH_ESP, rec->mount_point+1);
        if (!espfilename) {
            MBABORT("Can't get filename\n");
        }

        // get real device in MBPATH_DEV
        char *mbpathdevice = util_getmbpath_from_device(rec->blk_device);
        if (!mbpathdevice) {
            MBABORT("Can't get mbpath device\n");
        }

        // create partition image on ESP (in case it doesn't exist)
        rc = util_create_partition_backup(mbpathdevice, espfilename);
        if (rc) {
            MBABORT("Can't create partition image\n");
        }

        // path to loop device
        SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%s", rec->mount_point+1);

        // in native recovery, we don't want to block unmounting by setting up loop's
        char *loopfile = NULL;
        int losetup_done = 0;
        char *loop_sync_target = NULL;
        if (multiboot_data.is_recovery && !multiboot_data.is_multiboot) {
            // path to temporary partition backup
            SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), MBPATH_ROOT"/loopfile:%s", rec->mount_point+1);
            loopfile = safe_strdup(buf2);
            loop_sync_target = rec->mount_point+1;

            // create temporary partition backup
            rc = util_cp(espfilename, loopfile);
            if (rc) {
                MBABORT("Can't copy partition from esp to temp\n");
            }
        }

        else {
            // path to partition backup
            loopfile = espfilename;
        }

        // create new loop node
        rc = util_make_loop(buf);
        if (rc) {
            MBABORT("Can't create loop device at %s\n", buf);
        }


        // in Android we'll do that in the postfs stage
        if (multiboot_data.is_recovery) {
            // setup loop device
            rc = util_losetup(buf, loopfile, false);
            if (rc) {
                MBABORT("Can't setup loop device at %s for %s\n", buf, buf2);
            }
            losetup_done = 1;
        }

        part_replacement_t *replacement = safe_calloc(sizeof(part_replacement_t), 1);
        pthread_mutex_init(&replacement->lock, NULL);
        replacement->uevent_block = bi;
        replacement->mountmode = PART_REPLACEMENT_MOUNTMODE_LOOP;
        replacement->iomode = PART_REPLACEMENT_IOMODE_REDIRECT;
        replacement->losetup_done = losetup_done;
        replacement->loopdevice = safe_strdup(buf);
        replacement->loopfile = safe_strdup(loopfile);
        replacement->loop_sync_target = loop_sync_target;

        list_add_tail(&multiboot_data.replacements, &replacement->node);

        // cleanup
        free(mbpathdevice);
    }

    // in native-recovery, we don't want to block unmounting
    // in android and multiboot-recovery, we re-mount the esp in the postfs stage
    if (!multiboot_data.is_recovery || (multiboot_data.is_recovery && !multiboot_data.is_multiboot)) {
        // unmount ESP
        SAFE_UMOUNT(MBPATH_ESP);
    }

    return 0;
}

static char *efiguid2keyfile(const char *guid)
{
    int rc;
    char *buf = safe_malloc(PATH_MAX);
    char *ptr = buf;
    size_t size_left = PATH_MAX;

    rc = snprintf(ptr, size_left, MBPATH_DATA"/misc/vold/expand_");
    if (SNPRINTF_ERROR(rc, size_left)) {
        MBABORT("snprintf error\n");
    }
    ptr += rc;
    size_left -= rc;

    while (*guid) {
        if (size_left==0) {
            MBABORT("buffer is too small for guid\n");
        }

        if (*guid != '-') {
            *ptr = tolower(*guid);

            ptr++;
            size_left -= rc;
        }

        guid++;
    }

    SAFE_SNPRINTF_RET(MBABORT, NULL, ptr, size_left, ".key");

    return buf;
}

int multiboot_main(UNUSED int argc, char **argv)
{
    int rc = 0;
    int i;
    char buf[PATH_MAX];

    // basic multiboot_data init
    pthread_mutex_init(&multiboot_data.lock, NULL);
    list_initialize(&multiboot_data.replacements);

    // init logging
    log_init();

    multiboot_data.is_recovery = util_exists("/sbin/recovery", true);

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
    import_kernel_cmdline(MBPATH_PROC"/cmdline", import_kernel_nv);
    import_kernel_cmdline("/multiboot_cmdline", import_kernel_nv);

    // parse /sys/block
    LOGD("parse /sys/block\n");
    multiboot_data.blockinfo = get_block_devices();
    if (!multiboot_data.blockinfo) {
        LOGE("Can't retrieve blockinfo: %s\n", strerror(errno));
        return -errno;
    }

    // mount private dev fs
    LOGD("mount %s\n", MBPATH_DEV);
    SAFE_MOUNT("tmpfs", MBPATH_DEV, "tmpfs", MS_NOSUID, "mode=0755");

    // build private dev fs
    LOGD("build dev fs\n");
    rc = uevent_create_nodes(multiboot_data.blockinfo, MBPATH_DEV);
    if (rc) {
        MBABORT("Can't build devfs: %s\n", strerror(errno));
    }

    // check for hwname
    LOGV("verify hw name\n");
    if (!multiboot_data.hwname) {
        MBABORT("cmdline didn't contain a valid 'androidboot.hardware': %s\n", strerror(ENOENT));
    }

    // create directories
    LOGV("create %s\n", MBPATH_BIN);
    rc = util_mkdir(MBPATH_BIN);
    if (rc) {
        MBABORT("Can't create directory '"MBPATH_BIN"': %s\n", strerror(errno));
    }

    // extract fstab.multiboot
    LOGD("extract %s\n", MBPATH_FSTAB);
    rc = util_buf2file(PAYLOAD_PTR(fstab_multiboot), MBPATH_FSTAB, PAYLOAD_SIZE(fstab_multiboot));
    if (rc) {
        MBABORT("Can't extract fstab to "MBPATH_FSTAB": %s\n", strerror(errno));
    }

    // extract file_contexts
    LOGD("extract %s\n", MBPATH_FILE_CONTEXTS);
    rc = util_buf2file(PAYLOAD_PTR(file_contexts), MBPATH_FILE_CONTEXTS, PAYLOAD_SIZE(file_contexts));
    if (rc) {
        MBABORT("Can't extract file_contexts to "MBPATH_FILE_CONTEXTS": %s\n", strerror(errno));
    }

    // extract file_contexts.bin
    LOGD("extract %s\n", MBPATH_FILE_CONTEXTS_BIN);
    rc = util_buf2file(PAYLOAD_PTR(file_contexts_bin), MBPATH_FILE_CONTEXTS_BIN, PAYLOAD_SIZE(file_contexts_bin));
    if (rc) {
        MBABORT("Can't extract file_contexts.bin to "MBPATH_FILE_CONTEXTS_BIN": %s\n", strerror(errno));
    }

    // create symlinks
    LOGV("create symlink %s->%s\n", MBPATH_TRIGGER_BIN, argv[0]);
    rc = symlink(argv[0], MBPATH_TRIGGER_BIN);
    if (rc) {
        MBABORT("Can't create symlink "MBPATH_TRIGGER_BIN": %s\n", strerror(errno));
    }

    LOGV("create symlink %s->%s\n", MBPATH_BUSYBOX, argv[0]);
    rc = symlink(argv[0], MBPATH_BUSYBOX);
    if (rc) {
        MBABORT("Can't create symlink "MBPATH_BUSYBOX": %s\n", strerror(errno));
    }

    LOGV("create symlink %s->%s\n", MBPATH_MKE2FS, argv[0]);
    rc = symlink(argv[0], MBPATH_MKE2FS);
    if (rc) {
        MBABORT("Can't create symlink "MBPATH_MKE2FS": %s\n", strerror(errno));
    }

    // parse multiboot fstab
    LOGD("parse %s\n", MBPATH_FSTAB);
    multiboot_data.mbfstab = fs_mgr_read_fstab(MBPATH_FSTAB);
    if (!multiboot_data.mbfstab) {
        MBABORT("Can't parse multiboot fstab: %s\n", strerror(errno));
    }

    // verify mbfstab partitions
    for (i=0; i<multiboot_data.mbfstab->num_entries; i++) {
        struct fstab_rec *rec;

        // skip non-multiboot partitions
        rec = &multiboot_data.mbfstab->recs[i];
        if (!fs_mgr_is_uefi(rec)) continue;

        if (strcmp(rec->fs_type, "emmc")) {
            MBABORT("UEFI partition %s is not of type emmc\n", rec->mount_point);
        }
    }

    // build fstab name
    SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "/fstab.%s", multiboot_data.hwname);
    multiboot_data.romfstabpath = safe_strdup(buf);

    // parse ROM fstab
    LOGD("parse ROM fstab: %s\n", buf);
    multiboot_data.romfstab = fs_mgr_read_fstab(buf);
    if (!multiboot_data.romfstab) {
        // for Android, this fstab is mandatory
        if (!multiboot_data.is_recovery)
            MBABORT("Can't parse %s: %s\n", buf, strerror(errno));

        // try /etc/twrp.fstab
        LOGD("parse /etc/twrp.fstab\n");
        multiboot_data.romfstab = fs_mgr_read_fstab("/etc/twrp.fstab");
        if (multiboot_data.romfstab) {
            multiboot_data.romfstabpath = safe_strdup("/etc/twrp.fstab");
        }

        else {
            // try /etc/recovery.fstab
            LOGD("parse /etc/recovery.fstab\n");
            multiboot_data.romfstab = fs_mgr_read_fstab("/etc/recovery.fstab");
            if (multiboot_data.romfstab) {
                multiboot_data.romfstabpath = safe_strdup("/etc/recovery.fstab");
            }
        }
    }
    if (!multiboot_data.romfstab) {
        // create empty fstab to prevent null pointer access
        multiboot_data.romfstab = safe_calloc(1, sizeof(struct fstab));
    }

    // get ESP partition
    LOGV("get ESP from fs_mgr\n");
    multiboot_data.esp = fs_mgr_esp(multiboot_data.mbfstab);
    if (!multiboot_data.esp) {
        MBABORT("ESP partition not found\n");
    }

    LOGV("get blockinfo for ESP\n");
    wait_for_device(find_espdev);
    if (!multiboot_data.espdev) {
        MBABORT("can't get blockinfo for ESP\n");
    }

    // common multiboot initialization
    if (multiboot_data.guid!=NULL && multiboot_data.path!=NULL) {
        multiboot_data.is_multiboot = 1;
        LOGI("Booting from {%s}%s\n", multiboot_data.guid, multiboot_data.path);

        // get boot device
        LOGD("search for boot device\n");
        wait_for_device(find_bootdev);
        if (!multiboot_data.bootdev) {
            MBABORT("Boot device not found\n");
        }
        LOGI("Boot device: %s\n", multiboot_data.bootdev->devname);

        // mount data
        rc = util_mount_mbinipart("/data", MBPATH_DATA);
        if (rc) {
            MBABORT("Can't mount data: %s\n", strerror(errno));
        }

        LOGD("mount boot device\n");
        if (multiboot_data.bootdev->partname && !strcmp(multiboot_data.bootdev->partname, "android_expand")) {
            char out_crypto_blkdev[MAXPATHLEN];
            char real_blkdev[PATH_MAX];

            // get keyfile path
            char *keyfilepath = efiguid2keyfile(multiboot_data.guid);
            LOGV("keyfilepath: %s\n", keyfilepath);

            // open key
            size_t keysize;
            char *key = util_get_file_contents_ex(keyfilepath, &keysize);
            if (!key) {
                MBABORT("Can't read key data\n");
            }

            // get blk device
            rc = uevent_get_blkdev_path(multiboot_data.bootdev, real_blkdev, sizeof(real_blkdev));
            if (rc) {
                MBABORT("Can't get path to block device\n");
            }

            // dmcrypt setup
            rc = cryptfs_setup_ext_volume("multiboot_bootdev", real_blkdev, (unsigned char *)key, keysize, out_crypto_blkdev);
            if (rc) {
                MBABORT("Can't setup dmcrypt: %s\n", strerror(errno));
            }

            // mount
            rc = util_mount(out_crypto_blkdev, MBPATH_BOOTDEV, NULL, 0, NULL);
        } else {
            // mount
            rc = uevent_mount(multiboot_data.bootdev, MBPATH_BOOTDEV, NULL, 0, NULL);
        }

        if (rc) {
            MBABORT("Can't mount boot device: %s\n", strerror(errno));
        }

        // get data layout version
        uint32_t layout_version;
        rc = util_read_int(MBPATH_DATA"/.layout_version", &layout_version);
        if (!rc) {
            multiboot_data.native_data_layout_version = layout_version;
        }
        LOGI("layout_version: %u\n", multiboot_data.native_data_layout_version);

        // scan mounts
        mounts_state_t mounts_state = LIST_INITIAL_VALUE(mounts_state);
        LOGV("scan mounted volumes\n");
        rc = scan_mounted_volumes(&mounts_state);
        if (rc) {
            MBABORT("Can't scan mounted volumes: %s\n", strerror(errno));
        }

        // check for bind-mount support
        LOGV("search mounted bootdev\n");
        const mounted_volume_t *volume = find_mounted_volume_by_mount_point(&mounts_state, MBPATH_BOOTDEV);
        if (!volume) {
            MBABORT("boot device not mounted (DAFUQ?)\n");
        }
        if (util_fs_supports_multiboot_bind(volume->filesystem)) {
            LOGD("bootdev has bind mount support\n");
            multiboot_data.bootdev_supports_bindmount = 1;
        }

        // free mount state
        free_mounts_state(&mounts_state);

        // build multiboot.ini filename
        SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BOOTDEV"%s", multiboot_data.path);

        // count partitions in multiboot.ini
        LOGD("parse %s using mbini_count_handler\n", buf);
        rc = ini_parse(buf, mbini_count_handler, NULL);
        if (rc) {
            MBABORT("Can't count partitions in '%s': %s\n", buf, strerror(errno));
        }

        // parse multiboot.ini
        uint32_t index = 0;
        LOGD("parse %s using mbini_handler\n", buf);
        multiboot_data.mbparts = safe_calloc(sizeof(multiboot_partition_t), multiboot_data.num_mbparts);
        rc = ini_parse(buf, mbini_handler, &index);
        if (rc) {
            MBABORT("Can't parse '%s': %s\n", buf, strerror(errno));
        }
        if (index != multiboot_data.num_mbparts) {
            MBABORT("retrieved wrong number of partitions %u/%u\n", index, multiboot_data.num_mbparts);
        }

        // verify that every multiboot partition in mbfstab got replaced
        for (i=0; i<multiboot_data.mbfstab->num_entries; i++) {
            struct fstab_rec *rec = &multiboot_data.mbfstab->recs[i];

            if (!fs_mgr_is_multiboot(rec)) continue;

            // get multiboot partition
            multiboot_partition_t *part = multiboot_part_by_name(rec->mount_point+1);
            if (!part) {
                MBABORT("Can't find multiboot partition for '%s': %s\n", rec->mount_point, strerror(errno));
            }
        }
    }

    // grant ourselves some selinux permissions :)
    LOGD("patch sepolicy\n");
    selinux_fixup();

    // setup replacements
    LOGD("setup replacements\n");
    setup_partition_replacements();

    // boot recovery
    if (multiboot_data.is_recovery) {
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
