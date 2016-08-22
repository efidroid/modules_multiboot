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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/param.h>

#include <lib/klog.h>
#include <lib/fs_mgr.h>
#include <lib/dynfilefs.h>
#include <blkid/blkid.h>
#include <sepolicy_inject.h>

#include <common.h>
#include <util.h>

#define LOG_TAG "UTIL"
#include <lib/log.h>

char* util_basename(const char* path) {
    // duplicate input path
    char* str = safe_strdup(path);

    // get basename
    char* bname = basename(str);
    if(!bname) {
        free(str);
        return NULL;
    }

    // duplicate return value
    char* ret = safe_strdup(bname);

    // cleanup input path
    free(str);

    // return result
    return ret;
}

char* util_dirname(const char* path) {
    // duplicate input path
    char* str = safe_strdup(path);

    // get dirname
    char* dname = dirname(str);
    if(!dname) {
        free(str);
        return NULL;
    }

    // duplicate return value
    char* ret = safe_strdup(dname);

    // cleanup input path
    free(str);

    // return result
    return ret;
}

int util_buf2file(const void* buf, const char* filename, size_t size) {
    int fd;
    size_t nbytes;
    int rc = 0;

    // open file for writing
    fd = open(filename, O_WRONLY | O_CREAT, 0640);
    if(fd<0) {
        return fd;
    }

    // write data
    nbytes = write(fd, buf, size);
    if(nbytes!=size) {
        rc = (int)nbytes;
        goto err_close;
    }

err_close:
    // close
    close(fd);

    return rc;
}

int util_exists(const char *filename, bool follow) {
    struct stat buffer;
    int rc;

    if(follow)
        rc = stat(filename, &buffer);
    else
        rc = lstat(filename, &buffer);

    return rc==0;
}

uint64_t util_filesize(const char *filename, bool follow) {
    struct stat buffer;
    int rc;

    if(follow)
        rc = stat(filename, &buffer);
    else
        rc = lstat(filename, &buffer);

    if(rc)
        return 0;
    else
        return buffer.st_size;
}

// Source: http://web.archive.org/web/20130728160829/http://nion.modprobe.de/blog/archives/357-Recursive-directory-creation.html
//         http://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix
int util_mkdir(const char *dir) {
    char tmp[PATH_MAX+1];
    char *p = NULL;
    size_t len;
    int rc = 0;

    SAFE_SNPRINTF_RET(LOGE, -1, tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);

    if(tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    for(p = tmp + 1; *p; p++) {
        if(*p == '/') {
            *p = 0;
            if(!util_exists(tmp, true)) {
                rc = mkdir(tmp, S_IRWXU);
                if(rc) goto done;
            }

            *p = '/';
        }
    }


    if(!util_exists(tmp, true))
        rc = mkdir(tmp, S_IRWXU);

done:
    if(rc)
        LOGE("can't create dir %s: %s\n", dir, strerror(errno));

    return rc;
}

int util_exec_main(int argc, char** argv, int (*mainfn)(int, char**))
{
    pid_t pid;
    int status = 0;

    pid = safe_fork();
    if (!pid) {
        optind = 1;
        opterr = 1;
        optopt = '?';
        exit(mainfn(argc, argv));
    } else {
        waitpid(pid, &status, 0);
    }

    return status;
}

int util_sepolicy_inject(const char* source, const char* target, const char* clazz, const char* perm) {
    return sepolicy_inject_rule(source, target, clazz, perm, "/sepolicy", NULL);
}

int util_append_string_to_file(const char* filename, const char* str) {
    int rc = 0;

    int fd = open(filename, O_WRONLY|O_APPEND);
    if(fd<0) {
        return fd;
    }

    size_t len = strlen(str);
    size_t bytes_written = write(fd, str, len);
    if(bytes_written!=len) {
        rc = -errno;
        goto out;
    }

out:
    close(fd);

    return rc;
}

int util_setsighandler(int signum, void (*handler)(int, siginfo_t *, void *)) {
    struct sigaction usr_action;
    sigset_t block_mask;
    int rc;

    rc = sigfillset (&block_mask);
    if(rc) {
        return rc;
    }

    usr_action.sa_sigaction = handler;
    usr_action.sa_mask = block_mask;
    usr_action.sa_flags = SA_SIGINFO;
    return sigaction(signum, &usr_action, NULL);
}

int util_mount(const char *source, const char *target,
               const char *filesystemtype, unsigned long mountflags,
               const void *data)
{
    int rc = 0;
    char* util_fstype = NULL;

    // create target directory
    if(!util_exists(target, true)) {
        rc = util_mkdir(target);
        if(rc) {
            return rc;
        }
    }

    // get fstype
    if(!filesystemtype && !(mountflags&MS_BIND)) {
        filesystemtype = util_fstype = util_get_fstype(source);
        if(!filesystemtype) {
            LOGE("can't get filesystem for %s\n", source);
            return -1;
        }
    }

    // mount
    rc = mount(source, target, filesystemtype, mountflags, data);
    if(rc) {
        LOGE("mount(%s, %s, %s, %lu, %p) failed: %s\n", source, target, filesystemtype, mountflags, data, strerror(errno));
        return -1;
    }

    // cleanup
    free(util_fstype);

    return rc;
}

int util_make_loop(const char *path)
{
    static int loops_created = 0;
    int minor = 255 - loops_created;
    int rc;

    // create node
    rc = mknod(path, S_IRUSR | S_IWUSR | S_IFBLK, makedev(7, minor));
    if (rc) {
        return rc;
    }

    // increase count
    loops_created++;

    return rc;
}

int util_losetup(const char *_device, const char *_file, bool ro)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* device = safe_strdup(_device);
    char* file = safe_strdup(_file);

    // tool
    par[i++] = "losetup";

    // access mode
    if (ro)
        par[i++] = "-r";

    // paths
    par[i++] = device;
    par[i++] = file;

    // end
    par[i++] = (char *)0;

    rc = util_exec_main(i-1, par, busybox_main);

    // free arguments
    free(device);
    free(file);

    return rc;
}

int util_losetup_free(const char *device)
{
    const char* args[] = {"losetup", "-f", device, 0};
    return util_exec_main(3, (char**)args, busybox_main);
}

static int util_mke2fs(const char *device, const char* fstype)
{
    const char* args[] = {"mke2fs", "-t", fstype, "-m", "0", "-F", device, 0};
    return util_exec_main(7, (char**)args, mke2fs_main);
}

int util_mkfs(const char *device, const char* fstype) {
    if(!strcmp(fstype, "ext2") || !strcmp(fstype, "ext3") || !strcmp(fstype, "ext4"))
        return util_mke2fs(device, fstype);

    LOGE("filesystem %s is not supported\n", fstype);
    return -1;
}

int util_block_num(const char *path, unsigned long* numblocks)
{
    int fd;

    fd = open(path, O_RDONLY);
    if (fd<0)
        return fd;

    if (ioctl(fd, BLKGETSIZE, numblocks) == -1)
        return -1;

    close(fd);

    return 0;
}

int util_dd(const char *source, const char *target, unsigned long blocks)
{
    int rc;
    int i = 0;
    char *par[64];
    char buf[PATH_MAX];
    char *buf_if = NULL, *buf_of = NULL, *buf_bs = NULL, *buf_count = NULL;

    // get number of blocks
    if(blocks==0) {
        rc = util_block_num(source, &blocks);
        if(rc) return rc;
    }

    // tool
    par[i++] = "dd";

    // input
    SAFE_SNPRINTF_RET(LOGE, -1, buf, ARRAY_SIZE(buf), "if=%s", source);
    buf_if = safe_strdup(buf);
    par[i++] = buf_if;

    // output
    SAFE_SNPRINTF_RET(LOGE, -1, buf, ARRAY_SIZE(buf), "of=%s", target);
    buf_of = safe_strdup(buf);
    par[i++] = buf_of;

    // blocksize (get_blknum returns 512byte blocks)
    SAFE_SNPRINTF_RET(LOGE, -1, buf, ARRAY_SIZE(buf), "bs=%d", 512);
    buf_bs = safe_strdup(buf);
    par[i++] = buf_bs;

    // count
    SAFE_SNPRINTF_RET(LOGE, -1, buf, ARRAY_SIZE(buf), "count=%lu", blocks);
    buf_count = safe_strdup(buf);
    par[i++] = buf_count;

    // end
    par[i++] = (char *)0;

    // exec
    rc = util_exec_main(i-1, par, busybox_main);

    // cleanup
    free(buf_if);
    free(buf_of);
    free(buf_bs);
    free(buf_count);

    return rc;
}

int util_cp(const char *source, const char *target)
{
    const char* args[] = {"cp", source, target, 0};
    return util_exec_main(3, (char**)args, busybox_main);
}

int util_shell(const char *cmd)
{
    const char* args[] = {"sh", "-c", cmd, 0};
    return util_exec_main(3, (char**)args, busybox_main);
}

char *util_get_fstype(const char *filename)
{
    const char *type;
    char* ret = NULL;
    blkid_probe pr;

    // probe device
    pr = blkid_new_probe_from_filename(filename);
    if(!pr) {
        LOGE("can't create probe for %s\n", filename);
        return NULL;
    }

    if (blkid_do_fullprobe(pr)) {
        LOGE("can't probe %s\n", filename);
        return NULL;
    }

    // get type
    if (blkid_probe_lookup_value(pr, "TYPE", &type, NULL) < 0) {
        goto out;
    }

    // copy string
    ret = safe_strdup(type);

out:
    // free probe
    blkid_free_probe(pr);

    return ret;
}

char* util_get_espdir(const char* mountpoint) {
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    multiboot_data_t* multiboot_data = multiboot_get_data();

    if(!multiboot_data->esp) {
        return NULL;
    }

    // get esp directory
    const char* espdir = NULL;
    int is_datamedia = 0;
    if(multiboot_data->esp->esp[0]=='/')
        espdir = multiboot_data->esp->esp+1;
    else if(!strcmp(multiboot_data->esp->esp, "datamedia")) {
        espdir = "media";
        is_datamedia = 1;
    }
    else {
        LOGE("Invalid ESP path %s\n", multiboot_data->esp->esp);
        return NULL;
    }

    SAFE_SNPRINTF_RET(LOGE, NULL, buf, sizeof(buf), "%s/%s/UEFIESP", mountpoint, espdir);

    // check if UEFIESP exists in root dir
    if(!util_exists(buf, true) && is_datamedia) {
        SAFE_SNPRINTF_RET(LOGE, NULL, buf2, sizeof(buf2), "%s/%s/0", mountpoint, espdir);

        // check if /0 exists
        if(util_exists(buf2, true)) {
            SAFE_SNPRINTF_RET(LOGE, NULL, buf2, sizeof(buf2), "%s/%s/0/UEFIESP", mountpoint, espdir);
            return safe_strdup(buf2);
        }
    }

    // the caller may create the directory, so always return the root dir as a fallback
    return safe_strdup(buf);
}

char* util_get_esp_path_for_partition(const char* mountpoint, struct fstab_rec *rec) {
    int rc;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    // get espdir
    char* espdir = util_get_espdir(mountpoint);
    if(!espdir) {
        LOGE("Can't get ESP directory: %s\n", strerror(errno));
        return NULL;
    }

    // copy path
    rc = snprintf(buf, sizeof(buf), "%s", espdir);
    free(espdir);
    if(SNPRINTF_ERROR(rc, sizeof(buf))) {
        LOGE("snprintf error\n");
        return NULL;
    }

    // build partition name
    char* name = util_basename(rec->mount_point);
    if(!name) {
        LOGE("Can't get basename of %s\n", rec->mount_point);
        return NULL;
    }

    // create path for loop image
    rc = snprintf(buf2, sizeof(buf2), "%s/partition_%s.img", buf, name);
    free(name);
    if(SNPRINTF_ERROR(rc, sizeof(buf2))) {
        LOGE("snprintf error\n");
        return NULL;
    }

    // duplicate buffer
    return safe_strdup(buf2);
}

int util_create_partition_backup_ex(const char* device, const char* file, unsigned long num_blocks, bool force) {
    int rc;

    // get number of blocks
    if(num_blocks==0)
        util_block_num(device, &num_blocks);

    // create raw image if it doesn't exists yet
    if(force || !util_exists(file, false)) {
        rc = util_dd(device, file, num_blocks);
        if(rc) {
            LOGE("Can't copy %s to %s: %d\n", device, file, rc);
            return -1;
        }
    }

    return 0;
}

int util_create_partition_backup(const char* device, const char* file) {
    return util_create_partition_backup_ex(device, file, 0, false);
}

char* util_getmbpath_from_device(const char* device) {
    multiboot_data_t* multiboot_data = multiboot_get_data();
    char buf[PATH_MAX];

    if(!multiboot_data->blockinfo) {
        return NULL;
    }

    uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, device);
    if (!bi)
        return NULL;

    // build dev name
    SAFE_SNPRINTF_RET(LOGE, NULL, buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);

    return safe_strdup(buf);
}

static const char* multiboot_bind_whitelist[] = {
    "ext2",
    "ext3",
    "ext4",
    "f2fs",
};

int util_fs_supports_multiboot_bind(const char* type) {
    uint32_t i;

    for(i=0; i<ARRAY_SIZE(multiboot_bind_whitelist); i++) {
        if(!strcmp(multiboot_bind_whitelist[i], type))
            return 1;
    }

    return 0;
}

char* util_device_from_mbname(const char* name) {
    multiboot_data_t* multiboot_data = multiboot_get_data();

    int i;
    char buf[PATH_MAX];

    for(i=0; i<multiboot_data->mbfstab->num_entries; i++) {
        struct fstab_rec *rec = &multiboot_data->mbfstab->recs[i];

        if(!strcmp(rec->mount_point+1, name)) {
            uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, rec->blk_device);
            if (!bi) return NULL;

            SAFE_SNPRINTF_RET(LOGE, NULL, buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);

            return safe_strdup(buf);
        }
    }

    return NULL;
}

multiboot_partition_t* util_mbpart_by_name(const char* name) {
    uint32_t i;
    multiboot_data_t* multiboot_data = multiboot_get_data();

    for(i=0; i<multiboot_data->num_mbparts; i++) {
        multiboot_partition_t* part = &multiboot_data->mbparts[i];

        if(!strcmp(part->name, name))
            return part;
    }

    return NULL;
}

int util_mount_esp(int abort_on_error) {
    int rc;
    multiboot_data_t* multiboot_data = multiboot_get_data();

    rc = util_mount_blockinfo_with_romflags(multiboot_data->espdev, MBPATH_ESP);
    if(rc) {
        if(abort_on_error)
            MBABORT("Can't mount ESP: %s\n", strerror(errno));
        else
            LOGE("Can't mount ESP: %s\n", strerror(errno));
    }

    return 0;
}

int util_dynfilefs(const char *_source, const char *_target, uint64_t size)
{
    char *par[64];
    int i = 0;
    int rc;

    // create mountpoint directory
    rc = util_mkdir(_target);
    if(rc) {
        LOGE("Can't create directory at %s\n", _target);
        return -1;
    }

    // duplicate arguments
    char* source = safe_strdup(_source);
    char* target = safe_strdup(_target);

    // build size
    char* ssize = safe_malloc(PATH_MAX);
    SAFE_SNPRINTF_RET(LOGE, -1, ssize, PATH_MAX, "-s%llu", size);

    // tool
    par[i++] = "dynfilefs";

    par[i++] = "-o";
    par[i++] = "direct_io,kernel_cache";

    // size
    par[i++] = ssize;

    // source
    par[i++] = source;

    // target
    par[i++] = target;

    // end
    par[i++] = (char *)0;

    rc = util_exec_main(i-1, par, dynfilefs_main);

    // free arguments
    free(ssize);
    free(target);
    free(source);

    return rc;
}

int util_setup_partition_replacements(void) {
    multiboot_data_t* multiboot_data = multiboot_get_data();

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
        if(!util_exists("/dev/fuse", true)) {
            rc = mknod("/dev/fuse", S_IFCHR | 0600, makedev(10, 229));
            if(rc) {
                MBABORT("Can't create /dev/fuse: %s\n", strerror(errno));
            }
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
            pdata->rec = rec;
            pdata->u.multiboot.part = part;
            pdata->u.multiboot.partpath = partpath;

            list_add_tail(&multiboot_data->replacements, &pdata->node);
        }

        // TODO: check for optional replacement partitions

        free(basedir);
    }

    // internal system

    // mount ESP
    util_mount_esp(1);

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
        struct fstab_rec *rec = &multiboot_data->mbfstab->recs[i];

        // skip non-uefi partitions
        if(!fs_mgr_is_uefi(rec)) continue;
        // this partition got replaced by multiboot aready
        if(fs_mgr_is_multiboot(rec) && multiboot_data->is_multiboot) continue;

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
        SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_DEV"/block/loopdev:%s", rec->mount_point+1);

        // in native recovery, we don't want to block unmounting by setting up loop's
        if(multiboot_data->is_recovery && !multiboot_data->is_multiboot) {
            // path to temporary partition backup
            SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), MBPATH_ROOT"/loopfile:%s", rec->mount_point+1);

            // create temporary partition backup
            rc = util_cp(espfilename, buf2);
            if(rc) {
                MBABORT("Can't copy partition from esp to temp\n");
            }
        }

        else {
            // path to partition backup
            SAFE_SNPRINTF_RET(MBABORT, -1, buf2, sizeof(buf2), "%s", espfilename);
        }

        // create new loop node
        rc = util_make_loop(buf);
        if(rc) {
            MBABORT("Can't create loop device at %s\n", buf);
        }

        char* loopfile = NULL;
        // in Android we'll do that in the postfs stage
        if(multiboot_data->is_recovery) {
            // setup loop device
            rc = util_losetup(buf, buf2, false);
            if(rc) {
                MBABORT("Can't setup loop device at %s for %s\n", buf, buf2);
            }
        }
        else {
            loopfile = safe_strdup(buf2);
        }

        part_replacement_t* pdata = safe_calloc(sizeof(part_replacement_t), 1);
        if(!pdata) {
            MBABORT("Can't allocate hook device\n");
        }

        pthread_mutex_init(&pdata->lock, NULL);
        pdata->major = bi->major;
        pdata->minor = bi->minor;
        pdata->loopdevice = safe_strdup(buf);
        pdata->loopfile = loopfile?safe_strdup(loopfile):NULL;
        pdata->rec = rec;

        list_add_tail(&multiboot_data->replacements, &pdata->node);

        // cleanup
        free(mbpathdevice);
        free(espfilename);
    }

    // in native recovery, we don't want to block unmounting
    // in android recovery, we re-mount the esp in the postfs stage
    if(!multiboot_data->is_recovery || (multiboot_data->is_recovery && !multiboot_data->is_multiboot)) {
        // unmount ESP
        SAFE_UMOUNT(MBPATH_ESP);
    }

    return 0;
}

int util_mount_blockinfo_with_romflags(uevent_block_t* bi, const char* mountpoint) {
    multiboot_data_t* multiboot_data = multiboot_get_data();
    int rc;

    // get the ROM's mount flags
    unsigned long mountflags = 0;
    const void* data = NULL;
    struct fstab_rec* romrec = fs_mgr_get_by_ueventblock(multiboot_data->romfstab, bi);
    if(romrec) {
        mountflags = romrec->flags;
        data = (void*)romrec->fs_options;
        LOGD("use ROM mountflags for %s, flags:%lu, data:%s\n", bi->devname, mountflags, (const char*)data);
    }

    // mount data
    LOGD("mount %s at %s\n", bi->devname, mountpoint);
    rc = uevent_mount(bi, mountpoint, NULL, mountflags, data);
    if(rc) {
        // mount without flags
        LOGI("mount %s without flags\n", bi->devname);
        mountflags = 0;
        data = NULL;
        rc = uevent_mount(bi, mountpoint, NULL, mountflags, data);
        if(rc) {
            LOGE("Can't mount %s: %s\n", bi->devname, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int util_mount_mbinipart_with_romflags(const char* name, const char* mountpoint) {
    multiboot_data_t* multiboot_data = multiboot_get_data();

    // get rec from mb fstab
    LOGV("search fstab.multiboot for %s\n", name);
    struct fstab_rec* mbrec = fs_mgr_get_by_mountpoint(multiboot_data->mbfstab, name);
    if(!mbrec) {
        LOGE("Can't get rec for %s\n", name);
        errno = ENOENT;
        return -1;
    }

    // get blockinfo
    LOGV("get blockinfo for %s\n", mbrec->blk_device);
    uevent_block_t* bi = get_blockinfo_for_path(multiboot_data->blockinfo, mbrec->blk_device);
    if(!bi) {
        LOGE("Can't get blockinfo for %s\n", mbrec->blk_device);
        errno = ENOENT;
        return -1;
    }

    return util_mount_blockinfo_with_romflags(bi, mountpoint);
}
