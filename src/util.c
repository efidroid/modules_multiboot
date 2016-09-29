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
#include <time.h>
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
#include <ini.h>

#include <common.h>
#include <util.h>

#define LOG_TAG "UTIL"
#include <lib/log.h>

char *util_basename(const char *path)
{
    // duplicate input path
    char *str = safe_strdup(path);

    // get basename
    char *bname = basename(str);
    if (!bname) {
        free(str);
        return NULL;
    }

    // duplicate return value
    char *ret = safe_strdup(bname);

    // cleanup input path
    free(str);

    // return result
    return ret;
}

char *util_dirname(const char *path)
{
    // duplicate input path
    char *str = safe_strdup(path);

    // get dirname
    char *dname = dirname(str);
    if (!dname) {
        free(str);
        return NULL;
    }

    // duplicate return value
    char *ret = safe_strdup(dname);

    // cleanup input path
    free(str);

    // return result
    return ret;
}

int util_buf2file(const void *buf, const char *filename, size_t size)
{
    int fd;
    size_t nbytes;
    int rc = 0;

    // open file for writing
    fd = open(filename, O_WRONLY | O_CREAT, 0640);
    if (fd<0) {
        return fd;
    }

    // write data
    nbytes = write(fd, buf, size);
    if (nbytes!=size) {
        rc = (int)nbytes;
        goto err_close;
    }

err_close:
    // close
    close(fd);

    return rc;
}

int util_exists(const char *filename, bool follow)
{
    struct stat buffer;
    int rc;

    if (follow)
        rc = stat(filename, &buffer);
    else
        rc = lstat(filename, &buffer);

    return rc==0;
}

uint64_t util_filesize(const char *filename, bool follow)
{
    struct stat buffer;
    int rc;

    if (follow)
        rc = stat(filename, &buffer);
    else
        rc = lstat(filename, &buffer);

    if (rc)
        return 0;
    else
        return buffer.st_size;
}

// Source: http://web.archive.org/web/20130728160829/http://nion.modprobe.de/blog/archives/357-Recursive-directory-creation.html
//         http://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix
int util_mkdir(const char *dir)
{
    char tmp[PATH_MAX+1];
    char *p = NULL;
    size_t len;
    int rc = 0;

    SAFE_SNPRINTF_RET(LOGE, -1, tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);

    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (!util_exists(tmp, true)) {
                rc = mkdir(tmp, S_IRWXU);
                if (rc) goto done;
            }

            *p = '/';
        }
    }


    if (!util_exists(tmp, true))
        rc = mkdir(tmp, S_IRWXU);

done:
    if (rc)
        LOGE("can't create dir %s: %s\n", dir, strerror(errno));

    return rc;
}

int util_exec_main(int argc, char **argv, int (*mainfn)(int, char **))
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

int util_sepolicy_inject(const char *source, const char *target, const char *clazz, const char *perm)
{
    return sepolicy_inject_rule(source, target, clazz, perm, "/sepolicy", NULL);
}

int util_append_string_to_file(const char *filename, const char *str)
{
    int rc = 0;

    int fd = open(filename, O_WRONLY|O_APPEND);
    if (fd<0) {
        return fd;
    }

    size_t len = strlen(str);
    size_t bytes_written = write(fd, str, len);
    if (bytes_written!=len) {
        rc = -errno;
        goto out;
    }

out:
    close(fd);

    return rc;
}

int util_setsighandler(int signum, void (*handler)(int, siginfo_t *, void *))
{
    struct sigaction usr_action;
    sigset_t block_mask;
    int rc;

    rc = sigfillset (&block_mask);
    if (rc) {
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
    char *util_fstype = NULL;

    // create target directory
    if (!util_exists(target, true)) {
        rc = util_mkdir(target);
        if (rc) {
            return rc;
        }
    }

    // get fstype
    if (!filesystemtype && !(mountflags&MS_BIND)) {
        filesystemtype = util_fstype = util_get_fstype(source);
        if (!filesystemtype) {
            LOGE("can't get filesystem for %s\n", source);
            return -1;
        }
    }

    // mount
    rc = mount(source, target, filesystemtype, mountflags, data);
    LOGV("mount(%s, %s, %s, %lu, %p) = %d\n", source, target, filesystemtype, mountflags, data, rc);
    if (rc) {
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
    char *device = safe_strdup(_device);
    char *file = safe_strdup(_file);

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
    const char *args[] = {"losetup", "-f", device, 0};
    return util_exec_main(3, (char **)args, busybox_main);
}

static int util_mke2fs(const char *device, const char *fstype)
{
    const char *args[] = {"mke2fs", "-t", fstype, "-m", "0", "-F", device, 0};
    return util_exec_main(7, (char **)args, mke2fs_main);
}

int util_mkfs(const char *device, const char *fstype)
{
    if (!strcmp(fstype, "ext2") || !strcmp(fstype, "ext3") || !strcmp(fstype, "ext4"))
        return util_mke2fs(device, fstype);

    LOGE("filesystem %s is not supported\n", fstype);
    return -1;
}

int util_block_num(const char *path, unsigned long *numblocks)
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
    if (blocks==0) {
        rc = util_block_num(source, &blocks);
        if (rc) return rc;
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
    const char *args[] = {"cp", source, target, 0};
    return util_exec_main(3, (char **)args, busybox_main);
}

int util_shell(const char *cmd)
{
    const char *args[] = {"sh", "-c", cmd, 0};
    return util_exec_main(3, (char **)args, busybox_main);
}

char *util_get_fstype(const char *filename)
{
    const char *type;
    char *ret = NULL;
    blkid_probe pr;

    // probe device
    pr = blkid_new_probe_from_filename(filename);
    if (!pr) {
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

char *util_get_espdir(const char *mountpoint)
{
    char buf[PATH_MAX];
    char buf2[PATH_MAX];
    multiboot_data_t *multiboot_data = multiboot_get_data();

    if (!multiboot_data->esp) {
        return NULL;
    }

    // get esp directory
    const char *espdir = NULL;
    int is_datamedia = 0;
    if (multiboot_data->esp->esp[0]=='/')
        espdir = multiboot_data->esp->esp+1;
    else if (!strcmp(multiboot_data->esp->esp, "datamedia")) {
        espdir = "media";
        is_datamedia = 1;
    } else {
        LOGE("Invalid ESP path %s\n", multiboot_data->esp->esp);
        return NULL;
    }

    SAFE_SNPRINTF_RET(LOGE, NULL, buf, sizeof(buf), "%s/%s/UEFIESP", mountpoint, espdir);

    // check if UEFIESP exists in root dir
    if (!util_exists(buf, true) && is_datamedia) {
        SAFE_SNPRINTF_RET(LOGE, NULL, buf2, sizeof(buf2), "%s/%s/0", mountpoint, espdir);

        // check if /0 exists
        if (util_exists(buf2, true)) {
            SAFE_SNPRINTF_RET(LOGE, NULL, buf2, sizeof(buf2), "%s/%s/0/UEFIESP", mountpoint, espdir);
            return safe_strdup(buf2);
        }
    }

    // the caller may create the directory, so always return the root dir as a fallback
    return safe_strdup(buf);
}

char *util_get_esp_path_for_partition(const char *mountpoint, const char *name)
{
    int rc;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    // get espdir
    char *espdir = util_get_espdir(mountpoint);
    if (!espdir) {
        LOGE("Can't get ESP directory: %s\n", strerror(errno));
        return NULL;
    }

    // copy path
    rc = snprintf(buf, sizeof(buf), "%s", espdir);
    free(espdir);
    if (SNPRINTF_ERROR(rc, sizeof(buf))) {
        LOGE("snprintf error\n");
        return NULL;
    }

    // create path for loop image
    rc = snprintf(buf2, sizeof(buf2), "%s/partition_%s.img", buf, name);
    if (SNPRINTF_ERROR(rc, sizeof(buf2))) {
        LOGE("snprintf error\n");
        return NULL;
    }

    // duplicate buffer
    return safe_strdup(buf2);
}

int util_create_partition_backup_ex(const char *device, const char *file, unsigned long num_blocks, bool force)
{
    int rc;

    // get number of blocks
    if (num_blocks==0)
        util_block_num(device, &num_blocks);

    // create raw image if it doesn't exists yet
    if (force || !util_exists(file, false)) {
        rc = util_dd(device, file, num_blocks);
        if (rc) {
            LOGE("Can't copy %s to %s: %d\n", device, file, rc);
            return -1;
        }
    }

    return 0;
}

int util_create_partition_backup(const char *device, const char *file)
{
    return util_create_partition_backup_ex(device, file, 0, false);
}

char *util_getmbpath_from_device(const char *device)
{
    multiboot_data_t *multiboot_data = multiboot_get_data();
    char buf[PATH_MAX];

    if (!multiboot_data->blockinfo) {
        return NULL;
    }

    uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, device);
    if (!bi)
        return NULL;

    // build dev name
    SAFE_SNPRINTF_RET(LOGE, NULL, buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);

    return safe_strdup(buf);
}

static const char *multiboot_bind_whitelist[] = {
    "ext2",
    "ext3",
    "ext4",
    "f2fs",
};

int util_fs_supports_multiboot_bind(const char *type)
{
    uint32_t i;

    for (i=0; i<ARRAY_SIZE(multiboot_bind_whitelist); i++) {
        if (!strcmp(multiboot_bind_whitelist[i], type))
            return 1;
    }

    return 0;
}

int util_mount_esp(int abort_on_error)
{
    int rc;
    multiboot_data_t *multiboot_data = multiboot_get_data();

    rc = uevent_mount(multiboot_data->espdev, MBPATH_ESP, NULL, 0, NULL);
    if (rc) {
        if (abort_on_error)
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
    if (rc) {
        LOGE("Can't create directory at %s\n", _target);
        return -1;
    }

    // duplicate arguments
    char *source = safe_strdup(_source);
    char *target = safe_strdup(_target);

    // build size
    char *ssize = safe_malloc(PATH_MAX);
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

int util_mount_mbinipart(const char *name, const char *mountpoint)
{
    multiboot_data_t *multiboot_data = multiboot_get_data();

    // get rec from mb fstab
    LOGV("search fstab.multiboot for %s\n", name);
    struct fstab_rec *mbrec = fs_mgr_get_by_mountpoint(multiboot_data->mbfstab, name);
    if (!mbrec) {
        LOGE("Can't get rec for %s\n", name);
        errno = ENOENT;
        return -1;
    }

    // get blockinfo
    LOGV("get blockinfo for %s\n", mbrec->blk_device);
    uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, mbrec->blk_device);
    if (!bi) {
        LOGE("Can't get blockinfo for %s\n", mbrec->blk_device);
        errno = ENOENT;
        return -1;
    }

    return uevent_mount(bi, mountpoint, NULL, 0, NULL);
}

typedef struct {
    const char *propertyname;
    char *value;
} getprop_pdata_t;

static int getprop_handler(void *user, UNUSED const char *section, const char *name, const char *value)
{
    getprop_pdata_t *pdata = user;

    // we're interested in partitions only
    if (!strcmp(name, pdata->propertyname)) {
        pdata->value = safe_strdup(value);
        return 0;
    }

    return 1;
}

char *util_get_property(const char *filename, const char *propertyname)
{
    getprop_pdata_t pdata = {
        .propertyname = propertyname,
        .value = NULL,
    };
    ini_parse(filename, getprop_handler, &pdata);
    return pdata.value;
}

int util_read_int(const char *filename, uint32_t *pvalue)
{
    int rc;

    // validate arguments
    if (!filename || !pvalue) {
        errno = EINVAL;
        return -1;
    }

    // open file
    int fd = open(filename, O_RDONLY);
    if (fd<0) return -1;

    // read file
    char buffer[20];
    if (read(fd, buffer, sizeof(buffer))<0) {
        rc = -1;
        goto close_file;
    }

    // parse data
    if (sscanf(buffer, "%u", pvalue) != 1) {
        rc = -1;
        goto close_file;
    }

    rc = 0;

close_file:
    close(fd);

    return rc;
}

int util_write_int(char const *path, int value)
{
    int rc;
    ssize_t byte_count;

    // open file
    int fd = open(path, O_WRONLY|O_TRUNC|O_CREAT);
    if (fd<0) return -1;

    // convert value
    char buffer[20];
    rc = snprintf(buffer, sizeof(buffer), "%d\n", value);
    if (SNPRINTF_ERROR(rc, sizeof(buffer))) {
        rc = -1;
        goto close_file;
    }

    // write value
    byte_count = write(fd, buffer, rc);
    if (byte_count<0 || byte_count!=rc) {
        rc = -1;
        goto close_file;
    }

    rc = 0;

close_file:
    close(fd);

    return rc;
}

part_replacement_t *util_get_replacement_by_name(const char *name)
{
    multiboot_data_t *multiboot_data = multiboot_get_data();

    part_replacement_t *replacement;
    list_for_every_entry(&multiboot_data->replacements, replacement, part_replacement_t, node) {
        if (replacement->multiboot.part && !strcmp(replacement->multiboot.part->name, name)) {
            return replacement;
        }
    }
    return NULL;
}

const char *util_get_file_extension(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot + 1;
}

char *util_get_file_contents(const char *filename)
{
    char *buffer = NULL;

    // open file
    FILE *fh = fopen(filename, "rb");
    if (!fh) return NULL;

    // get file size
    fseek(fh, 0L, SEEK_END);
    long size = ftell(fh);
    rewind(fh);

    // allocate buffer
    buffer = malloc(size+1);
    if (!buffer) {
        goto close_file;
    }

    // read file
    if (fread(buffer, size, 1, fh)!=1) {
        goto free_buffer;
    }

    buffer[size] = 0;

    goto close_file;

free_buffer:
    free(buffer);
    buffer = NULL;

close_file:
    fclose(fh);

    return buffer;
}

part_replacement_t *util_get_replacement(unsigned int major, unsigned int minor)
{
    multiboot_data_t *multiboot_data = multiboot_get_data();

    part_replacement_t *replacement;
    list_for_every_entry(&multiboot_data->replacements, replacement, part_replacement_t, node) {
        if (replacement->uevent_block->major==major && replacement->uevent_block->minor==minor) {
            return replacement;
        }
    }
    return NULL;
}

uint64_t util_gettime_ns() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)(now.tv_sec) * UINT64_C(1000000000) + now.tv_nsec;
}

int util_wait_for_file(const char *filename, int timeout)
{
    struct stat info;
    uint64_t timeout_time_ns = util_gettime_ns() + timeout * UINT64_C(1000000000);
    int ret = -1;

    while (util_gettime_ns() < timeout_time_ns && ((ret = stat(filename, &info)) < 0))
        usleep(10000);

    return ret;
}
