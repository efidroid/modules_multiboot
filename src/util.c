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

#include <lib/klog.h>
#include <lib/fs_mgr.h>
#include <lib/efivars.h>
#include <blkid.h>

#include <common.h>
#include <util.h>

#define LOG_TAG "UTIL"
#include <lib/log.h>

int sepolicy_inject_main(int argc, char **argv);

char* util_basename(const char* path) {
    // duplicate input path
    char* str = strdup(path);
    if(!str) return NULL;

    // get basename
    char* bname = basename(str);
    if(!bname) {
        free(str);
        return NULL;
    }

    // duplicate return value
    char* ret = strdup(bname);

    // cleanup input path
    free(str);

    // return result
    return ret;
}

char* util_dirname(const char* path) {
    // duplicate input path
    char* str = strdup(path);
    if(!str) return NULL;

    // get dirname
    char* dname = dirname(str);
    if(!dname) {
        free(str);
        return NULL;
    }

    // duplicate return value
    char* ret = strdup(dname);

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

int util_extractbin(const void* buf, const char* filename, size_t size) {
    int rc;

    rc = util_buf2file(buf, filename, size);
    if(rc) {
        return rc;
    }
    rc = chmod(filename, 0755);
    if(rc) {
        return rc;
    }

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

    snprintf(tmp, sizeof(tmp), "%s", dir);
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
        return EFIVARS_LOG_TRACE(rc, "can't create dir %s\n", dir);

    return rc;
}

int util_exec(char **args)
{
    pid_t pid;
    int status = 0;

    pid = fork();
    if (!pid) {
        // redirect stdout and stderr to kmsg
        int fd = klog_get_fd();
        dup2(fd, 1);
        dup2(fd, 2);

        execve(args[0], args, NULL);
        exit(0);
    } else {
        waitpid(pid, &status, 0);
    }

    return status;
}

int util_replace(const char *_file, const char *_regex)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* file = strdup(_file);
    char* regex = strdup(_regex);
    if(!file || !regex) return -ENOMEM;

    // tool
    par[i++] = MBPATH_BUSYBOX;
    par[i++] = "sed";
    par[i++] = "-i";
    par[i++] = (char *)regex;
    par[i++] = (char *)file;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(file);
    free(regex);

    return rc;
}

static int util_sepolicy_inject_internal(const char** args) {
    int argc = 0;
    const char** argptr = args;
    int i;

    while(*argptr++)
        argc++;

    char** seargs = malloc(sizeof(char*)*argc+1);
    seargs[0] = strdup("sepolicy_inject");
    for(i=0; i<argc; i++) {
        seargs[i+1] = strdup(args[i]);
        if(!seargs[i+1]) return -ENOMEM;
    }

    int rc = sepolicy_inject_main(argc+1, seargs);

    for(i=0; i<argc+1; i++) {
        free(seargs[i]);
    }
    free(seargs);

    return rc;
}

int util_sepolicy_inject(const char* source, const char* target, const char* clazz, const char* perm) {
    const char* seargs[] = {"-s", source, "-t", target, "-c", clazz, "-p", perm, "-P", "/sepolicy", "-o", "/sepolicy", NULL};
    return util_sepolicy_inject_internal(seargs);
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
    if(!filesystemtype) {
        filesystemtype = util_fstype = util_get_fstype(source);
        if(!filesystemtype) return -EINVAL;
    }

    // mount
    rc = mount(source, target, filesystemtype, mountflags, data);

    // cleanup
    free(util_fstype);

    if(rc) {
        return EFIVARS_LOG_TRACE(rc, "mount(%s, %s, %s, %lu, %p) failed\n", source, target, filesystemtype, mountflags, data);
    }

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
    char* device = strdup(_device);
    char* file = strdup(_file);
    if(!device || !file) return -ENOMEM;

    // tool
    par[i++] = MBPATH_BUSYBOX;
    par[i++] = "losetup";

    // access mode
    if (ro)
        par[i++] = "-r";

    // paths
    par[i++] = device;
    par[i++] = file;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(device);
    free(file);

    return rc;
}

int util_losetup_free(const char *_device)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* device = strdup(_device);
    if(!device) return -ENOMEM;

    // tool
    par[i++] = MBPATH_BUSYBOX;
    par[i++] = "losetup";

    // disassociate
    par[i++] = "-d";

    // device
    par[i++] = device;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(device);

    return rc;
}

int util_mke2fs(const char *_device, const char* _fstype)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* device = strdup(_device);
    char* fstype = strdup(_fstype);
    if(!device || !fstype) return -ENOMEM;

    // tool
    par[i++] = MBPATH_MKE2FS;

    // filesystem
    par[i++] = "-t";
    par[i++] = fstype;

    // reserved blocks
    par[i++] = "-m";
    par[i++] = "0";

    // force
    par[i++] = "-F";

    // device
    par[i++] = device;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(fstype);
    free(device);

    return rc;
}

int util_mkfs_f2fs(const char *_device)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* device = strdup(_device);
    if(!device) return -ENOMEM;

    // tool
    par[i++] = MBPATH_MKFS_F2FS;

    // discard
    par[i++] = "-t";
    par[i++] = "1";

    // device
    par[i++] = device;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(device);

    return rc;
}

int util_mkfs(const char *device, const char* fstype) {
    if(!strcmp(fstype, "ext2") || !strcmp(fstype, "ext3") || !strcmp(fstype, "ext4"))
        return util_mke2fs(device, fstype);

    if(!strcmp(fstype, "f2fs"))
        return util_mkfs_f2fs(device);

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
    par[i++] = MBPATH_BUSYBOX;
    par[i++] = "dd";

    // input
    snprintf(buf, ARRAY_SIZE(buf), "if=%s", source);
    buf_if = strdup(buf);
    par[i++] = buf_if;

    // output
    snprintf(buf, ARRAY_SIZE(buf), "of=%s", target);
    buf_of = strdup(buf);
    par[i++] = buf_of;

    // blocksize (get_blknum returns 512byte blocks)
    snprintf(buf, ARRAY_SIZE(buf), "bs=%d", 512);
    buf_bs = strdup(buf);
    par[i++] = buf_bs;

    // count
    snprintf(buf, ARRAY_SIZE(buf), "count=%lu", blocks);
    buf_count = strdup(buf);
    par[i++] = buf_count;

    // end
    par[i++] = (char *)0;

    // exec
    rc = util_exec(par);

    // cleanup
    free(buf_if);
    free(buf_of);
    free(buf_bs);
    free(buf_count);

    return rc;
}

int util_cp(const char *source, const char *target)
{
    int rc;
    int i = 0;
    char *par[64];
    char *buf_source = NULL, *buf_target = NULL;

    // tool
    par[i++] = MBPATH_BUSYBOX;
    par[i++] = "cp";

    // source
    buf_source = strdup(source);
    par[i++] = buf_source;

    // target
    buf_target = strdup(target);
    par[i++] = buf_target;

    // end
    par[i++] = (char *)0;

    // exec
    rc = util_exec(par);

    // cleanup
    free(buf_target);
    free(buf_source);

    return rc;
}

int util_shell(const char *_cmd)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* cmd = strdup(_cmd);
    if(!cmd) return -ENOMEM;

    // tool
    par[i++] = MBPATH_BUSYBOX;
    par[i++] = "sh";

    // cmd
    par[i++] = "-c";
    par[i++] = cmd;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(cmd);

    return rc;
}

char *util_get_fstype(const char *filename)
{
    const char *type;
    char* ret = NULL;
    blkid_probe pr;

    // probe device
    pr = blkid_new_probe_from_filename(filename);
    if (blkid_do_fullprobe(pr)) {
        return NULL;
    }

    // get type
    if (blkid_probe_lookup_value(pr, "TYPE", &type, NULL) < 0) {
        goto out;
    }

    // copy string
    ret = strdup(type);

out:
    // free probe
    blkid_free_probe(pr);

    return ret;
}

char* util_get_espdir(const char* mountpoint, char* extbuf) {
    int rc;
    char buf[PATH_MAX];
    int use_extbuf = 0;
    multiboot_data_t* multiboot_data = multiboot_get_data();

    if(!multiboot_data->esp) {
        return NULL;
    }

    if(extbuf)
        use_extbuf = 1;
    else
        extbuf = buf;

    // get esp directory
    const char* espdir = NULL;
    if(multiboot_data->esp->esp[0]=='/')
        espdir = multiboot_data->esp->esp+1;
    else if(!strcmp(multiboot_data->esp->esp, "datamedia"))
        espdir = "media";
    else {
        EFIVARS_LOG_TRACE(-EINVAL, "Invalid ESP path %s\n", multiboot_data->esp->esp);
        return NULL;
    }

    // build UEFIESP mountpoint
    rc = snprintf(extbuf, PATH_MAX, "%s/%s/UEFIESP", mountpoint, espdir);
    if(rc<0 || rc>=PATH_MAX) {
        EFIVARS_LOG_TRACE(rc, "Can't build name for UEFIESP: %s\n", strerror(errno));
        return NULL;
    }

    if(use_extbuf) {
        return extbuf;
    }
    else {
        // duplicate UEFIESP mountpoint
        char* ret = strdup(extbuf);
        if(!ret) {
            EFIVARS_LOG_TRACE(-errno, "Can't alloc mem for UEFIESP: %s\n", strerror(errno));
            return NULL;
        }
        return ret;
    }
}

char* util_get_esp_path_for_partition(const char* mountpoint, struct fstab_rec *rec) {
    int rc;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    // get espdir
    char* espdir = util_get_espdir(mountpoint, buf);
    if(!espdir) {
        EFIVARS_LOG_TRACE(-1, "Can't get ESP directory: %s\n", strerror(errno));
        return NULL;
    }

    // build partition name
    char* name = util_basename(rec->mount_point);
    if(!name) {
        EFIVARS_LOG_TRACE(-1, "Can't get basename of %s\n", rec->mount_point);
        return NULL;
    }

    // create path for loop image
    rc = snprintf(buf2, PATH_MAX, "%s/partition_%s.img", espdir, name);
    if(rc<0 || rc>=PATH_MAX) {
        EFIVARS_LOG_TRACE(rc, "Can't build name for partition image\n");
        return NULL;
    }

    // duplicate buffer
    char* ret = strdup(buf2);
    if(!ret) {
        EFIVARS_LOG_TRACE(-errno, "Can't alloc mem for partition name: %s\n", strerror(errno));
        return NULL;
    }

    return ret;
}

int util_create_partition_backup_ex(const char* device, const char* file, unsigned long num_blocks, bool force) {
    int rc;

    // get number of blocks
    if(num_blocks==0)
        util_block_num(device, &num_blocks);

    // create raw image if it doesn't exists yet
    // or if it's size doesn't match the original partition
    if(force || !util_exists(file, false) || util_filesize(file, false)!=num_blocks*512llu) {
        rc = util_dd(device, file, num_blocks);
        if(rc) {
            return EFIVARS_LOG_TRACE(rc, "Can't copy %s to %s\n", device, file);
        }
    }

    return 0;
}

int util_create_partition_backup(const char* device, const char* file) {
    return util_create_partition_backup_ex(device, file, 0, false);
}

char* util_getmbpath_from_device(const char* device) {
    multiboot_data_t* multiboot_data = multiboot_get_data();
    int rc;
    char buf[PATH_MAX];

    if(!multiboot_data->blockinfo) {
        return NULL;
    }

    uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, device);
    if (!bi)
        return NULL;

    // build dev name
    rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);
    if(rc<0 || (size_t)rc>=sizeof(buf)) {
        return NULL;
    }

    return strdup(buf);
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
    int rc;
    char buf[PATH_MAX];

    for(i=0; i<multiboot_data->mbfstab->num_entries; i++) {
        struct fstab_rec *rec = &multiboot_data->mbfstab->recs[i];

        if(!strcmp(rec->mount_point+1, name)) {
            uevent_block_t *bi = get_blockinfo_for_path(multiboot_data->blockinfo, rec->blk_device);
            if (!bi) return NULL;

            rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);
            if(rc<0 || (size_t)rc>=sizeof(buf))
                return NULL;

            return strdup(buf);
        }
    }

    return NULL;
}

char* util_fd2name(pid_t pid, int fd) {
    int rc;
    char buf[PATH_MAX];
    char procfile[PATH_MAX];

    rc = snprintf(procfile, sizeof(procfile), "/proc/%d/fd/%d", pid, fd);
    if(rc<0 || (size_t)rc>=sizeof(procfile))
        return NULL;

    ssize_t size = readlink(procfile, buf, sizeof(buf));
    if(size<=0) return NULL;
    if(size==sizeof(buf)) buf[size-1] = 0;

    return strdup(buf);
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

int util_strcmpnull(const char * str1, const char * str2) {
    if(str1==NULL && str2!=NULL)
        return -1;
    if(str2==NULL && str1!=NULL)
        return -1;
    return strcmp(str1, str2);
}
