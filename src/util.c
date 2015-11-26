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
#include <common.h>
#include <util.h>
#include <blkid.h>

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
            if(!util_exists(tmp, true))
                rc = mkdir(tmp, S_IRWXU);
            if(rc) return rc;

            *p = '/';
        }
    }


    if(!util_exists(tmp, true))
        return mkdir(tmp, S_IRWXU);

    return 0;
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

int util_losetup(char *_device, char *_file, bool ro)
{
	char *par[64];
	int i = 0;
    int rc;

    // duplicate arguments
    char* device = strdup(_device);
    char* file = strdup(_file);
    if(!file || !file) return -ENOMEM;

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
