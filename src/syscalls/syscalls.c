#define _GNU_SOURCE
#include <fcntl.h>

#define LOG_TAG "SYSCALLS"
#include <lib/log.h>

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <syshook.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <lib/mounts.h>
#include <common.h>
#include <util.h>

#include "syscalls_private.h"

static long do_generic_dup(syshook_process_t* process, unsigned int oldfd, int flags) {
    long ret = syshook_invoke_hookee(process);
    if(ret>=0) {
        // add new fdinfo
        fdinfo_t* fdinfo = fdinfo_get(process, oldfd);
        if(fdinfo) {
            fdinfo_add(process, (int)ret, fdinfo->path, fdinfo->flags|flags, fdinfo->major, fdinfo->minor);
        }
    }
    return ret;
}

SYSCALL_DEFINE3(dup3, unsigned int, oldfd, UNUSED unsigned int, newfd, int, flags)
{
    return do_generic_dup(process, oldfd, flags);
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, UNUSED unsigned int, newfd)
{
    return do_generic_dup(process, oldfd, 0);
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
    return do_generic_dup(process, fildes, 0);
}

SYSCALL_DEFINE3(fcntl64, unsigned int, fd, unsigned int, cmd, UNUSED unsigned long, arg)
{
    if(cmd==F_DUPFD) {
        return do_generic_dup(process, fd, 0);
    }
    if(cmd==F_DUPFD_CLOEXEC) {
        return do_generic_dup(process, fd, O_CLOEXEC);
    }

    return syshook_invoke_hookee(process);
}

SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{	
    return SYSC_fcntl64(process, fd, cmd, arg);
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, UNUSED mode_t, mode)
{
    int rc;
    char kfilename[PATH_MAX];
    char abspath[PATH_MAX*2 + 1];
    long scno = syshook_syscall_get(process);
    char __user * uabspath = NULL;
    size_t uabspath_len = 0;
    part_replacement_t *replacement = NULL;

    // ignore calls we're not interested in
    if((flags&O_TMPFILE) || !filename)
        return syshook_invoke_hookee(process);

    // copy filename to our space
    kfilename[0] = 0;
    syshook_strncpy_user(process, kfilename, filename, sizeof(kfilename));

    // get absolute path
    rc = syshookutils_get_absolute_path(process, dfd, kfilename, abspath, sizeof(abspath));
    if(rc) {
        MBABORT("can't get absolute path\n");
    }

    // get lindev
    unsigned major = 0, minor = 0;
    rc = lindev_from_path(abspath, &major, &minor, 1);
    if(rc) {
        return syshook_invoke_hookee(process);
    }

    // get replacement
    replacement = syshook_get_replacement(major, minor);
    if(!replacement) {
        return syshook_invoke_hookee(process);
    }

    // copy loopdevice to child
    uabspath_len = strlen(replacement->loopdevice)+1;
    uabspath = syshookutils_copy_to_child(process, replacement->loopdevice, uabspath_len);
    if(!uabspath) {
        MBABORT("can't copy path to child\n");
    }

    // use loop device
    syshook_argument_set(process, scno==SYS_openat?1:0, (long)uabspath);

    long ret = syshook_invoke_hookee(process);
    if(ret>=0) {
        fdinfo_add(process, ret, abspath, flags, major, minor);
    }

    // free unused child memory
    if(uabspath) {
        syshook_free_user(process, uabspath, uabspath_len);
    }

    return ret;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, mode_t, mode)
{
    return SYSC_openat(process, AT_FDCWD, filename, flags, mode);
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
    long ret = syshook_invoke_hookee(process);
    if(ret==0) {
        fdinfo_t* fdinfo = fdinfo_get(process, fd);
        if(fdinfo) {
            fdinfo_free(fdinfo, 1);
        }
    }

    return ret;
}


SYSCALL_DEFINE5(mount, UNUSED char __user *, dev_name, UNUSED char __user *, dir_name,
		UNUSED char __user *, type, UNUSED unsigned long, flags, UNUSED void __user *, data)
{
    char __user * udevname = NULL;
    size_t udevname_len = 0;
    char kdirname[PATH_MAX];
    char kdevname[PATH_MAX];
    char buf[PATH_MAX];
    int rc;
    long ret;
    part_replacement_t *replacement = NULL;

    if(!syshook_multiboot_data->is_multiboot)
        goto continue_syscall;

    // copy dev_name to our space
    kdevname[0] = 0;
    syshook_strncpy_user(process, kdevname, dev_name, sizeof(kdevname));

    // get lindev
    unsigned major = 0, minor = 0;
    rc = lindev_from_path(kdevname, &major, &minor, 1);
    if(rc) {
        goto continue_syscall;
    }

    // get replacement
    replacement = syshook_get_replacement(major, minor);
    if(!replacement) {
        goto continue_syscall;
    }

    // bind
    if(replacement->u.multiboot.part->type==MBPART_TYPE_BIND) {
        // copy dir_name to our space
        kdirname[0] = 0;
        syshook_strncpy_user(process, kdirname, dir_name, sizeof(kdirname));

        // mount directly
        ret = mount(replacement->u.multiboot.partpath, kdirname, NULL, MS_BIND, NULL);
        if(ret) return ret;

        // mount datamedia
        if(!strcmp(replacement->u.multiboot.part->name, "data")) {
            LOGV("bind mount datamedia for: %s %s\n", kdevname, kdirname);

            // build target dir path
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s/media", kdirname);

            // create source dir
            if(!util_exists(MBPATH_DATA"/media", false)) {
                rc = util_mkdir(MBPATH_DATA"/media");
                if(rc) {
                    MBABORT("Can't create datamedia on source: %s\n", strerror(rc));
                }
            }

            // create target dir
            if(!util_exists(buf, false)) {
                rc = util_mkdir(buf);
                if(rc) {
                    MBABORT("Can't create datamedia on target: %s\n", strerror(rc));
                }
            }

            // bind mount
            rc = mount(MBPATH_DATA"/media", buf, NULL, MS_BIND, NULL);
            if(rc) {
                MBABORT("Can't bind mount datamedia: %s\n", strerror(errno));
            }
        }

        return 0;
    }

    // loop
    else {
        // use loop device
        udevname_len = strlen(replacement->loopdevice)+1;
        udevname = syshookutils_copy_to_child(process, replacement->loopdevice, udevname_len);
        if(!udevname) {
            MBABORT("can't copy path to child\n");
        }

        syshook_argument_set(process, 0, (long)udevname);
    }

continue_syscall:
    ret = syshook_invoke_hookee(process);

    if(udevname) {
        syshook_free_user(process, udevname, udevname_len);
    }

    return ret;
}

SYSCALL_DEFINE2(umount2, char __user *, name, UNUSED int, flags)
{
    char kname[PATH_MAX];
    char buf[PATH_MAX];
    int rc;
    part_replacement_t *replacement = NULL;

    if(!syshook_multiboot_data->is_multiboot)
        goto continue_syscall;

    // copy name to our space
    kname[0] = 0;
    syshook_strncpy_user(process, kname, name, sizeof(kname));

    // get lindev
    unsigned major = 0, minor = 0;
    rc = lindev_from_mountpoint(kname, &major, &minor);
    if(rc) {
        goto continue_syscall;
    }

    // get replacement
    replacement = syshook_get_replacement(major, minor);
    if(!replacement) {
        goto continue_syscall;
    }

    // unmount datamedia
    if(replacement->u.multiboot.part->type==MBPART_TYPE_BIND && !strcmp(replacement->u.multiboot.part->name, "data")) {
        // scan mounted volumes
        rc = scan_mounted_volumes();
        if(rc) {
            MBABORT("Can't scan mounted volumes: %s\n", strerror(errno));
        }

        if(!strcmp(kname, "/data")) {
            // build target dir path
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s/media", kname);

            // check if datamedia is mounted at this path
            const mounted_volume_t* volume = find_mounted_volume_by_mount_point(buf);
            if(volume) {
                LOGV("unmount datamedia for %s\n", kname);
                SAFE_UMOUNT(buf);
                if(rc) {
                    MBABORT("Can't unmount datamedia for %s\n", kname);
                }
            }
        }
    }

continue_syscall:
    return syshook_invoke_hookee(process);
}
