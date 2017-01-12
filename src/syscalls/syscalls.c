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

static long do_generic_dup(syshook_process_t *process, unsigned int oldfd, int flags)
{
    long ret = syshook_invoke_hookee(process);
    if (ret>=0) {
        // add new fdinfo
        fdinfo_t *fdinfo = fdinfo_get(process, oldfd);
        if (fdinfo) {
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
    if (cmd==F_DUPFD) {
        return do_generic_dup(process, fd, 0);
    }
    if (cmd==F_DUPFD_CLOEXEC) {
        return do_generic_dup(process, fd, O_CLOEXEC);
    }

    return syshook_invoke_hookee(process);
}

SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
    return SYSC_fcntl64(process, fd, cmd, arg);
}

static long do_openat(syshook_process_t *process, int is_openat, int dfd, const char __user *filename, int flags, UNUSED mode_t mode)
{
    int rc;
    long ret;
    char kfilename[PATH_MAX];
    char abspath[PATH_MAX*2 + 1];
    char __user *uabspath = NULL;
    size_t uabspath_len = 0;
    part_replacement_t *replacement = NULL;

    // ignore calls we're not interested in
    if ((flags&O_TMPFILE) || !filename)
        return syshook_invoke_hookee(process);

    // copy filename to our space
    kfilename[0] = 0;
    syshook_strncpy_user(process, kfilename, filename, sizeof(kfilename));

    // get absolute path
    rc = syshookutils_get_absolute_path(process, dfd, kfilename, abspath, sizeof(abspath));
    if (rc) {
        MBABORT("can't get absolute path\n");
    }

    // get lindev
    unsigned major = 0, minor = 0;
    rc = lindev_from_path(abspath, &major, &minor, 1);
    if (rc) {
        goto run_syscall;
    }

    // get replacement
    replacement = util_get_replacement(major, minor);
    if (!replacement) {
        goto run_syscall;
    }

    if (replacement->iomode==PART_REPLACEMENT_IOMODE_ALLOW) {
        return syshook_invoke_hookee(process);
    } else if (replacement->iomode==PART_REPLACEMENT_IOMODE_DENY) {
        return -1;
    } else if (replacement->iomode!=PART_REPLACEMENT_IOMODE_REDIRECT) {
        MBABORT("invalid iomode %d\n", replacement->iomode);
    }

    // copy loopdevice to child
    uabspath_len = strlen(replacement->loopdevice)+1;
    uabspath = syshookutils_copy_to_child(process, replacement->loopdevice, uabspath_len);
    if (!uabspath) {
        MBABORT("can't copy path to child\n");
    }

    // use loop device
    syshook_argument_set(process, is_openat?1:0, (long)uabspath);

run_syscall:
    ret = syshook_invoke_hookee(process);
    if (ret>=0) {
        fdinfo_add(process, ret, abspath, flags, major, minor);
    }

    if (replacement) {
        LOGV("%s: redirect %s -> %s = %d\n", __func__, kfilename, replacement->loopdevice, (int)ret);
    }

    // free unused child memory
    if (uabspath) {
        syshook_free_user(process, uabspath, uabspath_len);
    }

    return ret;
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, UNUSED mode_t, mode)
{
    return do_openat(process, 1, dfd, filename, flags, mode);
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, mode_t, mode)
{
    return do_openat(process, 0, AT_FDCWD, filename, flags, mode);
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
    long ret = syshook_invoke_hookee(process);
    if (ret==0) {
        fdinfo_t *fdinfo = fdinfo_get(process, fd);
        if (fdinfo) {
            fdinfo_free(fdinfo, 1);
        }
    }

    return ret;
}


SYSCALL_DEFINE5(mount, UNUSED char __user *, dev_name, UNUSED char __user *, dir_name,
                UNUSED char __user *, type, UNUSED unsigned long, flags, UNUSED void __user *, data)
{
    char __user *udevname = NULL;
    size_t udevname_len = 0;
    char kdirname[PATH_MAX];
    char kdevname[PATH_MAX];
    int rc;
    long ret;
    part_replacement_t *replacement = NULL;

    if (!syshook_multiboot_data->is_multiboot)
        goto continue_syscall;

    // ignore NULL devs and remounts
    if (!dev_name || flags&MS_REMOUNT)
        goto continue_syscall;

    // copy dev_name to our space
    kdevname[0] = 0;
    syshook_strncpy_user(process, kdevname, dev_name, sizeof(kdevname));

    // get lindev
    unsigned major = 0, minor = 0;
    rc = lindev_from_path(kdevname, &major, &minor, 1);
    if (rc) {
        goto continue_syscall;
    }

    // get replacement
    replacement = util_get_replacement(major, minor);
    if (!replacement) {
        goto continue_syscall;
    }

    // bind
    if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_BIND) {
        // copy dir_name to our space
        kdirname[0] = 0;
        syshook_strncpy_user(process, kdirname, dir_name, sizeof(kdirname));

        // mount directly
        ret = mount(replacement->bindsource, kdirname, NULL, MS_BIND, NULL);
        LOGV("%s: bind mount %s at %s = %d\n", __func__, replacement->bindsource, kdirname, (int)ret);

        // remount to apply requested mount-flags
        if (ret==0) {
            ret = mount(replacement->bindsource, kdirname, NULL, MS_BIND|MS_REMOUNT|flags, data);
            LOGV("%s: bind re-mount %s at %s = %d\n", __func__, replacement->bindsource, kdirname, (int)ret);
        }
        return ret;
    }

    // loop
    else if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_LOOP) {
        // use loop device
        udevname_len = strlen(replacement->loopdevice)+1;
        udevname = syshookutils_copy_to_child(process, replacement->loopdevice, udevname_len);
        if (!udevname) {
            MBABORT("can't copy path to child\n");
        }

        syshook_argument_set(process, 0, (long)udevname);
    }

    // allow
    else if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_ALLOW) {
        goto continue_syscall;
    }

    // deny
    else if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_DENY) {
        return -1;
    }

    else {
        MBABORT("invalid mountmode %d\n", replacement->mountmode);
    }

continue_syscall:
    ret = syshook_invoke_hookee(process);

    if (replacement) {
        //LOGV("%s: redirect %s -> %s = %d\n", __func__, kdevname, replacement->loopdevice, (int)ret);
    }

    if (udevname) {
        syshook_free_user(process, udevname, udevname_len);
    }

    return ret;
}

SYSCALL_DEFINE3(execve, const char __user *, name,
                const char __user *const __user *, argv,
                const char __user *const __user *, envp)
{
    char kname[PATH_MAX];

    kname[0] = 0;
    if (name) {
        syshook_strncpy_user(process, kname, name, sizeof(kname));
        LOGV("%s(%s, %p, %p)\n", __func__, kname, argv, envp);

        // don't trace ueventd to speed up the boot process
        if (!strcmp(kname, "/sbin/ueventd")) {
            syshook_stop_tracing(process);
        }
    }

    return syshook_invoke_hookee(process);
}
