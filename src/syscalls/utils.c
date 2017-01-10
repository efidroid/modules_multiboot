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
#include <sys/stat.h>
#include <sys/mount.h>
#include <lib/mounts.h>
#include <common.h>
#include <util.h>

#include "syscalls_private.h"

char *syshookutils_child_getcwd(syshook_process_t *process, char *buf, size_t size)
{
    char *ret = NULL;
    // allocate memory
    void __user *ubuf = (void *)syshook_alloc_user(process, size);
    if (!ubuf) return NULL;

    // call getcwd
    if (syshook_invoke_syscall(process, syshook_scno_to_native(process, SYSHOOK_SCNO_getcwd), ubuf, size)) {
        syshook_strncpy_user(process, buf, ubuf, size);
        ret = buf;
    }

    // free memory
    syshook_free_user(process, ubuf, size);

    return ret;
}

void __user *syshookutils_copy_to_child(syshook_process_t *process, void *buf, size_t size)
{
    // allocate memory
    void __user *ubuf = (void *)syshook_alloc_user(process, size);
    if (!ubuf) return NULL;

    // call getcwd
    if (syshook_copy_to_user(process, ubuf, buf, size)) {
        // free memory
        syshook_free_user(process, ubuf, size);

        return NULL;
    }

    return ubuf;
}

int syshookutils_get_absolute_path(syshook_process_t *process, int dfd, const char *filename, char *buf, size_t bufsz)
{
    buf[0] = 0;
    if (filename[0]!='/') {
        const char *filenameptr = filename;

        // make sure pathname starts with the folder and not with . or /
        if (!strncmp(filenameptr, "./", 2))
            filenameptr+=2;

        if (dfd==AT_FDCWD) {
            char cwd[PATH_MAX];
            if (syshookutils_child_getcwd(process, cwd, sizeof(cwd))) {
                // make sure there's no trailing / in cwd
                int cwdlen = strlen(cwd);
                int trailingslash = 0;
                if (cwdlen>0 && cwd[cwdlen-1]=='/')
                    trailingslash = 1;

                SAFE_SNPRINTF_RET(LOGE, -1, buf, bufsz, "%s%s%s", cwd, (trailingslash?"":"/"), filenameptr);
            }
        }

        else {
            // get filename from dfd
            fdinfo_t *fdinfo = fdinfo_get(process, dfd);
            if (fdinfo && fdinfo->path) {
                // make sure there's no trailing / in cwd
                int pathlen = strlen(fdinfo->path);
                int trailingslash = 0;
                if (pathlen>0 && (fdinfo->path)[pathlen-1]=='/')
                    trailingslash = 1;

                SAFE_SNPRINTF_RET(LOGE, -1, buf, bufsz, "%s%s%s", fdinfo->path, (trailingslash?"":"/"), filenameptr);
            }
        }
    } else {
        strncpy(buf, filename, bufsz);
    }

    return 0;
}

fdinfo_t *fdinfo_dup(fdinfo_t *olditem)
{
    fdinfo_t *newitem = safe_calloc(1, sizeof(fdinfo_t));
    if (!newitem) {
        return NULL;
    }

    pthread_mutex_init(&newitem->lock, NULL);
    newitem->fd = olditem->fd;
    newitem->path = olditem->path?safe_strdup(olditem->path):NULL;
    newitem->flags = olditem->flags;
    newitem->major = olditem->major;
    newitem->minor = olditem->minor;

    return newitem;
}

void fdinfo_add(syshook_process_t *process, int fd, const char *path, int flags, unsigned major, unsigned minor)
{
    syshook_pdata_t *pdata = process->pdata;
    if (!pdata) return;

    // remove existing fd with the same number
    fdinfo_t *olditem = fdinfo_get(process, fd);
    if (olditem) {
        fdinfo_free(olditem, 1);
    }

    fdinfo_t *newitem = safe_calloc(1, sizeof(fdinfo_t));
    if (!newitem) {
        return;
    }

    pthread_mutex_init(&newitem->lock, NULL);
    newitem->fd = fd;
    newitem->path = path?safe_strdup(path):NULL;
    newitem->flags = flags;
    newitem->major = major;
    newitem->minor = minor;

    pthread_mutex_lock(&pdata->fdtable->lock);
    list_add_tail(&pdata->fdtable->files, &newitem->node);
    pthread_mutex_unlock(&pdata->fdtable->lock);
}

fdinfo_t *fdinfo_get(syshook_process_t *process, int fd)
{
    fdinfo_t *ret = NULL;
    syshook_pdata_t *pdata = process->pdata;
    if (!pdata) return NULL;

    pthread_mutex_lock(&pdata->fdtable->lock);
    fdinfo_t *entry;
    list_for_every_entry(&pdata->fdtable->files, entry, fdinfo_t, node) {
        if (entry->fd==fd) {
            ret = entry;
            break;
        }
    }
    pthread_mutex_unlock(&pdata->fdtable->lock);

    return ret;
}

void fdinfo_free(fdinfo_t *fdinfo, int remove_from_list)
{
    syshook_handle_fd_close(fdinfo);

    if (remove_from_list) {
        list_delete(&fdinfo->node);
    }

    free(fdinfo->path);
    pthread_mutex_destroy(&fdinfo->lock);
    free(fdinfo);
}

fdtable_t *fdtable_create(void)
{
    // allocate new fdtable
    fdtable_t *fdtable = safe_calloc(1, sizeof(fdtable_t));
    if (!fdtable) return NULL;
    list_initialize(&fdtable->files);
    pthread_mutex_init(&fdtable->lock, NULL);
    fdtable->refs = 1;

    return fdtable;
}

fdtable_t *fdtable_dup(fdtable_t *src)
{
    fdtable_t *newfdtable = fdtable_create();
    if (!newfdtable) return NULL;

    pthread_mutex_lock(&src->lock);
    fdinfo_t *entry;
    list_for_every_entry(&src->files, entry, fdinfo_t, node) {
        fdinfo_t *newfdinfo = fdinfo_dup(entry);
        if (!newfdinfo) {
            pthread_mutex_unlock(&src->lock);
            return NULL;
        }
        list_add_tail(&newfdtable->files, &newfdinfo->node);
    }
    pthread_mutex_unlock(&src->lock);

    return newfdtable;
}

void fdtable_free(fdtable_t *fdtable)
{
    // free fdinfo's
    if (!list_is_empty(&fdtable->files)) {
        fdinfo_t *fdinfo = list_remove_tail_type(&fdtable->files, fdinfo_t, node);
        fdinfo_free(fdinfo, 0);
    }

    // free table
    pthread_mutex_unlock(&fdtable->lock);
    pthread_mutex_destroy(&fdtable->lock);
    free(fdtable);
}

int lindev_from_path(const char *filename, unsigned *major, unsigned *minor, int resolve_symlinks)
{
    int rc;
    struct stat sb;

    if (resolve_symlinks)
        rc = stat(filename, &sb);
    else
        rc = lstat(filename, &sb);
    if (rc)
        return rc;

    *major = major(sb.st_rdev);
    *minor = minor(sb.st_rdev);

    return 0;
}

int lindev_from_mountpoint(const char *mountpoint, unsigned *major, unsigned *minor)
{
    int rc;
    const mounted_volume_t *volume;
    mounts_state_t mounts_state = LIST_INITIAL_VALUE(mounts_state);

    rc = scan_mounted_volumes(&mounts_state);
    if (rc) {
        MBABORT("Can't scan mounted volumes\n");
    }

    volume =  find_mounted_volume_by_mount_point(&mounts_state, mountpoint);
    if (!volume) {
        rc = -ENOENT;
    } else {
        *major = volume->major;
        *minor = volume->minor;

        // free mount state
        free_mounts_state(&mounts_state);

        rc = 0;
    }

    return 0;
}

static int syshookutil_handle_close_synctarget(part_replacement_t *replacement)
{
    int rc;
    const char *mountpoint = NULL;
    mounts_state_t mounts_state = LIST_INITIAL_VALUE(mounts_state);

    if (replacement) {
        LOGI("%s has changed. syncing ESP replacement\n", replacement->loopdevice);
    } else {
        LOGI("ESP dev got closed. syncing ALL ESP replacements\n");
    }

    // scan mounted volumes
    rc = scan_mounted_volumes(&mounts_state);
    if (rc) {
        MBABORT("Can't scan mounted volumes: %s\n", strerror(errno));
        return -1;
    }

    // find esp
    const mounted_volume_t *volume = find_mounted_volume_by_majmin(&mounts_state, syshook_multiboot_data->espdev->major, syshook_multiboot_data->espdev->minor, 0);
    if (volume) {
        mountpoint = volume->mount_point;
    } else {
        // mount ESP
        util_mount_esp(1);

        mountpoint = MBPATH_ESP;
    }

    if (replacement) {
        // get ESP filename
        char *espfilename = util_get_esp_path_for_partition(mountpoint, replacement->loop_sync_target);
        if (!espfilename) {
            MBABORT("Can't get filename\n");
        }

        // copy loop to esp
        rc = util_dd(replacement->loopdevice, espfilename, 0);
        if (rc) {
            MBABORT("Can't dd %s to %s\n", replacement->loopdevice, espfilename);
        }
    } else {
        // get espdir
        char *espdir = util_get_espdir(mountpoint);
        if (!espdir) {
            MBABORT("Can't get ESP directory: %s\n", strerror(errno));
        }

        // (re-)create esp dir
        if (!util_exists(espdir, false)) {
            rc = util_mkdir(espdir);
            if (rc) {
                MBABORT("Can't create directory at %s\n", espdir);
            }
        }

        // copy all loop devices to ESP
        list_for_every_entry(&syshook_multiboot_data->replacements, replacement, part_replacement_t, node) {
            pthread_mutex_lock(&replacement->lock);

            // get ESP filename
            char *espfilename = util_get_esp_path_for_partition(mountpoint, replacement->loop_sync_target);
            if (!espfilename) {
                MBABORT("Can't get filename\n");
            }

            // copy loop to esp
            if (!util_exists(replacement->loop_sync_target, false)) {
                rc = util_dd(replacement->loopdevice, espfilename, 0);
                if (rc) {
                    MBABORT("Can't dd %s to %s\n", replacement->loopdevice, espfilename);
                }
            }

            pthread_mutex_unlock(&replacement->lock);
        }

        // cleanup
        free(espdir);
    }

    if (!volume) {
        // unmount ESP
        SAFE_UMOUNT(MBPATH_ESP);
    } else {
        // free mount state
        free_mounts_state(&mounts_state);
    }

    return 0;
}

static int syshookutil_handle_close_formatdetect(part_replacement_t *replacement)
{
    int rc;
    char buf[PATH_MAX];

    if (replacement->loopdevice) {
        // mount loop
        // TODO: use random path
        SAFE_MOUNT(replacement->loopdevice, MBPATH_STUB, NULL, 0, NULL);

        // check if id file exists
        if (!util_exists(MBPATH_STUB_IDFILE, false)) {
            LOGI("%s got formatted!\n", replacement->loopdevice);

            // create id file
            int fd = open(MBPATH_STUB_IDFILE, O_RDWR|O_CREAT);
            if (fd<0) {
                MBABORT("Can't create ID file\n");
            }
            close(fd);

            // build format command
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), MBPATH_BUSYBOX" rm -Rf %s/*", replacement->bindsource);

            // format bind source
            rc = util_shell(buf);
            if (rc) {
                MBABORT("Can't format bind source at %s\n", replacement->bindsource);
            }
        }

        // unmount loop device
        SAFE_UMOUNT(MBPATH_STUB);
    }

    return 0;
}

int syshook_handle_fd_close(fdinfo_t *fdinfo)
{
    int rc;
    part_replacement_t *replacement;

    // ignore if this was readonly
    if (!(fdinfo->flags & (O_WRONLY|O_RDWR))) {
        return 0;
    }

    if (!syshook_multiboot_data->is_multiboot) {
        // check if this was the ESP
        if (fdinfo->major==syshook_multiboot_data->espdev->major && fdinfo->minor==syshook_multiboot_data->espdev->minor) {
            pthread_mutex_lock(&syshook_multiboot_data->lock);

            // sync all replacements because the real ESP just got formatted
            rc = syshookutil_handle_close_synctarget(NULL);

            pthread_mutex_unlock(&syshook_multiboot_data->lock);

            return rc;
        }
    }

    // get replacement
    replacement = util_get_replacement(fdinfo->major, fdinfo->minor);
    if (!replacement) {
        return 0;
    }

    // validate mode for native recovery
    if (!syshook_multiboot_data->is_multiboot) {
        if (!(replacement->iomode==PART_REPLACEMENT_IOMODE_REDIRECT && replacement->loop_sync_target)) {
            MBABORT("in native recovery, all replacements should be synced\n");
        }
    }

    // lock replacement
    pthread_mutex_lock(&replacement->lock);

    if (replacement->mountmode==PART_REPLACEMENT_MOUNTMODE_BIND) {
        rc = syshookutil_handle_close_formatdetect(replacement);
    } else if (replacement->loop_sync_target) {
        // we need to hold the global lock to prevent running at the same time as a full ESP restore
        pthread_mutex_lock(&syshook_multiboot_data->lock);
        rc = syshookutil_handle_close_synctarget(replacement);
        pthread_mutex_unlock(&syshook_multiboot_data->lock);
    } else {
        rc = 0;
    }

    // unlock replacement
    pthread_mutex_unlock(&replacement->lock);

    return rc;
}
