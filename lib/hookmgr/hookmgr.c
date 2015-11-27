/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>

#include <lib/mounts.h>
#include <lib/efivars.h>
#include <lib/hookmgr.h>
#include <common.h>
#include <tracy.h>

#define LOG_TAG "HOOKMGR"
#include <lib/log.h>

#include "hookmgr_priv.h"

#define try_hook(syscall, callback) \
rc = tracy_set_hook(mgr->tracy, #syscall, TRACY_ABI_NATIVE, callback); \
if (rc) { \
    EFIVARS_LOG_TRACE(rc, "Can't hook " #syscall " with " #callback); \
	goto error; \
}

tracy_child_addr_t hookmgr_child_alloc(struct tracy_child * child, size_t size)
{
	long rc;
	tracy_child_addr_t addr = NULL;
    hookmgr_child_data_t *cdata = child->custom;

	// allocate memory for new devname
	rc = tracy_mmap(child, &addr, NULL, size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rc < 0 || !addr) {
        EFIVARS_LOG_TRACE(rc, "Can't allocate child memory\n");
		return NULL;
	}

    ll_add(cdata->allocs, (int)addr, (void*)size);

	return addr;
}

int hookmgr_child_free(struct tracy_child * child, tracy_child_addr_t addr)
{
    int rc;
	long ret;
    hookmgr_child_data_t *cdata = child->custom;

    struct tracy_ll_item* item = ll_find(cdata->allocs, (int)addr);
    if(!item) {
        return EFIVARS_LOG_TRACE(-ENOENT, "Can't find child addr in alloc list\n");
    }

    rc = tracy_munmap(child, &ret, addr, (size_t)item->data);
    if(rc<0) {
        return EFIVARS_LOG_TRACE(rc, "tracy_munmap returned an error\n");
    }

    if((int)ret<0) {
        return EFIVARS_LOG_TRACE((int)ret, "munmap syscall returned an error\n");
    }

    ll_del(cdata->allocs, (int)addr);

    return 0;
}

char* strfromchild(struct tracy_child *child, tracy_child_addr_t addr)
{
	static const int len = PATH_MAX;
	char buf[PATH_MAX];
    int rc;

    if(!addr)
        return NULL;

	// read string
	memset(buf, 0, len);
    rc = tracy_read_mem(child, buf, addr, len);
	if (rc < 0) {
        EFIVARS_LOG_TRACE(rc, "tracy_read_mem returned an error\n");
		return NULL;
	}

	return strdup(buf);
}

tracy_child_addr_t strtochild(struct tracy_child * child, const char *path)
{
	long rc;
	int len;
	tracy_child_addr_t path_new = NULL;
    hookmgr_child_data_t *cdata = child->custom;

    if(!path)
        return NULL;

    len = strlen(path) + 1;
	if (len > PATH_MAX + 1) {
		EFIVARS_LOG_TRACE(-EINVAL, "path exceeds maximum length\n");
		goto err;
	}

	// allocate memory for new devname
	rc = tracy_mmap(child, &path_new, NULL, len,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rc < 0 || !path_new) {
        EFIVARS_LOG_TRACE(rc, "Can't allocate child memory\n");
		goto err;
	}
	// copy new devname
	rc = tracy_write_mem(child, path_new, (char*)path, (size_t)len);
	if (rc < 0) {
        EFIVARS_LOG_TRACE(rc, "Can't copy memory to child\n");
		goto err_munmap;
	}

    ll_add(cdata->allocs, (int)path_new, (void*)len);

	return path_new;

err_munmap:
	tracy_munmap(child, &rc, path_new, len);
err:
	return NULL;
}

int lindev_from_path(const char* filename, unsigned* major, unsigned* minor, int resolve_symlinks) {
    int rc;
    struct stat sb;

    if(resolve_symlinks)
        rc = stat(filename, &sb);
    else
        rc = lstat(filename, &sb);
    if(rc)
        return rc;

    *major = major(sb.st_rdev);
    *minor = minor(sb.st_rdev);

    return 0;
}

int lindev_from_mountpoint(const char* mountpoint, unsigned* major, unsigned* minor) {
    int rc;
    const mounted_volume_t* volume;

    rc = scan_mounted_volumes();
    if(rc) {
        EFIVARS_LOG_TRACE(errno, "Can't scan mounted volumes\n");
        return rc;
    }

    volume =  find_mounted_volume_by_mount_point(mountpoint);
    if(!volume)
        return -ENOENT;

    *major = volume->major;
    *minor = volume->minor;

    return 0;
}

static void hookmgr_child_create(struct tracy_child *child)
{
	if (child->custom) {
		EFIVARS_LOG_TRACE(errno, "child is initialized already\n");
        tracy_quit(child->tracy, errno);
        return;
    }

	// allocate
	child->custom = malloc(sizeof(hookmgr_child_data_t));
	if (!child->custom) {
		EFIVARS_LOG_TRACE(errno, "can't allocate custom child mem\n");
        tracy_quit(child->tracy, errno);
        return;
	}

	// initialize
	hookmgr_child_data_t *cdata = child->custom;
	memset(cdata, 0, sizeof(*cdata));

    cdata->files = ll_init();
    if(!cdata->files) {
		EFIVARS_LOG_TRACE(errno, "can't allocate list for files\n");
        tracy_quit(child->tracy, errno);
        return;
    }

    cdata->allocs = ll_init();
    if(!cdata->files) {
		EFIVARS_LOG_TRACE(errno, "can't allocate list for allocations\n");
        tracy_quit(child->tracy, errno);
        return;
    }
}

static void hookmgr_child_destroy(struct tracy_child *child)
{
	if (!child->custom) {
		EFIVARS_LOG_TRACE(errno, "child is not initialized\n");
        tracy_quit(child->tracy, errno);
        return;
    }

	hookmgr_child_data_t *cdata = child->custom;

    // free all filenames
    struct tracy_ll_item *t;
    tracy_ll_each(cdata->files, t) {
        free(t->data);
    }

    // free lists
    free(cdata->allocs);
    free(cdata->files);

	// free child data
	free(cdata);
	child->custom = NULL;
}

static int hookmgr_hook_unimplemented(struct tracy_event* e) {
    EFIVARS_LOG_FATAL(-1, "syscall %s(%d) is unimplemented!\n", get_syscall_name_abi(e->syscall_num, e->abi), e->syscall_num);
    return TRACY_HOOK_ABORT;
}

hookmgr_t* hookmgr_init(struct tracy *tracy) {
    int rc;
    hookmgr_t* mgr = calloc(sizeof(hookmgr_t), 1);
    if(!mgr) {
        EFIVARS_LOG_TRACE(errno, "Can't allocate hookmgr\n");
        return NULL;
    }

    list_initialize(&mgr->devices);

    mgr->tracy = tracy;
    mgr->tracy->pdata = (void*) mgr;

    tracy->se.child_create = hookmgr_child_create;
    tracy->se.child_destroy = hookmgr_child_destroy;

    // mount
    try_hook(mount, hookmgr_hook_mount);
    try_hook(umount2, hookmgr_hook_umount);

    // IO
    try_hook(open, hookmgr_hook_open);
    try_hook(openat, hookmgr_hook_openat);
    try_hook(close, hookmgr_hook_close);
    try_hook(name_to_handle_at, hookmgr_hook_unimplemented);
    try_hook(truncate, hookmgr_hook_generic_truncate);
    try_hook(truncate64, hookmgr_hook_generic_truncate);
    try_hook(acct, hookmgr_hook_unimplemented);

    // our path resolution would break with chroots
    try_hook(pivot_root, hookmgr_hook_unimplemented);
    try_hook(chroot, hookmgr_hook_unimplemented);

    return mgr;

error:
    if(mgr)
        free(mgr);
    return NULL;
}

int hookmgr_redirect_device(hookmgr_t* mgr, hookmgr_device_t* dev) {
    dev->mgr = mgr;

    list_add_head(&mgr->devices, &dev->node);

    return 0;
}
