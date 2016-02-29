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

#ifndef HOOKMGR_PRIV_H
#define HOOKMGR_PRIV_H

#include <lib/efivars.h>

#define mgr_from_tracy(tracy) ((hookmgr_t*)((tracy)->pdata))
#define mgr_from_child(child) (mgr_from_tracy((child)->tracy))
#define mgr_from_event(event) (mgr_from_child((event)->child))

#define set_arg(arg, val) \
event->tracyevent->args.arg = (long)val; \
if (tracy_modify_syscall_args(event->tracyevent->child, event->tracyevent->args.syscall, &event->tracyevent->args)) { \
    EFIVARS_LOG_FATAL(-1, "Can't set syscall argument\n"); \
    return -1; \
}

#define tracy_ll_each(list, t) \
    for((t)=(list)->head; (t); (t) = (t)->next)

#define hookmgr_str_setter(name, type, reg, field) \
static int name (type* event, const char* str) { \
    int rc; \
\
    tracy_child_addr_t addr = strtochild(event->tracyevent->child, str);\
    if(!addr) { \
        rc = -ENOMEM; \
        EFIVARS_LOG_FATAL(rc, "Can't copy target string to child\n"); \
        return rc; \
    } \
\
	set_arg(reg, addr); \
\
    if(event->alloc_##field) { \
        rc = hookmgr_child_free(event->tracyevent->child, event->alloc_##field); \
        if(rc) { \
            EFIVARS_LOG_FATAL(rc, "Can't free child data\n"); \
            return rc; \
        } \
        event->alloc_##field = 0; \
    } \
    event->alloc_##field = addr; \
\
    free((void*)event->field); \
    event->field = strdup(str); \
\
    return 0; \
}

#define hookmgr_primitive_setter(name, type, reg, field, fieldtype) \
static int name(type* event, fieldtype arg) { \
	set_arg(reg, (long)arg); \
\
    event->field = arg; \
    return 0; \
}

#define hookmgr_abort_function(name, type) \
static int name(type* event, int code) { \
    event->do_abort = 1; \
    event->returncode = code; \
    return 0; \
}

typedef struct {
    dev_t dev;
    char* path;
    int flags;
} file_list_item_t;

typedef struct {
    int oldfd;
    int newfd;
    int flags;
} hookmgr_dup_event_t;

typedef struct {
    tracy_child_addr_t pipesaddr;
    int* pipefd;
    int flags;
} hookmgr_pipe_event_t;

typedef struct {
    int domain;
    int type;
    int protocol;
    tracy_child_addr_t svaddr;
    int* sv;
} hookmgr_socket_event_t;

typedef struct {
    struct tracy_ll* files;
    struct tracy_ll* allocs;
    hookmgr_mount_event_t* mountdata;
    hookmgr_close_event_t* closedata;
    hookmgr_open_event_t* opendata;
    hookmgr_open_event_t* openatdata;
    hookmgr_dup_event_t* dupdata;
    hookmgr_pipe_event_t* pipedata;
    hookmgr_socket_event_t* socketdata;
} hookmgr_child_data_t;


tracy_child_addr_t hookmgr_child_alloc(struct tracy_child * child, size_t size);
int hookmgr_child_free(struct tracy_child * child, tracy_child_addr_t addr);
char* strfromchild(struct tracy_child *child, tracy_child_addr_t addr);
tracy_child_addr_t strtochild(struct tracy_child * child, const char *path);
void* datafromchild(struct tracy_child *child, tracy_child_addr_t addr, size_t len);
int lindev_from_path(const char* filename, unsigned* major, unsigned* minor, int resolve_symlinks);
int lindev_from_mountpoint(const char* mountpoint, unsigned* major, unsigned* minor);

int hookmgr_hook_mount(struct tracy_event *e);
int hookmgr_hook_umount(struct tracy_event *e);
int hookmgr_hook_open(struct tracy_event *e);
int hookmgr_hook_openat(struct tracy_event *e);
int hookmgr_hook_close(struct tracy_event *e);

int hookmgr_hook_generic_truncate(struct tracy_event *e);
int hookmgr_hook_generic_dup(struct tracy_event *e);
int hookmgr_hook_generic_pipe(struct tracy_event *e);
int hookmgr_hook_generic_socket(struct tracy_event *e);

static inline file_list_item_t* fditem_dup(file_list_item_t* olditem) {
    file_list_item_t* newitem = malloc(sizeof(file_list_item_t));
    if(!newitem) {
        return NULL;
    }

    newitem->dev = olditem->dev;
    newitem->path = strdup(olditem->path);
    newitem->flags = olditem->flags;

    return newitem;
}

#endif // HOOKMGR_PRIV_H

