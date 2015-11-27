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
#include <sys/syscall.h>

#include <lib/hookmgr.h>
#include <tracy.h>

#include <common.h>

#define LOG_TAG "HOOKMGR_IO"
#include <lib/log.h>

#include "hookmgr_priv.h"

static int child_sys_getcwd(struct tracy_child *child, char* buf, size_t size) {
    long ret;
    int rc;
    struct tracy_sc_args a;

    // alloc child buffer
    tracy_child_addr_t childbuf = hookmgr_child_alloc(child, size);
    if(!childbuf) {
        return EFIVARS_LOG_FATAL(-ENOMEM, "Can't alloc child memory\n");
    }

    // run syscall
    a.a0 = (long)childbuf;
    a.a1 = size;
    rc = tracy_inject_syscall(child, __NR_getcwd, &a, &ret);

    // tracy error
    if(rc<0) {
        EFIVARS_LOG_FATAL(rc, "error in tracy_inject_syscall\n");
        return rc;
    }
    // getpwd error
    if((int)ret<=0) {
        rc = (int)ret;
        goto out;
    }

    // copy buffer from child
	rc =tracy_read_mem(child, buf, childbuf, size);
    if(rc<0) {
		return rc;
	}

out:
    // free child buffer
    rc = hookmgr_child_free(child, childbuf);
    if(rc) {
        return EFIVARS_LOG_FATAL(rc, "Can't alloc child memory\n");
    }

    return rc;
}

static char* child_getcwd(struct tracy_child *child, char* buf, size_t size) {
    int retval;

    retval = child_sys_getcwd(child, buf, size);
    if(retval>=0)
        return buf;

    errno = -retval;
    return NULL;
}

hookmgr_str_setter(hookmgr_open_set_pathname, hookmgr_open_event_t, a0, pathname);
hookmgr_primitive_setter(hookmgr_open_set_flags, hookmgr_open_event_t, a1, flags, int);
hookmgr_primitive_setter(hookmgr_open_set_mode, hookmgr_open_event_t, a2, mode, mode_t);
hookmgr_abort_function(hookmgr_open_abort, hookmgr_open_event_t);

int hookmgr_hook_open(struct tracy_event *e) {
    hookmgr_t* mgr = mgr_from_event(e);
    hookmgr_child_data_t *cdata = e->child->custom;
    int rc;
    int tracyrc = TRACY_HOOK_CONTINUE;
    hookmgr_open_event_t* hookevent = NULL;

    if (e->child->pre_syscall) {
        if(cdata->opendata) {
            EFIVARS_LOG_FATAL(-1, "cdata->opendata is not empty\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent = calloc(sizeof(hookmgr_open_event_t), 1);
        if(!hookevent) {
            EFIVARS_LOG_FATAL(-1, "can't allocate cdata\n");
            return TRACY_HOOK_ABORT;
        }

        cdata->opendata = hookevent;
        hookevent->tracyevent = e;

        hookevent->pathname = strfromchild(e->child, (void*)e->args.a0);
        hookevent->flags = (int)e->args.a1;
        hookevent->mode = (mode_t)e->args.a2;

        if(e->args.a0 && !hookevent->pathname) {
            EFIVARS_LOG_FATAL(-1, "Can't receive arguments\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent->set_pathname = hookmgr_open_set_pathname;
        hookevent->set_flags = hookmgr_open_set_flags;
        hookevent->set_mode = hookmgr_open_set_mode;
        hookevent->abort = hookmgr_open_abort;

        unsigned major, minor;

        // ignore devices we can't find
        rc = lindev_from_path(hookevent->pathname, &major, &minor, 1);
        if(!rc) {
            hookevent->dev = makedev(major, minor);

	        // call open hook
	        hookmgr_device_t *entry;
	        list_for_every_entry(&mgr->devices, entry, hookmgr_device_t, node) {
                if(entry->open && entry->major==major && entry->minor==minor) {
                    entry->open(entry, hookevent);

                    // check if we were requested to abort the syscall
                    if(hookevent->do_abort) {
                        e->child->return_code = hookevent->returncode;
                        e->child->change_return_code = 1;
                        tracyrc = TRACY_HOOK_DENY;

                        break;
                    }
                    
                    break;
                }
	        }
        }
    }

    else {
        hookevent = cdata->opendata;
        if(!hookevent) {
            LOGW("cdata->opendata is NULL\n");
            return tracyrc;
        }

        if(!hookevent->do_abort) {
            // store filename
            if(e->child->return_code>=0) {
                file_list_item_t* item = malloc(sizeof(file_list_item_t));
                if(!item) {
                    EFIVARS_LOG_FATAL(-1, "can't allocate list item data\n");
                    return TRACY_HOOK_ABORT;
                }

                item->dev = hookevent->dev;
                item->path = strdup(hookevent->pathname);
                ll_add(cdata->files, e->child->return_code, item);
            }
        }

        // cleanup
        free((void*)hookevent->pathname);
        free(hookevent);
        cdata->opendata = NULL;
    }

    return tracyrc;
}

int hookmgr_hook_openat(struct tracy_event *e) {
    hookmgr_t* mgr = mgr_from_event(e);
    hookmgr_child_data_t *cdata = e->child->custom;
    int rc;
    char buf[PATH_MAX];
    int tracyrc = TRACY_HOOK_CONTINUE;
    hookmgr_open_event_t* hookevent = NULL;

    if (e->child->pre_syscall) {
        if(cdata->openatdata) {
            EFIVARS_LOG_FATAL(-1, "cdata->openatdata is not empty\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent = calloc(sizeof(hookmgr_open_event_t), 1);
        if(!hookevent) {
            EFIVARS_LOG_FATAL(-1, "can't allocate cdata\n");
            return TRACY_HOOK_ABORT;
        }

        cdata->openatdata = hookevent;

        hookevent->tracyevent = e;

        hookevent->pathname = strfromchild(e->child, (void*)e->args.a1);
        hookevent->flags = (int)e->args.a2;
        hookevent->mode = (mode_t)e->args.a3;

        if(e->args.a1 && !hookevent->pathname) {
            EFIVARS_LOG_FATAL(-1, "Can't receive arguments\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent->set_pathname = hookmgr_open_set_pathname;
        hookevent->set_flags = hookmgr_open_set_flags;
        hookevent->set_mode = hookmgr_open_set_mode;
        hookevent->abort = hookmgr_open_abort;

        // get absolute pathname
        if(hookevent->pathname[0]!='/') {
            int dirfd = (int)e->args.a0;
            const char* pathnameptr = hookevent->pathname;

            // make sure pathname starts with the folder and not with . or /
            if(!strncmp(pathnameptr, "./", 2))
                pathnameptr+=2;

            // pathname is relative to cwd
            if(dirfd==AT_FDCWD) {
                char cwdbuf[PATH_MAX];
                char* cwd = child_getcwd(e->child, cwdbuf, sizeof(cwdbuf));
                if(!cwd) {
                    EFIVARS_LOG_FATAL(-1, "Can't get cwd\n");
                    return TRACY_HOOK_ABORT;
                }

                // make sure there's no trailing / in cwd
                int cwdlen = strlen(cwd);
                int trailingslash = 0;
                if(cwdlen>0 && cwd[cwdlen-1]=='/')
                    trailingslash = 1;
                
                rc = snprintf(buf, sizeof(buf), "%s%s%s", cwd, (trailingslash?"":"/"), pathnameptr);
                if(rc<0) {
                    EFIVARS_LOG_FATAL(-1, "Can't build new path\n");
                    return TRACY_HOOK_ABORT;
                }

                free((void*)hookevent->pathname);
                hookevent->pathname = strdup(buf);
            }

            else {
                struct tracy_ll_item* item = ll_find(cdata->files, dirfd);
                if(!item || !item->data) {
                    EFIVARS_LOG_FATAL(-1, "invalid FD\n");
                    return TRACY_HOOK_ABORT;
                }

                file_list_item_t* fditem = item->data;

                const char* fdpath = (const char*)fditem->path;
                // check if there's a trailing slash
                int fdpathlen = strlen(fdpath);
                int trailingslash = 0;
                if(fdpathlen>0 && fdpath[fdpathlen-1]=='/')
                    trailingslash = 1;

                rc = snprintf(buf, sizeof(buf), "%s%s%s", (const char*)item->data, (trailingslash?"":"/"), pathnameptr);
                if(rc<0) {
                    EFIVARS_LOG_FATAL(-1, "Can't build new path\n");
                    return TRACY_HOOK_ABORT;
                }

                free((void*)hookevent->pathname);
                hookevent->pathname = strdup(buf);
            }
        }

        unsigned major, minor;

        // ignore devices we can't find
        rc = lindev_from_path(hookevent->pathname, &major, &minor, 1);
        if(!rc) {
	        // call open hook
	        hookmgr_device_t *entry;
	        list_for_every_entry(&mgr->devices, entry, hookmgr_device_t, node) {
                hookevent->dev = makedev(major, minor);

                if(entry->open && entry->major==major && entry->minor==minor) {
                    // change args for open()
                    const char* name = hookevent->pathname;
                    hookevent->pathname = NULL;
                    hookevent->set_pathname(hookevent, name);
                    hookevent->set_flags(hookevent, hookevent->flags);
                    hookevent->set_mode(hookevent, hookevent->mode);

                    entry->open(entry, hookevent);

                    // check if we were requested to abort the syscall
                    if(hookevent->do_abort) {
                        e->child->return_code = hookevent->returncode;
                        e->child->change_return_code = 1;
                        tracyrc = TRACY_HOOK_DENY;

                        break;
                    }

                    // inject open() syscall
                    long ret;
                    rc = tracy_inject_syscall(e->child, __NR_open, NULL, &ret);
                    if(rc<0) {
                        EFIVARS_LOG_FATAL(rc, "Can't inject open() syscall\n");
                        return TRACY_HOOK_ABORT;
                    }
                    
                    // suppress openat() syscall and return the result of open()
                    e->child->return_code = ret;
                    e->child->change_return_code = 1;
                    tracyrc = TRACY_HOOK_DENY;
                    hookevent->do_abort = 1;

                    // add fd to our list
                    if(e->child->return_code>=0) {
                        file_list_item_t* item = malloc(sizeof(file_list_item_t));
                        if(!item) {
                            EFIVARS_LOG_FATAL(-1, "can't allocate list item data\n");
                            return TRACY_HOOK_ABORT;
                        }

                        item->dev = hookevent->dev;
                        item->path = strdup(hookevent->pathname);
                        ll_add(cdata->files, e->child->return_code, item);
                    }
                    
                    break;
                }
	        }
        }
    }

    else {
        hookevent = cdata->openatdata;
        if(!hookevent) {
            LOGW("cdata->openatdata is NULL\n");
            return tracyrc;
        }

        if(!hookevent->do_abort) {
            // add fd to our list
            if(e->args.return_code>=0) {
                file_list_item_t* item = malloc(sizeof(file_list_item_t));
                if(!item) {
                    EFIVARS_LOG_FATAL(-1, "can't allocate list item data\n");
                    return TRACY_HOOK_ABORT;
                }

                item->dev = hookevent->dev;
                item->path = strdup(hookevent->pathname);
                ll_add(cdata->files, e->args.return_code, item);
            }
        }

        // cleanup
        free((void*)hookevent->pathname);
        free(hookevent);
        cdata->openatdata = NULL;
    }

    return tracyrc;
}

hookmgr_primitive_setter(hookmgr_close_set_fd, hookmgr_close_event_t, a0, fd, int);
hookmgr_abort_function(hookmgr_close_abort, hookmgr_close_event_t);

int hookmgr_hook_close(struct tracy_event *e) {
    hookmgr_t* mgr = mgr_from_event(e);
    hookmgr_child_data_t *cdata = e->child->custom;
    int tracyrc = TRACY_HOOK_CONTINUE;
    hookmgr_close_event_t* hookevent = NULL;

    if (e->child->pre_syscall) {
        if(cdata->closedata) {
            EFIVARS_LOG_FATAL(-1, "cdata->closedata is not empty\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent = calloc(sizeof(hookmgr_close_event_t), 1);
        if(!hookevent) {
            EFIVARS_LOG_FATAL(-1, "can't allocate cdata\n");
            return TRACY_HOOK_ABORT;
        }

        cdata->closedata = hookevent;
        hookevent->tracyevent = e;

        hookevent->fd = (int)e->args.a0;

        hookevent->set_fd = hookmgr_close_set_fd;
        hookevent->abort = hookmgr_close_abort;

        struct tracy_ll_item* item = ll_find(cdata->files, hookevent->fd);
        if(item && item->data) {
            file_list_item_t* fditem = item->data;
            hookevent->pathname = fditem->path;

            // call close hook
            hookmgr_device_t *entry;
            list_for_every_entry(&mgr->devices, entry, hookmgr_device_t, node) {
                if(entry->close && entry->major==major(fditem->dev) && entry->minor==minor(fditem->dev)) {
                    entry->close(entry, hookevent);

                    // check if we were requested to abort the syscall
                    if(hookevent->do_abort) {
                        e->child->return_code = hookevent->returncode;
                        e->child->change_return_code = 1;
                        tracyrc = TRACY_HOOK_DENY;

                        break;
                    }

                    break;
                }
            }
        }
    }

    else {
        hookevent = cdata->closedata;
        if(!hookevent) {
            LOGW("cdata->closedata is NULL\n");
            return tracyrc;
        }

        if(!hookevent->do_abort) {
            // remove fd from our list
            if(e->args.return_code>=0) {
                struct tracy_ll_item* item = ll_find(cdata->files, hookevent->fd);
                if(item && item->data) {
                    free(item->data);
                }
                ll_del(cdata->files, hookevent->fd);
            }
        }

        // cleanup
        free(hookevent);
        cdata->closedata = NULL;
    }

    return tracyrc;
}

hookmgr_str_setter(hookmgr_generic_truncate_set_pathname, hookmgr_truncate_event_t, a0, pathname);
hookmgr_abort_function(hookmgr_generic_truncate_abort, hookmgr_truncate_event_t);

int hookmgr_hook_generic_truncate(struct tracy_event *e) {
    hookmgr_t* mgr = mgr_from_event(e);
    int rc;
    int tracyrc = TRACY_HOOK_CONTINUE;

    if (e->child->pre_syscall) {
        hookmgr_truncate_event_t  _hookevent = {0};
        hookmgr_truncate_event_t* hookevent = &_hookevent;

        hookevent->tracyevent = e;
        hookevent->pathname = strfromchild(e->child, (void*)e->args.a0);

        hookevent->set_pathname = hookmgr_generic_truncate_set_pathname;
        hookevent->abort = hookmgr_generic_truncate_abort;

        unsigned major, minor;
        
        // ignore devices we can't find
        rc = lindev_from_path(hookevent->pathname, &major, &minor, 1);
        if(!rc) {
	        // call truncate hook
	        hookmgr_device_t *entry;
	        list_for_every_entry(&mgr->devices, entry, hookmgr_device_t, node) {
                if(entry->truncate && entry->major==major && entry->minor==minor) {
                    entry->truncate(entry, hookevent);

                    // check if we were requested to abort the syscall
                    if(hookevent->do_abort) {
                        e->child->return_code = hookevent->returncode;
                        e->child->change_return_code = 1;
                        tracyrc = TRACY_HOOK_DENY;

                        break;
                    }
                    
                    break;
                }
	        }
        }

        // cleanup
        free((void*)hookevent->pathname);
    }

    return tracyrc;
}
