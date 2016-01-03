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

#include <lib/efivars.h>
#include <lib/hookmgr.h>
#include <tracy.h>

#include <common.h>

#define LOG_TAG "HOOKMGR_MOUNT"
#include <lib/log.h>

#include "hookmgr_priv.h"

hookmgr_str_setter(hookmgr_mount_set_source, hookmgr_mount_event_t, a0, source);
hookmgr_str_setter(hookmgr_mount_set_target, hookmgr_mount_event_t, a1, target);
hookmgr_str_setter(hookmgr_mount_set_filesystemtype, hookmgr_mount_event_t, a2, filesystemtype);
hookmgr_primitive_setter(hookmgr_mount_set_mountflags, hookmgr_mount_event_t, a3, mountflags, unsigned long);
hookmgr_abort_function(hookmgr_mount_abort, hookmgr_mount_event_t);

static int hookmgr_mount_set_data(hookmgr_mount_event_t* event, void* data, size_t size) {
    (void)(event);
    (void)(data);
    (void)(size);

    return -1;
}

int hookmgr_hook_mount(struct tracy_event *e) {
    hookmgr_t* mgr = mgr_from_event(e);
    int rc;
    int tracyrc = TRACY_HOOK_CONTINUE;

    if (e->child->pre_syscall) {
        hookmgr_mount_event_t  _hookevent = {0};
        hookmgr_mount_event_t* hookevent = &_hookevent;

        hookevent->tracyevent = e;
        hookevent->source = strfromchild(e->child, (void*)e->args.a0);
        hookevent->target = strfromchild(e->child, (void*)e->args.a1);
        hookevent->filesystemtype = strfromchild(e->child, (void*)e->args.a2);
        hookevent->mountflags = (unsigned long)e->args.a3;
        hookevent->data = (tracy_child_addr_t)e->args.a4;

        if( (e->args.a0 && !hookevent->source)
                || (e->args.a1 && !hookevent->target)
                || (e->args.a2 && !hookevent->filesystemtype))
        {
            EFIVARS_LOG_FATAL(-1, "Can't receive arguments\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent->set_source = hookmgr_mount_set_source;
        hookevent->set_target = hookmgr_mount_set_target;
        hookevent->set_filesystemtype = hookmgr_mount_set_filesystemtype;
        hookevent->set_mountflags = hookmgr_mount_set_mountflags;
        hookevent->set_data = hookmgr_mount_set_data;
        hookevent->abort = hookmgr_mount_abort;

        unsigned major, minor;

        // ignore devices we can't find
        rc = lindev_from_path(hookevent->source, &major, &minor, 1);
        if(!rc) {
            // call mount hook
            hookmgr_device_t *entry;
            list_for_every_entry(&mgr->devices, entry, hookmgr_device_t, node) {
                if(entry->mount && entry->major==major && entry->minor==minor) {
                    entry->mount(entry, hookevent);
                    break;
                }
            }

            // check if we were requested to abort the syscall
            if(hookevent->do_abort) {
                e->child->return_code = hookevent->returncode;
                e->child->change_return_code = 1;
                tracyrc = TRACY_HOOK_DENY;
            }
        }

        // cleanup
        free((void*)hookevent->filesystemtype);
        free((void*)hookevent->target);
        free((void*)hookevent->source);
    }

    return tracyrc;
}

hookmgr_str_setter(hookmgr_umount_set_target, hookmgr_umount_event_t, a0, target);
hookmgr_primitive_setter(hookmgr_umount_set_flags, hookmgr_umount_event_t, a1, flags, int);
hookmgr_abort_function(hookmgr_umount_abort, hookmgr_umount_event_t);

int hookmgr_hook_umount(struct tracy_event *e) {
    hookmgr_t* mgr = mgr_from_event(e);
    int rc;
    int tracyrc = TRACY_HOOK_CONTINUE;

    if (e->child->pre_syscall) {
        hookmgr_umount_event_t  _hookevent = {0};
        hookmgr_umount_event_t* hookevent = &_hookevent;

        hookevent->tracyevent = e;
        hookevent->target = strfromchild(e->child, (void*)e->args.a0);
        hookevent->flags = (int)e->args.a1;

        if(e->args.a0 && !hookevent->target) {
            EFIVARS_LOG_FATAL(-1, "Can't receive arguments\n");
            return TRACY_HOOK_ABORT;
        }

        hookevent->set_target = hookmgr_umount_set_target;
        hookevent->set_flags = hookmgr_umount_set_flags;
        hookevent->abort = hookmgr_umount_abort;

        unsigned major, minor;

        // ignore devices we can't find
        rc = lindev_from_mountpoint(hookevent->target, &major, &minor);
        if(!rc) {
            // call umount hook
            hookmgr_device_t *entry;
            list_for_every_entry(&mgr->devices, entry, hookmgr_device_t, node) {
                if(entry->umount && entry->major==major && entry->minor==minor) {
                    entry->umount(entry, hookevent);
                    break;
                }
            }

            // check if we were requested to abort the syscall
            if(hookevent->do_abort) {
                e->child->return_code = hookevent->returncode;
                e->child->change_return_code = 1;
                tracyrc = TRACY_HOOK_DENY;
            }
        }

        // cleanup
        free((void*)hookevent->target);
    }

    return tracyrc;
}
