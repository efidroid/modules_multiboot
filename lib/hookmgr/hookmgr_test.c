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

#include <common.h>
#include <tracy.h>
#include <lib/hookmgr.h>

#define LOG_TAG "HOOKMGR_TEST"
#include <log.h>

static void dev_mount(hookmgr_device_t* dev, hookmgr_mount_event_t* event) {
    (void)(dev);
    (void)(event);

    LOGI("mount(%s, %s, %s, %lu, %p)\n", event->source, event->target, event->filesystemtype, event->mountflags, event->data);

    event->set_source(event, "tmpfs");
    event->set_filesystemtype(event, "tmpfs");
    event->abort(event, 0);
}

static void dev_umount(hookmgr_device_t* dev, hookmgr_umount_event_t* event) {
    (void)(dev);
    (void)(event);

    LOGI("umount(%s, %d)\n", event->target, event->flags);

    event->abort(event, 0);
}

static void dev_open(hookmgr_device_t* dev, hookmgr_open_event_t* event) {
    (void)(dev);
    (void)(event);
    LOGE("open(%s, %d, %d)\n", event->pathname, event->flags, event->mode);

    //event->set_pathname(event, "/proc/cmdline");
}

static void dev_close(hookmgr_device_t* dev, hookmgr_close_event_t* event) {
    (void)(dev);
    (void)(event);
    LOGE("close(%d,%s)\n", event->fd, event->pathname);
}

static void dev_truncate(hookmgr_device_t* dev, hookmgr_truncate_event_t* event) {
    (void)(dev);
    (void)(event);
    LOGE("truncate(%s)\n", event->pathname);
}

static hookmgr_device_t hookdevice = {
    .major = 259,
    .minor = 3,
    .mount = dev_mount,
    .umount = dev_umount,
    .open = dev_open,
    .close = dev_close,
    .truncate = dev_truncate,
};

int main(int argc, char** argv) {
    // check args
    if (argc < 2) {
        LOGE("Usage: ./example <program-name>\n");
        return -EINVAL;
    }

    // init log
    log_init();

    // init tracy
    struct tracy *tracy = tracy_init(TRACY_TRACE_CHILDREN | TRACY_WORKAROUND_ARM_7475_1);

    // init hookmgr
    hookmgr_t* hookmgr = hookmgr_init(tracy);
    if(!hookmgr) {
        LOGE("Can't initialize hookmgr\n");
        return -1;
    }

    hookmgr_redirect_device(hookmgr, &hookdevice);

    // start app
    argv++; argc--;
    if (!tracy_exec(tracy, argv)) {
        LOGE("tracy_exec");
        return -1;
    }

    // run tracy
    tracy_main(tracy);
    tracy_free(tracy);

    return 0;
}
