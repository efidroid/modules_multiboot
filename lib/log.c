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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <lib/log.h>
#include <lib/klog.h>
#include <lib/android_reboot.h>
#include <common.h>

static int log_level = LOG_DEFAULT_LEVEL;

int log_get_level(void) {
    return log_level;
}

void log_set_level(int level) {
    log_level = level;
}


void log_init(void) {
    klog_init();
    klog_set_level(KLOG_DEBUG_LEVEL);
}

void log_vwrite(int level, const char *fmt, va_list ap)
{
    if (level < log_level) return;

    // print
    vfprintf(stderr, fmt, ap);
}

static void sim_kpan(void) {
    int fd = open(MBPATH_PROC"/sysrq-trigger", O_WRONLY);
    if(fd<0) {
        fd = open("/proc/sysrq-trigger", O_WRONLY);
        if(fd<0) return;
    }

    char c = 'c';
    write(fd, &c, 1);

    close(fd);
}

void log_write(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vwrite(level, fmt, ap);
    va_end(ap);

    if(level==LOGF_LEVEL) {
        // try to reboot
        android_reboot(ANDROID_RB_RESTART, 0, 0);

        // simulate kernel panic
        LOGE("reboot failed, trigger kernel panic\n");
        sim_kpan();

        // exit if that fails(we're init)
        exit(1);

        // never return
        for(;;);
    }
}
