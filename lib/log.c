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

#include <lib/log.h>
#include <lib/klog.h>

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

    // forward to klog
    klog_vwrite(KLOG_DEFAULT_LEVEL, fmt, ap);

    // print
    vfprintf(stderr, fmt, ap);
}

void log_write(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vwrite(level, fmt, ap);
    va_end(ap);
}
