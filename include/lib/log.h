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

#ifndef _LOG_H_
#define _LOG_H_

#ifndef LOG_TAG
#define LOG_TAG "GLOBAL"
#endif

#ifndef LOG_SHOW_CODELINE
#define LOG_SHOW_CODELINE 0
#endif

#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <unistd.h>
#include <lib/efivars.h>

__BEGIN_DECLS

void log_init(void);
int  log_get_level(void);
void log_set_level(int level);
void log_close(void);
void log_write(int level, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
void log_vwrite(int level, const char *fmt, va_list ap);

__END_DECLS

#define LOGV_LEVEL 2
#define LOGD_LEVEL 3
#define LOGI_LEVEL 4
#define LOGW_LEVEL 5
#define LOGE_LEVEL 6
#define LOGF_LEVEL 7
#define LOGS_LEVEL 8

#define LOG_INTERNAL(level, levelprefix, fmt, ...) \
    log_write(level, levelprefix "/" LOG_TAG "(%d:%d): " fmt, getpid(), (pid_t)syscall(SYS_gettid), ##__VA_ARGS__)

#define LOGV(fmt, ...) LOG_INTERNAL(LOGV_LEVEL, "V", fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) LOG_INTERNAL(LOGD_LEVEL, "D", fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG_INTERNAL(LOGI_LEVEL, "I", fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) LOG_INTERNAL(LOGW_LEVEL, "W", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG_INTERNAL(LOGE_LEVEL, "E", fmt, ##__VA_ARGS__)
#define LOGF(fmt, ...) do {\
    efivars_set_error(fmt, ##__VA_ARGS__); \
    LOG_INTERNAL(LOGF_LEVEL, "F", fmt, ##__VA_ARGS__); \
} while(0)

#define MBABORT LOGF
#define MBABORT_RET(fmt, ...) do {\
    MBABORT(fmt, ##__VA_ARGS__); \
    return -1; \
} while(0)

#define LOG_DEFAULT_LEVEL  LOGD_LEVEL  /* messages >= this level are logged */

#endif
