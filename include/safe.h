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

#ifndef _SAFE_H_
#define _SAFE_H_

#define SNPRINTF_ERROR(rc, sz) ((rc)<0 || (size_t)(rc) >=(sz))

#define SAFE_SNPRINTF_RET(fn, rc, s, n, fmt, ...) do{ \
    int safe_snprintf_rc = snprintf((s), (n), (fmt), ##__VA_ARGS__); \
    if(safe_snprintf_rc<0 || (size_t)safe_snprintf_rc >=(n)) { \
        fn("snprintf error\n"); \
        return (rc); \
    } \
}while(0)

char *safe_strdup(const char *s);
pid_t safe_fork(void);
void* safe_malloc(size_t size);
void* safe_calloc(size_t num, size_t size);

#endif
