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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include <lib/fs_mgr.h>
#include <common.h>

#define WAIT_FOR_SIGNAL(sig, cond) { \
    sigset_t mask, oldmask; \
    sigemptyset (&mask); \
    sigaddset (&mask, sig); \
\
    sigprocmask (SIG_BLOCK, &mask, &oldmask); \
    while (cond) \
        sigsuspend (&oldmask); \
    sigprocmask (SIG_UNBLOCK, &mask, NULL); \
}

int busybox_main(int argc, char *argv[]);
int mke2fs_main(int argc, char *argv[]);

char *util_basename(const char *path);
char *util_dirname(const char *path);
int util_buf2file(const void *buf, const char *filename, size_t size);
int util_exists(const char *filename, bool follow);
int util_startswith(const char *str, const char *pre);
uint64_t util_filesize(const char *filename, bool follow);
int util_mkdir(const char *dir);
int util_append_buffer_to_file(const char *filename, const void *buf, size_t len);
int util_append_string_to_file(const char *filename, const char *str);
int util_setsighandler(int signum, void (*handler)(int, siginfo_t *, void *));
int util_mount(const char *source, const char *target,
               const char *filesystemtype, unsigned long mountflags,
               const void *data);
int util_make_loop(const char *path);
int util_losetup(const char *device, const char *file, bool ro);
int util_losetup_free(const char *_device);
int util_mkfs(const char *device, const char *fstype);
int util_block_num(const char *path, unsigned long *numblocks);
int util_dd(const char *source, const char *target, unsigned long blocks);
int util_cp(const char *source, const char *target);
int util_shell(const char *cmd);
char *util_get_fstype(const char *filename);
char *util_get_espdir(const char *mountpoint);
int util_create_partition_backup_ex(const char *device, const char *file, unsigned long num_blocks, bool force);
int util_create_partition_backup(const char *device, const char *file);
char *util_getmbpath_from_device(const char *device);
int util_fs_supports_multiboot_bind(const char *type);
int util_mount_esp(int abort_on_error);
int util_dynfilefs(const char *_source, const char *_target, uint64_t size);
int util_mount_mbinipart(const char *name, const char *mountpoint);
char *util_get_property(const char *filename, const char *propertyname);
int util_read_int(const char *filename, uint32_t *pvalue);
int util_write_int(char const *path, int value);
part_replacement_t *util_get_replacement_by_mbfstabname(const char *name);
const char *util_get_file_extension(const char *filename);
char *util_get_file_contents_ex(const char *filename, size_t *psize);
char *util_get_file_contents(const char *filename);
char *util_get_esp_path_for_partition(const char *mountpoint, const char *name);
part_replacement_t *util_get_replacement(unsigned int major, unsigned int minor);
part_replacement_t *util_get_replacement_by_ueventblock(uevent_block_t *block);
void util_hexdump(const void *ptr, size_t len);
int util_replace(const char *filename, const char *regex);

#endif
