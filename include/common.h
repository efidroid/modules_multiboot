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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>

#include <lib/uevent.h>
#include <lib/list.h>
#include <syshook.h>
#include <safe.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

#define ANYEQ_2(var, val1, val2) ((var)==(val1) || (var)==(val2))

#define PAYLOAD_IMPORT(name) \
    extern int _binary_##name##_start; \
    extern int _binary_##name##_end; \
    extern int _binary_##name##_size;

#define PAYLOAD_PTR(name) ((void*)&_binary_##name##_start)
#define PAYLOAD_SIZE(name) ((unsigned)(((void*)&_binary_##name##_end) - ((void*)&_binary_##name##_start)))

#define MBPATH_ROOT "/multiboot"
#define MBPATH_FSTAB MBPATH_ROOT "/fstab.multiboot"
#define MBPATH_FILE_CONTEXTS MBPATH_ROOT "/file_contexts"
#define MBPATH_FILE_CONTEXTS_BIN MBPATH_ROOT "/file_contexts.bin"
#define MBPATH_PROC MBPATH_ROOT "/proc"
#define MBPATH_DEV MBPATH_ROOT "/dev"
#define MBPATH_SYS MBPATH_ROOT "/sys"
#define MBPATH_BIN MBPATH_ROOT "/bin"
#define MBPATH_ESP MBPATH_ROOT "/esp"
#define MBPATH_BOOTDEV MBPATH_ROOT "/bootdev"
#define MBPATH_STUB MBPATH_ROOT "/stub"
#define MBPATH_DATA MBPATH_ROOT "/data"
#define MBPATH_MB_SYSTEM MBPATH_ROOT "/mb_system"
#define MBPATH_MB_DATA MBPATH_ROOT "/mb_data"
#define MBPATH_STUB_IDFILE MBPATH_STUB "/.idfile"
#define MBPATH_BUSYBOX MBPATH_BIN "/busybox"
#define MBPATH_MKE2FS MBPATH_BIN "/mke2fs"
#define MBPATH_TRIGGER_BIN MBPATH_BIN "/trigger"
#define MBPATH_TRIGGER_CMD MBPATH_ROOT "/.trigger_cmd"
#define MBPATH_TRIGGER_WAIT_FILE MBPATH_ROOT "/.trigger_wait"
#define MBPATH_STATEFILE MBPATH_ROOT "/mbstate"

#define UNUSED __attribute__((unused))

extern size_t strlcat(char *__restrict, const char *__restrict, size_t);
extern size_t strlcpy(char *__restrict, const char *__restrict, size_t);

typedef enum {
    MBPART_TYPE_LOOP = 0,
    MBPART_TYPE_BIND,
} multiboot_partition_type_t;

typedef struct {
    char *name;
    char *path;

    multiboot_partition_type_t type;
    uevent_block_t *uevent_block;
} multiboot_partition_t;

typedef struct {
    // thread safety
    pthread_mutex_t lock;

    int is_multiboot;
    int is_recovery;

    // ESP
    struct fstab_rec *esp;
    uevent_block_t *espdev;

    // device info
    struct fstab *mbfstab;
    list_node_t *blockinfo;
    char *hwname;
    char *slot_suffix;
    struct fstab *romfstab;
    char *romfstabpath;

    // partition replacement list
    list_node_t replacements;

    // only available during multiboot

    // boot device
    char *guid;
    char *path;
    uevent_block_t *bootdev;
    int bootdev_supports_bindmount;

    // multiboot.ini data
    multiboot_partition_t *mbparts;
    uint32_t num_mbparts;

    // datamedia
    uint32_t native_data_layout_version;
    const char *datamedia_source;
    const char *datamedia_target;
} multiboot_data_t;


typedef enum {
    PART_REPLACEMENT_MOUNTMODE_ALLOW = 0,
    PART_REPLACEMENT_MOUNTMODE_DENY,
    PART_REPLACEMENT_MOUNTMODE_LOOP,
    PART_REPLACEMENT_MOUNTMODE_BIND,
} part_replacement_mountmode_t;

typedef enum {
    PART_REPLACEMENT_IOMODE_ALLOW = 0,
    PART_REPLACEMENT_IOMODE_DENY,
    PART_REPLACEMENT_IOMODE_REDIRECT,
} part_replacement_iomode_t;

typedef struct {
    list_node_t node;
    pthread_mutex_t lock;

    uevent_block_t *uevent_block;

    part_replacement_mountmode_t mountmode;
    part_replacement_iomode_t iomode;

    // mount: bind
    char *bindsource;

    // mount: loop, also used for direct IO
    char *loopdevice;

    // optional, for delayed losetup
    int losetup_done;
    char *loopfile;

    // optional, file to sync changes to
    char *loop_sync_target;
} part_replacement_t;


int run_init(int trace);
int multiboot_main(int argc, char **argv);
int multiboot_exec_tracee(char **par);
multiboot_data_t *multiboot_get_data(void);
int boot_recovery(void);
int boot_android(void);

int handle_trigger(char *cmd);
int state_save(void);
int state_restore(void);

#endif
