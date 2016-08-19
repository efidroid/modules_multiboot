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

#define PAYLOAD_IMPORT(name) \
    extern int _binary_##name##_start; \
    extern int _binary_##name##_end; \
    extern int _binary_##name##_size;

#define PAYLOAD_PTR(name) ((void*)&_binary_##name##_start)
#define PAYLOAD_SIZE(name) ((unsigned)(((void*)&_binary_##name##_end) - ((void*)&_binary_##name##_start)))

#define MBPATH_ROOT "/multiboot"
#define MBPATH_FSTAB MBPATH_ROOT "/fstab.multiboot"
#define MBPATH_PROC MBPATH_ROOT "/proc"
#define MBPATH_DEV MBPATH_ROOT "/dev"
#define MBPATH_SYS MBPATH_ROOT "/sys"
#define MBPATH_BIN MBPATH_ROOT "/bin"
#define MBPATH_ESP MBPATH_ROOT "/esp"
#define MBPATH_BOOTDEV MBPATH_ROOT "/bootdev"
#define MBPATH_STUB MBPATH_ROOT "/stub"
#define MBPATH_DATA MBPATH_ROOT "/data"
#define MBPATH_STUB_IDFILE MBPATH_STUB "/.idfile"
#define MBPATH_TRIGGER_POSTFS_DATA MBPATH_BIN "/trigger-postfs-data"
#define MBPATH_BUSYBOX MBPATH_BIN "/busybox"
#define MBPATH_MKE2FS MBPATH_BIN "/mke2fs"
#define POSTFS_NOTIFICATION_FILE "/dev/.trigger-postfs-data"

#define UNUSED __attribute__((unused))

extern size_t strlcat(char* __restrict, const char* __restrict, size_t);
extern size_t strlcpy(char* __restrict, const char* __restrict, size_t);

typedef enum {
    MBPART_TYPE_LOOP = 0,
    MBPART_TYPE_DYN,
    MBPART_TYPE_BIND,
} multiboot_partition_type_t;

typedef struct {
    char* name;
    char* path;
    multiboot_partition_type_t type;
} multiboot_partition_t;

typedef struct {
    // boot device
    char* guid;
    char* path;
    uevent_block_t* bootdev;
    int is_multiboot;
    int bootdev_supports_bindmount;
    multiboot_partition_t* mbparts;
    uint32_t num_mbparts;

    // ESP
    struct fstab_rec* esp;
    uevent_block_t* espdev;

    // device info
    struct fstab *mbfstab;
    list_node_t* blockinfo;
    char* hwname;
    struct fstab *romfstab;
    char* romfstabpath;

    // partition replacement list
    list_node_t replacements;

} multiboot_data_t;

typedef struct {
    list_node_t node;
    pthread_mutex_t lock;

    unsigned major;
    unsigned minor;

    // raw part for loop, stub part for bind
    char* loopdevice;

    union {
        struct {
            multiboot_partition_t* part;

            // bind
            char* partpath;
        } multiboot;

        struct {
            struct fstab_rec* rec;
        } native;
    } u;
} part_replacement_t;


int run_init(int trace);
int multiboot_main(int argc, char** argv);
int multiboot_exec_tracee(char** par);
multiboot_data_t* multiboot_get_data(void);
int boot_recovery(void);
int boot_android(void);

#endif
