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

#ifndef _LIB_UEVENT_H_
#define _LIB_UEVENT_H_

#include <lib/list.h>

typedef enum {
    UEVENT_BLOCK_TYPE_UNKNOWN,
    UEVENT_BLOCK_TYPE_DISK,
    UEVENT_BLOCK_TYPE_PARTITION
} uevent_block_type_t;

typedef struct {
    list_node_t node;
    char *filename;

    unsigned major;
    unsigned minor;
    unsigned partn;
    char *devname;
    char *partname;
    uevent_block_type_t type;
} uevent_block_t;

list_node_t *get_block_devices(void);
void add_new_block_devices(list_node_t *info);
void free_block_devices(list_node_t *info);
uevent_block_t *get_blockinfo_for_path(list_node_t *info, const char *path);
uevent_block_t *get_blockinfo_for_partname(list_node_t *info, const char *partname);
uevent_block_t *get_blockinfo_for_devname(list_node_t *info, const char *devname);
char *uevent_realpath(list_node_t *info, const char *path, char *resolved_path);
char *uevent_realpath_prefix(list_node_t *info, const char *path, char *resolved_path, const char *prefix);
int uevent_create_nodes(list_node_t *info, const char *path);
int uevent_mount(uevent_block_t *bi, const char *target,
                 const char *filesystemtype, unsigned long mountflags,
                 const void *data);
#endif
