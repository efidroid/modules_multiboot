#ifndef _LIB_UEVENT_H_
#define _LIB_UEVENT_H_

typedef enum {
    UEVENT_BLOCK_TYPE_UNKNOWN,
    UEVENT_BLOCK_TYPE_DISK,
    UEVENT_BLOCK_TYPE_PARTITION
} uevent_block_type_t;

typedef struct {
    unsigned major;
    unsigned minor;
    unsigned partn;
    char *devname;
    char *partname;
    uevent_block_type_t type;
} uevent_block_t;

typedef struct {
    int num_entries;
    uevent_block_t *entries;
} uevent_block_info_t;

uevent_block_info_t *get_block_devices(void);
void free_block_devices(uevent_block_info_t *info);
uevent_block_t *get_blockinfo_for_path(uevent_block_info_t *info, const char *path);
char *uevent_realpath(uevent_block_info_t *info, const char *path, char *resolved_path);
int uevent_create_nodes(uevent_block_info_t *info, const char *path);
int uevent_mount(uevent_block_t *bi, const char *target,
                 const char *filesystemtype, unsigned long mountflags,
                 const void *data);
#endif
