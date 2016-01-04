#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>

#include <lib/uevent.h>
#include <tracy.h>

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
#define MBPATH_BUSYBOX MBPATH_BIN "/busybox"
#define MBPATH_MKE2FS MBPATH_BIN "/mke2fs"
#define MBPATH_TRIGGER_POSTFS_DATA MBPATH_BIN "/trigger-postfs-data"
#define POSTFS_NOTIFICATION_FILE "/dev/.trigger-postfs-data"

#define unused __attribute__((unused))

extern size_t strlcat(char* __restrict, const char* __restrict, size_t);
extern size_t strlcpy(char* __restrict, const char* __restrict, size_t);

typedef struct {
    char* name;
    char* path;
    int is_bind;
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
    uevent_block_info_t* blockinfo;
    char* hwname;
    struct fstab *romfstab;

} multiboot_data_t;

int run_init(struct tracy *tracy);
int multiboot_main(int argc, char** argv);
multiboot_data_t* multiboot_get_data(void);
int boot_recovery(void);

#endif
