#ifndef LIB_HOOKMGR_H
#define LIB_HOOKMGR_H

#include <lib/list.h>
#include <tracy.h>

// HOOKMGR
typedef struct {
    struct tracy *tracy;
    struct list_node devices;
} hookmgr_t;

// EVENTS
typedef struct hookmgr_mount_event {
    const char* source;
    const char* target;
    const char* filesystemtype;
    unsigned long mountflags;
    tracy_child_addr_t data;

    int (*set_source)(struct hookmgr_mount_event*, const char*);
    int (*set_target)(struct hookmgr_mount_event*, const char*);
    int (*set_filesystemtype)(struct hookmgr_mount_event*, const char*);
    int (*set_mountflags)(struct hookmgr_mount_event*, unsigned long);
    int (*set_data)(struct hookmgr_mount_event*, void*, size_t);
    int (*abort)(struct hookmgr_mount_event*, int);

    // internal
    int do_abort;
    int returncode;
    struct tracy_event *tracyevent;
    tracy_child_addr_t alloc_source;
    tracy_child_addr_t alloc_target;
    tracy_child_addr_t alloc_filesystemtype;
} hookmgr_mount_event_t;

typedef struct hookmgr_umount_event {
    const char* target;
    int flags;

    int (*set_target)(struct hookmgr_umount_event*, const char*);
    int (*set_flags)(struct hookmgr_umount_event*, int);
    int (*abort)(struct hookmgr_umount_event*, int);

    // internal
    int do_abort;
    int returncode;
    struct tracy_event *tracyevent;
    tracy_child_addr_t alloc_target;
} hookmgr_umount_event_t;

typedef struct hookmgr_open_event {
    const char* pathname;
    int flags;
    mode_t mode;

    int (*set_pathname)(struct hookmgr_open_event*, const char*);
    int (*set_flags)(struct hookmgr_open_event*, int);
    int (*set_mode)(struct hookmgr_open_event*, mode_t);
    int (*abort)(struct hookmgr_open_event*, int);

    // internal
    int do_abort;
    int returncode;
    struct tracy_event *tracyevent;
    tracy_child_addr_t alloc_pathname;
    dev_t dev;
} hookmgr_open_event_t;

typedef struct hookmgr_close_event {
    int fd;
    const char* pathname;
    int flags;

    int (*set_fd)(struct hookmgr_close_event*, int);
    int (*abort)(struct hookmgr_close_event*, int);

    // internal
    int do_abort;
    int returncode;
    struct tracy_event *tracyevent;
} hookmgr_close_event_t;

typedef struct hookmgr_truncate_event {
    const char* pathname;

    int (*set_pathname)(struct hookmgr_truncate_event*, const char*);
    int (*abort)(struct hookmgr_truncate_event*, int);

    // internal
    int do_abort;
    int returncode;
    struct tracy_event *tracyevent;
    tracy_child_addr_t alloc_pathname;
} hookmgr_truncate_event_t;

// DEVICE
typedef struct hookmgr_device {
    struct list_node node;
    hookmgr_t* mgr;
    unsigned major;
    unsigned minor;

    void (*mount)(
        struct hookmgr_device* dev,
        hookmgr_mount_event_t* event
    );
    void (*umount)(
        struct hookmgr_device* dev,
        hookmgr_umount_event_t* event
    );

    void (*open)(
        struct hookmgr_device* dev,
        hookmgr_open_event_t* event
    );
    void (*close)(
        struct hookmgr_device* dev,
        hookmgr_close_event_t* event
    );
    void (*close_post)(
        struct hookmgr_device* dev,
        hookmgr_close_event_t* event
    );
    void (*truncate)(
        struct hookmgr_device* dev,
        hookmgr_truncate_event_t* event
    );
} hookmgr_device_t;

hookmgr_t* hookmgr_init(struct tracy *tracy);
int hookmgr_redirect_device(hookmgr_t* mgr, hookmgr_device_t* dev);

#endif // LIB_HOOKMGR_H

