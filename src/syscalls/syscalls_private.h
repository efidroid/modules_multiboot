#ifndef SYSCALLS_PRIVATE_H
#define SYSCALLS_PRIVATE_H

#include <syshook.h>
#include <lib/list.h>

typedef struct {
    list_node_t node;
    pthread_mutex_t lock;

    int fd;
    char* path;
    int flags;

    unsigned major;
    unsigned minor;
} fdinfo_t;

typedef struct {
    list_node_t files;
    int refs;
    pthread_mutex_t lock;
} fdtable_t;

typedef struct {
    fdtable_t* fdtable;
} syshook_pdata_t;

extern multiboot_data_t* syshook_multiboot_data;

fdinfo_t* fdinfo_dup(fdinfo_t* olditem);
void fdinfo_add(syshook_process_t* process, int fd, const char* path, int flags, unsigned major, unsigned minor);
fdinfo_t* fdinfo_get(syshook_process_t* process, int fd);
void fdinfo_free(fdinfo_t* fdinfo, int remove_from_list);

fdtable_t* fdtable_create(void);
fdtable_t* fdtable_dup(fdtable_t* src);
void fdtable_free(fdtable_t* fdtable);

int lindev_from_path(const char* filename, unsigned* major, unsigned* minor, int resolve_symlinks);
int lindev_from_mountpoint(const char* mountpoint, unsigned* major, unsigned* minor);
part_replacement_t* syshook_get_replacement(unsigned int major, unsigned int minor);

char* syshookutils_child_getcwd(syshook_process_t* process, char* buf, size_t size);
void __user * syshookutils_copy_to_child(syshook_process_t* process, void* buf, size_t size);
int syshookutils_get_absolute_path(syshook_process_t* process, int dfd, const char* filename, char* buf, size_t bufsz);
int syshook_handle_fd_close(fdinfo_t* fdinfo);

asmlinkage long sys_openat(syshook_process_t* process, int dfd, const char __user *filename, int flags, mode_t mode);
asmlinkage long sys_open(syshook_process_t* process, const char __user *filename, int flags, mode_t mode);
asmlinkage long sys_close(syshook_process_t* process, unsigned int fd);
asmlinkage long sys_dup(syshook_process_t* process, unsigned int fildes);
asmlinkage long sys_dup2(syshook_process_t* process, unsigned int oldfd, unsigned int newfd);
asmlinkage long sys_dup3(syshook_process_t* process, unsigned int oldfd, unsigned int newfd, int flags);
asmlinkage long sys_fcntl(syshook_process_t* process, unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long sys_fcntl64(syshook_process_t* process, unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long sys_mount(syshook_process_t* process, char __user *dev_name, char __user *dir_name,
				char __user *type, unsigned long flags,
				void __user *data);

#endif // SYSCALLS_PRIVATE_H
