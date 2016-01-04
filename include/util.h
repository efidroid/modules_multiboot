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

char* util_basename(const char* path);
char* util_dirname(const char* path);
int util_buf2file(const void* buf, const char* filename, size_t size);
int util_extractbin(const void* buf, const char* filename, size_t size);
int util_exists(const char *filename, bool follow);
uint64_t util_filesize(const char *filename, bool follow);
int util_mkdir(const char *dir);
int util_exec(char **args);
int util_replace(const char *file, const char *regex);
int util_sepolicy_inject(const char* source, const char* target, const char* clazz, const char* perm);
int util_append_string_to_file(const char* filename, const char* str);
int util_setsighandler(int signum, void (*handler)(int, siginfo_t *, void *));
int util_mount(const char *source, const char *target,
               const char *filesystemtype, unsigned long mountflags,
               const void *data);
int util_make_loop(const char *path);
int util_losetup(const char *device, const char *file, bool ro);
int util_losetup_free(const char *_device);
int util_mke2fs(const char *device, const char* fstype);
int util_mkfs_f2fs(const char *device);
int util_mkfs(const char *device, const char* fstype);
int util_block_num(const char *path, unsigned long* numblocks);
int util_dd(const char *source, const char *target, unsigned long blocks);
int util_cp(const char *source, const char *target);
int util_shell(const char *cmd);
char *util_get_fstype(const char *filename);
char* util_get_espdir(const char* mountpoint, char* extbuf);
char* util_get_esp_path_for_partition(const char* mountpoint, struct fstab_rec *rec);
int util_create_partition_backup_ex(const char* device, const char* file, unsigned long num_blocks, bool force);
int util_create_partition_backup(const char* device, const char* file);
char* util_getmbpath_from_device(const char* device);
int util_fs_supports_multiboot_bind(const char* type);
char* util_device_from_mbname(const char* name);
char* util_fd2name(pid_t pid, int fd);
multiboot_partition_t* util_mbpart_by_name(const char* name);
int util_strcmpnull(const char * str1, const char * str2);

#endif
