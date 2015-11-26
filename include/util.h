#ifndef _UTIL_H_
#define _UTIL_H_

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

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
int util_losetup(char *device, char *file, bool ro);
int util_block_num(const char *path, unsigned long* numblocks);
int util_dd(const char *source, const char *target, unsigned long blocks);
char *util_get_fstype(const char *filename);

#endif
