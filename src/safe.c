#define LOG_TAG "SAFE"
#include <lib/log.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>

char *safe_strdup(const char *s) {
    char* ret = strdup(s);
    if(!ret) {
        MBABORT("strdup: %s\n", strerror(ENOMEM));
    }

    return ret;
}


pid_t safe_fork(void) {
    pid_t pid = fork();
    if(pid<0) {
        MBABORT("fork: %s\n", strerror(errno));
    }

    return pid;
}
