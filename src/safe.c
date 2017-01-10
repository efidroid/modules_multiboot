#define LOG_TAG "SAFE"
#include <lib/log.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

char *safe_strdup(const char *s)
{
    char *ret = strdup(s);
    if (!ret) {
        MBABORT("strdup: %s\n", strerror(ENOMEM));
    }

    return ret;
}


pid_t safe_fork(void)
{
    pid_t pid = fork();
    if (pid<0) {
        MBABORT("fork: %s\n", strerror(errno));
    }

    return pid;
}

void *safe_malloc(size_t size)
{
    char *ret = malloc(size);
    if (!ret) {
        MBABORT("malloc(%"PRIuPTR"): %s\n", size, strerror(ENOMEM));
    }

    return ret;
}

void *safe_calloc(size_t num, size_t size)
{
    char *ret = calloc(num, size);
    if (!ret) {
        MBABORT("calloc(%"PRIuPTR", %"PRIuPTR"): %s\n", num, size, strerror(ENOMEM));
    }

    return ret;
}
