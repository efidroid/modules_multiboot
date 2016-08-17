#define LOG_TAG "SAFE"
#include <lib/log.h>

#include <string.h>
#include <errno.h>

char *safe_strdup(const char *s) {
    char* ret = strdup(s);
    if(!ret) {
        MBABORT("strdup: %s\n", strerror(ENOMEM));
    }

    return ret;
}

