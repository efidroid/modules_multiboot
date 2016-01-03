#ifndef _LOG_H_
#define _LOG_H_

#ifndef LOG_TAG
#define LOG_TAG "GLOBAL"
#endif

#ifndef LOG_SHOW_CODELINE
#define LOG_SHOW_CODELINE 0
#endif

#include <sys/cdefs.h>
#include <stdarg.h>

__BEGIN_DECLS

void log_init(void);
int  log_get_level(void);
void log_set_level(int level);
void log_close(void);
void log_write(int level, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
void log_vwrite(int level, const char *fmt, va_list ap);

__END_DECLS

#define LOGV_LEVEL 2
#define LOGD_LEVEL 3
#define LOGI_LEVEL 4
#define LOGW_LEVEL 5
#define LOGE_LEVEL 6
#define LOGA_LEVEL 7

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#if LOG_SHOW_CODELINE
#define LOG_TAG_STR(tag) tag " (" __FILE__ ":" STR(__LINE__) ")"
#else
#define LOG_TAG_STR(tag) tag
#endif

#define LOGV(x...) log_write(LOGV_LEVEL, "V/" LOG_TAG_STR(LOG_TAG) ": " x)
#define LOGD(x...) log_write(LOGD_LEVEL, "D/" LOG_TAG_STR(LOG_TAG) ": " x)
#define LOGI(x...) log_write(LOGI_LEVEL, "I/" LOG_TAG_STR(LOG_TAG) ": " x)
#define LOGW(x...) log_write(LOGW_LEVEL, "W/" LOG_TAG_STR(LOG_TAG) ": " x)
#define LOGE(x...) log_write(LOGE_LEVEL, "E/" LOG_TAG_STR(LOG_TAG) ": " x)
#define LOGA(x...) log_write(LOGA_LEVEL, "A/" LOG_TAG_STR(LOG_TAG) ": " x)

#define LOG_DEFAULT_LEVEL  LOGD_LEVEL  /* messages >= this level are logged */

#endif
