#ifndef __NG_LOGGING_H__
#define __NG_LOGGING_H__

#include <stdio.h>

#ifdef WITH_HTTPD
#include "httpd.h"
#include "http_log.h"
#include "http_client.h"
#include "http_config.h"

extern module AP_MODULE_DECLARE_DATA gandalf_module;

/* For Apache 2.4+ */
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(datadome_shield);
#endif

extern int LOGLEVEL;

extern __thread server_rec *datadome_shield_server_rec;

#define LOG_ME(__level, __str, __arg...)\
    ap_log_error(APLOG_MARK, __level, 0, datadome_shield_server_rec, __str, ##__arg)

#define DM_LOG_CRIT(__str, __arg...)    LOG_ME(APLOG_CRIT, __str, ##__arg)
#define DM_LOG_ERROR(__str, __arg...)   LOG_ME(APLOG_ERR, __str, ##__arg)
#define DM_LOG_INFO(__str, __arg...)    LOG_ME(APLOG_INFO, __str, ##__arg)
#define DM_LOG_DEBUG(__str, __arg...)   LOG_ME(APLOG_DEBUG, __str, ##__arg)
#ifdef APLOG_TRACE1
#define DM_LOG_TRACE(__str, __arg...)   LOG_ME(APLOG_TRACE1, __str, ##__arg)
#else
#define DM_LOG_TRACE(__str, __arg...)   LOG_ME(APLOG_DEBUG, __str, ##__arg)
#endif

#else
/* Log level definition */
typedef enum {
    DM_LOG_LEVEL_EMERG=0,
    DM_LOG_LEVEL_ALERT=1,
    DM_LOG_LEVEL_CRIT=2,
    DM_LOG_LEVEL_ERROR=3,
    DM_LOG_LEVEL_WARNING=4,
    DM_LOG_LEVEL_NOTICE=5,
    DM_LOG_LEVEL_INFO=6,
    DM_LOG_LEVEL_DEBUG=7,
    DM_LOG_LEVEL_TRACE=8,
    DM_LOG_LEVEL_MAX=9
}log_level_type;

/* This variable should be defined at somewhere in c file */
extern int LOGLEVEL;

#define LOG_ME(__level, __str, __arg...)\
    if (LOGLEVEL >= DM_LOG_LEVEL_ ## __level) {\
        fprintf(stderr, "["#__level"] [%s][%s:%d] "__str, __FILE__, __FUNCTION__, __LINE__, ##__arg);\
    }

#define DM_LOG_CRIT(__str, __arg...)    LOG_ME(CRIT, __str, ##__arg)
#define DM_LOG_ERROR(__str, __arg...)   LOG_ME(ERROR, __str, ##__arg)
#define DM_LOG_INFO(__str, __arg...)    LOG_ME(INFO, __str, ##__arg)
#define DM_LOG_DEBUG(__str, __arg...)   LOG_ME(DEBUG, __str, ##__arg)
#define DM_LOG_TRACE(__str, __arg...)   LOG_ME(TRACE, __str, ##__arg)

#endif

#endif
