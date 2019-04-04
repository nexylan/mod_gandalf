#ifndef __NG_HTTP_CLIENT_H__
#define __NG_HTTP_CLIENT_H__

#include "common.h"

#include <apr_general.h>
#include <apr_tables.h>

typedef enum {
    PROTO_NONE = 0,
    PROTO_HTTP,
    PROTO_TLS_1_0,
    PROTO_TLS_1_1,
    PROTO_TLS_1_2,
    PROTO_MAX
} protocol_type;

struct _client_config {
    apr_pool_t *pool;
    int config_validated;
    struct in_addr server_ip;
    const char *server_hostname;
    const char *server_uri;
    uint16_t server_port;
    uint16_t conn_timeout;  /* Connection Timeout in miliseconds */
    uint16_t request_timeout;  /* Request Timeout in miliseconds */
    protocol_type proto_type;

    void *extra_config;
};

#define DEF_API_HOST    "api.datadome.co"
#define DEF_API_PORT    443
#define DEF_API_PROTOCOL "HTTPS"
#define DEF_API_URI     "/validate-request/"
#define DEF_TIMEOUT_MS  100
#define DEF_URI_REGEX ""
#define DEF_URI_REGEX_EXCLUSION "\\.(js|css|jpg|jpeg|png|ico|gif|tiff|svg|woff|woff2|ttf|eot|mp4|otf)$"
#define DEF_DOME_STATUS "auto"
#define DEF_DATA_EXCLUDE "" // Multiple options should space seperated
#define DEF_DEBUG_MODE 0
#define DEF_REQ_TIMEOUT_MS  50

/* Below macros for the http post request, Dome to API server */
#define CONTENT_TYPE "application/x-www-form-urlencoded"
#define EXTRA_HEADERS "User-Agent: DataDome\r\n"

extern __thread struct _client_config *client_config;

extern int http_client_init(int *max_timeout_ms);
extern int append_param(const char *name, int nlen, const char *value, int vlen, int limit, int use_url_encode, unsigned from_end);
extern int http_client_post(int *max_timeout_ms, apr_pool_t *pool, apr_table_t **headers,
    const uint8_t **response, uint32_t *response_len, int *response_code,
    const char **response_msg);
extern void http_client_reset();
extern void http_close_connection(int *max_timeout_ms);

extern int check_client_config(struct _client_config *cc);

#endif
