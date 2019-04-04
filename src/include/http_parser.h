#ifndef __NG_HTTP_PARSER_H__
#define __NG_HTTP_PARSER_H__

#include "common.h"

typedef int (RESPONSE_CB) (const char *http, const char *code, const char *string);
typedef int (HEADER_PARAM_CB) (const char *key, const char *value);
typedef int (POST_DATA_CB) (const uint8_t *data, int len);

extern int parse_http_response(uint8_t *data_head, int data_len, int *http_version_11, int *connection_keep_alive);
extern int init_http_parser(RESPONSE_CB *r_cb, HEADER_PARAM_CB *hp_cb, POST_DATA_CB *d_cb);

#endif
