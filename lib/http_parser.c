#include "common.h"
#include "http_parser.h"

typedef enum {
    HTTP_NONE,
    HTTP_RESPONSE,
    HTTP_RESPONSE_HEADER_PARAM,
    HTTP_RESPONSE_HEADER_END,
    HTTP_POST_DATA,
    HTTP_POST_PARAM
}http_status;

typedef enum {
    CONNECTION_CLOSE,
    CONNECTION_KEEP_ALIVE
}connection_type;

struct _http_data {
    http_status status;
    connection_type conn_type;
    int content_len;
    int connection_keep_alive;
    int parsed_offset;
    int data_offset;

    RESPONSE_CB *response_cb;
    HEADER_PARAM_CB *header_param_cb;
    POST_DATA_CB *data_cb;
};

static __thread struct _http_data global_hd;

int
init_http_parser(RESPONSE_CB *r_cb, HEADER_PARAM_CB *hp_cb, POST_DATA_CB *d_cb)
{
    memset(&global_hd, 0, sizeof(struct _http_data));
    global_hd.response_cb = r_cb;
    global_hd.header_param_cb = hp_cb;
    global_hd.data_cb = d_cb;

    return SUCCESS;
}

static inline int
replace_CRLF(uint8_t *data, int dlen, uint8_t new_ch)
{
    int ret = -1;
    int i = 0;

    for (i=0 ; i<dlen-1 ; i++) {
        if (data[i] == '\r' && data[i+1] == '\n') {
            data[i] = data[i+1] = new_ch;
            ret = i;
            break;
        }
    }

    return ret;
}

static uint8_t *
replace_CHAR(uint8_t *data, int dlen, uint8_t org_ch, uint8_t new_ch)
{
    int i = 0;
    for (i=0 ; i<dlen ; i++) {
        if (data[i] == org_ch) {
            data[i] = new_ch;
            return data+i;
        }
    }
    return NULL;
}

#define SKIP_SPACE(__p) for ( ; *(__p) == ' ' ; (__p) = (__p)+1)

static void
parse_header_param(const uint8_t *param, const uint8_t *value, struct _http_data *hd)
{
    if (strcmp((const char *)param, "Content-Length") == 0) {
        hd->content_len = atoi((const char *)value);
    }
    if (strcmp((const char *)param, "Connection") == 0) {
        if (strcmp((const char *)param, "keep-alive") == 0) {
            hd->connection_keep_alive = 1;
        }
    }
}

int
parse_http_response(uint8_t *data_head, int data_len, int *http_version_11, int *connection_keep_alive)
{
    struct _http_data *hd = &global_hd;
    uint8_t *data = data_head + hd->parsed_offset;
    uint8_t *p1 = NULL, *p2 = NULL, *p3 = NULL;
    int i = 0, len = data_len - hd->parsed_offset;
    int n = 0, ret = 1;

    *http_version_11 = 0;

    if (len < (sizeof("HTTP/1.1") - 1)) {
        DM_LOG_ERROR("Not HTTP response");
        ret = 1;
        goto end;
    }

    if (strncmp((char *)data, "HTTP/1.1", sizeof("HTTP/1.1") - 1) == 0) {
        *http_version_11 = 1;
    }

    for (i=0 ; i<len ; ) {
        p1 = p2 = p3 = NULL;
        switch (hd->status) {
            case HTTP_NONE:
                hd->status = HTTP_RESPONSE;
                break;
            case HTTP_RESPONSE:
                n = replace_CRLF(data+i, len-i, '\0');
                if (n == -1) {
                    DM_LOG_ERROR("Incomplete data, response not found");
                    ret = 1;
                    goto end;
                }
                p3 = data+i;
                p1 = replace_CHAR(p3, len-i, ' ', '\0');
                if (p1) {
                    *p1++ = '\0';
                    SKIP_SPACE(p1);
                    p2 = replace_CHAR(p1+1, len-i-strlen((char *)(data+i))-1, ' ', '\0');
                    if (p2) {
                        *p2++ = '\0';
                        SKIP_SPACE(p2);
                    }
                }
                hd->response_cb((const char *)p3, (const char *)p1, (const char *)p2);
                hd->parsed_offset += (n + 2); i += (n+2);
                hd->status = HTTP_RESPONSE_HEADER_PARAM;
                break;
            case HTTP_RESPONSE_HEADER_PARAM:
                n = replace_CRLF(data+i, len-i, '\0');
                if (n == -1) {
                    DM_LOG_DEBUG("Incomplete data, response not found");
                    ret = 1;
                    goto end;
                }
                p3 = data+i;
                if (n == 0) {
                    DM_LOG_DEBUG("HTTP header parameters end\n");
                    hd->status = HTTP_RESPONSE_HEADER_END;
                    //hd->header_end_cb();
                    hd->status = HTTP_POST_DATA;
                    hd->data_offset = hd->parsed_offset + n + 2;
                        /* If content len is 0, then HTTP_POST_DATA case will be never hit */
                        if (hd->content_len == 0) {
                            DM_LOG_DEBUG("Content-Length is 0\n");
                            hd->data_cb(NULL, 0);
                            ret = 0;
                        }
                } else {
                    p1 = p2 = NULL;
                    p1 = replace_CHAR(p3, len-i, ':', '\0');
                    if (p1) {
                        *p1++ = '\0';
                        SKIP_SPACE(p1);
                    }
                    parse_header_param(p3, p1, hd);
                    hd->header_param_cb((const char *)p3, (const char *)p1);
                }
                hd->parsed_offset += (n + 2); i += (n+2);
                break;
            case HTTP_POST_DATA:
                hd->parsed_offset += (len-i);
                if (hd->parsed_offset - hd->data_offset < hd->content_len) {
                    DM_LOG_DEBUG("Not enough data received, parsed_offset: %d hd->data_offset: %d hd->content_len: %d\n",
                        hd->parsed_offset, hd->data_offset, hd->content_len);
                    ret = 1;
                } if (hd->parsed_offset - hd->data_offset == hd->content_len) {
                    hd->data_cb(data_head + hd->data_offset, hd->content_len);
                    ret = 0;
                } else {
                    DM_LOG_ERROR("Read more bytes (%d) what expected at content_len (%d)", hd->parsed_offset - hd->data_offset, hd->content_len);
                    ret = -1;
                }
                i = len; // => i += (len-i);
                break;
            default:
                DM_LOG_ERROR("You should not be here");
                ret = -1;
                goto end;
                break; /* Formal break statement */
        }
    }
end:

    *connection_keep_alive = hd->connection_keep_alive;

    return ret;
}
