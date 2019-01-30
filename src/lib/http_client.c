#include <ctype.h>
#include <fcntl.h>

#include "common.h"
#include "http_parser.h"
#include "http_client.h"

#define MAX_PARAM_DATALEN (10 * 1024)

#ifndef WITH_HTTPD
int LOGLEVEL = DEF_DEBUG_MODE ? DM_LOG_LEVEL_MAX : DM_LOG_LEVEL_EMERG;
#endif

typedef enum {
    NONE=0,
    CONNECTED,
    DISCONNECTED
}connection_status;

#define PRE_RESERVED_HTTP_HEADER_SIZE 256
#define TABLE_INIT_SZ 32

struct _client_data {
    int fd;
    int connection_status;
    rw_buff *rb, *wb;
    connection_status status;

    /* Response variables */
    const uint8_t *response_data;
    uint32_t response_data_len;
    int response_code;
    const char *response_msg;

    apr_table_t *headers;

#ifdef ENABLE_HTTPS
    /* HTTPS options */
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
#endif
};
static __thread struct _client_data client_data = {-1, 0, NULL, NULL, NONE, NULL, 0, 0, NULL, NULL
#ifdef ENABLE_HTTPS
, NULL, NULL, NULL
#endif
};

__thread struct _client_config *client_config = NULL;

static int
header_callback(const char *p1, const char *p2, const char *p3)
{
    DM_LOG_DEBUG("HTTP HEADER [%s %s %s]", p1, p2, p3);

    client_data.response_code = atoi(p2);
    client_data.response_msg = p3;

    return SUCCESS;
}

static int
param_callback(const char *key, const char *value)
{
    DM_LOG_TRACE("HTTP PARAM Key[%s] Value[%s]", key, value);

    if (client_data.headers != NULL) {
        apr_table_set(client_data.headers, key, value);
    }

    return SUCCESS;
}

static int
data_callback(const uint8_t *data, int dlen)
{
    DM_LOG_DEBUG("POST Data received length: %d", dlen);
    DM_LOG_TRACE("DATA [len: %d data: '%s']", dlen, data);
    client_data.response_data = data;
    client_data.response_data_len = dlen;

    return SUCCESS;
}

#ifdef ENABLE_HTTPS
static int
https_init(int fd, int *max_timeout_ms)
{
    char errormsg[1024];

    // cleanup old SSL data
    if (client_data.ssl) {
        if (client_data.fd > 0) {
            ssl_shutdown(client_data.ssl, client_data.fd, max_timeout_ms);
        }
        SSL_free(client_data.ssl);
        client_data.ssl = NULL;
    }
    if (client_data.fd > 0) {
        NG_CLOSE(client_data.fd);
        client_data.fd = -1;
    }
    if (client_data.ctx) {
        SSL_CTX_free(client_data.ctx);
        client_data.ctx = NULL;
    }

    int ret = SUCCESS;
    int ssl_connect_ret = SUCCESS;

    short revents;

    /* Set SSL/TLS client hello */
    if (client_config->proto_type == PROTO_TLS_1_0) {
        client_data.ctx = SSL_CTX_new(TLSv1_client_method());
    } else if (client_config->proto_type == PROTO_TLS_1_1) {
        #ifdef TLSv1_1_client_method
            client_data.ctx = SSL_CTX_new(TLSv1_1_client_method());
        #else
            client_data.ctx = SSL_CTX_new(TLSv1_client_method());
        #endif
    } else if (client_config->proto_type == PROTO_TLS_1_2) {
        #ifdef TLSv1_2_client_method
            client_data.ctx = SSL_CTX_new(TLSv1_2_client_method());
        #else
            client_data.ctx = SSL_CTX_new(TLSv1_client_method());
        #endif
    } else {
        DM_LOG_ERROR("Invalid protocol[%d]", client_config->proto_type);
        ret = FAILURE;
        goto end;
    }

    if (client_data.ctx == NULL) {
        ERR_error_string(ERR_get_error(), errormsg);
        DM_LOG_ERROR("Unable to create a new SSL context structure: %s", errormsg);
        ret = FAILURE;
        goto end;
    }

    /* Disabling SSLv2 and SSLv3, will leave TSLv1, TSLv1.1 and TSLv1.2 for negotiation */
    SSL_CTX_set_options(client_data.ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(client_data.ctx, SSL_OP_NO_SSLv3);

    /* Create new SSL connection state object */
    client_data.ssl = SSL_new(client_data.ctx);
    if (client_data.ssl == NULL) {
        DM_LOG_ERROR("Unable to create a new SSL");
        ret = FAILURE;
        goto end;
    }

    /* prepare SSL object to work in client mode */
    SSL_set_connect_state(client_data.ssl);

    /* Attach the SSL session to the socket descriptor */
    SSL_set_fd(client_data.ssl, fd);

    for (;;) {
        ssl_connect_ret = SSL_connect(client_data.ssl);
        if (ssl_connect_ret == 1) {
            ret = SUCCESS;
            break;
        }

        ret = ssl_wait_socket(client_data.ssl, ssl_connect_ret, fd, POLLHUP | POLLOUT | POLLIN, &revents, max_timeout_ms);
        if (ret == 0) {
            DM_LOG_DEBUG("SSL_connect timed");
            ret = TIMED_OUT;
            goto end;
        }
        if (ret == -1 || revents & POLLERR) {
            DM_LOG_DEBUG("SSL_connect failed, ret: %d, revents %d", ret, revents);
            ret = FAILURE;
            goto end;
        }
        if (revents & POLLHUP) {
            DM_LOG_DEBUG("SSL_connect failed: socket closed");
            ret = FAILURE;
            goto end;
        }
    }

    DM_LOG_DEBUG("Successfully enabled SSL/TLS session");

end:
    if (ret != SUCCESS) {
        /* Free the structures we don't need anymore */
        if (client_data.ssl) {
            if (client_data.fd > 0) {
                ssl_shutdown(client_data.ssl, client_data.fd, max_timeout_ms);
            }
            SSL_free(client_data.ssl);
            client_data.ssl = NULL;
        }
        if (client_data.fd > 0) {
            NG_CLOSE(client_data.fd);
            client_data.fd = -1;
        }
        if (client_data.ctx) {
            SSL_CTX_free(client_data.ctx);
            client_data.ctx = NULL;
        }
    }
    return ret;
}
#endif

static int
connect_to_api_server(int *max_timeout_ms)
{
    short revents;
    int fd = -1, ret = SUCCESS;
    struct sockaddr_in serv;
    int socket_flags = SOCK_STREAM;
    
#if defined(SOCK_CLOEXEC)
    socket_flags |= SOCK_CLOEXEC;
#endif

    if ((fd = socket(AF_INET, socket_flags, 0)) < 0) {
        DM_LOG_ERROR("socket(AF_INET, SOCK_STREAM) failed due to '%s'", strerror(errno));
        ret = FAILURE;
        goto end;
    }

    set_socketopt_nodelay(fd, 1);
#if defined(TCP_QUICKACK)
    set_socketopt_quickack(fd, 0);
#endif

    socket_flags = fcntl(fd, F_GETFL, 0);
    if (socket_flags == -1) {
        DM_LOG_ERROR("fcntl(F_GETFL) failed due to '%s'", strerror(errno));
        ret = FAILURE;
        goto end;
    }

    socket_flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, socket_flags) == -1 ) {
        DM_LOG_ERROR("fcntl(F_SETFL, O_NONBLOCK) failed due to '%s'", strerror(errno));
        ret = FAILURE;
        goto end;
    }

    memset(&serv, 0 ,sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(client_config->server_port);
    serv.sin_addr = client_config->server_ip;

    DM_LOG_DEBUG("trying to connect with %s:%d", inet_ntoa(client_config->server_ip), client_config->server_port);
    ret = connect(fd, (struct sockaddr *)&serv, sizeof(serv));
    if (ret == -1) {
        if (errno != EINPROGRESS) {
            DM_LOG_DEBUG("connect() failed: %d: %s", errno, strerror(errno));
            ret = FAILURE;
            goto end;
        }
        ret = wait_socket(fd, POLLHUP | POLLOUT, &revents, max_timeout_ms);
        if (ret == 0) {
            DM_LOG_DEBUG("connect timed");
            ret = TIMED_OUT;
            goto end;
        }
        if (ret == -1 || revents & POLLERR) {
            DM_LOG_DEBUG("connect failed, ret: %d, revents: %d", ret, revents);
            ret = FAILURE;
            goto end;
        }
        if (revents & POLLHUP) {
            DM_LOG_DEBUG("connect failed: socket closed");
            ret = FAILURE;
            goto end;
        }
    }
    DM_LOG_DEBUG("client successfully connected with %s:%d",
        inet_ntoa(client_config->server_ip), client_config->server_port);
#ifdef ENABLE_HTTPS
    if (client_config->proto_type != PROTO_HTTP) {
        ret = https_init(fd, max_timeout_ms);
        if (ret != SUCCESS) {
            goto end;
        }
    }
#endif
    client_data.fd = fd;
    client_data.status = CONNECTED;
    return ret;

end:
    NG_CLOSE(fd);
    return ret;
}

int
http_client_init(int *max_timeout_ms)
{
    int ret = SUCCESS, zero_timeout = 0;
    short revents;

    if (client_data.wb == NULL) {
        if (MAX_PARAM_DATALEN + PRE_RESERVED_HTTP_HEADER_SIZE > DEFAULT_BUF_SIZE ) {
          client_data.wb = create_rw_buff(MAX_PARAM_DATALEN + PRE_RESERVED_HTTP_HEADER_SIZE);
        } else {
          client_data.wb = create_rw_buff(DEFAULT_BUF_SIZE);
        }
    }
    if (client_data.wb == NULL) {
        return FAILURE;
    }
    if (client_data.rb == NULL) {
        client_data.rb = create_rw_buff(DEFAULT_BUF_SIZE);
    }
    if (client_data.rb == NULL) {
        return FAILURE;
    }
    if (client_data.status == CONNECTED) {
        DM_LOG_TRACE("Check that socket still alive");
        // check if socket is still alive
        ret = wait_socket(client_data.fd, POLLHUP | POLLOUT, &revents, &zero_timeout); // we want block here
        if (ret == 0 || revents & POLLERR) {
            DM_LOG_DEBUG("Reconnect to server, because socket has error, ret: %d, revents: %d", ret, revents);
            client_data.status = DISCONNECTED;
            NG_CLOSE(client_data.fd);
        } else if (revents & POLLHUP) {
            DM_LOG_DEBUG("Reconnect to server, because socket has been closed");
            client_data.status = DISCONNECTED;
            NG_CLOSE(client_data.fd);
        }
        ret = SUCCESS;
    }

    if (client_data.status != CONNECTED) {
        ret = connect_to_api_server(max_timeout_ms);
        if(ret == SUCCESS){
          ret = RECONNECTION;
        }
    }

    return ret;
}

void
http_client_reset()
{
    if (client_data.wb) {
        reset_rw_buff(client_data.wb);
    }
    if (client_data.rb) {
        reset_rw_buff(client_data.rb);
    }
}

void
http_close_connection(int *max_timeout_ms)
{
    if (client_data.wb) {
        FREE_RW_BUFF(client_data.wb);
    }
    DM_LOG_TRACE("client_data.wb is free");

    if (client_data.rb) {
        FREE_RW_BUFF(client_data.rb);
    }
    DM_LOG_TRACE("client_data.rb is free");

    if (client_data.fd > 0) {
#ifdef ENABLE_HTTPS
        if (client_config->proto_type != PROTO_HTTP) {
            ssl_shutdown(client_data.ssl, client_data.fd, max_timeout_ms);
        }
#endif
        NG_CLOSE(client_data.fd);
    }
    client_data.status = NONE;
}

static int
prepare_http_header(rw_buff *wbuf)
{
    int content_len = wbuf->off - PRE_RESERVED_HTTP_HEADER_SIZE;
    uint8_t *buf = NULL;
    int ret = SUCCESS, nret = 0, size = 0;

again:
    nret = snprintf((char *)buf, size, "POST %s HTTP/1.1\r\n"\
                    "Host: %s\r\nConnection: keep-alive\r\nAccept: text/html\r\n"\
                    "Content-Type: %s\r\n%sContent-Length: %d\r\n\r\n",
                    client_config->server_uri, client_config->server_hostname,
                    CONTENT_TYPE, EXTRA_HEADERS, content_len);
    if (buf == NULL) {
        if (nret > PRE_RESERVED_HTTP_HEADER_SIZE) {
            DM_LOG_ERROR("trying very long http header");
            ret = FAILURE;
            goto end;
        } else {
            buf = wbuf->buf + PRE_RESERVED_HTTP_HEADER_SIZE - nret;
            size = nret;
            goto again;
        }
    }
    buf[nret-1] = '\n';
    wbuf->rw_len -= nret;

end:
    return ret;
}


char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

const char *url_encode_start(const char *str, ssize_t value_len, ssize_t limit) {
  do {
    str--;
    value_len--;
    limit--;
    if (!isalnum(*str) && *str != '-' && *str != '_' && *str != '.' && *str != '~' && *str != ' ') {
      limit -= 2;
    }
  } while (value_len > 0 && limit > 0);

  return str;
}

ssize_t url_encode(const char *str, unsigned char *buf, ssize_t value_len, ssize_t limit) {
  const char *pstr = str;
  unsigned char *pbuf = buf;

  while (value_len && *pstr && limit) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
      *pbuf++ = *pstr;
      limit--;
    } else if (*pstr == ' ') {
      *pbuf++ = '+';
      limit--;
    } else {
      if (limit < 3) {
        break;
      }
      *pbuf++ = '%';
      *pbuf++ = to_hex(*pstr >> 4);
      *pbuf++ = to_hex(*pstr & 15);
      limit -= 3;
    }
    pstr++;
    if (value_len > 0) {
      value_len--;
    }
  }

  return pbuf-buf;
}


int
append_param(const char *name, int nlen, const char *value, int vlen, int limit, int use_url_encode, unsigned from_end)
{
    int ret = SUCCESS;

    DM_LOG_TRACE("Name[%s] Nlen[%d] Value[%s] Vlen[%d]", name, nlen, value, vlen);

    ssize_t max_length = vlen * (use_url_encode ? 3 : 1);
    if (max_length > limit) {
        max_length = limit;
    }

    if (client_data.wb->size < (client_data.wb->off+nlen+max_length+PRE_RESERVED_HTTP_HEADER_SIZE)) {
        int overspace = client_data.wb->size - (client_data.wb->off+nlen+PRE_RESERVED_HTTP_HEADER_SIZE);
        max_length -= overspace;
        limit -= overspace;
    }

    ssize_t free_space = client_data.wb->size - (client_data.wb->off+nlen+PRE_RESERVED_HTTP_HEADER_SIZE);

    if (limit > free_space) {
        limit = free_space;
    }

    if (vlen > 0 && from_end && limit > 0) {
        const char* end = value + vlen;

        if (use_url_encode) {
            value = url_encode_start(end, vlen, limit);
            vlen = end - value;
        } else if (vlen > limit) {
            value = end - limit;
            vlen = end - value;
        }

    }

    if (client_data.wb->off == 0) {
        /* reserver space for HTTP header, so we can place header & data in single buffer.
            So we can write in signle shot */
        client_data.wb->off += PRE_RESERVED_HTTP_HEADER_SIZE;
        client_data.wb->rw_len = client_data.wb->off;
    } else {
        client_data.wb->buf[client_data.wb->off] = '&'; client_data.wb->off++;
    }
    if (nlen) {
        memcpy(client_data.wb->buf + client_data.wb->off, name, nlen);
        client_data.wb->off += nlen;
        client_data.wb->buf[client_data.wb->off] = '='; client_data.wb->off++;
        if (vlen) {
            if (use_url_encode) {
                client_data.wb->off += url_encode(value, client_data.wb->buf + client_data.wb->off, vlen, limit);
            } else {
                if (vlen > limit) {
                    vlen = limit;
                }
                memcpy(client_data.wb->buf + client_data.wb->off, value, vlen);
                client_data.wb->off += vlen;
            }
        }
    }

    client_data.wb->off = client_data.wb->off > MAX_PARAM_DATALEN ? MAX_PARAM_DATALEN : client_data.wb->off;

    return ret;
}

static int
safe_write(int *max_timeout_ms, int fd, rw_buff *w)
{
    int off = w->rw_len, size = w->off;
    int ret, nret = 0;

    short revents;

    DM_LOG_TRACE("Send Data [max_timeout_ms: %d, off: %d size: %d len: %d data: '%.*s']",
        *max_timeout_ms, off, size, size-off, size-off, w->buf+off);
    for ( ; off < size ; ) {
        ret = wait_socket(fd, POLLHUP | POLLOUT, &revents, max_timeout_ms);
        if (ret > 0 && revents & POLLOUT) {
#ifdef ENABLE_HTTPS
            if (client_config->proto_type != PROTO_HTTP) {
                nret = SSL_write(client_data.ssl, w->buf+off, size-off);
            } else {
#endif
                nret = send(fd, w->buf+off, size-off, 0);
#ifdef ENABLE_HTTPS
            }
#endif
            DM_LOG_DEBUG("send fd[%d] Ret[%d] Off[%d] Size[%d]", fd, nret, off, size);
            if (nret <= 0) {
                DM_LOG_DEBUG("send(%d) failed due to '%s'", fd, strerror(errno));
                return FAILURE;
            } else {
                DM_LOG_DEBUG("send(%d) returned %d", fd, nret);
                off += nret;
            }
        } else {
            if (ret == 0) {
                DM_LOG_DEBUG("socket timed out");
                return TIMED_OUT;
            }
            if (ret == -1 || revents & POLLERR) {
                DM_LOG_DEBUG("socket error, ret: %d, revents: %d", ret, revents);
                return FAILURE;
            }
            if (revents & POLLHUP) {
                DM_LOG_DEBUG("socket closed");
                return FAILURE;
            }
        }
    }

    return SUCCESS;
}

static int
read_http_response(int *max_timeout_ms, int fd, rw_buff *rbuf)
{
    int ret = SUCCESS, n = 0, wret;

    int connection_keep_alive = 0;
    int http_version_11 = 0;

    short revents;

    reset_rw_buff(rbuf);
    init_http_parser(header_callback, param_callback, data_callback);

    DM_LOG_TRACE("Readting response: max_timeout_ms: %d", *max_timeout_ms);

    for ( ;; ) {
#ifdef ENABLE_HTTPS
        if (client_config->proto_type != PROTO_HTTP) {
            n = SSL_read(client_data.ssl, rbuf->buf + rbuf->off, rbuf->size - rbuf->off - 1);
            if (n <= 0) {
                wret = ssl_wait_socket(client_data.ssl, n, fd, POLLHUP | POLLIN, &revents, max_timeout_ms);
                if (revents & POLLIN) {
                    continue;
                }
                if (wret == 0) {
                    DM_LOG_DEBUG("SSL socket timed out");
                    ret = TIMED_OUT;
                    goto end;
                }
                if (wret == -1 || revents & POLLERR) {
                    DM_LOG_DEBUG("SSL socket error, ret: %d, revents: %d", wret, revents);
                    ret = FAILURE;
                    goto end;
                }
                if (revents & POLLHUP ) {
                    DM_LOG_DEBUG("SSL socket closed");
                    ret = FAILURE;
                    goto end;
                }
            }
        } else {
#endif
            wret = wait_socket(fd, POLLHUP | POLLIN, &revents, max_timeout_ms);
            if (wret > 0 && revents & POLLIN) {
                n = recv(fd, rbuf->buf + rbuf->off, rbuf->size - rbuf->off - 1, 0);
                if (n <= 0) {
                    DM_LOG_DEBUG("recv(%d) failed due to '%s'", fd, strerror(errno));
                    ret = FAILURE;
                    goto end;
                }
            } else {
                if (wret == 0) {
                    ret = TIMED_OUT;
                    DM_LOG_DEBUG("socket timed out");
                    goto end;
                }
                if (wret == -1 || revents & POLLERR) {
                    DM_LOG_DEBUG("socket error, ret: %d, revenets: %d", wret, revents);
                    ret = FAILURE;
                    goto end;
                }
                if (revents & POLLHUP ) {
                    DM_LOG_DEBUG("socket closed");
                    ret = FAILURE;
                    goto end;
                }
            }
#ifdef ENABLE_HTTPS
        }
#endif
        DM_LOG_DEBUG("Read DATA fd[%d] Ret[%d] Off[%d] Size[%d]", fd, n, rbuf->off, rbuf->size);
        DM_LOG_TRACE("DATA [len: %d data: '%s']", n, rbuf->buf);

        rbuf->off += n;
        n = parse_http_response(rbuf->buf, rbuf->off, &http_version_11, &connection_keep_alive);
        if (n == 0) {
            ret = SUCCESS;
            break;
        } else if (n == 1) {
            continue;
        } else {
            ret = FAILURE;
            break;
        }
    }

end:
    // HTTP/1.1 use Keep-alive by default
    if (!connection_keep_alive && !http_version_11) {
        DM_LOG_DEBUG("Close socket because keep-alive: %d, http/1.1: %d", connection_keep_alive, http_version_11);
        http_close_connection(max_timeout_ms);
    }
    DM_LOG_DEBUG("Data received %s", (ret == SUCCESS) ? "successfully" : "fail");

    return ret;
}

int
http_client_post(int *max_timeout_ms, apr_pool_t *pool, apr_table_t **headers, const uint8_t **response_data, uint32_t *response_data_len,
    int *response_code, const char **response_msg)
{
    int ret = SUCCESS;
    int init_http_client_ret = SUCCESS;
    if (prepare_http_header(client_data.wb) != SUCCESS) {
        DM_LOG_DEBUG("prepare_http_header failed");
        ret = FAILURE;
        goto end;
    }
    DM_LOG_DEBUG("sending request to API server");

    while (safe_write(max_timeout_ms, client_data.fd, client_data.wb) != SUCCESS) {
        if (*max_timeout_ms <= 0) {
            ret = TIMED_OUT;
            goto end;
        }
        DM_LOG_DEBUG("retrying");
#ifdef ENABLE_HTTPS
        if (client_config->proto_type != PROTO_HTTP) {
            ssl_shutdown(client_data.ssl, client_data.fd, max_timeout_ms);
        }
#endif
        NG_CLOSE(client_data.fd);
        client_data.status = NONE;
        init_http_client_ret = http_client_init(max_timeout_ms);
        if ( init_http_client_ret == SUCCESS || init_http_client_ret == RECONNECTION) {
           continue;
        }
        ret = FAILURE;
        goto end;
    }
    DM_LOG_DEBUG("reading response from API server");
    client_data.headers = apr_table_make(pool, TABLE_INIT_SZ);
    ret = read_http_response(max_timeout_ms, client_data.fd, client_data.rb);
    if (ret != SUCCESS) {
        goto end;
    }
    *headers = client_data.headers;
    *response_data = client_data.response_data;
    *response_data_len = client_data.response_data_len;
    *response_code = client_data.response_code;
    *response_msg = client_data.response_msg;
    DM_LOG_DEBUG("Got verdict from API server: %d %s", client_data.response_code, client_data.response_msg);

    return SUCCESS;

end:
    DM_LOG_ERROR("failed to get response from API server, max_timeout_ms: %d, ret: %d", *max_timeout_ms, ret);
    http_close_connection(max_timeout_ms);
    return ret;
}

/* This function checks the client configurations, whether it's properly configured or not */
int
check_client_config(struct _client_config *cc)
{
    if (cc->server_hostname[0] == '\0') {
        DM_LOG_ERROR("Server hostname not configured");
        return FAILURE;
    } else if (cc->server_uri[0] == '\0') {
        DM_LOG_ERROR("Server URI not configured");
        return FAILURE;
    } else if (cc->server_port == 0) {
        DM_LOG_ERROR("Server port not configured");
        return FAILURE;
    } else if (cc->proto_type <= PROTO_NONE || cc->proto_type >= PROTO_MAX) {
        DM_LOG_ERROR("Protocol type not configured");
        return FAILURE;
    } else if (cc->conn_timeout <= 0) {
        DM_LOG_ERROR("Timeout should be greater then 0");
        return FAILURE;
    }

    return SUCCESS;
}

#ifdef STAND_ALONE
static int
init_server_config()
{
    char ip[32];
    client_config = calloc(1, sizeof(*client_config));

    client_config->server_port = DEF_API_PORT;
    client_config->conn_timeout = DEF_TIMEOUT_MS;
    client_config->request_timeout= DEF_REQ_TIMEOUT_MS
    client_config->server_hostname = DEF_API_HOST;
    client_config->server_uri = DEF_API_URI;
#ifdef ENABLE_HTTPS
    client_config->proto_type = strcmp(DEF_API_PROTOCOL, "HTTP") == 0 ? PROTO_HTTP : PROTO_TLS_1_2;
#else
    client_config->proto_type = PROTO_HTTP;
#endif
    if (hostname_to_ip(client_config->server_hostname, ip, sizeof(ip)) == SUCCESS) {
        client_config->server_ip.s_addr = inet_addr(ip);
    } else {
        return FAILURE;
    }

    return SUCCESS;
}

int
main()
{
    const uint8_t *response_data = NULL;
    const char *location = NULL;
    const char *rmsg = NULL;
    uint32_t response_data_len = 0;
    int ret = SUCCESS, rcode = 0;
    int init_http_client_ret = SUCCESS;

    apr_pool_t *pool;
    apr_table_t *headers;

    apr_initialize();
    apr_pool_create(&mp, NULL);


    init_server_config();

    init_http_client_ret = http_client_init();
    /* STEP-1 */
    if (init_http_client_ret != SUCCESS && init_http_client_ret != RECONNECTION) {
        ret = FAILURE;
        goto end;
    }

    /* STEP-2 */
    append_param("Param1", sizeof("param1")-1, "Value1", sizeof("Value1")-1);
    append_param("Param2", sizeof("param2")-1, "Value2", sizeof("Value2")-1);

    /* STEP-3 */
    if (http_client_post(pool, headers, &response_data, &response_data_len, &rcode, &rmsg) != SUCCESS) {
        ret = FAILURE;
        goto end;
    }
    DM_LOG_INFO("HTTP post communication successfully finished");
    DM_LOG_INFO("Response Len[%u] Data[%.*s]", response_data_len, response_data_len, response_data);

end:
    /* STEP-4 */
    /* http_client_reset() // If you are supposed to use the same connection for future request */
    http_client_cleanup();
    return ret;
}
#endif
