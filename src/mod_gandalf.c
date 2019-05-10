/* Include the required headers from httpd */
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_base64.h"
#define CORE_PRIVATE /* for ap_top_module */
#include "http_config.h"

#include "include/common.h"

#define MODULE_VERSION "2.41"
#define DEF_SERVERNAME "DataDome"
#define REFRESH_IN (5 * 60)

#define DOME_LOGF_EMERG(str, arg...) ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, str, ##arg)
#define get_dome_srv_cfg(srv) (struct _client_config *) ap_get_module_config(srv->module_config, &gandalf_module)
#define get_dome_cfg(r) (struct _client_config *) ap_get_module_config(r->per_dir_config, &gandalf_module)

#define ENABLE  1
#define DISABLE 0
#define IS_ENABLED(s) ((s)->flag)
#define SET_FLAG(s, f) (s)->flag = f

/* DOME module status */
typedef enum {
    DOME_OFF=0,     /* Off */
    DOME_LEARNING,  /* Learning */
    DOME_FILTERING, /* Filtering */
    DOME_AUTO,      /* Auto */
} DOME_STATUS;

struct _string_ident {
    const char *string;
    uint16_t ident;
    uint8_t length;
    uint8_t flag;
    uint16_t max_length;
    uint16_t use_url_encode;
    uint16_t from_end;
};

struct client_id {
  char         *client_id;
};

#define FILL_STR_IDENT(n, s, f, m, e, fe) {.string=s, .length=sizeof(s)-1, .ident=n, .flag=f, .max_length=m, .use_url_encode=e, .from_end=fe}
#define LAST_STR_IDENT {NULL, 0, 0, 0, 0, 0}

/* DOME parameter list */
typedef enum {
    DOME_PARAM_KEY,
    DOME_PARAM_USERAGENT,
    DOME_PARAM_IP,
    DOME_PARAM_PORT,
    DOME_PARAM_CLIENTID,
    DOME_PARAM_HOST,
    DOME_PARAM_REFERER,
    DOME_PARAM_REQUEST,
    DOME_PARAM_PROTOCOL,
    DOME_PARAM_METHOD,
    DOME_PARAM_COOKIE_LEN,
    DOME_PARAM_AUTHORIZATION_LEN,
    DOME_PARAM_X_REQUESTED_WITH,
    DOME_PARAM_ORIGIN,
    DOME_PARAM_TIMEREQUEST,
    DOME_PARAM_SERVERHOSTNAME,
    DOME_PARAM_MODULEVERSION,
    DOME_PARAM_POSTPARAM_LEN,
    DOME_PARAM_SERVERNAME,
    DOME_PARAM_XFORWAREDFORIP,
    DOME_PARAM_HEADERSLIST,
    DOME_PARAM_ACCEPT,
    DOME_PARAM_ACCEPT_CHARSET,
    DOME_PARAM_ACCEPT_ENCODING,
    DOME_PARAM_ACCEPT_LANGUAGE,
    DOME_PARAM_CONNECTION,
    DOME_PARAM_PRAGMA,
    DOME_PARAM_CACHE_CONTROL,
    DOME_PARAM_CONNECTIONSTATE,
    DOME_PARAM_MODULENAME,
    DOME_PARAM_CONTENT_TYPE,
    DOME_PARAM_FROM,
    DOME_PARAM_X_REAL_IP,
    DOME_PARAM_VIA,
    DOME_PARAM_TRUE_CLIENT_IP,
} DOME_PARAMLIST;

/* DOME parameter list
    Formate : PARAM_ID, "PARAM_NAME", ENABLE/DISABLE, MAX length */
struct _string_ident dome_param_list[] = {
    FILL_STR_IDENT(DOME_PARAM_KEY, "Key", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_USERAGENT, "UserAgent", ENABLE, 768, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_IP, "IP", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_PORT, "Port", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_CLIENTID, "ClientID", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_HOST, "Host", ENABLE, 512, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_REFERER, "Referer", ENABLE, 1024, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_REQUEST, "Request", ENABLE, 2048, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_PROTOCOL, "Protocol", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_METHOD, "Method", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_COOKIE_LEN, "CookiesLen", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_AUTHORIZATION_LEN, "AuthorizationLen", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_X_REQUESTED_WITH, "X-Requested-With", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_ORIGIN, "Origin", ENABLE, 512, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_SERVERHOSTNAME, "ServerHostname", ENABLE, 512, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_MODULEVERSION, "ModuleVersion", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_POSTPARAM_LEN, "PostParamLen", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_SERVERNAME, "ServerName", ENABLE, 512, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_XFORWAREDFORIP, "X-Forwarded-For", ENABLE, 512, 1, 1),
    FILL_STR_IDENT(DOME_PARAM_HEADERSLIST, "HeadersList", ENABLE, 512, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_ACCEPT, "Accept", ENABLE, 512, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_ACCEPT_CHARSET, "AcceptCharset", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_ACCEPT_ENCODING, "AcceptEncoding", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_ACCEPT_LANGUAGE, "AcceptLanguage", ENABLE, 256, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_CONNECTION, "Connection", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_PRAGMA, "Pragma", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_CACHE_CONTROL, "CacheControl", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_CONNECTIONSTATE, "APIConnectionState", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_MODULENAME, "RequestModuleName", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_TIMEREQUEST, "TimeRequest", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_PARAM_CONTENT_TYPE, "ContentType", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_FROM, "From", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_X_REAL_IP, "X-Real-IP", ENABLE, 128, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_VIA, "Via", ENABLE, 256, 1, 0),
    FILL_STR_IDENT(DOME_PARAM_TRUE_CLIENT_IP, "TrueClientIP", ENABLE, 128, 1, 0),
    LAST_STR_IDENT
};

struct _string_ident dome_status_list[] = {
    FILL_STR_IDENT(DOME_OFF, "Off", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_LEARNING, "Learning", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_FILTERING, "Filtering", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_AUTO, "Auto", ENABLE, -1, 0, 0),
    FILL_STR_IDENT(DOME_AUTO, "On", ENABLE, -1, 0, 0),
    LAST_STR_IDENT
};

/* DOME configurations */
struct _dome_config {
    DOME_STATUS dome_status;    /* DOME status : DOME_STATUS */
    const char *key;    /* Customer KEY */
    const char *cookie; /* Client Cookie name */
    long refresh_in;
    int do_not_refresh;
    const char *servername; /* ServerName from /etc/hostname */

    ap_regex_t uri_preg;
    const char *uri_reg;

    ap_regex_t uri_preg_exclusion;
    const char *uri_reg_exclusion;
};

static __thread uint32_t connection_state = SUCCESS;
static __thread long last_refresh;
static __thread apr_table_t *responsed_headers = NULL;
static __thread struct timeval tv;

/* Define prototypes of our functions in this module */
static int dome_match_regex_handler(request_rec *r);
static int dome_handler(request_rec *r);
static int dome_evaluate_headers_handler(request_rec *r);
static void init_dome_connection(apr_pool_t *p, server_rec *s);

__thread server_rec *datadome_shield_server_rec = NULL;

static int
match_string_from_array(const char *str_arr[], const char *str, int def_ret)
{
    int i = 0;

    for (i=0 ; str_arr[i] != NULL && strcasecmp(str_arr[i], str) != 0 ; i++);
    i = (str_arr[i] == NULL) ? def_ret : i;

    return i;
}

static struct _string_ident *
find_string_ident(struct _string_ident *s, const char *str, int (cmp)(const char *s1, const char *s2))
{
    int i=0;

    for (i=0 ; s[i].string && cmp(str, s[i].string) ; i++);
    return (s[i].string) ? &s[i] : NULL ;
}

static void
validate_config(struct _client_config *cc)
{
    struct _dome_config *dc = cc->extra_config;

    cc->server_ip.s_addr = hostname_to_ip(cc->server_hostname);
    if (cc->server_ip.s_addr != INADDR_NONE) {
        cc->config_validated = SUCCESS;
        memset(&tv, 0, sizeof(tv));

        gettimeofday(&tv, NULL);
        last_refresh = tv.tv_sec;
        return;
    }


    cc->server_ip.s_addr = inet_addr(cc->server_hostname);
    if (cc->server_ip.s_addr != INADDR_NONE) {
        cc->config_validated = SUCCESS;
        dc->do_not_refresh = 1;
        return;
    }

    DM_LOG_ERROR("failed to resolve hostname [%s]", cc->server_hostname);
}

static const char*
dome_config_parse_deprecated(cmd_parms *parms, void *cfg, int argc, char *const argv[]) {
    const char*(*real)(cmd_parms *parms, void *mconfig, int argc, char *const argv[]);

    real = parms->cmd->cmd_data;

    DM_LOG_ERROR("%s is deprecated, use Dome%s", parms->cmd->name, parms->cmd->name);

    return real(parms, cfg, argc, argv);
}

/* This function parse the dome configurations and keep it in appropriate structure */
static const char *
dome_config_parser(cmd_parms *parms, void *cfg, int argc, char *const argv[])
{
    int n = 0;
    // get server config from default server
    struct _client_config *cc = get_dome_srv_cfg(parms->server);
    struct _dome_config *dc = (struct _dome_config *)(((struct _client_config *)cfg)->extra_config);
    struct _string_ident *s = NULL;

    DM_LOG_DEBUG("dome_config_parser: srv: %ld, cc: %ld, dc: %ld, cfg: %ld", (long)parms->server, (long)cc, (long)dc, (long)cfg);

    /* Every configuration required atleast 1 argument */
    if (argc < 1) {
        return "Requires at least one arguments";
    }

    if (!strcasecmp(parms->cmd->name, "Key") || !strcasecmp(parms->cmd->name, "DomeKey")) {
        if (strlen(argv[0]) > 20 || strlen(argv[0]) < 15) {
            return "Invalid \"Dome Key\", Key should be 15-20 chars";
        }
        dc->key = argv[0];
    } else if (!strcasecmp(parms->cmd->name, "DomeCookieName")) {
        dc->cookie = argv[0];
    } else if (!strcasecmp(parms->cmd->name, "DomeRefreshIN")) {
        dc->refresh_in = atoi(argv[0]);
    } else if (!strcasecmp(parms->cmd->name, "DomeStatus")) {
        s = find_string_ident(dome_status_list, argv[0], strcasecmp);
        if (s == NULL) {
            return "Invalid DomeStatus";
        }
        dc->dome_status = s->ident;
    } else if (!strcasecmp(parms->cmd->name, "DataExclude") || !strcasecmp(parms->cmd->name, "DomeDataExclude")) {
        for (n=0 ; n<argc ; n++) {
            s = find_string_ident(dome_param_list, argv[n], strcasecmp);
            if (s) {
                SET_FLAG(s, 0);
            }
        }
    } else if (!strcasecmp(parms->cmd->name, "ApiURI") || !strcasecmp(parms->cmd->name, "DomeApiURI")) {
        cc->server_uri = argv[0];
    } else if (!strcasecmp(parms->cmd->name, "ApiHost") || !strcasecmp(parms->cmd->name, "DomeApiHost")) {
        cc->server_hostname = argv[0];
        cc->server_ip.s_addr = 0;
    } else if (!strcasecmp(parms->cmd->name, "ApiPort") || !strcasecmp(parms->cmd->name, "DomeApiPort")) {
        if (atoi(argv[0]) > 65535 || atoi(argv[0]) < 0) {
            return "Invalid ApiPort";
        }
        cc->server_port = atoi(argv[0]);
    } else if (!strcasecmp(parms->cmd->name, "DomeTimeOut")) {
        if (atoi(argv[0]) <= 0) {
            return "Timeout should be greater than 0 milliseconds";
        }
        cc->conn_timeout = atoi(argv[0]);
    } else if (!strcasecmp(parms->cmd->name, "RequestTimeOut") || !strcasecmp(parms->cmd->name, "DomeRequestTimeOut")) {
        if (atoi(argv[0]) <= 0) {
            return "RequestTimeOut should be greater than 0 milliseconds";
        }
        cc->request_timeout = atoi(argv[0]);
    } else if (!strcasecmp(parms->cmd->name, "URIRegex") || !strcasecmp(parms->cmd->name, "DomeURIRegex")) {
        if (ap_regcomp(&dc->uri_preg, argv[0], AP_REG_ICASE) != APR_SUCCESS) {
            return "Invalid URIRegex config, It should be valid PCRE regex";
        }
        dc->uri_reg = apr_pstrdup(cc->pool, argv[0]);
    } else if (!strcasecmp(parms->cmd->name, "URIRegexExclusion") || !strcasecmp(parms->cmd->name, "DomeURIRegexExclusion")) {
        if (ap_regcomp(&dc->uri_preg_exclusion, argv[0], AP_REG_ICASE) != APR_SUCCESS) {
            return "Invalid URIRegexExclusion config, It should be valid PCRE regex";
        }
        dc->uri_reg_exclusion = apr_pstrdup(cc->pool, argv[0]);
    } else if (!strcasecmp(parms->cmd->name, "ApiProtocol") || !strcasecmp(parms->cmd->name, "DomeApiProtocol")) {
        const char *proto_list[] = {"HTTP", "HTTPS"};
        if ((n = match_string_from_array(proto_list, argv[0], -1)) == -1) {
            return "Invalid ApiProtocol";
        }
        cc->proto_type = (n == 0) ? PROTO_HTTP : PROTO_TLS_1_2;
    } else {
        return "Invalid config option";
    }

    validate_config(cc);

    return NULL;
}

#define ADD_CONFIG_CMD_GLOBAL(cmd, help) AP_INIT_TAKE_ARGV(cmd, dome_config_parser, NULL, RSRC_CONF, help)
#define ADD_CONFIG_CMD_LOCAL(cmd, help) AP_INIT_TAKE_ARGV(cmd, dome_config_parser, NULL, OR_ALL, help)

#define ADD_CONFIG_CMD_DEPRECATED_GLOBAL(cmd, help) AP_INIT_TAKE_ARGV(cmd, dome_config_parse_deprecated, (void *)dome_config_parser, RSRC_CONF, help)
#define ADD_CONFIG_CMD_DEPRECATED_LOCAL(cmd, help) AP_INIT_TAKE_ARGV(cmd, dome_config_parse_deprecated, (void *)dome_config_parser, OR_ALL, help)

static const command_rec dome_config_cmds[] = {
    ADD_CONFIG_CMD_DEPRECATED_LOCAL("Key", "15 charactors customer Key (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_GLOBAL("DataExclude", "Parameter(s) we won't send to the API"),
    ADD_CONFIG_CMD_DEPRECATED_GLOBAL("ApiHost", "The host to access the API (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_GLOBAL("ApiPort", "The port to access the API (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_GLOBAL("ApiURI", "The uri to access the API (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_LOCAL("URIRegex", "URI regex to handle (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_LOCAL("URIRegexExclusion", "URI regex to exclusion (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_GLOBAL("ApiProtocol", "API protocol [HTTP/HTTPS] (deprecated)"),
    ADD_CONFIG_CMD_DEPRECATED_GLOBAL("RequestTimeOut", "Timeout within which API Server neds to start responding (deprecated)"),

    ADD_CONFIG_CMD_LOCAL("DomeKey", "15 charactors customer Key"),
    ADD_CONFIG_CMD_LOCAL("DomeCookieName", "DataDome ClientID cookie name"),
    ADD_CONFIG_CMD_GLOBAL("DomeRefreshIN", "DataDome will refresh DNS records each N seconds"),
    ADD_CONFIG_CMD_LOCAL("DomeStatus", "DOME status [ Off, Learning, Filtering, Auto ]"),
    ADD_CONFIG_CMD_GLOBAL("DomeDataExclude", "Parameter(s) we won't send to the API"),
    ADD_CONFIG_CMD_GLOBAL("DomeApiURI", "The uri to access the API"),
    ADD_CONFIG_CMD_GLOBAL("DomeApiHost", "The host to access the API"),
    ADD_CONFIG_CMD_GLOBAL("DomeApiPort", "The port to access the API"),
    ADD_CONFIG_CMD_GLOBAL("DomeTimeOut", "API response timeout in milliseconds"),
    ADD_CONFIG_CMD_LOCAL("DomeURIRegex", "URI regex to handle"),
    ADD_CONFIG_CMD_LOCAL("DomeURIRegexExclusion", "URI regex to exclusion"),
    ADD_CONFIG_CMD_GLOBAL("DomeApiProtocol", "API protocol [HTTP/HTTPS]"),
    ADD_CONFIG_CMD_GLOBAL("DomeRequestTimeOut", "Timeout within which API Server neds to start responding"),
    { NULL }
};

#ifdef ENABLE_HTTPS
static int dome_hook_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{

    module *modp;
    for (modp = ap_top_module; modp; modp = modp->next) {
        if (strcmp(modp->name, "mod_ssl.c") == 0) {
            return OK;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
      "mod_datadome.c requires mod_ssl.c, you should load it or disable SSL support");

    return HTTP_INTERNAL_SERVER_ERROR;
}
#endif

/* Adds a hook to the httpd process for dome module */
static void dome_hooks(apr_pool_t *pool)
{
#ifdef ENABLE_HTTPS
    static const char *const mod_ssl[] = { "mod_ssl.c", NULL};

    ap_hook_pre_config(dome_hook_pre_config, mod_ssl, NULL, APR_HOOK_MIDDLE);
#endif
#ifdef PRE_INIT_CONNECTION
    ap_hook_child_init(init_dome_connection, NULL, NULL, APR_HOOK_FIRST);
#endif
    ap_hook_handler(dome_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_handler(dome_evaluate_headers_handler, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_hook_header_parser(dome_match_regex_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static void lookup_client_id(request_rec *r, struct client_id *client_id)
{
  const char *cp;
  char       *end;

  struct _dome_config *dc = ((struct _client_config *)get_dome_cfg(r))->extra_config;

  memset(client_id, 0, sizeof(struct client_id));

  cp = apr_table_get(r->headers_in, "Cookie");
  if (cp != NULL) {
    while (1) {
      cp = strstr((char *)cp, dc->cookie);
      if (cp == NULL) {
	break;
      }

      cp += strlen(dc->cookie);

      while (*cp == ' ') {
	cp++;
      }

      if (*cp != '=') {
	cp++;
	continue;
      }

      cp++; //skip =

      while (*cp == ' ') {
	cp++;
      }

      end = strchr(cp, ';');
      if (end == NULL) {
	end = (char *)(cp + strlen(cp));
      }

      client_id->client_id = apr_pcalloc(r->pool, end - cp + 1);
      if (client_id->client_id == NULL) {
        return;
      }

      memcpy(client_id->client_id, cp, end - cp);
    }
  }
}


struct headers {
    char *pos;
    char *end;
    apr_size_t count;
};


static int count_headers(void *h_, const char *key, const char *value)
{
    struct headers *h = h_;

    h->count += strlen(key) + 1;

    return TRUE;
}

static int join_headers(void *h_, const char *key, const char *value)
{
    struct headers *h = h_;

    for (; *key; key++, h->pos++) {
        *h->pos = tolower(*key);
    }

    if (h->pos + 1 == h->end) {
        *h->pos = '\0';
        return FALSE;
    }

    *h->pos = ',';
    h->pos++;

    return TRUE;
}

/* Get HTTP headers */
static void
get_http_headers(request_rec *r)
{
    const char *param, *tmp;
    char curr_time[64];
    uint32_t i, param_len;
    int ret = SUCCESS;
    int n_headers=0;
    struct client_id client_id;
    struct headers headers_in;

    struct _dome_config *dc = ((struct _client_config *)get_dome_cfg(r))->extra_config;

    lookup_client_id(r, &client_id);

    for (i=0 ; ret == SUCCESS && dome_param_list[i].string ; i++) {
        if (!IS_ENABLED(&dome_param_list[i])) {
            DM_LOG_DEBUG("Bypassing Param[%s]", dome_param_list[i].string);
            continue;
        }
        n_headers++;
        param = NULL; param_len=0;
        switch (dome_param_list[i].ident) {
            case DOME_PARAM_KEY:
                param = dc->key;
                break;
            case DOME_PARAM_USERAGENT:
                param = apr_table_get(r->headers_in, "User-Agent");
                break;
            case DOME_PARAM_IP:
#if (AP_SERVER_MINORVERSION_NUMBER == 2)
                param = (r->connection) ? r->connection->remote_ip : "0.0.0.0";
#else
                param = r->useragent_ip;
#endif
                break;
            case DOME_PARAM_PORT:
	        if (!r->connection) {
		    param = "0";
		    break;
		}
#if (AP_SERVER_MINORVERSION_NUMBER == 2)
		param = apr_psprintf(r->pool, "%u", r->connection->remote_addr->port);
#else
		param = apr_psprintf(r->pool, "%u", r->connection->client_addr->port);
#endif
                break;
            case DOME_PARAM_CLIENTID:
                param = client_id.client_id;
                break;
            case DOME_PARAM_HOST:
                param = apr_table_get(r->headers_in, "Host");
                break;
            case DOME_PARAM_REFERER:
                param = apr_table_get(r->headers_in, "Referer");
                break;
            case DOME_PARAM_REQUEST:
                param = r->unparsed_uri; /* GET /test.html HTTP/1.1 */
                tmp = strchr(param, ' ');
                if (tmp == NULL) break;
                param = tmp++;
                tmp = strchr(param, ' ');
                if (tmp == NULL) break;
                param_len = (uint8_t *)tmp - (uint8_t *)param;
                break;
            case DOME_PARAM_PROTOCOL:
                param = (char *) ap_http_scheme(r);
                break;
            case DOME_PARAM_METHOD:
                param = r->method;
                break;
            case DOME_PARAM_COOKIE_LEN:
                tmp = apr_table_get(r->headers_in, "Cookie");
                if (tmp == NULL) {
                    tmp = "";
                }
                param_len = sizeof("2147483647") - 1;
                param = apr_pcalloc(r->pool, param_len + 1);
                if (param == NULL) {
                    return;
                }
                param_len = snprintf((char *)param, param_len, "%d", (int)strlen(tmp));
                break;
            case DOME_PARAM_AUTHORIZATION_LEN:
                tmp = apr_table_get(r->headers_in, "Authorization");
                if (tmp == NULL) {
                    tmp = "";
                }
                param_len = sizeof("2147483647") - 1;
                param = apr_pcalloc(r->pool, param_len + 1);
                if (param == NULL) {
                    return;
                }
                param_len = snprintf((char *)param, param_len, "%d", (int)strlen(tmp));
                break;
            case DOME_PARAM_X_REQUESTED_WITH:
                param = apr_table_get(r->headers_in, "X-Requested-With");
                break;
            case DOME_PARAM_ORIGIN:
                param = apr_table_get(r->headers_in, "Origin");
                break;
            case DOME_PARAM_TIMEREQUEST:
                memset(&tv, 0, sizeof(tv));

                gettimeofday(&tv, NULL);
                /* Want to send UTC time in milliseconds */
                snprintf(curr_time, sizeof(curr_time), "%li%06li",
                     (long)tv.tv_sec, (long)tv.tv_usec);

                param = (const char *)curr_time;
                break;
            case DOME_PARAM_SERVERHOSTNAME:
                param = r->server->server_hostname;
                break;
            case DOME_PARAM_MODULEVERSION:
                param = MODULE_VERSION;
                break;
            case DOME_PARAM_POSTPARAM_LEN:
                param = apr_table_get(r->headers_in, "Content-Length");
                if (param == NULL) {
                    if (r->chunked) {
                        param = "-1";
                    } else {
                        param = "0";
                    }
                }
                break;
            case DOME_PARAM_SERVERNAME:
                param = dc->servername;
                if (param == NULL) {
                    param = DEF_SERVERNAME;
                }
                break;
            case DOME_PARAM_XFORWAREDFORIP:
                param = apr_table_get(r->headers_in, "X-Forwarded-For");
                break;
            case DOME_PARAM_HEADERSLIST:

                param_len = 0;
                param = NULL;

                memset(&headers_in, 0, sizeof(struct headers));
                apr_table_do(count_headers, &headers_in, r->headers_in, NULL);

                if (headers_in.count > 0) {
                    param = apr_palloc(r->pool, headers_in.count);
                }

                if (param != NULL) {
                    headers_in.pos = (char *)param;
                    headers_in.end = (char *)param + headers_in.count;
                    apr_table_do(join_headers, &headers_in, r->headers_in, NULL);
                }

                break;
            case DOME_PARAM_ACCEPT:
                param = apr_table_get(r->headers_in, "Accept");
                break;
            case DOME_PARAM_ACCEPT_CHARSET:
                param = apr_table_get(r->headers_in, "Accept-Charset");
                break;
            case DOME_PARAM_ACCEPT_ENCODING:
                param = apr_table_get(r->headers_in, "Accept-Encoding");
                break;
            case DOME_PARAM_ACCEPT_LANGUAGE:
                param = apr_table_get(r->headers_in, "Accept-Language");
                break;
            case DOME_PARAM_CONNECTION:
                param = apr_table_get(r->headers_in, "Connection");
                break;
            case DOME_PARAM_PRAGMA:
                param = apr_table_get(r->headers_in, "Pragma");
                break;
            case DOME_PARAM_CACHE_CONTROL:
                param = apr_table_get(r->headers_in, "Cache-Control");
                break;
            case DOME_PARAM_CONTENT_TYPE:
                param = apr_table_get(r->headers_in, "Content-Type");
                break;
            case DOME_PARAM_FROM:
                param = apr_table_get(r->headers_in, "From");
                break;
            case DOME_PARAM_X_REAL_IP:
                param = apr_table_get(r->headers_in, "X-Real-IP");
                break;
            case DOME_PARAM_VIA:
                param = apr_table_get(r->headers_in, "Via");
                break;
            case DOME_PARAM_TRUE_CLIENT_IP:
                param = apr_table_get(r->headers_in, "True-Client-IP");
                break;
            case DOME_PARAM_CONNECTIONSTATE:
                if(connection_state == RECONNECTION) {
                    param = "New";
                } else {
                  param = "Reused";
                }
                break;
            case DOME_PARAM_MODULENAME:
                param = "Apache";
                break;
            default:
                break;
        }
        if(param != NULL && param_len == 0) {
            param_len = strlen(param);
        }

        ret = append_param(dome_param_list[i].string, dome_param_list[i].length, param, param_len,
            dome_param_list[i].max_length, dome_param_list[i].use_url_encode, dome_param_list[i].from_end);
    }
}

#ifdef PRE_INIT_CONNECTION
/* This function will initialize the connection with API server on httpd process/thread startup */
static void
init_dome_connection(apr_pool_t *p, server_rec *s)
{
    int max_timeout_ms;
    client_config = get_dome_srv_cfg(s);

    datadome_shield_server_rec = s;

    DM_LOG_DEBUG("init_dome_connection: srv: %ld, cc: %ld", (long)s, (long)client_config);

    if (client_config->config_validated != SUCCESS) {
        DM_LOG_ERROR("Dome is not configured properly");
        goto end;
    }

    max_timeout_ms = client_config->conn_timeout;

    /* STEP-1 */
    http_client_init(&max_timeout_ms);

end:
    DM_LOG_TRACE("init_dome_connection finished");
    datadome_shield_server_rec = NULL;
}
#endif

static int
dome_match_regex_handler(request_rec *r)
{
    ap_regmatch_t matches;

    datadome_shield_server_rec = r->server;

    client_config = get_dome_srv_cfg(r->server);
    struct _dome_config *dc = ((struct _client_config *)get_dome_cfg(r))->extra_config;

    if (dc->uri_reg_exclusion) {
        memset(&matches, 0, sizeof(matches));
        if (ap_regexec(&dc->uri_preg_exclusion, r->uri, 1, &matches, 0) == 0) {
            /* match found in uri */
            DM_LOG_DEBUG("REGEX MISS by URIRegexExclusion: '%s', unset ENV URL: %s, so: %d eo: %d", dc->uri_reg_exclusion, r->uri, matches.rm_so, matches.rm_eo);
            apr_table_unset(r->subprocess_env, "DATA_DOME_IS_URI_REGEX_MATCHED");
            datadome_shield_server_rec = NULL;
            return DECLINED;
        }
    }

    if (dc->uri_reg) {
        memset(&matches, 0, sizeof(matches));
        if (ap_regexec(&dc->uri_preg, r->uri, 1, &matches, 0) == 0) {
            /* match found in uri */
            DM_LOG_DEBUG("REGEX HIT by URIRegex: '%s', setup ENV to 1 URL: %s, so: %d eo: %d", dc->uri_reg, r->uri, matches.rm_so, matches.rm_eo);
            apr_table_setn(r->subprocess_env, "DATA_DOME_IS_URI_REGEX_MATCHED", "1");
            datadome_shield_server_rec = NULL;
            return DECLINED;
        } else {
            apr_table_unset(r->subprocess_env, "DATA_DOME_IS_URI_REGEX_MATCHED");
            DM_LOG_DEBUG("REGEX MISS, unset ENV URL: %s, regex: %s", r->uri, dc->uri_reg);
            datadome_shield_server_rec = NULL;
            return DECLINED;
        }
    }

    apr_table_setn(r->subprocess_env, "DATA_DOME_IS_URI_REGEX_MATCHED", "1");
    DM_LOG_DEBUG("URIRegex doesn't setup, set ENV");
    datadome_shield_server_rec = NULL;
    return DECLINED;
}


static void
execute_x_datadome_headers(request_rec *r, const char *x_datadome_header, apr_table_t *src, apr_table_t *dst)
{
  const char *x_datadome_headers;

  x_datadome_headers = apr_table_get(src, x_datadome_header);
  if (x_datadome_headers == NULL) {
    return;
  }

  while (strlen(x_datadome_headers) > 0) {
    const char *end = strstr(x_datadome_headers, " ");
    if (end == NULL) {
        end = (const char *) x_datadome_headers + strlen(x_datadome_headers);
    }

    char *key = apr_pcalloc(r->pool, end - x_datadome_headers + 1);
    if (key == NULL) {
        return;
    }

    memcpy(key, x_datadome_headers, end - x_datadome_headers);

    const char *header = apr_table_get(src, key);

    if (header != NULL) {
      if (strcasecmp(key, "Content-Type") == 0) {
        ap_set_content_type(r, header);
      } else {
        apr_table_set(dst, key, header);
      }
    }

    x_datadome_headers = end;
    while (*x_datadome_headers == ' ') {
        x_datadome_headers++;
    }
  }
}


static int
dome_evaluate_headers_handler(request_rec *r)
{
    datadome_shield_server_rec = r->server;
    if (responsed_headers != NULL) {
        if (r->main) {
            execute_x_datadome_headers(r->main, "X-DataDome-request-headers", responsed_headers, r->main->headers_in);
            execute_x_datadome_headers(r->main, "X-DataDome-headers", responsed_headers, r->main->err_headers_out);
        }
        execute_x_datadome_headers(r, "X-DataDome-request-headers", responsed_headers, r->headers_in);
        execute_x_datadome_headers(r, "X-DataDome-headers", responsed_headers, r->err_headers_out);
        responsed_headers = NULL;
    }
    datadome_shield_server_rec = NULL;
    return DECLINED;
}


/* DOME callback entry point */
static int
dome_handler(request_rec *r)
{
    const uint8_t *response = NULL;
    apr_table_t *headers = NULL;
    const char *rmsg = NULL;
    uint32_t response_len = 0;
    int ret;
    int rcode, xdd_response_code;
    struct _dome_config *dc = NULL;
    int init_http_client_ret = SUCCESS;
    const request_rec *top = r;
    const char *location = NULL;
    const char *xdd_response = NULL;

    int max_timeout_ms;

    datadome_shield_server_rec = r->server;

    struct timespec ts1, ts2, tsd;
    clock_gettime(CLOCK_MONOTONIC, &ts1);

    client_config = get_dome_srv_cfg(r->server);
    dc = ((struct _client_config *)get_dome_cfg(r))->extra_config;

    max_timeout_ms = client_config->request_timeout;

    if (dc->key == NULL) {
        DM_LOG_DEBUG("KEY is empty, skip datadome handler");
        rcode = 702;
        ret = DECLINED;
        goto end;
    }

    if (apr_table_get(r->subprocess_env, "DATA_DOME_DISABLE")) {
        DM_LOG_DEBUG("Dome is OFF by ENV variable");
        rcode = 701;
        ret = DECLINED;
        goto end;
    }

    for (;;) {
        DM_LOG_DEBUG("Looking for existed call: top: %p, top->prev: %p, top->main: %p",
            (void *)top, (void *)top->prev, (void *)top->main);
        if (apr_table_get(top->notes, "mod_datadome_shield_send")) {
            DM_LOG_DEBUG("dome has sent API call about this request");
            const char *status = apr_table_get(top->subprocess_env, "DATA_DOME_STATUS");
            if (status) {
                apr_table_setn(r->subprocess_env, "DATA_DOME_STATUS", apr_pstrdup(r->pool, status));
            }
            const char *spent_time = apr_table_get(top->subprocess_env, "DATA_DOME_SPENT_TIME");
            if (spent_time) {
                apr_table_setn(r->subprocess_env, "DATA_DOME_SPENT_TIME", apr_pstrdup(r->pool, spent_time));
            }
            return DECLINED; // we processed this request before, don't override ENV
        }

        if (top->prev) {
            top = top->prev;
            continue;
        }

        if (!top->prev && top->main) {
            top = top->main;
            continue;
        }

        break;
    }

    apr_table_setn(r->notes, "mod_datadome_shield_send", "yes");

    if (client_config->config_validated != SUCCESS) {
        DM_LOG_ERROR("Dome is not configured properly");
        rcode = 703;
        ret = DECLINED;
        goto end;
    }

    if (dc->dome_status == DOME_OFF) {
        DM_LOG_DEBUG("Dome is OFF");
        rcode = 701;
        ret = DECLINED;
        goto end;
    }

    if (apr_table_get(r->subprocess_env, "DATA_DOME_IS_URI_REGEX_MATCHED") == NULL) {
        rcode = 700;
        ret = DECLINED;
        goto end;
    }

    if (!dc->do_not_refresh && last_refresh + dc->refresh_in < tv.tv_sec) {
        in_addr_t addr = hostname_to_ip(client_config->server_hostname);
        if (addr != INADDR_NONE) {
            client_config->server_ip.s_addr = addr;
            last_refresh = tv.tv_sec;
        } else {
            DM_LOG_ERROR("failed to resolve hostname [%s]", client_config->server_hostname);
            rcode = HTTP_BAD_GATEWAY;
            ret = DECLINED;
            goto end;
        }
    }

    /* STEP-1
    If connection is not established by init_dome_connection, then this will initiate the connection */
    init_http_client_ret = http_client_init(&max_timeout_ms);
    if (init_http_client_ret == FAILURE) {
        rcode = HTTP_BAD_GATEWAY;
        ret = DECLINED;
        http_close_connection(&max_timeout_ms);
        goto end;
    }

    if (init_http_client_ret == TIMED_OUT) {
        rcode = HTTP_GATEWAY_TIME_OUT;
        ret = DECLINED;
        http_close_connection(&max_timeout_ms);
        goto end;
    }

    connection_state = init_http_client_ret;

    /* STEP-2 */
    get_http_headers(r);

    /* STEP-3 */
    ret = http_client_post(&max_timeout_ms, r->pool, &headers, &response, &response_len, &rcode, &rmsg);
    if (ret == SUCCESS) {
        DM_LOG_DEBUG("HTTP client successfully fetched data. Response code[%d] msg[%s]", rcode, rmsg);
        DM_LOG_TRACE("Response Len[%u] Data[%.*s]", response_len, response_len, response);
    } else {
        DM_LOG_INFO("HTTP client failed to fetch data");
        if (ret == TIMED_OUT) {
            rcode = HTTP_GATEWAY_TIME_OUT;
        } else {
            rcode = HTTP_BAD_GATEWAY;
        }
        ret = DECLINED;
        http_close_connection(&max_timeout_ms);
        goto end;
    }

    if (headers == NULL) {
        DM_LOG_DEBUG("Response hasn't got headers");
        ret = DECLINED;
        rcode = 704;
        goto cleanup;
    }

    xdd_response = apr_table_get(headers, "X-DataDomeResponse");
    if (xdd_response == NULL) {
        DM_LOG_DEBUG("Response hasn't got X-DataDomeResponse");
        ret = DECLINED;
        rcode = 704;
        goto cleanup;
    }

    xdd_response_code = atoi(xdd_response);
    if (rcode != xdd_response_code) {
        DM_LOG_DEBUG("X-DataDomeResponse: %s != rcode: %d", xdd_response, rcode);
        ret = DECLINED;
        rcode = 704;
        goto cleanup;
    }

    if (r->main) {
        execute_x_datadome_headers(r->main, "X-DataDome-request-headers", responsed_headers, r->main->headers_in);
        execute_x_datadome_headers(r->main, "X-DataDome-headers", responsed_headers, r->main->err_headers_out);
    }
    execute_x_datadome_headers(r, "X-DataDome-request-headers", headers, r->headers_in);
    execute_x_datadome_headers(r, "X-DataDome-headers", headers, r->err_headers_out);
    responsed_headers = headers;

    switch (rcode) {
        case HTTP_MOVED_PERMANENTLY:
        case HTTP_MOVED_TEMPORARILY:
            if (headers != NULL) {
                location = apr_table_get(headers, "Location");
            }
            if (location != NULL) {
                apr_table_setn(r->headers_out, "Location", location);
            } else {
                DM_LOG_ERROR("Redirect response hasn't got Location");
            }

        case HTTP_UNAUTHORIZED:
        case HTTP_FORBIDDEN:
            if (response_len) {
                r->status = rcode;
                ap_set_content_length(r, response_len);
                ap_rputs((const char*)response, r);
                ap_rflush(r);
                ret = DONE;
            } else {
                ret = rcode;
            }

            break;

        case HTTP_OK:
            ret = DECLINED;
            break;

        default:
            DM_LOG_ERROR("Unknown response code received from API. Code[%d] Msg[%s]", rcode, rmsg);
            ret = DECLINED;
            break;
    }

    if (dc->dome_status == DOME_LEARNING) {
        ret = DECLINED;
    }

cleanup:
    /* STEP-4 */
    http_client_reset();

end:
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    diff_ts(&ts1, &ts2, &tsd);
    DM_LOG_DEBUG("Spent [%.3f] ms", (double) tsd.tv_sec*1000 + (double) tsd.tv_nsec/1000000);
    apr_table_setn(r->subprocess_env, "DATA_DOME_STATUS", apr_psprintf(r->pool, "%d", rcode));
    apr_table_setn(r->subprocess_env, "DATA_DOME_SPENT_TIME", apr_psprintf(r->pool, "%.3f", (double)tsd.tv_sec*1000 + (double) tsd.tv_nsec/1000000));

    datadome_shield_server_rec = NULL;
    return ret;
}

static void *
create_dome_configuration(apr_pool_t *p)
{
    struct _client_config *cc = (void *)apr_pcalloc(p, sizeof(struct _client_config));
    struct _dome_config *dc = (void *)apr_pcalloc(p, sizeof(struct _dome_config));
    char *str = NULL, *tmp = NULL, *saveptr = NULL, *token = NULL;
    struct _string_ident *si = NULL;
    char hostname[128] = {0};

    cc->pool = p;
    cc->extra_config = dc;
    dc->cookie = "datadome";
    dc->refresh_in = REFRESH_IN;
    dc->do_not_refresh = 0;

    cc->server_hostname = DEF_API_HOST;
    cc->server_uri = DEF_API_URI;
    cc->server_port = DEF_API_PORT;
    cc->conn_timeout = DEF_TIMEOUT_MS;
    cc->request_timeout = DEF_REQ_TIMEOUT_MS;
    cc->proto_type = strcmp(DEF_API_PROTOCOL, "HTTP") == 0 ? PROTO_HTTP : PROTO_TLS_1_2;
    cc->config_validated = FAILURE;

    /* Set dome status to default dome status */
    if ((si = find_string_ident(dome_status_list, DEF_DOME_STATUS, strcasecmp)) != NULL) {
        dc->dome_status = si->ident;
    }

    /* Set parameter flags as per default data exclude */
    if (*DEF_DATA_EXCLUDE != '\0') {
        /* This memory will be autmatically freed */
        str = apr_pstrdup(p, DEF_DATA_EXCLUDE);

        for (tmp=str ; str ; tmp=NULL) {
            token = strtok_r(tmp, " ", &saveptr);
            if (token == NULL) {
                break;
            }
            if ((si = find_string_ident(dome_param_list, token, strcasecmp)) != NULL) {
                SET_FLAG(si, 0);
            }
        }
    }

    dc->uri_reg = NULL;
    if (*DEF_URI_REGEX != '\0') {
        if (ap_regcomp(&dc->uri_preg, DEF_URI_REGEX, AP_REG_ICASE) == APR_SUCCESS) {
            dc->uri_reg = DEF_URI_REGEX;
        } else {
            DM_LOG_ERROR("Invalid default URIRegex settings, It should be valid PCRE regex");
        }
    }

    dc->uri_reg_exclusion = NULL;
    if (*DEF_URI_REGEX_EXCLUSION != '\0') {
        if (ap_regcomp(&dc->uri_preg_exclusion, DEF_URI_REGEX_EXCLUSION, AP_REG_ICASE) == APR_SUCCESS) {
            dc->uri_reg_exclusion = DEF_URI_REGEX_EXCLUSION;
        } else {
            DM_LOG_ERROR("Invalid default URIRegexExclusion settings, It should be valid PCRE regex");
        }
    }

    /* Set host name of the local server */
    gethostname(hostname, 128);
    dc->servername = apr_pstrdup(p, hostname);

    return cc;
}


static void *
create_dir_dome_config(apr_pool_t *p, char *loc) {
    return create_dome_configuration(p);
}


static void *
create_srv_dome_config(apr_pool_t *p, server_rec *srv) {
    return create_dome_configuration(p);
}


static void *
merge_dome_configuration(apr_pool_t *p, void *parent_conf, void *new_conf) {
    struct _client_config *cc = (void *)apr_pcalloc(p, sizeof(struct _client_config));
    struct _dome_config *dc = (void *)apr_pcalloc(p, sizeof(struct _dome_config));

    struct _client_config *parent_cc = (struct _client_config *) parent_conf;
    struct _dome_config *parent_dc = parent_cc->extra_config;

    struct _client_config *new_cc = (struct _client_config *) new_conf;
    struct _dome_config *new_dc = new_cc->extra_config;

    DM_LOG_DEBUG("merge_dome_configuration: cc: %ld, parent_cc: %ld, new_cc: %ld", (long)cc, (long)parent_cc, (long)new_cc);

    cc->config_validated = parent_cc->config_validated;
    cc->server_ip = parent_cc->server_ip;

    if (parent_cc->server_hostname != NULL) {
        cc->server_hostname = apr_pstrdup(p, parent_cc->server_hostname);
    }
    if (parent_cc->server_uri != NULL) {
        cc->server_uri = apr_pstrdup(p, parent_cc->server_uri);
    }

    cc->server_port = parent_cc->server_port;
    cc->conn_timeout = parent_cc->conn_timeout;
    cc->request_timeout = parent_cc->request_timeout;
    cc->proto_type = parent_cc->proto_type;

    cc->pool = p;
    cc->extra_config = dc;

    dc->servername = apr_pstrdup(p, parent_dc->servername);
    dc->do_not_refresh = parent_dc->do_not_refresh;
    dc->refresh_in = parent_dc->refresh_in;

    dc->cookie = strcmp(new_dc->cookie, "datadome") ? new_dc->cookie : parent_dc->cookie;
    if (dc->cookie != NULL) {
        dc->cookie = apr_pstrdup(p, dc->cookie);
    } else {
        dc->cookie = apr_pstrdup(p, "datadome");
    }

    dc->key = new_dc->key != NULL ? new_dc->key : parent_dc->key;
    if (dc->key != NULL) {
        dc->key = apr_pstrdup(p, dc->key);
    }

    dc->dome_status = new_dc->dome_status != DOME_AUTO ? new_dc->dome_status : parent_dc->dome_status;
    if (dc->dome_status != DOME_OFF && dc->dome_status != DOME_LEARNING && dc->dome_status != DOME_FILTERING && dc->dome_status != DOME_AUTO) {
        DM_LOG_ERROR("Incorrect dome status: %d", dc->dome_status);
        return NULL;
    }

    dc->uri_reg = NULL;
    if (parent_dc->uri_reg == NULL
        || (new_dc->uri_reg && strcmp(new_dc->uri_reg, DEF_URI_REGEX))) {
        if (new_dc->uri_reg != NULL) {
            dc->uri_reg = apr_pstrdup(p, new_dc->uri_reg);
            if (ap_regcomp(&dc->uri_preg, new_dc->uri_reg, AP_REG_ICASE) != APR_SUCCESS) {
                DM_LOG_ERROR("Invalid default URIRegex settings, It should be valid PCRE regex");
                return NULL;
            }
        }
    } else {
        if (parent_dc->uri_reg != NULL) {
            dc->uri_reg = apr_pstrdup(p, parent_dc->uri_reg);
            if (ap_regcomp(&dc->uri_preg, parent_dc->uri_reg, AP_REG_ICASE) != APR_SUCCESS) {
                DM_LOG_ERROR("Invalid default URIRegex settings, It should be valid PCRE regex");
                return NULL;
            }
        }
    }

    dc->uri_reg_exclusion = NULL;
    if (parent_dc->uri_reg_exclusion == NULL
        || (new_dc->uri_reg_exclusion != NULL && strcmp(new_dc->uri_reg_exclusion, DEF_URI_REGEX_EXCLUSION))) {
            if (new_dc->uri_reg_exclusion != NULL) {
            dc->uri_reg_exclusion = apr_pstrdup(p, new_dc->uri_reg_exclusion);
            if (ap_regcomp(&dc->uri_preg_exclusion, new_dc->uri_reg_exclusion, AP_REG_ICASE) != APR_SUCCESS) {
                DM_LOG_ERROR("Invalid default URIRegexExclusion settings, It should be valid PCRE regex");
                return NULL;
            }
        }
    } else {
        if (parent_dc->uri_reg_exclusion != NULL) {
            dc->uri_reg_exclusion = apr_pstrdup(p, parent_dc->uri_reg_exclusion);
            if (ap_regcomp(&dc->uri_preg_exclusion, parent_dc->uri_reg_exclusion, AP_REG_ICASE) != APR_SUCCESS) {
                DM_LOG_ERROR("Invalid default URIRegexExclusion settings, It should be valid PCRE regex");
                return NULL;
            }
        }
    }

    return cc;
}


/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA gandalf_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_dome_config,     // Per-directory configuration handler
    merge_dome_configuration,   // Merge handler for per-directory configurations
    create_srv_dome_config,  // Per-server config structure
    merge_dome_configuration,   // Merge handler for per-server configurations
    dome_config_cmds,           // Any directives we may have for httpd
    dome_hooks,                 // Our hook registering function
};
