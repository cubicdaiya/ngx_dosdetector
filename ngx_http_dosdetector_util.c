/*
 * Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 */

#include "ngx_http_dosdetector_util.h"

#if (NGX_HTTP_X_FORWARDED_FOR)
u_char *ngx_http_dosdetector_client_ip_from_xfwd(ngx_http_request_t *r, u_char *xfwd)
{
    int i;
    u_char *p, *ip;
    i = 0;
    p = xfwd;
    while(*p != '\0' && *p != ',') {
        i++;
        p++;
    }
    ip = ngx_palloc(r->pool, i + 1);
    if (ip == NULL) {
        return NULL;
    }
    ngx_cpystrn(ip, xfwd, i + 1);
    return ip;
}
#endif

ngx_int_t ngx_http_dosdetector_is_ignore_content_type(ngx_http_request_t *r, ngx_str_t *content_type, ngx_str_t *pattern)
{
    ngx_regex_compile_t rgc;
    u_char errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rgc, sizeof(ngx_regex_compile_t));
    rgc.pattern  = *pattern;
    rgc.pool     = r->pool;
    rgc.err.len  = NGX_MAX_CONF_ERRSTR;
    rgc.err.data = errstr;

    if (ngx_regex_compile(&rgc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V", &rgc.err);
        return 0;
    }

    if (ngx_regex_exec(rgc.regex, content_type, NULL, 0) == NGX_REGEX_NO_MATCHED) {
        return 0;
    }

    return 1;
}
