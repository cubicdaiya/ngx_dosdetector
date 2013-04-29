/*
 * Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 */

#ifndef NGX_HTTP_DOSDETECTOR_UTIL_H
#define NGX_HTTP_DOSDETECTOR_UTIL_H

#include <ngx_core.h>
#include <ngx_http.h>

u_char *ngx_http_dosdetector_client_ip_from_xfwd(ngx_http_request_t *r, u_char *xfwd);
ngx_int_t ngx_http_dosdetector_is_ignore_content_type(ngx_http_request_t *r, ngx_str_t *content_type, ngx_str_t *pattern);

#endif // NGX_HTTP_DOSDETECTOR_UTIL_H
