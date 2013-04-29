/*
 * Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 * Copyright (C) 2007 Hatena Inc.
 * The original author is Shinji Tanaka <stanaka@hatena.ne.jp>.
 */

#ifndef NGX_HTTP_DOSDETECTOR_CLIENT_H
#define NGX_HTTP_DOSDETECTOR_CLIENT_H

typedef struct ngx_http_dosdetector_client_t {
    in_addr_t addr;
    ngx_uint_t count;
    time_t interval;
    time_t last;
    struct ngx_http_dosdetector_client_t *next;
    time_t suspected;
    time_t hard_suspected;
} ngx_http_dosdetector_client_t;

typedef struct {
    ngx_http_dosdetector_client_t *head;
    ngx_http_dosdetector_client_t  base[1];
    size_t table_size;
} ngx_http_dosdetector_client_list_t;

void ngx_http_dosdetector_count_increment(ngx_http_dosdetector_client_t *client, ngx_uint_t threshold);
ngx_http_dosdetector_client_t *ngx_http_dosdetector_get_client(ngx_http_dosdetector_client_list_t *client_list, in_addr_t clientip, ngx_int_t period);

#endif // NGX_HTTP_DOSDETECTOR_CLIENT_H
