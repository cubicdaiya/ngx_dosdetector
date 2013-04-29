/*
 * Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 * Copyright (C) 2007 Hatena Inc.
 * The original author is Shinji Tanaka <stanaka@hatena.ne.jp>.
 */

#include <ngx_core.h>

#include "ngx_http_dosdetector_client.h"

void ngx_http_dosdetector_count_increment(ngx_http_dosdetector_client_t *client, ngx_uint_t threshold)
{
    if (client->count < client->interval * threshold) {
        client->count = 0;
    } else {
        client->count = client->count - client->interval * threshold;
    }
    client->count++;
}

ngx_http_dosdetector_client_t *ngx_http_dosdetector_get_client(ngx_http_dosdetector_client_list_t *client_list, in_addr_t clientip, ngx_int_t period)
{
    ngx_http_dosdetector_client_t *index;
    ngx_http_dosdetector_client_t **prev;
    time_t now;
    ngx_int_t rest;

    prev = &client_list->head;

    for(index=client_list->head;index->next!=NULL;index=index->next){
        if(index->addr == INADDR_NONE || index->addr == clientip) {
            break;
        }
        prev = &index->next;
    }

    if(index == NULL) {
        return NULL;
    }

    *prev             = index->next;
    index->next       = client_list->head;
    client_list->head = index;

    now = time((time_t*)NULL);
    if(now - index->last > period){
        index->interval = (now - index->last) / period;
        rest = (now - index->last) % period;
        index->last = now - rest;
    } else {
        index->interval = 0;
    }
    if(index->addr != clientip){
        index->count          = 0;
        index->interval       = 0;
        index->suspected      = 0;
        index->hard_suspected = 0;
        index->addr           = clientip;
    }

    return index;
}
