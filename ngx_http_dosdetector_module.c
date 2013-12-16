/*
 * Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdlib.h>
#include "ngx_http_dosdetector_client.h"
#include "ngx_http_dosdetector_util.h"

#define NGX_HTTP_DOSDETECTOR_DEFAULT_THRESHOLD      10000
#define NGX_HTTP_DOSDETECTOR_DEFAULT_HARD_THRESHOLD 20000
#define NGX_HTTP_DOSDETECTOR_DEFAULT_PERIOD         10
#define NGX_HTTP_DOSDETECTOR_DEFAULT_HARD_PERIOD    300
#define NGX_HTTP_DOSDETECTOR_DEFAULT_TABLE_SIZE     100

static ngx_str_t DosdetectorShmname            = ngx_string("ngx_dosdetector");
static ngx_str_t DosdetectorDefaultContentType = ngx_string("text/html");

typedef struct ngx_http_dosdetector_conf_t {
    ngx_flag_t enable;
    ngx_uint_t threshold;
    ngx_uint_t hard_threshold;
    ngx_uint_t period;
    ngx_uint_t hard_period;
    size_t     table_size;
    ngx_flag_t forwarded;
    ngx_str_t  ignore_content_type;
    ngx_shm_zone_t *shm_zone;
} ngx_http_dosdetector_conf_t;

typedef struct {
    ngx_str_t                   name;
    ngx_http_get_variable_pt    handler;
    uintptr_t                   data;
} ngx_http_dosdetector_variable_t;

static void *ngx_http_dosdetector_create_conf(ngx_conf_t *cf);
static char *ngx_http_dosdetector_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_dosdetector_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dosdetector_init(ngx_conf_t *cf);

static char *ngx_http_dosdetector_shm_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_dosdetector_shm_zone_init(ngx_shm_zone_t *shm_zone, void *data);

static ngx_command_t ngx_http_dosdetector_commands[] = {

    {
        ngx_string("dos_detector"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, enable),
        NULL
    },

    {
        ngx_string("dos_threshold"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, threshold),
        NULL
    },

    {
        ngx_string("dos_hard_threshold"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, hard_threshold),
        NULL
    },

    {
        ngx_string("dos_period"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, period),
        NULL
    },

    {
        ngx_string("dos_hard_period"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, hard_period),
        NULL
    },

    {
        ngx_string("dos_table_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_http_dosdetector_shm_init,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, table_size),
        NULL
    },

    {
        ngx_string("dos_forwarded"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, forwarded),
        NULL
    },

    {
        ngx_string("dos_ignore_content_type"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_dosdetector_conf_t, ignore_content_type),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_dosdetector_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_dosdetector_init,         /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_http_dosdetector_create_conf,  /* create server configuration */
    ngx_http_dosdetector_merge_conf,   /* merge server configuration */

    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
};

ngx_module_t ngx_http_dosdetector_module = {
    NGX_MODULE_V1,
    &ngx_http_dosdetector_module_ctx, /* module context */
    ngx_http_dosdetector_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_dosdetector_handler(ngx_http_request_t *r)
{
    size_t i;
    ngx_http_dosdetector_conf_t *dcf;
    ngx_str_t *content_type;
    u_char *ip;
#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_array_t *xfwd;
    ngx_table_elt_t **xfwd_elts;
#endif
    ngx_slab_pool_t *shpool;
    ngx_http_dosdetector_client_list_t *client_list;
    struct sockaddr_in *sin;
    in_addr_t addr;
    ngx_http_dosdetector_client_t *client;
    time_t now;

    dcf = ngx_http_get_module_srv_conf(r, ngx_http_dosdetector_module);
    if (!dcf->enable) {
        return NGX_DECLINED;
    }

    if (r->headers_in.content_type) {
        content_type = &r->headers_in.content_type->value;
    } else {
        content_type = &DosdetectorDefaultContentType;
    }

    if (ngx_http_dosdetector_is_ignore_content_type(r, content_type, &dcf->ignore_content_type)) {
        return NGX_DECLINED;
    }

    ip = NULL;

#if (NGX_HTTP_X_FORWARDED_FOR)
    if (dcf->forwarded) {
        xfwd      = &r->headers_in.x_forwarded_for;
        xfwd_elts = xfwd->elts;
        for (i=0;i<xfwd->nelts;i++) {
            ip = ngx_http_dosdetector_client_ip_from_xfwd(r, xfwd_elts[i]->value.data);
        }
    }
#endif

    if (ip == NULL) {
        sin  = (struct sockaddr_in *)r->connection->sockaddr;
        addr = sin->sin_addr.s_addr;
        ip   = r->connection->addr_text.data;
    } else {
        addr = ngx_inet_addr(ip, ngx_strlen(ip));
    }

    if(addr == INADDR_NONE){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dosdetector: '%s' is not  a valid IP addresss %s:%d", ip, __FUNCTION__, __LINE__);
        return NGX_DECLINED;
    }

    client_list = dcf->shm_zone->data;
    shpool      = (ngx_slab_pool_t *) dcf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);
    client = ngx_http_dosdetector_get_client(client_list, addr, dcf->period);
    ngx_shmtx_unlock(&shpool->mutex);

    ngx_http_dosdetector_count_increment(client, dcf->threshold);

    now = time((time_t *)NULL);
    // TODO: set dos suspected condition to nginx variable
    if(client->suspected > 0 && client->suspected + dcf->hard_period > (ngx_uint_t)now){
        if(client->count > dcf->hard_threshold){
            if(client->hard_suspected == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dosdetector: '%s' is suspected as Hard DoS attack! (counter: %d) %s:%d", ip, client->count, __FUNCTION__, __LINE__);
            }
            client->hard_suspected = now;
            ngx_http_finalize_request(r, NGX_HTTP_CLOSE);
            return NGX_HTTP_CLOSE;
        }
    } else {
        if(client->suspected > 0){
            client->suspected = 0;
            client->hard_suspected = 0;
            client->count = 0;
        }

        if(client->count > dcf->threshold){
            client->suspected = now;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dosdetector: '%s' is suspected as DoS attack! (counter: %d) %s:%d", ip, client->count, __FUNCTION__, __LINE__);
        }
    }

    return NGX_DECLINED;
}

static void *ngx_http_dosdetector_create_conf(ngx_conf_t *cf)
{
    ngx_http_dosdetector_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dosdetector_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable         = NGX_CONF_UNSET;
    conf->threshold      = NGX_CONF_UNSET_UINT;
    conf->hard_threshold = NGX_CONF_UNSET_UINT;
    conf->period         = NGX_CONF_UNSET_UINT;
    conf->hard_period    = NGX_CONF_UNSET_UINT;
    conf->table_size     = NGX_CONF_UNSET_SIZE;
    conf->forwarded      = NGX_CONF_UNSET;
    conf->shm_zone       = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *ngx_http_dosdetector_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dosdetector_conf_t *prev = parent;
    ngx_http_dosdetector_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,                  prev->enable,              0);
    ngx_conf_merge_uint_value(conf->threshold,          prev->threshold,           NGX_HTTP_DOSDETECTOR_DEFAULT_THRESHOLD);
    ngx_conf_merge_uint_value(conf->hard_threshold,     prev->hard_threshold,      NGX_HTTP_DOSDETECTOR_DEFAULT_HARD_THRESHOLD);
    ngx_conf_merge_uint_value(conf->period,             prev->period,              NGX_HTTP_DOSDETECTOR_DEFAULT_PERIOD);
    ngx_conf_merge_uint_value(conf->hard_period,        prev->hard_period,         NGX_HTTP_DOSDETECTOR_DEFAULT_HARD_PERIOD);
    ngx_conf_merge_value(conf->forwarded,               prev->forwarded,           0);
    ngx_conf_merge_str_value(conf->ignore_content_type, prev->ignore_content_type, "")

    ngx_conf_merge_size_value(conf->table_size,         prev->table_size,          NGX_HTTP_DOSDETECTOR_DEFAULT_TABLE_SIZE);
    ngx_conf_merge_ptr_value(conf->shm_zone,            prev->shm_zone,            NULL);
;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_dosdetector_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h    = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dosdetector_handler;

    return NGX_OK;
}

static char *ngx_http_dosdetector_shm_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dosdetector_conf_t *srv_conf;
    ngx_str_t *value;
    size_t size;
    ngx_shm_zone_t *shm_zone;
    ngx_http_dosdetector_client_list_t *client_list;

    srv_conf = conf;
    value    = cf->args->elts;
    size     = ngx_parse_size(&value[1]);

    shm_zone = ngx_shared_memory_add(cf, &DosdetectorShmname, size, &ngx_http_dosdetector_module);

    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        return NGX_CONF_ERROR;
    }

    client_list = ngx_pcalloc(cf->pool, 
                              sizeof(ngx_http_dosdetector_client_list_t) + sizeof(ngx_http_dosdetector_client_t) * size);
    if (client_list == NULL) {
        return NGX_CONF_ERROR;
    }
    client_list->table_size = size;

    shm_zone->init = ngx_http_dosdetector_shm_zone_init;
    shm_zone->data = client_list;

    srv_conf->table_size = size;
    srv_conf->shm_zone   = shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_dosdetector_shm_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t i;
    ngx_http_dosdetector_client_list_t *client_list;
    ngx_http_dosdetector_client_t *client;

    client_list       = shm_zone->data;
    client_list->head = client_list->base;
    client            = client_list->base;

    for (i = 1; i < client_list->table_size; i++) {
        client->next = (client + 1);
        client++;
    }
    client->next = NULL;

    return NGX_OK;
}
