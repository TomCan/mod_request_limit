/* Core Apache modules required */
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
/* Other libs required */
#include <stdlib.h>

/** structs */
typedef struct {
    char    name[255];      /* Name of the bucket */
    int     requests;       /* Number of requests to allow */
    int     timespan;       /* Number of seconds */
    apr_table_t *ips;        /* Holds requests per ip */
} mrl_bucket;

typedef struct {
    char    src[255];
    int     enabled;        /* Enable or disable our module */
    server_rec *server;           /* the corresponding server indicator */
    apr_array_header_t *buckets;        /* Buckets within this server */
    mrl_bucket *bucket;        /* Actual bucket to use by request */
} mrl_config;

/** prototypes */
const char *mrl_create_bucket(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2, const char *arg3);
const char *mrl_set_enabled(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_set_bucket(cmd_parms *cmd, void *cfg, const char *arg);
void *create_server_conf(apr_pool_t *pool, server_rec *server);
void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD);
void *create_dir_conf(apr_pool_t *pool, char *arg);
void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD);
static void register_hooks(apr_pool_t *pool);
static int request_handler(request_rec *r);

/** directives */
static const command_rec directives[] =
{
    AP_INIT_TAKE1("ReqLimitEngine", mrl_set_enabled, NULL, ACCESS_CONF, "Enable or disable mod_request_limit processing"),
    AP_INIT_TAKE3("ReqLimitBucket", mrl_create_bucket, NULL, RSRC_CONF, "Create a bucket"),
    AP_INIT_TAKE1("ReqLimitSetBucket", mrl_set_bucket, NULL, ACCESS_CONF, "Set the name of the bucket to use"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA request_limit_module = 
{ 
    STANDARD20_MODULE_STUFF,
    create_dir_conf, /* Per-directory configuration handler */
    merge_dir_conf,  /* Merge handler for per-directory configurations */
    create_server_conf, /* Per-server configuration handler */
    merge_server_conf,  /* Merge handler for per-server configurations */
    directives,      /* Any directives we may have for httpd */
    register_hooks   /* Our hook registering function */
};

static void register_hooks(apr_pool_t *pool)
{
    /* Create a hook in the request handler, so we get called when a request arrives */
    ap_hook_handler(request_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


void *create_server_conf(apr_pool_t *pool, server_rec *server) {
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, server, "create_server_conf %s", server->defn_name);
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        strcpy(cfg->src, "cs");
        cfg->enabled = 0;
        cfg->bucket = NULL;
        cfg->server = server;
        cfg->buckets = apr_array_make(pool, 5, sizeof(mrl_bucket*));
    }
    return cfg;
}

void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD) {

    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;

    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, base->server, "merge_server_conf %s", base->server->defn_name);

    /* Merge configurations */
    cfg->enabled = ( add->enabled == 0 ) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;

    strcpy(cfg->src, "ms");
    
    return cfg;
}

void *create_dir_conf(apr_pool_t *pool, char *arg) {
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "create_dir_conf");
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        cfg->enabled = 0;
        cfg->bucket = NULL;
        strcpy(cfg->src, "cd");
    }
    return cfg;
}

void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "merge_dir_conf");
    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;
    mrl_config *cfg = (mrl_config *) create_dir_conf(pool, "");
    
    /* Merge configurations */
    cfg->enabled = ( add->enabled == 0 ) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    strcpy(cfg->src, "md");
    
    return cfg;
}

static int request_handler(request_rec *r)
{
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "request_handler %s", r->server->defn_name);
    mrl_config *conf = (mrl_config *) r->request_config;
    mrl_config *server_conf = (mrl_config *) ap_get_module_config(r->server->module_config, &request_limit_module);

    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "request_handler buckets %d", conf->buckets->nelts);
    for (int i = 0; i < server_conf->buckets->nelts; i++) {
        mrl_bucket **bucket_pointer = ((mrl_bucket **)server_conf->buckets->elts) + i;
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "request_handler %s", (*bucket_pointer)->name);
        mrl_bucket *bucket = (mrl_bucket *)bucket_pointer;
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "request_handler %s", bucket->name);
    }


    /* TODO: Check if this request is limited */
    if (!conf->enabled) {
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "request_handler not enabled");
        return (DECLINED);
    } 
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "request_handler enabled");

    /* TODO: Add IP to list */
    // r->useragent_ip

    /* TODO: Check if this request has exceeded the limit */
    if (TRUE) {
        /* block request */
        return (HTTP_FORBIDDEN);
    } else {
        /* We're not acting on this request */
        return (DECLINED);
    }

}

/**
======================
Configuration handlers
======================
*/

const char *mrl_create_bucket(cmd_parms *cmd, void *cfg, const char *name, const char *requests, const char *timespan)
{
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_create_bucket %s %s %s", name, requests, timespan);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_create_bucket %s", cmd->server->defn_name);
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_create_bucket src %s", conf->src);

        // Create bucket object and populate config
        mrl_bucket *bucket = apr_pcalloc(cmd->pool, sizeof(mrl_bucket));
        bucket->ips = apr_table_make(cmd->pool, 1024);
        strcpy(bucket->name, name);
        bucket->requests = strtol(requests, NULL, 10);
        bucket->timespan = strtol(timespan, NULL, 10);

        // Add newly created bucket to server config, segfault be here
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_create_bucket %s", "3");
        *(mrl_bucket **)apr_array_push(conf->buckets) = bucket;
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_create_bucket %s", "4");
    }

    return NULL;
}


/** ReqLimitEngine mrl_set_enabled */
const char *mrl_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        if(!strcasecmp(arg, "on"))
            conf->enabled = 1;
        else
            conf->enabled = 0;
    }

    return NULL;
}

/** ReqLimitSetBucket mrl_set_bucket */
const char *mrl_set_bucket(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
    }

    return NULL;
}

