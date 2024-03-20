/* Core Apache modules required */
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_strings.h"
/* Other libs required */
#include <stdlib.h>

/** structs */
typedef struct {
    char    *name;      /* Name of the bucket */
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
        cfg->enabled = 2;
        cfg->bucket = NULL;
        cfg->server = server;
        cfg->buckets = apr_array_make(pool, 5, sizeof(mrl_bucket*));
    }
    return cfg;
}

void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD) {

    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;
    //mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    mrl_config *cfg = (mrl_config *) create_server_conf(pool, (add->server) ? add->server : base->server);

    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, base->server, "merge_server_conf %s", base->server->defn_name);
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, base->server, "merge_server_conf %s", add->server->defn_name);
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, base->server, "merge_server_conf %s", cfg->server->defn_name);

    /* Merge configurations */
    cfg->enabled = (add->enabled == 2) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    cfg->buckets = (add->buckets) ? (apr_array_header_t *)add->buckets : (apr_array_header_t *)base->buckets;

    strcpy(cfg->src, "ms");
    
    return cfg;
}

void *create_dir_conf(apr_pool_t *pool, char *arg) {
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, NULL, "create_dir_conf");
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        cfg->enabled = 2;
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
    cfg->enabled = (add->enabled == 2) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    strcpy(cfg->src, "md");
    
    return cfg;
}

static int request_handler(request_rec *r)
{
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler %s", r->server->defn_name);
    mrl_config *server_conf = (mrl_config *) ap_get_module_config(r->server->module_config, &request_limit_module);
    mrl_config *per_dir_conf = (mrl_config *) ap_get_module_config(r->per_dir_config, &request_limit_module);
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler %s", server_conf->src);
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler %s", per_dir_conf->src);

    /* TODO: Check if this request is limited */
    if (per_dir_conf->enabled == 0 || (per_dir_conf->enabled == 2 && server_conf->enabled != 1)) {
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler not enabled");
        return (DECLINED);
    } 
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler enabled");

    mrl_bucket *bucket = NULL;    
    if (per_dir_conf->bucket) {
        bucket = (mrl_bucket *)per_dir_conf->bucket;
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler bucket set (dir) %s", bucket->name);
    } else if (server_conf->bucket) {
        bucket = (mrl_bucket *)server_conf->bucket;
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler bucket set (server) %s", bucket->name);
    } else {
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler bucket not set");
        return (DECLINED);
    }

    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler bucket %s %d %d", bucket->name, bucket->requests, bucket->timespan);

    /* Add IP to list */
    char *ip;
    char *hits;
    long numHits = 0;
    apr_sockaddr_ip_get(&ip, r->useragent_addr);
    hits = (char *)apr_table_get(bucket->ips, ip);
    if (hits != NULL) {
        numHits = strtol(hits, NULL, 10);
    }
    numHits++;

    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler ip %s %d/%d", ip, (int)numHits, bucket->requests);
    apr_table_set(bucket->ips, ip, apr_ltoa(r->pool, (long) numHits));

    /* TODO: Check if this request has exceeded the limit */
    if (numHits > bucket->requests) {
        /* block request */
        ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, "request_handler blocked ip %s", ip);
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
        bucket->name = (char *)name;
        bucket->requests = strtol(requests, NULL, 10);
        bucket->timespan = strtol(timespan, NULL, 10);

        // Add newly created bucket to server config
        *(mrl_bucket **)apr_array_push(conf->buckets) = bucket;
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
const char *mrl_set_bucket(cmd_parms *cmd, void *cfg, const char *name)
{
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_set_bucket %s", name);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) cfg;
    mrl_config    *server_conf = (mrl_config *) ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/


    if (server_conf && server_conf->buckets) {
        int i;
        int num_buckets = server_conf->buckets->nelts;    
        for (i = 0; i < num_buckets; i++) {
            mrl_bucket *current_bucket = APR_ARRAY_IDX(server_conf->buckets, i, mrl_bucket *);
            if (0 == strcmp(name, current_bucket->name)) {
                ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_set_bucket %s equals %s ", name, current_bucket->name);
                conf->bucket = current_bucket;
                return NULL;
            }
        }
    }

    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, cmd->server, "mrl_set_bucket bucket %s not found", name);

    return NULL;
}

