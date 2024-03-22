/* Core Apache modules required */
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_network_io.h"
/* Other libs required */
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h> // For inet_pton and inet_ntop functions

/** structs */
typedef struct {
    char    *name;      /* Name of the bucket */
    int     requests;       /* Number of requests to allow */
    int     timespan;       /* Number of milliseconds between clears */
    long    lastReset;      /* Last time the bucket was cleared */
    apr_table_t *ips;        /* Holds requests per ip */
} mrl_bucket;

typedef struct {
    char    src[255];
    int     enabled;        /* Enable or disable our module */
    server_rec *server;           /* the corresponding server indicator */
    apr_array_header_t *buckets;        /* Buckets within this server */
    mrl_bucket *bucket;        /* Actual bucket to use by request */
    int     netmask4;                /* netmask to apply to IPv4 address */
    int     netmask6;                /* netmask to apply to IPv6 address */
} mrl_config;

/** prototypes */
const char *mrl_create_bucket(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2, const char *arg3);
const char *mrl_set_enabled(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_set_bucket(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_set_netmask4(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_set_netmask6(cmd_parms *cmd, void *cfg, const char *arg);
uint64_t mrl_get_time_ms();
void *mrl_apply_mask4(char *dest, const char *ipv4_address_str, int mask_bits);
void *mrl_apply_mask6(char *dest, const char *ipv6_address_str, int mask_bits);
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
    AP_INIT_TAKE1("ReqLimitSetNetmask4", mrl_set_netmask4, NULL, ACCESS_CONF, "Set the netmask bits for IPv4 addresses"),
    AP_INIT_TAKE1("ReqLimitSetNetmask6", mrl_set_netmask6, NULL, ACCESS_CONF, "Set the netmask bits for IPv6 addresses"),
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
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, server, "create_server_conf for %s", server->defn_name);
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        strcpy(cfg->src, "cs");
        cfg->enabled = 2;
        cfg->bucket = NULL;
        cfg->server = server;
        cfg->buckets = apr_array_make(pool, 5, sizeof(mrl_bucket*));
        cfg->netmask4 = 32;
        cfg->netmask6 = 64;
    }
    return cfg;
}

void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD) {

    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;
    mrl_config *cfg = (mrl_config *) create_server_conf(pool, (add->server) ? add->server : base->server);

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, base->server, "merge_server_conf %s", add->server->defn_name);

    /* Merge configurations */
    cfg->enabled = (add->enabled == 2) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    cfg->buckets = (add->buckets) ? (apr_array_header_t *)add->buckets : (apr_array_header_t *)base->buckets;
    cfg->netmask4 = (add->netmask4) ? add->netmask4 : base->netmask4;
    cfg->netmask6 = (add->netmask6) ? add->netmask6 : base->netmask6;

    strcpy(cfg->src, "ms");
    
    return cfg;
}

void *create_dir_conf(apr_pool_t *pool, char *arg) {
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        cfg->enabled = 2;
        cfg->bucket = NULL;
        cfg->netmask4 = 32;
        cfg->netmask6 = 64;
        strcpy(cfg->src, "cd");
    }
    return cfg;
}

void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "merge_dir_conf");
    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;
    mrl_config *cfg = (mrl_config *) create_dir_conf(pool, "");
    
    /* Merge configurations */
    cfg->enabled = (add->enabled == 2) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    cfg->netmask4 = (add->netmask4) ? add->netmask4 : base->netmask4;
    cfg->netmask6 = (add->netmask6) ? add->netmask6 : base->netmask6;
    strcpy(cfg->src, "md");
    
    return cfg;
}

static int request_handler(request_rec *r)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler %s", r->server->defn_name);
    mrl_config *server_conf = (mrl_config *) ap_get_module_config(r->server->module_config, &request_limit_module);
    mrl_config *per_dir_conf = (mrl_config *) ap_get_module_config(r->per_dir_config, &request_limit_module);

    /* Check if this request is limited */
    if (per_dir_conf->enabled == 0 || (per_dir_conf->enabled == 2 && server_conf->enabled != 1)) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler not enabled");
        return (DECLINED);
    } 
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler enabled");

    mrl_bucket *bucket = NULL;    
    if (per_dir_conf->bucket) {
        bucket = (mrl_bucket *)per_dir_conf->bucket;
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler bucket set (per_dir) %s", bucket->name);
    } else if (server_conf->bucket) {
        bucket = (mrl_bucket *)server_conf->bucket;
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler bucket set (server) %s", bucket->name);
    } else {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler bucket not set");
        return (DECLINED);
    }

    /* Check to see if we need to clear the bucket */
    uint64_t now = mrl_get_time_ms();
    if (now > (bucket->lastReset + bucket->timespan)) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler clearing bucket %s %lu %d", bucket->name, bucket->lastReset, bucket->timespan);
        bucket->lastReset = now;
        apr_table_clear(bucket->ips);
    }

    /* Add IP to list */
    apr_sockaddr_t *ipAdd;
    apr_sockaddr_info_copy(&ipAdd, r->useragent_addr, r->pool);

    char *ip;
    char *masked;
    apr_sockaddr_ip_get(&ip, ipAdd);

    // check if IPv4 or IPv6
    if (ipAdd->ipaddr_len == 4) {
        int maskBits = (per_dir_conf->netmask4) ? per_dir_conf->netmask4 : server_conf->netmask4;
        masked = apr_pcalloc(r->pool, INET_ADDRSTRLEN);
        mrl_apply_mask4(masked, ip, maskBits);
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler ip %s masked %d to %s", ip, maskBits, masked);
    } else {
        int maskBits = (per_dir_conf->netmask6) ? per_dir_conf->netmask6 : server_conf->netmask6;
        masked = apr_pcalloc(r->pool, INET6_ADDRSTRLEN);
        mrl_apply_mask6(masked, ip, maskBits);
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler ip %s masked %d to %s", ip, maskBits, masked);
    }

    long numHits = 0;
    char *hits;
    hits = (char *)apr_table_get(bucket->ips, ip);
    if (hits != NULL) {
        numHits = strtol(hits, NULL, 10);
    }
    numHits++;

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler ip %s %d/%d", ip, (int)numHits, bucket->requests);
    apr_table_set(bucket->ips, ip, apr_ltoa(r->pool, (long) numHits));

    /* TODO: Check if this request has exceeded the limit */
    if (numHits > bucket->requests) {
        /* block request */
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, r->server, "request_handler blocked ip %s bucket %s %lu/%d", ip, bucket->name, numHits, bucket->requests);
        return (HTTP_FORBIDDEN);
    } else {
        /* We're not acting on this request */
        ap_log_error (APLOG_MARK, APLOG_TRACE1, 0, r->server, "request_handler allowed ip %s bucket %s %lu/%d", ip, bucket->name, numHits, bucket->requests);
        return (DECLINED);
    }
}

/**
===========
Time Helper
===========
*/
uint64_t mrl_get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (((uint64_t)tv.tv_sec)*1000)+(tv.tv_usec/1000);    
}

/** 
==============
Subnet helpers
==============
*/
void *mrl_apply_mask4(char *dest, const char *ipv4_address_str, int mask_bits) {
    struct in_addr ipv4_address, subnet_mask, subnet_address;

    // Convert IPv4 address from string to binary form
    if (inet_pton(AF_INET, ipv4_address_str, &ipv4_address) != 1) {
        return NULL;
    }

    // Generate subnet mask based on the number of mask bits
    subnet_address.s_addr = ipv4_address.s_addr & (0xffffffff >> (32 - mask_bits)); 

    // Convert subnet address from binary form to string
    inet_ntop(AF_INET, &subnet_address, dest, INET_ADDRSTRLEN);

    return NULL;
}

void *mrl_apply_mask6(char *dest, const char *ipv6_address_str, int mask_bits) {
    struct in6_addr ipv6_address, subnet_mask, subnet_address;

    // Convert IPv6 address from string to binary form
    if (inet_pton(AF_INET6, ipv6_address_str, &ipv6_address) != 1) {
        return NULL;
    }

    // Generate subnet mask based on the number of mask bits
    for (int i = 0; i < 16; i++) {
        if (mask_bits >= 8) {
            subnet_address.s6_addr[i] = ipv6_address.s6_addr[i]; // implied & 0xFF << 0
            mask_bits -= 8;
        } else if (mask_bits > 0) {
            subnet_address.s6_addr[i] = ipv6_address.s6_addr[i] & (0xFF << (8 - mask_bits));
            mask_bits = 0;
        } else {
            subnet_address.s6_addr[i] = 0;
        }
    }

    // Convert subnet address from binary form to string
    inet_ntop(AF_INET6, &subnet_address, dest, INET6_ADDRSTRLEN);

    return NULL;
}

/**
======================
Configuration handlers
======================
*/

const char *mrl_create_bucket(cmd_parms *cmd, void *cfg, const char *name, const char *requests, const char *timespan)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_create_bucket %s %s %s %s", cmd->server->defn_name, name, requests, timespan);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        // Create bucket object and populate config
        mrl_bucket *bucket = apr_pcalloc(cmd->pool, sizeof(mrl_bucket));
        bucket->ips = apr_table_make(cmd->pool, 1024);
        bucket->name = (char *)name;
        bucket->requests = strtol(requests, NULL, 10);
        bucket->timespan = strtol(timespan, NULL, 10) * 1000;
        bucket->lastReset = mrl_get_time_ms();

        // Add newly created bucket to server config
        *(mrl_bucket **)apr_array_push(conf->buckets) = bucket;
    }

    return NULL;
}


/** ReqLimitEngine mrl_set_enabled */
const char *mrl_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_set_enabled %s %s", cmd->server->defn_name, arg);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        if (!strcasecmp(arg, "on")) {
            conf->enabled = 1;
        } else if (!strcasecmp(arg, "off")) {
            conf->enabled = 0;
        } else {
            return "ReqLimitEngine value is invalid";
        }
    }

    return NULL;
}

/** ReqLimitSetBucket mrl_set_bucket */
const char *mrl_set_bucket(cmd_parms *cmd, void *cfg, const char *name)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_set_bucket %s %s", cmd->server->defn_name, name);

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
                ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_set_bucket using bucket %s", current_bucket->name);
                conf->bucket = current_bucket;
                return NULL;
            }
        }
    }

    return "ReqLimitSetBucket bucket does not exist";
}

/** ReqLimitSetNetmask4 mrl_set_netmask4 */
const char *mrl_set_netmask4(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_set_netmask4 %s %s", cmd->server->defn_name, arg);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        conf->netmask4 = strtol(arg, NULL, 10);
        if (conf->netmask4 < 0 || conf->netmask4 > 32) {
            return "ReqLimitSetNetmask4 value must be between 0 and 32";
        }
    }

    return NULL;
}

/** ReqLimitSetNetmask6 mrl_set_netmask6 */
const char *mrl_set_netmask6(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_set_netmask6 %s %s", cmd->server->defn_name, arg);

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config    *conf = (mrl_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(conf)
    {
        conf->netmask6 = strtol(arg, NULL, 10);
        if (conf->netmask6 < 0 || conf->netmask4 > 128) {
            return "ReqLimitSetNetmask6 value must be between 0 and 128";
        }
    }

    return NULL;
}
