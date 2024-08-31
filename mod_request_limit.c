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
    char    *name;          /* Name of the bucket */
    int     requests;       /* Number of requests to allow */
    int     timespan;       /* Number of milliseconds between clears */
    long    lastReset;      /* Last time the bucket was cleared */
    apr_table_t *ips;       /* Holds requests per ip */
} mrl_bucket;

typedef struct {
    char    src[255];
    int     enabled;                /* Enable or disable our module */
    server_rec *server;             /* the corresponding server indicator */
    apr_array_header_t *buckets;    /* Buckets within this server */
    mrl_bucket *bucket;             /* Actual bucket to use by request */
    int     netmask4;               /* netmask to apply to IPv4 address */
    int     netmask6;               /* netmask to apply to IPv6 address */
    int     statusCode;             /* HTTP Status code to return on block */
    apr_array_header_t *allowed;    /* List of ips to be allowed */
} mrl_config;

typedef struct {
    char    *cidr;          /* ip or CIDR notation */
} mrl_ip;


/** constants / defines */
#define MRL_DEFAULT_STATUS_CODE 429
#define MRL_ENGINE_MODE_INHERIT -1
#define MRL_ENGINE_MODE_OFF 0
#define MRL_ENGINE_MODE_ON 1
#define MRL_ENGINE_MODE_REPORTONLY 2

/** prototypes */
const char *mrl_cmd_bucket(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2, const char *arg3);
const char *mrl_cmd_engine(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_cmd_set_bucket(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_cmd_set_netmask4(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_cmd_set_netmask6(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_cmd_set_httpstatus(cmd_parms *cmd, void *cfg, const char *arg);
const char *mrl_cmd_allow(cmd_parms *cmd, void *cfg, const char *arg);
uint64_t mrl_get_time_ms();
void *mrl_apply_mask4(char *dest, const char *ipv4_address_str, int mask_bits);
void *mrl_apply_mask6(char *dest, const char *ipv6_address_str, int mask_bits);
int mrl_check_allowed (request_rec *r, mrl_config *conf);
void *create_server_conf(apr_pool_t *pool, server_rec *server);
void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD);
void *create_dir_conf(apr_pool_t *pool, char *arg);
void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD);
static void register_hooks(apr_pool_t *pool);
static int request_handler(request_rec *r);

/** directives */
static const command_rec directives[] =
{
    AP_INIT_TAKE1("ReqLimitEngine", mrl_cmd_engine, NULL, OR_FILEINFO, "Enable or disable mod_request_limit processing"),
    AP_INIT_TAKE3("ReqLimitBucket", mrl_cmd_bucket, NULL, RSRC_CONF, "Create a bucket"),
    AP_INIT_TAKE1("ReqLimitSetBucket", mrl_cmd_set_bucket, NULL, OR_FILEINFO, "Set the name of the bucket to use"),
    AP_INIT_TAKE1("ReqLimitSetNetmask4", mrl_cmd_set_netmask4, NULL, OR_FILEINFO, "Set the netmask bits for IPv4 addresses"),
    AP_INIT_TAKE1("ReqLimitSetNetmask6", mrl_cmd_set_netmask6, NULL, OR_FILEINFO, "Set the netmask bits for IPv6 addresses"),
    AP_INIT_TAKE1("ReqLimitHTTPStatus", mrl_cmd_set_httpstatus, NULL, OR_FILEINFO, "Set the HTTP status code used when blocking"),
    AP_INIT_TAKE1("ReqLimitAllow", mrl_cmd_allow, NULL, OR_FILEINFO, "Add IP to allow list"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA request_limit_module = 
{ 
    STANDARD20_MODULE_STUFF,    /* You know, standard 20 module stuff */
    create_dir_conf,            /* Per-directory configuration handler */
    merge_dir_conf,             /* Merge handler for per-directory configurations */
    create_server_conf,         /* Per-server configuration handler */
    merge_server_conf,          /* Merge handler for per-server configurations */
    directives,                 /* Any directives we may have for httpd */
    register_hooks              /* Our hook registering function */
};

static void register_hooks(apr_pool_t *pool)
{
    /* Create a hook in the request handler, so we get called when a request arrives */
    ap_hook_handler(request_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}


void *create_server_conf(apr_pool_t *pool, server_rec *server) {
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, server, "create_server_conf for %s", server->defn_name);
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        strcpy(cfg->src, "cs");
        cfg->enabled = MRL_ENGINE_MODE_OFF;
        cfg->bucket = NULL;
        cfg->server = server;
        cfg->buckets = apr_array_make(pool, 5, sizeof(mrl_bucket*));
        cfg->netmask4 = 32;
        cfg->netmask6 = 64;
        cfg->statusCode = MRL_DEFAULT_STATUS_CODE;
        cfg->allowed = apr_array_make(pool, 0, sizeof(mrl_ip*));

    }
    return cfg;
}

void *merge_server_conf(apr_pool_t *pool, void *BASE, void *ADD) {

    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;
    mrl_config *cfg = (mrl_config *) create_server_conf(pool, (add->server) ? add->server : base->server);

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, base->server, "merge_server_conf %s", add->server->defn_name);

    /* Merge configurations */
    cfg->enabled = (add->enabled == MRL_ENGINE_MODE_INHERIT) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    cfg->buckets = (add->buckets) ? (apr_array_header_t *)add->buckets : (apr_array_header_t *)base->buckets;
    cfg->netmask4 = (add->netmask4) ? add->netmask4 : base->netmask4;
    cfg->netmask6 = (add->netmask6) ? add->netmask6 : base->netmask6;
    cfg->statusCode = (add->statusCode) ? add->statusCode : base->statusCode;
    cfg->allowed = (add->allowed) ? add->allowed : base->allowed;

    strcpy(cfg->src, "ms");
    
    return cfg;
}

void *create_dir_conf(apr_pool_t *pool, char *arg) {
    mrl_config *cfg = apr_pcalloc(pool, sizeof(mrl_config));
    if(cfg) {
        /* Set some default values */
        cfg->enabled = MRL_ENGINE_MODE_INHERIT;
        cfg->bucket = NULL;
        cfg->netmask4 = 32;
        cfg->netmask6 = 64;
        cfg->statusCode = 0;
        strcpy(cfg->src, "cd");
        cfg->allowed = apr_array_make(pool, 0, sizeof(mrl_ip));
    }
    return cfg;
}

void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD) {
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "merge_dir_conf");
    mrl_config *base = (mrl_config *) BASE ;
    mrl_config *add = (mrl_config *) ADD ;
    mrl_config *cfg = (mrl_config *) create_dir_conf(pool, "");
    
    /* Merge configurations */
    cfg->enabled = (add->enabled == MRL_ENGINE_MODE_INHERIT) ? base->enabled : add->enabled ;
    cfg->bucket = (add->bucket) ? add->bucket : base->bucket;
    cfg->netmask4 = (add->netmask4) ? add->netmask4 : base->netmask4;
    cfg->netmask6 = (add->netmask6) ? add->netmask6 : base->netmask6;
    cfg->statusCode = (add->statusCode) ? add->statusCode : base->statusCode;
    strcpy(cfg->src, "md");
    cfg->allowed = (add->allowed) ? add->allowed : base->allowed;
    
    return cfg;
}

static int request_handler(request_rec *r)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler %s", r->server->defn_name);
    mrl_config *server_conf = (mrl_config *) ap_get_module_config(r->server->module_config, &request_limit_module);
    mrl_config *per_dir_conf = (mrl_config *) ap_get_module_config(r->per_dir_config, &request_limit_module);

    /* Check if this request is limited */
    if (per_dir_conf->enabled == MRL_ENGINE_MODE_OFF || (per_dir_conf->enabled == MRL_ENGINE_MODE_INHERIT && server_conf->enabled < MRL_ENGINE_MODE_ON)) {
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
/*    
    if (now > (bucket->lastReset + bucket->timespan)) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler clearing bucket %s %lu %d", bucket->name, bucket->lastReset, bucket->timespan);
        bucket->lastReset = now;
        apr_table_clear(bucket->ips);
    }
*/
    /* Add IP to list */
    apr_sockaddr_t *ipAdd;
    apr_sockaddr_info_copy(&ipAdd, r->useragent_addr, r->pool);

    char *ip;
    char *masked;
    apr_sockaddr_ip_get(&ip, ipAdd);

    if ((mrl_check_allowed(r, per_dir_conf) + mrl_check_allowed(r, server_conf)) > 0) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler ip %s on allow list", ip);
        return (DECLINED);
    }

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
    
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler getting array from table");
    apr_array_header_t *hitQueue = (apr_array_header_t *)apr_table_get(bucket->ips, ip);
    if (hitQueue == NULL) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler hitqueue == NULL");
        hitQueue = apr_array_make(r->pool, bucket->requests, sizeof(uint64_t));
    }

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler Looping over elements");
    int i = 0;
    while (i < hitQueue->nelts) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request handler i = %d , nelts = %d", i, hitQueue->nelts);
//        uint64_t element = APR_ARRAY_IDX(hitQueue, i, uint64_t);
        uint64_t element = (((uint64_t *)hitQueue->elts)[i]);
        if (element < now - bucket->timespan) {
            // Remove the element by shifting the remaining elements
            memmove(&(hitQueue->elts[i]), &(hitQueue->elts[i+1]), (hitQueue->nelts - i - 1) * sizeof(uint64_t));
            hitQueue->nelts--;
        } else {
            i++;
        }
    }

    if (hitQueue->nelts < bucket->requests) {
        // add request to array
        // APR_ARRAY_PUSH(hitQueue, uint64_t) = now;
        (*((uint64_t *)apr_array_push(hitQueue))) = now;
    }
    // re-save queue
    apr_table_set(bucket->ips, ip, (const char *)hitQueue);

    int numHits = (int)hitQueue->nelts;
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "request_handler ip %s %d/%d", ip, numHits, bucket->requests);

    /* Check if this request has exceeded the limit */
    if (numHits > bucket->requests) {
        /* Limit exceeded */
        if (per_dir_conf->enabled == MRL_ENGINE_MODE_ON || (per_dir_conf->enabled == MRL_ENGINE_MODE_INHERIT && server_conf->enabled == MRL_ENGINE_MODE_ON)) {
            // block request
            ap_log_error (APLOG_MARK, APLOG_ERR, 0, r->server, "request_handler blocked ip %s bucket %s %d/%d", ip, bucket->name, numHits, bucket->requests);
            return (per_dir_conf->statusCode ? per_dir_conf->statusCode : server_conf->statusCode);
        } else {
            // report only, don't block
            ap_log_error (APLOG_MARK, APLOG_ERR, 0, r->server, "request_handler report-only ip %s bucket %s %d/%d", ip, bucket->name, numHits, bucket->requests);
            return (DECLINED);
        }
    } else {
        /* We're not acting on this request */
        ap_log_error (APLOG_MARK, APLOG_TRACE1, 0, r->server, "request_handler allowed ip %s bucket %s %d/%d", ip, bucket->name, numHits, bucket->requests);
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
==================
Allowedlist helper
==================
*/
int mrl_check_allowed (request_rec *r, mrl_config *conf) {

    mrl_ip *allowedIps = (mrl_ip *) conf->allowed->elts;
    mrl_ip *ip;

    char *clientIpC;
    apr_sockaddr_ip_get(&clientIpC, r->useragent_addr);

    int allowed = 0;

    apr_ipsubnet_t *checkSubnet;
    char *checkAddress;
    char *checkIp;
    char *checkMask;

    for (int i = 0; i < conf->allowed->nelts; i++) {
        ip = &allowedIps[i];

        if (strchr(ip->cidr, '/') == NULL) {
            /* Not CIDR, try exact match */
            if (strcmp(ip->cidr, clientIpC) == 0) {
                allowed = 1;
                continue;
            }
        } else {
            /* assume CIDR, subnet match */
            checkAddress = apr_pstrdup(r->pool, ip->cidr);
            checkIp = apr_strtok(checkAddress, "/", &checkMask);
            apr_ipsubnet_create(&checkSubnet, checkIp, checkMask, r->pool);

            if (apr_ipsubnet_test(checkSubnet, r->useragent_addr) != 0) {
                allowed = 1;
            }
        }
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, r->server, "Matching ip %s against %s. Allowed = %d", clientIpC, ip->cidr, allowed);
    }

    return allowed;
}

/**
======================
Configuration handlers
======================
*/

/** ReqLimitBucket mrl_cmd_bucket */
const char *mrl_cmd_bucket(cmd_parms *cmd, void *cfg, const char *name, const char *requests, const char *timespan)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_bucket %s %s %s %s", cmd->server->defn_name, name, requests, timespan);

    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(sconf)
    {
        // Create bucket object and populate config
        mrl_bucket *bucket = apr_pcalloc(cmd->pool, sizeof(mrl_bucket));
        bucket->ips = apr_table_make(cmd->pool, 1024);
        bucket->name = (char *)name;
        bucket->requests = strtol(requests, NULL, 10);
        bucket->timespan = strtol(timespan, NULL, 10) * 1000;
        bucket->lastReset = mrl_get_time_ms();

        // Add newly created bucket to server config
        *(mrl_bucket **)apr_array_push(sconf->buckets) = bucket;
    }

    return NULL;
}


/** ReqLimitEngine mrl_cmd_engine */
const char *mrl_cmd_engine(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_engine %s %s %s", cmd->server->defn_name, arg, cmd->path);

    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *dconf = cfg;
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if (!strcasecmp(arg, "on")) {
        dconf->enabled = MRL_ENGINE_MODE_ON;
    } else if (!strcasecmp(arg, "off")) {
        dconf->enabled = MRL_ENGINE_MODE_OFF;
    } else if (!strcasecmp(arg, "reportonly")) {
        dconf->enabled = MRL_ENGINE_MODE_REPORTONLY;
    } else {
        return "ReqLimitEngine value is invalid";
    }

    if(cmd->path == NULL)
    {
        // server config, also set sconf
        sconf->enabled = dconf->enabled;
    }

    return NULL;
}

/** ReqLimitSetBucket mrl_cmd_set_bucket */
const char *mrl_cmd_set_bucket(cmd_parms *cmd, void *cfg, const char *name)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_set_bucket %s %s %s", cmd->server->defn_name, name, cmd->path);

    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *dconf = cfg;
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if (sconf && sconf->buckets) {
        int i;
        int num_buckets = sconf->buckets->nelts;    
        for (i = 0; i < num_buckets; i++) {
            mrl_bucket *current_bucket = APR_ARRAY_IDX(sconf->buckets, i, mrl_bucket *);
            if (0 == strcmp(name, current_bucket->name)) {
                ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_set_bucket using bucket %s", current_bucket->name);
                dconf->bucket = current_bucket;
                if (cmd->path == NULL) {
                    // server config, also set values in sconf
                    sconf->bucket = dconf->bucket;
                }
                return NULL;
            }
        }
    }

    return "ReqLimitSetBucket bucket does not exist";
}

/** ReqLimitSetNetmask4 mrl_cmd_set_netmask4 */
const char *mrl_cmd_set_netmask4(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_set_netmask4 %s %s %s", cmd->server->defn_name, arg, cmd->path);

    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *dconf = cfg;
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    dconf->netmask4 = strtol(arg, NULL, 10);
    if (dconf->netmask4 < 0 || dconf->netmask4 > 32) {
        return "ReqLimitSetNetmask4 value must be between 0 and 32";
    }

    if (cmd->path == NULL) {
        // server config, also set values in sconf
        sconf->netmask4 = dconf->netmask4;
    }

    return NULL;
}

/** ReqLimitSetNetmask6 mrl_cmd_set_netmask6 */
const char *mrl_cmd_set_netmask6(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_set_netmask6 %s %s %s", cmd->server->defn_name, arg, cmd->path);

    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *dconf = cfg;
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    dconf->netmask6 = strtol(arg, NULL, 10);
    if (dconf->netmask6 < 0 || dconf->netmask6 > 128) {
        return "ReqLimitSetNetmask6 value must be between 0 and 128";
    }

    if (cmd->path == NULL) {
        // server config, also set values in sconf
        sconf->netmask6 = dconf->netmask6;
    }

    return NULL;
}

/** ReqLimitHTTPStatus mrl_cmd_set_httpstatus */
const char *mrl_cmd_set_httpstatus(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_set_httpstatus %s %s %s", cmd->server->defn_name, arg, cmd->path);

    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *dconf = cfg;
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    dconf->statusCode = strtol(arg, NULL, 10);
    if (dconf->statusCode < 100 || dconf->statusCode > 999) {
        return "ReqLimitHTTPStatus value must be between 100 and 999";
    }

    if (cmd->path == NULL) {
        // server config, also set values in sconf
        sconf->statusCode = dconf->statusCode;
    }

    return NULL;
}

/** ReqLimitAllow mrl_cmd_allow */
const char *mrl_cmd_allow(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_allow %s %s %s", cmd->server->defn_name, arg, cmd->path);
 
    /*~~~ get configs ~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    mrl_config *dconf = cfg;
    mrl_config *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &request_limit_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    // push on list
    mrl_ip *ip = apr_array_push(dconf->allowed);
    ip->cidr = (char *) arg;

    if (cmd->path == NULL) {
        // server config, also set values in sconf
        mrl_ip *ip = apr_array_push(sconf->allowed);
        ip->cidr = (char *) arg;
    }
 
   ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "mrl_cmd_allow now contains elts d %d s %d", dconf->allowed->nelts, sconf->allowed->nelts);
 
    return NULL;
}