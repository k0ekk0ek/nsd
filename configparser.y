/*
 * configparser.y -- yacc grammar for NSD configuration files
 *
 * Copyright (c) 2001-2019, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

%{
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "options.h"
#include "util.h"
#include "dname.h"
#include "tsig.h"
#include "rrl.h"
#include "configyyrename.h"

int yylex(void);

#ifdef __cplusplus
extern "C"
#endif

/* these need to be global, otherwise they cannot be used inside yacc */
extern config_parser_state_type *cfg_parser;

static void append_acl(struct acl_options **list, struct acl_options *acl);
static int parse_boolean(const char *str, int *bln);
static int parse_number(const char *str, long long *num);

struct component {
  struct component *next;
  char *str;
};

%}

%union {
  char *str;
  long long llng;
  int bln;
  struct ip_address_option *ip;
  char **strv;
  struct component *comp;
}

%token <str> STRING

%type <llng> number
%type <bln> boolean
%type <ip> ip_address
%type <llng> verifier_timeout
%type <bln> verifier_feed_zone
%type <strv> command
%type <comp> arguments

/* server */
%token VAR_SERVER
%token VAR_SERVER_COUNT
%token VAR_IP_ADDRESS
%token VAR_IP_TRANSPARENT
%token VAR_IP_FREEBIND
%token VAR_REUSEPORT
%token VAR_SEND_BUFFER_SIZE
%token VAR_RECEIVE_BUFFER_SIZE
%token VAR_DEBUG_MODE
%token VAR_IP4_ONLY
%token VAR_IP6_ONLY
%token VAR_DO_IP4
%token VAR_DO_IP6
%token VAR_PORT
%token VAR_USE_SYSTEMD
%token VAR_VERBOSITY
%token VAR_USERNAME
%token VAR_CHROOT
%token VAR_ZONESDIR
%token VAR_ZONELISTFILE
%token VAR_DATABASE
%token VAR_LOGFILE
%token VAR_PIDFILE
%token VAR_DIFFFILE
%token VAR_XFRDFILE
%token VAR_XFRDIR
%token VAR_HIDE_VERSION
%token VAR_HIDE_IDENTITY
%token VAR_VERSION
%token VAR_IDENTITY
%token VAR_NSID
%token VAR_TCP_COUNT
%token VAR_TCP_REJECT_OVERFLOW
%token VAR_TCP_QUERY_COUNT
%token VAR_TCP_TIMEOUT
%token VAR_TCP_MSS
%token VAR_OUTGOING_TCP_MSS
%token VAR_IPV4_EDNS_SIZE
%token VAR_IPV6_EDNS_SIZE
%token VAR_STATISTICS
%token VAR_XFRD_RELOAD_TIMEOUT
%token VAR_LOG_TIME_ASCII
%token VAR_ROUND_ROBIN
%token VAR_MINIMAL_RESPONSES
%token VAR_REFUSE_ANY
%token VAR_ZONEFILES_CHECK
%token VAR_ZONEFILES_WRITE
%token VAR_RRL_SIZE
%token VAR_RRL_RATELIMIT
%token VAR_RRL_SLIP
%token VAR_RRL_IPV4_PREFIX_LENGTH
%token VAR_RRL_IPV6_PREFIX_LENGTH
%token VAR_RRL_WHITELIST_RATELIMIT
%token VAR_TLS_SERVICE_KEY
%token VAR_TLS_SERVICE_PEM
%token VAR_TLS_SERVICE_OCSP
%token VAR_TLS_PORT
%token VAR_ENABLE

/* dnstap */
%token VAR_DNSTAP
%token VAR_DNSTAP_ENABLE
%token VAR_DNSTAP_SOCKET_PATH
%token VAR_DNSTAP_SEND_IDENTITY
%token VAR_DNSTAP_SEND_VERSION
%token VAR_DNSTAP_IDENTITY
%token VAR_DNSTAP_VERSION
%token VAR_DNSTAP_LOG_AUTH_QUERY_MESSAGES
%token VAR_DNSTAP_LOG_AUTH_RESPONSE_MESSAGES

/* remote-control */
%token VAR_REMOTE_CONTROL
%token VAR_CONTROL_ENABLE
%token VAR_CONTROL_INTERFACE
%token VAR_CONTROL_PORT
%token VAR_SERVER_KEY_FILE
%token VAR_SERVER_CERT_FILE
%token VAR_CONTROL_KEY_FILE
%token VAR_CONTROL_CERT_FILE

/* key */
%token VAR_KEY
%token VAR_ALGORITHM
%token VAR_SECRET

/* pattern */
%token VAR_PATTERN
%token VAR_NAME
%token VAR_ZONEFILE
%token VAR_NOTIFY
%token VAR_PROVIDE_XFR
%token VAR_AXFR
%token VAR_UDP
%token VAR_NOTIFY_RETRY
%token VAR_ALLOW_NOTIFY
%token VAR_REQUEST_XFR
%token VAR_ALLOW_AXFR_FALLBACK
%token VAR_OUTGOING_INTERFACE
%token VAR_MAX_REFRESH_TIME
%token VAR_MIN_REFRESH_TIME
%token VAR_MAX_RETRY_TIME
%token VAR_MIN_RETRY_TIME
%token VAR_MULTI_MASTER_CHECK
%token VAR_SIZE_LIMIT_XFR
%token VAR_ZONESTATS
%token VAR_INCLUDE_PATTERN

/* zone */
%token VAR_ZONE
%token VAR_RRL_WHITELIST

/* verifier */
%token VAR_VERIFY
%token VAR_VERIFIER
%token VAR_VERIFIER_COUNT
%token VAR_VERIFIER_FEED_ZONE
%token VAR_VERIFIER_TIMEOUT

%%

blocks:
    /* may be empty */
  | blocks block ;

block:
    server
  | dnstap
  | remote_control
  | key
  | pattern
  | zone
  | verify ;

server:
    VAR_SERVER server_block ;

server_block:
    server_block server_option | ;

server_option:
    VAR_IP_ADDRESS ip_address
    {
      struct ip_address_option *ip = cfg_parser->opt->ip_addresses;
      if(ip == NULL) {
        cfg_parser->opt->ip_addresses = $2;
      } else {
        while(ip->next) { ip = ip->next; }
        ip->next = $2;
      }
    }
  | VAR_SERVER_COUNT number
    { cfg_parser->opt->server_count = (int)$2; }
  | VAR_IP_TRANSPARENT boolean
    { cfg_parser->opt->ip_transparent = (int)$2; }
  | VAR_IP_FREEBIND boolean
    { cfg_parser->opt->ip_freebind = $2; }
  | VAR_SEND_BUFFER_SIZE number
    { cfg_parser->opt->send_buffer_size = (int)$2; }
  | VAR_RECEIVE_BUFFER_SIZE number
    { cfg_parser->opt->receive_buffer_size = (int)$2; }
  | VAR_DEBUG_MODE boolean
    { cfg_parser->opt->debug_mode = $2; }
  | VAR_USE_SYSTEMD boolean
    { /* ignored, deprecated */ }
  | VAR_HIDE_VERSION boolean
    { cfg_parser->opt->hide_version = $2; }
  | VAR_HIDE_IDENTITY boolean
    { cfg_parser->opt->hide_identity = $2; }
  | VAR_IP4_ONLY boolean
    { if($2) { cfg_parser->opt->do_ip4 = 1; cfg_parser->opt->do_ip6 = 0; } }
  | VAR_IP6_ONLY boolean
    { if($2) { cfg_parser->opt->do_ip4 = 0; cfg_parser->opt->do_ip6 = 1; } }
  | VAR_DO_IP4 boolean
    { cfg_parser->opt->do_ip4 = $2; }
  | VAR_DO_IP6 boolean
    { cfg_parser->opt->do_ip6 = $2; }
  | VAR_DATABASE STRING
    {
      cfg_parser->opt->database = region_strdup(cfg_parser->opt->region, $2);
      if(cfg_parser->opt->database[0] == 0
      && cfg_parser->opt->zonefiles_write == 0) {
        cfg_parser->opt->zonefiles_write = ZONEFILES_WRITE_INTERVAL;
      }
    }
  | VAR_IDENTITY STRING
    { cfg_parser->opt->identity = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_VERSION STRING
    { cfg_parser->opt->version = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_NSID STRING
    {
      unsigned char* nsid = 0;
      size_t nsid_len = strlen($2);

      if (strncasecmp($2, "ascii_", 6) == 0) {
        nsid_len += 6;
        if(nsid_len < 65535) {
          cfg_parser->opt->nsid = region_alloc(cfg_parser->opt->region, nsid_len*2+1);
          hex_ntop((uint8_t*)$2+6, nsid_len, (char*)cfg_parser->opt->nsid, nsid_len*2+1);
        } else {
          yyerror("NSID too long");
        }
      } else if (nsid_len % 2 != 0) {
        yyerror("the NSID must be a hex string of an even length.");
      } else {
        nsid_len = nsid_len / 2;
        if(nsid_len < 65535) {
          nsid = xalloc(nsid_len);
          if (hex_pton($2, nsid, nsid_len) == -1) {
            yyerror("hex string cannot be parsed in NSID.");
          } else {
            cfg_parser->opt->nsid = region_strdup(cfg_parser->opt->region, $2);
          }
          free(nsid);
        } else {
          yyerror("NSID too long");
        }
      }
    }
  | VAR_LOGFILE STRING
    { cfg_parser->opt->logfile = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_TCP_COUNT number
    { cfg_parser->opt->tcp_count = (int)$2; }
  | VAR_TCP_REJECT_OVERFLOW number
    { cfg_parser->opt->tcp_reject_overflow = (int)$2; }
  | VAR_TCP_QUERY_COUNT number
    { cfg_parser->opt->tcp_query_count = (int)$2; }
  | VAR_TCP_TIMEOUT number
    { cfg_parser->opt->tcp_timeout = (int)$2; }
  | VAR_TCP_MSS number
    { cfg_parser->opt->tcp_mss = (int)$2; }
  | VAR_OUTGOING_TCP_MSS number
    { cfg_parser->opt->outgoing_tcp_mss = (int)$2; }
  | VAR_IPV4_EDNS_SIZE number
    { cfg_parser->opt->ipv4_edns_size = (size_t)$2; }
  | VAR_IPV6_EDNS_SIZE number
    { cfg_parser->opt->ipv6_edns_size = (size_t)$2; }
  | VAR_PIDFILE STRING
    { cfg_parser->opt->pidfile = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_PORT number
    {
      /* port number, stored as a string */
      char buf[16];
      (void)snprintf(buf, sizeof(buf), "%lld", $2);
      cfg_parser->opt->port = region_strdup(cfg_parser->opt->region, buf);
    }
  | VAR_REUSEPORT boolean
    { cfg_parser->opt->reuseport = $2; }
  | VAR_STATISTICS number
    { cfg_parser->opt->statistics = (int)$2; }
  | VAR_CHROOT STRING
    { cfg_parser->opt->chroot = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_USERNAME STRING
    { cfg_parser->opt->username = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_ZONESDIR STRING
    { cfg_parser->opt->zonesdir = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_ZONELISTFILE STRING
    { cfg_parser->opt->zonelistfile = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_DIFFFILE STRING
    { /* ignored, deprecated */ }
  | VAR_XFRDFILE STRING
    { cfg_parser->opt->xfrdfile = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_XFRDIR STRING
    { cfg_parser->opt->xfrdir = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_XFRD_RELOAD_TIMEOUT number
    { cfg_parser->opt->xfrd_reload_timeout = (int)$2; }
  | VAR_VERBOSITY number
    { cfg_parser->opt->verbosity = (int)$2; }
  | VAR_RRL_SIZE number
    {
#ifdef RATELIMIT
      cfg_parser->opt->rrl_size = (size_t)$2;
#endif
    }
  | VAR_RRL_RATELIMIT number
    {
#ifdef RATELIMIT
      cfg_parser->opt->rrl_ratelimit = (size_t)$2;
#endif
    }
  | VAR_RRL_SLIP number
    {
#ifdef RATELIMIT
      cfg_parser->opt->rrl_slip = (size_t)$2;
#endif
    }
  | VAR_RRL_IPV4_PREFIX_LENGTH number
    {
#ifdef RATELIMIT
      cfg_parser->opt->rrl_ipv4_prefix_length = (size_t)$2;
#endif
    }
  | VAR_RRL_IPV6_PREFIX_LENGTH number
    {
#ifdef RATELIMIT
      cfg_parser->opt->rrl_ipv6_prefix_length = (size_t)$2;
#endif
    }
  | VAR_RRL_WHITELIST_RATELIMIT number
    {
#ifdef RATELIMIT
      cfg_parser->opt->rrl_whitelist_ratelimit = (size_t)$2;
#endif
    }
  | VAR_ZONEFILES_CHECK boolean
    { cfg_parser->opt->zonefiles_check = $2; }
  | VAR_ZONEFILES_WRITE number
    { cfg_parser->opt->zonefiles_write = (int)$2; }
  | VAR_LOG_TIME_ASCII boolean
    { cfg_parser->opt->log_time_ascii = $2; }
  | VAR_ROUND_ROBIN boolean
    { cfg_parser->opt->round_robin = $2; }
  | VAR_MINIMAL_RESPONSES boolean
    { cfg_parser->opt->minimal_responses = $2; }
  | VAR_REFUSE_ANY boolean
    { cfg_parser->opt->refuse_any = $2; }
  | VAR_TLS_SERVICE_KEY STRING
    { cfg_parser->opt->tls_service_key = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_TLS_SERVICE_OCSP STRING
    { cfg_parser->opt->tls_service_ocsp = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_TLS_SERVICE_PEM STRING
    { cfg_parser->opt->tls_service_pem = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_TLS_PORT number
    {
      /* port number, stored as string */
      char buf[16];
      (void)snprintf(buf, sizeof(buf), "%lld", $2);
      cfg_parser->opt->tls_port = region_strdup(cfg_parser->opt->region, buf);
    }
  ;

dnstap:
    VAR_DNSTAP dnstap_block ;

dnstap_block:
    dnstap_block dnstap_option | ;

dnstap_option:
    VAR_DNSTAP_ENABLE boolean
    { cfg_parser->opt->dnstap_enable = $2; }
  | VAR_DNSTAP_SOCKET_PATH STRING
    { cfg_parser->opt->dnstap_socket_path = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_DNSTAP_SEND_IDENTITY boolean
    { cfg_parser->opt->dnstap_send_identity = $2; }
  | VAR_DNSTAP_SEND_VERSION boolean
    { cfg_parser->opt->dnstap_send_version = $2; }
  | VAR_DNSTAP_IDENTITY STRING
    { cfg_parser->opt->dnstap_identity = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_DNSTAP_VERSION STRING
    { cfg_parser->opt->dnstap_version = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_DNSTAP_LOG_AUTH_QUERY_MESSAGES boolean
    { cfg_parser->opt->dnstap_log_auth_query_messages = $2; }
  | VAR_DNSTAP_LOG_AUTH_RESPONSE_MESSAGES boolean
    { cfg_parser->opt->dnstap_log_auth_response_messages = $2; }
  ;

remote_control:
    VAR_REMOTE_CONTROL remote_control_block ;

remote_control_block:
    remote_control_block remote_control_option | ;

remote_control_option:
    VAR_CONTROL_ENABLE boolean
    { cfg_parser->opt->control_enable = $2; }
  | VAR_CONTROL_INTERFACE ip_address
    {
      struct ip_address_option *ip = cfg_parser->opt->control_interface;
      if(ip == NULL) {
        cfg_parser->opt->control_interface = $2;
      } else {
        while(ip->next != NULL) { ip = ip->next; }
        ip->next = $2;
      }
    }
  | VAR_CONTROL_PORT number
    { cfg_parser->opt->control_port = (int)$2; }
  | VAR_SERVER_KEY_FILE STRING
    { cfg_parser->opt->server_key_file = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_SERVER_CERT_FILE STRING
    { cfg_parser->opt->server_cert_file = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_CONTROL_KEY_FILE STRING
    { cfg_parser->opt->control_key_file = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_CONTROL_CERT_FILE STRING
    { cfg_parser->opt->control_cert_file = region_strdup(cfg_parser->opt->region, $2); }
  ;

key:
    VAR_KEY
      {
        key_options_type *key = key_options_create(cfg_parser->opt->region);
        key->algorithm = region_strdup(cfg_parser->opt->region, "sha256");
        assert(cfg_parser->block.key == NULL);
        cfg_parser->block.key = key;
      }
      key_block
    {
      struct key_options *key = cfg_parser->block.key;
      if(key->name == NULL) {
        yyerror("key has no name");
      } else if(key->algorithm == NULL) {
        yyerror("key %s has no algorithm", key->name);
      } else if(key->secret == NULL) {
        yyerror("key %s has no secret blob", key->name);
      } else {
        key_options_insert(cfg_parser->opt, key);
        cfg_parser->block.key = NULL;
      }
    } ;

key_block:
    key_block key_option | ;

key_option:
    VAR_NAME STRING
    { cfg_parser->block.key->name = region_strdup(cfg_parser->opt->region, $2);  }
  | VAR_ALGORITHM STRING
    {
      if(cfg_parser->block.key->algorithm != NULL) {
        size_t len = strlen(cfg_parser->block.key->algorithm) + 1;
        region_recycle(cfg_parser->opt->region, cfg_parser->block.key->algorithm, len);
      }
      if(tsig_get_algorithm_by_name($2) == NULL) {
        yyerror("Bad tsig algorithm %s", $2);
      } else {
        cfg_parser->block.key->algorithm = region_strdup(cfg_parser->opt->region, $2);
      }
    }
  | VAR_SECRET STRING
    {
      uint8_t data[16384];
      int size;

      cfg_parser->block.key->secret = region_strdup(cfg_parser->opt->region, $2);
      size = b64_pton($2, data, sizeof(data));
      if(size == -1) {
        yyerror("Cannot base64 decode tsig secret %s",
          cfg_parser->block.key->name?
          cfg_parser->block.key->name:"");
      } else if(size != 0) {
        memset(data, 0xdd, size); /* wipe secret */
      }
    } ;

pattern:
    VAR_PATTERN
      {
        assert(cfg_parser->block.pattern == NULL);
        cfg_parser->block.pattern = pattern_options_create(cfg_parser->opt->region);
      }
      pattern_block
    {
      pattern_options_type *pattern = cfg_parser->block.pattern;
      if(pattern->pname == NULL) {
        yyerror("pattern has no name");
      } else if(!nsd_options_insert_pattern(cfg_parser->opt, pattern)) {
        yyerror("duplicate pattern %s", pattern->pname);
      }
      cfg_parser->block.pattern = NULL;
    } ;

pattern_block:
    pattern_block pattern_option | ;

pattern_option:
    VAR_NAME STRING
    { cfg_parser->block.pattern->pname = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_ZONEFILE STRING
    { cfg_parser->block.pattern->zonefile = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_ZONESTATS STRING
    { cfg_parser->block.pattern->zonestats = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_SIZE_LIMIT_XFR number
    { cfg_parser->block.pattern->size_limit_xfr = (int)$2; }
  | VAR_MULTI_MASTER_CHECK boolean
    { cfg_parser->block.pattern->multi_master_check = (int)$2; }
  | VAR_INCLUDE_PATTERN STRING
    { config_apply_pattern(cfg_parser->block.pattern, $2); }
  | VAR_REQUEST_XFR STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      if(acl->blocked)
        yyerror("blocked address used for request-xfr");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for request-xfr");
      append_acl(&cfg_parser->block.pattern->request_xfr, acl);
    }
  | VAR_REQUEST_XFR VAR_AXFR STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $3, $4);
      acl->use_axfr_only = 1;
      if(acl->blocked)
        yyerror("blocked address used for request-xfr");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for request-xfr");
      append_acl(&cfg_parser->block.pattern->request_xfr, acl);
    }
  | VAR_REQUEST_XFR VAR_UDP STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $3, $4);
      acl->allow_udp = 1;
      if(acl->blocked)
        yyerror("blocked address used for request-xfr");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for request-xfr");
      append_acl(&cfg_parser->block.pattern->request_xfr, acl);
    }
  | VAR_ALLOW_NOTIFY STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      append_acl(&cfg_parser->block.pattern->allow_notify, acl);
    }
  | VAR_NOTIFY STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      if(acl->blocked)
        yyerror("blocked address used for notify");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for notify");
      append_acl(&cfg_parser->block.pattern->notify, acl);
    }
  | VAR_PROVIDE_XFR STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      append_acl(&cfg_parser->block.pattern->provide_xfr, acl);
    }
  | VAR_OUTGOING_INTERFACE STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, "NOKEY");
      append_acl(&cfg_parser->block.pattern->outgoing_interface, acl);
    }
  | VAR_ALLOW_AXFR_FALLBACK boolean
    {
      cfg_parser->block.pattern->allow_axfr_fallback = $2;
      cfg_parser->block.pattern->allow_axfr_fallback_is_default = 0;
    }
  | VAR_NOTIFY_RETRY number
    {
      cfg_parser->block.pattern->notify_retry = $2;
      cfg_parser->block.pattern->notify_retry_is_default = 0;
    }
  | VAR_MAX_REFRESH_TIME number
    {
      cfg_parser->block.pattern->max_refresh_time = $2;
      cfg_parser->block.pattern->max_refresh_time_is_default = 0;
    }
  | VAR_MIN_REFRESH_TIME number
    {
      cfg_parser->block.pattern->min_refresh_time = $2;
      cfg_parser->block.pattern->min_refresh_time_is_default = 0;
    }
  | VAR_MAX_RETRY_TIME number
    {
      cfg_parser->block.pattern->max_retry_time = $2;
      cfg_parser->block.pattern->max_retry_time_is_default = 0;
    }
  | VAR_MIN_RETRY_TIME number
    {
      cfg_parser->block.pattern->min_retry_time = $2;
      cfg_parser->block.pattern->min_retry_time_is_default = 0;
    }
  | VAR_VERIFIER command
    { cfg_parser->block.pattern->verifier = $2; }
  | verifier_feed_zone
    { cfg_parser->block.pattern->verifier_feed_zone = (uint8_t)$1; }
  | verifier_timeout
    { cfg_parser->block.pattern->verifier_timeout = (int32_t)$1; }
 ;

zone:
    VAR_ZONE
      {
        assert(cfg_parser->block.zone == NULL);
        cfg_parser->block.zone = zone_options_create(cfg_parser->opt->region);
        cfg_parser->block.zone->part_of_config = 1;
        cfg_parser->block.zone->pattern = pattern_options_create(
          cfg_parser->opt->region);
        cfg_parser->block.zone->pattern->implicit = 1;
      }
    zone_block
    {
      assert(cfg_parser->block.zone != NULL);
      if(cfg_parser->block.zone->name == NULL) {
        yyerror("zone has no name");
      } else if(!nsd_options_insert_zone(cfg_parser->opt, cfg_parser->block.zone)) {
        yyerror("duplicate zone %s", cfg_parser->block.zone->name);
      } else if(!nsd_options_insert_pattern(cfg_parser->opt, cfg_parser->block.zone->pattern)) {
        yyerror("duplicate zone %s", cfg_parser->block.zone->pattern->pname);
      }
      cfg_parser->block.zone = NULL;
    } ;

zone_block:
    zone_block zone_option | ;

zone_option:
    VAR_NAME STRING
    {
      const char *marker = PATTERN_IMPLICIT_MARKER;
      char *pname = region_alloc(cfg_parser->opt->region, strlen($2) + strlen(marker) + 1);
      memcpy(pname, marker, strlen(marker));
      memcpy(pname + strlen(marker), $2, strlen($2) + 1);
      cfg_parser->block.zone->pattern->pname = pname;
      cfg_parser->block.zone->name = region_strdup(cfg_parser->opt->region, $2);
      if(pattern_options_find(cfg_parser->opt, pname)) {
        yyerror("zone %s cannot be created because implicit pattern %s "
                    "already exists", $2, pname);
      }
    }
  | VAR_ZONEFILE STRING
    { cfg_parser->block.zone->pattern->zonefile = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_ZONESTATS STRING
    { cfg_parser->block.zone->pattern->zonestats = region_strdup(cfg_parser->opt->region, $2); }
  | VAR_RRL_WHITELIST STRING
    {
#ifdef RATELIMIT
      cfg_parser->block.zone->pattern->rrl_whitelist |= rrlstr2type($2);
#endif
    }
  | VAR_INCLUDE_PATTERN STRING
    { config_apply_pattern(cfg_parser->block.zone->pattern, $2); }
  | VAR_REQUEST_XFR STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      if(acl->blocked)
        yyerror("blocked address used for request-xfr");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for request-xfr");
      append_acl(&cfg_parser->block.zone->pattern->request_xfr, acl);
    }
  | VAR_REQUEST_XFR VAR_AXFR STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $3, $4);
      acl->use_axfr_only = 1;
      if(acl->blocked)
        yyerror("blocked address used for request-xfr");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for request-xfr");
      append_acl(&cfg_parser->block.zone->pattern->request_xfr, acl);
    }
  | VAR_REQUEST_XFR VAR_UDP STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $3, $4);
      acl->allow_udp = 1;
      if(acl->blocked)
        yyerror("blocked address used for request-xfr");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for request-xfr");
      append_acl(&cfg_parser->block.zone->pattern->request_xfr, acl);
    }
  | VAR_ALLOW_NOTIFY STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      append_acl(&cfg_parser->block.zone->pattern->allow_notify, acl);
    }
  | VAR_NOTIFY STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      if(acl->blocked)
        yyerror("blocked address used for notify");
      if(acl->rangetype != acl_range_single)
        yyerror("address range used for notify");
      append_acl(&cfg_parser->block.zone->pattern->notify, acl);
    }
  | VAR_PROVIDE_XFR STRING STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, $3);
      append_acl(&cfg_parser->block.zone->pattern->provide_xfr, acl);
    }
  | VAR_OUTGOING_INTERFACE STRING
    {
      acl_options_type *acl = parse_acl_info(cfg_parser->opt->region, $2, "NOKEY");
      append_acl(&cfg_parser->block.zone->pattern->outgoing_interface, acl);
    }
  | VAR_NOTIFY_RETRY number
    {
      cfg_parser->block.zone->pattern->notify_retry = $2;
      cfg_parser->block.zone->pattern->notify_retry_is_default = 0;
    }
  | VAR_ALLOW_AXFR_FALLBACK boolean
    {
      cfg_parser->block.zone->pattern->allow_axfr_fallback = $2;
      cfg_parser->block.zone->pattern->allow_axfr_fallback_is_default = 0;
    }
  | VAR_MAX_REFRESH_TIME number
    {
      cfg_parser->block.zone->pattern->max_refresh_time = $2;
      cfg_parser->block.zone->pattern->max_refresh_time_is_default = 0;
    }
  | VAR_MIN_REFRESH_TIME number
    {
      cfg_parser->block.zone->pattern->min_refresh_time = $2;
      cfg_parser->block.zone->pattern->min_refresh_time_is_default = 0;
    }
  | VAR_MAX_RETRY_TIME number
    {
      cfg_parser->block.zone->pattern->max_retry_time = $2;
      cfg_parser->block.zone->pattern->max_retry_time_is_default = 0;
    }
  | VAR_MIN_RETRY_TIME number
    {
      cfg_parser->block.zone->pattern->min_retry_time = $2;
      cfg_parser->block.zone->pattern->min_retry_time_is_default = 0;
    }
  | VAR_VERIFIER command
    { cfg_parser->block.zone->pattern->verifier = $2; }
  | verifier_feed_zone
    { cfg_parser->block.zone->pattern->verifier_feed_zone = (uint8_t)$1; }
  | verifier_timeout
    { cfg_parser->block.zone->pattern->verifier_timeout = (int32_t)$1; } ;

verify:
    VAR_VERIFY verify_block ;

verify_block:
    verify_block verify_option | ;

verify_option:
    VAR_ENABLE boolean
    { cfg_parser->opt->verify_enable = $2; }
  | VAR_IP_ADDRESS ip_address
    {
      struct ip_address_option *ip = cfg_parser->opt->verify_ip_addresses;
      if(!ip) {
        cfg_parser->opt->verify_ip_addresses = $2;
      } else {
        while(ip->next) { ip = ip->next; }
        ip->next = $2;
      }
    }
  | VAR_PORT number
    {
      /* port number, stored as a string */
      char buf[16];
      (void)snprintf(buf, sizeof(buf), "%lld", $2);
      cfg_parser->opt->verify_port = region_strdup(cfg_parser->opt->region, buf);
    }
  | VAR_VERIFIER command
    { cfg_parser->opt->verifier = $2; }
  | VAR_VERIFIER_COUNT number
    { cfg_parser->opt->verifier_count = (int)$2; }
  | VAR_VERIFIER_TIMEOUT number
    { cfg_parser->opt->verifier_timeout = (int)$2; }
  | VAR_VERIFIER_FEED_ZONE boolean
    { cfg_parser->opt->verifier_feed_zone = $2; } ;

verifier_feed_zone:
    VAR_VERIFIER_FEED_ZONE STRING
    {
      int bln = 0;
      $$ = 0;
      if(strcmp($2, "inherit") == 0) {
        $$ = ZONE_VERIFIER_FEED_ZONE_INHERIT;
      } else if(parse_boolean($2, &bln)) {
        $$ = bln;
      } else {
        yyerror("expected inherit, yes or no");
        YYABORT;
      }
    } ;

verifier_timeout:
    VAR_VERIFIER_TIMEOUT STRING
    {
      long long llng = 0;
      $$ = 0;
      if(strcmp($2, "inherit") == 0) {
        $$ = ZONE_VERIFIER_TIMEOUT_INHERIT;
      } else if(parse_number($2, &llng)) {
        $$ = llng;
      } else {
        yyerror("expected inherit or a number");
        YYABORT;
      }
    } ;

command:
    STRING arguments
    {
      char **argv;
      size_t argc = 1;
      for(struct component *i = $2; i; i = i->next) {
        argc++;
      }
      argv = region_alloc_zero(
        cfg_parser->opt->region, (argc + 1) * sizeof(char *));
      argc = 0;
      argv[argc++] = $1;
      for(struct component *j, *i = $2; i; i = j) {
        j = i->next;
        argv[argc++] = i->str;
        region_recycle(cfg_parser->opt->region, i, sizeof(*i));
      }
      $$ = argv;
    } ;

arguments:
    /* may be empty */
    {
      $$ = NULL;
    }
  | arguments STRING
    {
      struct component *comp = region_alloc_zero(
        cfg_parser->opt->region, sizeof(*comp));
      comp->str = region_strdup(cfg_parser->opt->region, $2);
      if($1) {
        struct component *tail = $1;
        while(tail->next) {
          tail = tail->next;
        }
        tail->next = comp;
        $$ = $1;
      } else {
        $$ = comp;
      }
    } ;

ip_address:
    STRING
    {
      struct ip_address_option *ip = region_alloc_zero(
        cfg_parser->opt->region, sizeof(*ip));
      ip->address = region_strdup(cfg_parser->opt->region, $1);
      $$ = ip;
    } ;

number:
    STRING
    {
      $$ = 0;
      if(!parse_number($1, &$$)) {
        yyerror("expected a number");
        YYABORT; /* trigger a parser error */
      }
    } ;

boolean:
    STRING
    {
      $$ = 0;
      if(!parse_boolean($1, &$$)) {
        yyerror("expected yes or no");
        YYABORT; /* trigger a parser error */
      }
    } ;

%%

static int
parse_boolean(const char *str, int *bln)
{
	if(strcmp(str, "yes") == 0) {
		*bln = 1;
	} else if(strcmp(str, "no") == 0) {
		*bln = 0;
	} else {
		return 0;
	}

	return 1;
}

static int
parse_number(const char *str, long long *num)
{
	/* ensure string consists entirely of digits */
	size_t pos = 0;
	while(str[pos] >= '0' && str[pos] <= '9') {
		pos++;
	}

	if(str[pos] == '\0') {
		int err = errno;
		errno = 0;
		*num = strtoll(str, NULL, 10);
		errno = err;
		return 1;
	}

	return 0;
}

static void
append_acl(struct acl_options **list, struct acl_options* acl)
{
	assert(list != NULL);

	if(*list == NULL) {
		*list = acl;
	} else {
		struct acl_options *tail = *list;
		while(tail->next != NULL)
			tail = tail->next;
		tail->next = acl;
	}
}

