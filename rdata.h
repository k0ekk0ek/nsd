/*
 * rdata.h -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef RDATA_H
#define RDATA_H

#include "dns.h"
#include "namedb.h"

/* High bit of the APL length field is the negation bit.  */
#define APL_NEGATION_MASK      0x80U
#define APL_LENGTH_MASK	       (~APL_NEGATION_MASK)

/* read functions */
int32_t read_generic_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_a_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_ns_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_md_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_mf_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_cname_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_soa_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_mb_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_mg_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_mr_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_wks_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_ptr_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_hinfo_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_minfo_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_mx_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_txt_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_x25_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_isdn_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_rt_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_key_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_px_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_aaaa_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_loc_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_nxt_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_srv_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_naptr_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_kx_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_cert_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_dname_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_apl_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_ds_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_sshfp_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_ipseckey_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_nsec_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_dnskey_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_dhcid_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_nsec3_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_nsec3param_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_tlsa_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_openpgpkey_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_csync_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_zonemd_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_svcb_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_nid_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_l32_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_l64_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_lp_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_eui48_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_eui64_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_uri_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_caa_rdata(
	struct domain_table *, struct buffer *, struct rr **);

int32_t read_dlv_rdata(
	struct domain_table *, struct buffer *, struct rr **);


/* write functions */
void write_generic_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_ns_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_md_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_mf_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_cname_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_soa_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_ptr_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_minfo_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_mx_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_rp_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_afsdb_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_rt_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_px_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_nxt_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_srv_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_naptr_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_kx_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_dname_rdata(
	const struct domain_table *, const struct rr *, struct query *);

void write_svcb_rdata(
	const struct domain_table *, const struct rr *, struct query *);

#endif /* RDATA_H */
