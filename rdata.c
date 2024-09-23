/*
 * rdata.c -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "rdata.h"
#include "zonec.h"

nsd_nonnull((1,3))
static nsd_always_inline int32_t
skip_name(struct buffer *packet, uint16_t *offset)
{
	if (length >= *offset)
		return MALFORMED;
	//
}

nsd_nonnull((1))
static nsd_always_inline int32_t
skip_string(struct buffer *packet, uint16_t *offset)
{
	if (rdlength < 1)
		return -1;
	const uint8_t length = rdata[0];
	if (1 + length > rdlength)
		return -1;
	return 1 + length;
}

nsd_nonnull((1))
static nsd_always_inline int32_t
skip_strings(struct buffer *packet, uint16_t *offset)
{
	// implement
}

nsd_nonnull((1))
static nsd_always_inline int32_t
skip_nsec(struct buffer *packet, uint16_t rdlength)
{
	uint16_t length = 0;
	uint8_t last_window;

	while (rdlength - length > 2) {
		uint8_t window = rdata[count];
		uint8_t blocks = rdata[count + 1];
		if (window <= last_window)
			return -1; // could make this a semantic error...
		if (!blocks || blocks > 32)
			return -1;
		if (rdlength - length < 2 + blocks)
			return -1;
		length += 2 + blocks;
		last_window = window;
	}

	if (rdlength != length)
		return -1;

	return length;
}

nsd_nonnull_all
static nsd_always_inline int32_t
skip_apl(struct buffer *buffer, uint16_t *length)
{
//	uint16_t length = 0;
//
//	while (rdlength - length < 4) {
//		uint8_t afdlength = rdata[length + 3] & 0x7fu;
//		if (rdlength - (length + 4) < afdlength)
//			break;
//		length += 4 + afdlength;
//	}
}

nsd_nonnull_all
static nsd_always_inline int32_t
skip_svcparams(struct buffer *packet, uint16_t *length)
{
//	const uint8_t *params = rdata + length;
//	const uint16_t params_offset = length;
//	while (rdlength - length >= 4) {
//		const uint16_t count = read_uint16(rdata + length + 2);
//		if (rdlength - (4 + length) < count)
//			return -1;
//		length += count;
//	}
//	if (length != rdlength)
//		return -1;
}

nsd_nonnull_all
static nsd_always_inline int32_t read_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	const uint16_t rdlength = buffer_read_u16(packet);
	if (buffer_remaining(packet) < rdlength)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	buffer_read(packet, (*rr)->rdata, rdlength);
	rr->rdlength = rdlength;
	return rdlength;
}

nsd_nonnull_all
static nsd_always_inline int32_t
read_compressed_name_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;

	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);
	if (!dname_make_wire_from_packet_buffered(&dname, packet, 1, 1) ||
	    rdlength != buffer_position(packet) - mark)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	memcpy((*rr)->rdata, domain, sizeof(void*));
	(*rr)->rdlength = sizeof(void*);
	return rdlength;
}

nsd_nonnull((1,2))
static nsd_always_inline int32_t
read_uncompressed_name_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;

	const uint16_t rdlength = buffer_read_u16(packet);
	if (!dname_make_wire_from_packet_buffered(&dname, packet, 0, 1) ||
			rdlength != dname.dname.name_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	memcpy((*rr)->rdata, domain, sizeof(void*));
	(*rr)->rdlength = sizeof(void*);
	return rdlength;
}

static void
encode_dname(query_type *q, domain_type *domain)
{
	while (domain->parent && query_get_dname_offset(q, domain) == 0) {
		query_put_dname_offset(q, domain, buffer_position(q->packet));
		DEBUG(DEBUG_NAME_COMPRESSION, 2,
		      (LOG_INFO, "dname: %s, number: %lu, offset: %u\n",
		       domain_to_string(domain),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		buffer_write(q->packet, dname_name(domain_dname(domain)),
			     label_length(dname_name(domain_dname(domain))) + 1U);
		domain = domain->parent;
	}
	if (domain->parent) {
		DEBUG(DEBUG_NAME_COMPRESSION, 2,
		      (LOG_INFO, "dname: %s, number: %lu, pointer: %u\n",
		       domain_to_string(domain),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		assert(query_get_dname_offset(q, domain) <= MAX_COMPRESSION_OFFSET);
		buffer_write_u16(q->packet,
				 0xc000 | query_get_dname_offset(q, domain));
	} else {
		buffer_write_u8(q->packet, 0);
	}
}

nsd_nonnull_all
static nsd_always_inline void write_compressed_name_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	assert(rr->rdlength == sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	encode_dname(query, domain);
}

nsd_nonnull_all
static nsd_always_inline void write_uncompressed_name_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct dname *dname;
	const struct domain *domain;
	assert(rdlength >= sizeof(void*));
	memcpy(domain, rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t read_generic_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_rdata(domains, packet, rr);
}

void write_generic_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	buffer_write(query->packet, rr->rdata, rr->rdlength);
}

void copy_generic_rdata(
	struct buffer *src, struct buffer *dest, struct pktcompression *pcomp)
{
	const int32_t rdlength = (int32_t)buffer_read_u16(src);

	(void)pcomp;
	if (!buffer_available(dest, rdlength + 2))
		return rdlength + 2;
	const uint8_t *rdata = buffer_current(src);
	buffer_write_u16(dest, (uint16_t)rdlength);
	buffer_write(dest, rdata, rdlength);
	return rdlength + 2;
}

int32_t read_a_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_peek_u16(packet) != 4)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_ns_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_compressed_name_rdata(domains, packet, rr);
}

void write_ns_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	write_compressed_name_rdata(domains, rr, query);
}

int32_t read_md_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_uncompressed_name_rdata(domains, packet, rr);
}

void write_md_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	write_uncompressed_name_rdata(domains, rr, query);
}

int32_t read_mf_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_uncompressed_name_rdata(domains, packet, rr);
}

void write_mf_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	write_uncompressed_name_rdata(domains, packet, rr);
}

int32_t read_cname_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_compressed_name_rdata(domains, packet, rr);
}

void write_cname_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	write_compressed_name_rdata(domains, rr, query);
}

int32_t read_soa_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	uint16_t length;
	struct domain *primary_domain, *mailbox_domain;
	struct dname_buffer primary, mailbox;

	/* name + name + long + long + long + long + long */
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);
	if (!dname_make_from_packet_buffered(&primary, packet, 1, 1) ||
	    !dname_make_from_packet_buffered(&mailbox, packet, 1, 1) ||
	    rdlength != (buffer_position(packet) - mark) + 20)
		return MALFORMED;

	static const size_t size = sizeof(**rr) + 2 * sizeof(struct domain *) + 20;
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	primary_domain = domain_table_insert(domains, (void*)&primary);
	primary_domain->usage++;
	mailbox_domain = domain_table_insert(domains, (void*)&mailbox);
	mailbox_domain->usage++;

	memcpy((*rr)->rdata, primary_domain, sizeof(void*));
	memcpy((*rr)->rdata + sizeof(void*), mailbox_domain, sizeof(void*));
	buffer_read(packet, (*rr)->rdata + 2 * sizeof(void*), 20);
	(*rr)->rdlength = 2 * sizeof(void*) + 20;
	return rdlength;
}

//
// i think it'd work better if we abstracted the compression object
//
void write_soa_rdata(
	const struct rr *rr, struct query *query, struct buffer *packet)
{
	const struct *domains[2];
	const size_t mark = buffer_position(packet);
	/* domain + domain + long + long + long + long + long */
	assert(rr->rdlength == 2 * sizeof(void*) + 20);
	memcpy(domains[0], rr->rdata, sizeof(void*));
	memcpy(domains[1], rr->rdata + sizeof(void*), sizeof(void*));
	if (query) {
		encode_dname(query, domains[0]);
		encode_dname(query, domains[1]);
	} else {
		const struct *dnames[2];
		dnames[0] = domain_dname(primary);
		dnames[1] = domain_dname(mailbox);
		buffer_write(packet, dname_name(dnames[0]), dnames[0]->name_size);
		buffer_write(packet, dname_name(dnames[1]), dnames[1]->name_size);
	}
	buffer_write(packet, rr->rdata + (2 * sizeof(void*)), 20);
	return buffer_position(packet) - mark;
}

//int32_t uncompressed_soa_rdlength(
//	struct buffer *source, const struct rr *rr)
//{
//	const struct domain *domains[2];
//	const struct dname *dnames[2];
//	memcpy(&domains[0], rr->rdata, sizeof(void*));
//	memcpy(&domains[1], rr->rdata + sizeof(void*), sizeof(void*));
//	dnames[0] = domain_dname(domains[0]);
//	dnames[1] = domain_dname(domains[1]);
//	return dnames[0]->name_size + dnames[1]->name_size + 20;
//}

//
// we must return the number of bytes that would have been written!
//
int32_t copy_soa_rdata(
	struct buffer *src, struct buffer *dest, void *pcomp)
{
	struct dname_buffer primary, mailbox;
	const size_t mark = buffer_position(src);
	const int32_t rdlength = (int32_t)buffer_read_u16(src);

	if (rdlength < 20 ||
	    !dname_make_from_packet_static(&primary, src, 1, 1) ||
	    !dname_make_from_packet_static(&mailbox, src, 1, 1) ||
			buffer_remaining(src) < 20 ||
	    buffer_position(src) - mark != rdlength - 20)
		return MALFORMED;
	const uint16_t length =
		primary.dname.name_size + mailbox.dname.name_size + 20;
	if (pcomp) {
		const size_t offset = buffer_position(dest);
		if (pktcompression_write_dname(
			dest, pcomp, dname_name(&primary), primary.dname.name_size) > 0)
			goto no_space;
		if (pktcompression_write_dname(
			dest, pcomp, dname_name(&mailbox), mailbox.dname.name_size) > 0)
			goto no_space;
		//
	}

	//
	// this is tricky, because we cannot determine how much space
	// is needed for the name because it's compressed...
	//





	//if (!buffer_available(dest, 2 + length))
	//	return length;
	//buffer_
	//buffer_write_u16(dest, length);
	//buffer_write(dest, dname_name(&primary), primary.dname.name_size);
	//buffer_write(dest, dname_name(&mailbox), mailbox.dname.name_size);
	//const uint8_t *
	//buffer_write(dest,
	//	return MALFORMED;
	//const size_t length =
	//	2 + primary.dname.name_size + mailbox.dname.name_size + 20;
	//if (

//	if ((count = copy_compressed_name(src, dest, pcomp)) < 0)
//		return count;
//	length += count;
//	if ((count = copy_compressed_name(src, dest, pcomp)) < 0)
//		return count;
//	length += count;
//	if (length != rdlength - 20)
//		return MALFORMED;
//	if (!buffer_available

	//
//	    copy_compressed_name(src, dest, pcomp) < 0 ||
//	    rdlength != buffer_position(src) - mark + 22)
//		return MALFORMED;
//	if (!buffer_available(dest, 20))
	//if (!dname_make_from_packet_static(&dname, src, 1, 1) ||
	//    rdlength >= (buffer_position(src) - mark) - 2)
	//	return MALFORMED;

	//
	// we know we get two dnames first
	//
}








int32_t read_wks_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	//
	// implement
	//
}

int32_t read_ptr_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_compressed_name_rdata(domains, packet, rr);
}

void write_ptr_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	write_compressed_name_rdata(query, rdata, rdlength);
}

int32_t read_hinfo_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	// implement
}

int32_t read_minfo_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	// implement
}

void write_minfo_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *rmailbx, *emailbx;
	assert(rdlength == 2 * sizeof(void*));
	memcpy(rmailbx, rdata, sizeof(void*));
	memcpy(emailbx, rdata + sizeof(void*), sizeof(void*));
	encode_dname(query, rmailbx);
	encode_dname(query, emailbx);
}

int32_t read_mx_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer exchange;

	/* short + name */
	const uint16_t rdlength = buffer_read_u16(packet);
	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&exchange, packet, 1, 1))
		return MALFORMED;
	if (rdlength != 2 + exchange.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return -1;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void write_mx_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;
	assert(rdlength == 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	buffer_write(query->packet, rr->rdata, 2);
	encode_dname(query, domain);
}

uint16_t count_mx_rdlength(const struct *rr)
{
	const struct domain *domain;
	const struct dname *dname;
	assert(rdlength == 2 + sizeof(void*));
	memcpy(&domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	return 2 + dname->name_size;
}

int32_t read_txt_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const size_t mark = buffer_position(packet);
	const uint16_t rdlength = buffer_read_u16(packet);

	if (skip_strings(packet, &length) < 0
	 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, buffer, rr);
}

int32_t read_rp_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *mbox_domain, *txt_domain;
	struct dname_buffer mbox, txt;
	const uint16_t rdlength = buffer_read_u16(packet);

	if (buffer_remaining(packet) < rdlength ||
	    !dname_make_from_packet_buffered(&mbox, packet, 0, 1) ||
			!dname_make_from_packet_buffered(&txt, packet, 0, 1) ||
	    rdlength != mbox.dname.name_size + txt.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 * sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	mbox_domain = domain_table_insert(domains, (void*)&mbox);
	mbox_domain->usage++;
	txt_domain = domain_table_insert(domain, (void*)&txt);
	txt_domain->usage++;
	memcpy((*rr)->rdata, mbox_domain, sizeof(void*));
	memcpy((*rr)->rdata + sizeof(void*), txt_domain, sizeof(void*));
	(*rr)->rdlength = 2 * sizeof(void*);
	return rdlength;
}

void write_rp_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *mbox_domain, *txt_domain;
	const struct dname *mbox, *txt;

	assert(rr->rdlength == 2 * sizeof(void*));
	memcpy(mbox_domain, rr->rdata, sizeof(void*));
	memcpy(txt_domain, rr->rdata + sizeof(void*), sizeof(void*));
	mbox = domain_dname(mbox_domain);
	txt = domain_dname(txt_domain);
	buffer_write(packet, dname_name(mbox), mbox->name_size);
	buffer_write(packet, dname_name(txt), txt->name_size);
}

uint16_t count_rp_rdata(const struct rr

int32_t read_afsdb_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer hostname;
	/* short + uncompressed name */
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&hostname, packet, 1, 1) ||
	    rdlength != 2 + hostname.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&hostname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void write_afsdb_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(packet, rr->rdata, 2);
	buffer_write(packet, dname_name(dname), dname->name_size);
}

int32_t read_x25_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	if (skip_string(packet, &length) < 0
	 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, buffer, rr);
}

int32_t read_isdn_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	if (skip_string(packet, &length) < 0
	 || skip_string(packet, &length) < 0
	 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, buffer, rr);
}

int32_t read_rt_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	if (rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&dname, packet, 1, 1))
		return MALFORMED;
	if (rdlength != 2 + dname.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return -1;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void write_rt_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rdlength == 2 + sizeof(void*));
	memcpy(domain, (*rr)->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	const uint16_t rdlength = 2 + dname->name_size;
	if (!try_buffer_write_u16(query->packet, rdlength) ||
	    !try_buffer_write(query->packet, rr->rdata, 2) ||
			!try_buffer_write(query->packet, dname_name(dname), dname->name_size))
		return TRUNCATED;
	return rdlength;
}

int32_t read_px_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *map822_domain, *mapx400_domain;
	struct dname_buffer map822, mapx400;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + uncompressed name + uncompressed name */
	if (buffer_remaining(packet) < rdlength ||
	    rdlength < 2 ||
	    !dname_make_from_packet_buffered(&map822, packet, 0, 1) ||
	    !dname_make_from_packet_buffered(&mapx400, packet, 0, 1) ||
	    rdlength != 2 + map822.dname.name_size + mapx400.dname.name_size)
		return MALFORMED;

	static const size_t size = sizeof(**rr) + 2 + 2*sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	map822_domain = domain_table_insert(domains, (void*)&map822);
	map822_domain->usage++;
	mapx400_domain = domain_table_insert(domains, (void*)&mapx400);
	mapx400_domain->usage++;

	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata, map822_domain, sizeof(void*));
	memcpy((*rr)->rdata, mapx400_domain, sizeof(void*));
	(*rr)->rdlength = 2 + 2*sizeof(void*);
	return rdlength;
}

void write_px_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *map822_domain, *mapx400_domain;
	const struct dname *map822, *mapx400;

	memcpy(map822_domain, rr->rdata + 2, sizeof(void*));
	memcpy(mapx400_domain, rr->rdata + 2 + sizeof(void*), sizeof(void*));
	map822 = domain_dname(map822_domain);
	mapx400 = domain_dname(mapx400_domain);
	const uint16_t rdlength = 2 + map822->name_size + mapx400->name_size;
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(map822), map822->name_size);
	buffer_write(query->packet, dname_name(mapx400), mapx400->name_size);
}

int32_t read_aaaa_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_remaining(packet) < 18 || buffer_peek_u16(packet) != 16)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_loc_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* version (byte) */
	const uint16_t rdlength = buffer_peek_u16(packet);
	if (buffer_remaining(packet) < 3 || rdlength < 1)
		return MALFORMED;
	/* version (byte) + size (byte) + horiz pre (byte) + vert pre (byte)
	 * latitude (long) + longitude (long) + altitude (long) */
	const size_t mask = buffer_position(packet);
	const uint8_t version = buffer_read_u8_at(packet, mark + 2);
	static const uint16_t size_version_0 = 16u;
	if (version == 0 && rdlength != size_version_0)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_nxt_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const uint16_t rdlength = buffer_read_u16(packet);

	/* name + nxt */
	if (!dname_make_from_packet_buffered(&dname, packet, 1, 1))
		return MALFORMED;
	if (buffer_remaining(packet) < 2)
		return MALFORMED;
	const uint16_t bitmap_size = buffer_peek_u16(packet);
	if (bitmap_size >= 8192 || buffer_remaining(packet) < 2 + bitmap_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + sizeof(domain) + bitmap_size;
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&next);
	domain->usage++;
	memcpy((*rr)->rdata, domain, sizeof(void*));
	buffer_read(packet, (*rr)->rdata + sizeof(void*), 2 + bitmap_size);
	(*rr)->rdlength = sizeof(void*) + bitmap_size;
	return rdlength;
}

void write_nxt_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength >= sizeof(void*));
  memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
  buffer_write(query->packet, dname_name(dname), dname->name_size);
  buffer_write(query->packet, rr->rdata + sizeof(void*), rr->rdlength - sizeof(void*));
}

int32_t read_srv_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + short + short + name */
	if (buffer_remaining(packet) < rdlength || rdlength < 6)
		return MALFORMED;
	buffer_skip(packet, 6);
	if (!dname_make_from_packet_buffered(&dname, packet, 0, 1) ||
	    rdlength != 6 + dname.dname.name_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + 6 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 6);
	memcpy((*rr)->rdata + 6, domain, sizeof(void*));
	(*rr)->rdlength = 6 + sizeof(void*);
	return rdlength;
}

void write_srv_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 6 + sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
	uint16_t rdlength = 6 + dname->name_size;
	buffer_write(query->packet, rr->rdata, 6);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t read_naptr_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	uint16_t length = 4;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + short + text + text + text + name */
	if (buffer_remaining(packet) < rdlength ||
	    rdlength < length ||
	    skip_string(packet, &length) < 0 ||
	    skip_string(packet, &length) < 0 ||
	    skip_string(packet, &length) < 0 ||
	    !dname_make_from_packet_buffered(&dname, packet, 1, 1) ||
	    rdlength - length != dname.dname.name_size)
		return MALFORMED;

	const size_t size = sizeof(**rr) + length + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&next);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, length);
	memcpy((*rr)->rdata + length, domain, sizeof(void*));
	(*rr)->rdlength += length + sizeof(void*);
	return rdlength;
}

void write_naptr_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;

	/* short + short + string + string + string + uncompressed name */
	assert(rr->rdlength < 7 + sizeof(void*));
	uint16_t length = rr->rdlength - sizeof(void*);
	memcpy(domain, rdata + length, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, length);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t read_kx_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + uncompressed name */
	if (buffer_remaining(packet) < rdlength || rdlength < 2 ||
	    !dname_make_from_packet_buffered(&dname, packet, 0, 1) ||
			rdlength - 2 != dname.dname.name_size)
		return MALFORMED;

	const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void write_kx_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *dname;

	/* short + uncompressed name */
	assert(rr->rdlength != 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t read_cert_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* short + short + byte + binary */
	if (buffer_peek_u16(packet) < 5)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_dname_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* uncompressed name */
	return read_uncompressed_name_rdata(domains, packet, rr);
}

void write_dname_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	write_uncompressed_name_rdata(domains, rr, query);
}

int32_t read_apl_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
//	uint16_t length = 0;
//
//	while (rdlength - length < 4) {
//		uint8_t afdlength = rdata[length + 3] & 0x7fu;
//		if (rdlength - (length + 4) < afdlength)
//			break;
//		length += 4 + afdlength;
//	}
//
//	if (length != rdlength)
//		return -1;
	return read_rdata(domains, rdata, rdlength, rr);
}

int32_t read_ds_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (buffer_peek_u16(packet) < 4)
		return MALFORMED;
	return read_rdata(domains, rr, query);
}

int32_t read_sshfp_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* byte + byte + binary */
	if (buffer_peek_u16(packet) < 2)
		return MALFORMED;
	return read_rdata(domains, rr, query);
}

int32_t read_ipseckey_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct dname_buffer gateway;
	const uint8_t *gateway_rdata, *rdata;
	uint8_t gateway_length = 0;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* byte + byte + byte + gateway + binary */
	if (buffer_remaining(buffer) < rdlength || rdlength < 3)
		return MALFORMED;

	buffer_skip(packet, 3);

	switch (buffer_read_u8_at(mark + 2)) {
		case 0:
			break;
		case 1: // ipv4
			gateway_length = 4;
			if (rdlength != 3 + 4)
				return MALFORMED;
			break;
		case 2: // ipv6
			gateway_length = 16;
			if (rdlength != 3 + 16)
				return MALFORMED;
			break;
		case 3: // domain name
	    if (!dname_make_from_packet_buffered(&gateway, packet, 0, 1))
				return MALFORMED;
			gateway_length = gateway.dname.dname_size;
			gateway_rdata = dname_name((void*)&gateway);
			break;
		default:
			return MALFORMED;
	}

	if (rdlength < 3 + gateway_length)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;

	buffer_read_at(packet, mark, (*rr)->rdata, 3);
	memcpy((*rr)->rdata + 3, gateway_rdata, gateway_length);
	const uint16_t length = 3 + gateway_length;
	buffer_read(packet, (*rr)->rdata + length, rdlength - length);
	(*rr)->rdlength = rdlength;
	return rdlength;
}

int32_t read_rrsig_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct dname_buffer signer;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + byte + byte + long + long + long + short */
	if (buffer_remaining(packet) < rdlength || rdlength < 18)
		return MALFORMED;
	buffer_skip(packet, 18);
	if (!dname_make_from_packet_buffered(&signer, packet, 0, 1))
		return MALFORMED;
	if (rdlength < 18 + signer.dname.name_size)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	buffer_read_at(packet, mark, (*rr)->rdata, 18);
	const uint8_t length = 18 + signer.dname.name_size;
	memcpy((*rr)->rdata + 18, dname_name(&signer), signer.dname.name_size);
	(*rr)->rdlength = rdlength;
	return rdlength;
}

int32_t read_nsec_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct dname_storage next;
	const uint16_t rdlength = buffer_read_u16(packet);

	/* uncompressed name + nsec */
	if (buffer_remaining(packet) < rdlength ||
	    !dname_make_from_packet_buffered(&next, packet, 0, 1))
		return MALFORMED;

	uint16_t length = next.dname.name_size;
	const size_t mark = buffer_position(packet);
	if (skip_nsec(packet, &length) < 0 || rdlength != length)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	memcpy((*rr)->rdata, dname_name((void*)&next), next.dname.name_size);
	buffer_read_at(packet, mark, (*rr)->rdata + next.dname.name_size, rdlength - next.dname.name_size);
	return rdlength;
}

int32_t read_dnskey_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (buffer_peek_u16(packet) < 5)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_dhcid_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* short + byte + digest */
	if (buffer_peek_u16(packet) < 3)
		return MALFORMED;
	return read_rdata(domains, rdata, rdlength, rr);
}

int32_t read_nsec3_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	uint16_t length = 4;
	/* byte + byte + short + string + string + binary */
	const size_t mark = buffer_position(packet);
	const uint16_t rdlength = buffer_read_u16(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (skip_string(packet, &length) < 0 ||
			skip_string(packet, &length) < 0 ||
			skip_nsec(packet, &length) < 0 ||
			rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, packet, rr);
}

int32_t read_nsec3param_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	uint16_t length = 4;
	/* byte + byte + short + string */
	const size_t mark = buffer_position(packet);
	const uint16_t rdlength = buffer_read_u16(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (skip_string(packet, &length) < 0 ||
	    rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, packet, rr);
}

int32_t read_tlsa_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* byte + byte + byte + binary */
	if (buffer_peek_u16(packet) < 3)
		return MALFORMED;
	return read_rdata(domains, data, rdlength, rr);
}

int32_t read_openpgpkey_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	return read_rdata(domains, rdata, rdlength, rr);
}

int32_t read_csync_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* long + short + binary */
	if (buffer_peek_u16(packet) < 6)
		return MALFORMED;
	return read_rdata(domains, rdata, rdlength, rr);
}

int32_t read_zonemd_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* long + byte + byte + binary */
	if (buffer_peek_u16(packet) < 6)
		return MALFORMED;
	return read_rdata(domains, rdata, rdlength, rr);
}

int32_t read_svcb_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer target;
	uint16_t length = 2, svcparams_length = 0;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + name + svc_params */
	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (!dname_make_from_packet_buffered(&next, packet, 0, 1))
		return MALFORMED;
	length += target.dname.name_size;
	if (skip_svcparams(packet, &svcparams_length) < 0 ||
			rdlength != length + svcparams_length)
		return MALFORMED;

	const uint16_t size = sizeof(**rr) + 2 + sizeof(void*) + svcparams_length;
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void)&target);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	buffer_read_at(packet, mark + length, (*rr)->rdata, svcparams_length);
	(*rr)->rdlength = 2 + sizeof(void*) + svcparams_length;
	return rdlength;
}

void write_svcb_rdata(
	const struct domain_table *domains, const struct rr *rr, struct query *query)
{
	const struct domain *domain;
	const struct dname *target;

	assert(rr->rdlength >= 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(target), target->name_size);
	const uint8_t length = 2 + sizeof(void*);
	buffer_write(query->packet, rr->rdata + length, rr->rdlength - length);
}

int32_t read_nid_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_peek_u16(packet) != 10)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_l32_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_peek_u16(packet) != 6)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_l64_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_peek_u16(packet) != 10)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_lp_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer target;
	/* short + name */
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&target, packet, 0, 1) ||
	    rdlength != 2 + target.dname.name_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, &target);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

int32_t read_eui48_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_peek_u16(packet) != 8)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_eui64_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	if (buffer_peek_u16(packet) != 10)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_uri_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* short + short + binary (must be greater than zero) */
	if (buffer_peek_u16(packet) < 5)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}

int32_t read_caa_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	const size_t mark = buffer_position(packet);
	const uint16_t rdlength = buffer_read_u16(packet);

	/* byte + string */
	if (buffer_remaining(packet) < rdlength || rdlength < 3)
		return MALFORMED;
	uint16_t length = 1;
	if (skip_string(packet, &length) < 0 ||
	    rdlength <= length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, packet, rr);
}

int32_t read_dlv_rdata(
	struct domain_table *domains, struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (buffer_peek_u16(packet) < 4)
		return MALFORMED;
	return read_rdata(domains, packet, rr);
}
