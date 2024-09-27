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

/* Taken from RFC 4398, section 2.1.  */
lookup_table_type dns_certificate_types[] = {
/*	0		Reserved */
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
	{ 3, "PGP" },	/* OpenPGP packet */
	{ 4, "IPKIX" },	/* The URL of an X.509 data object */
	{ 5, "ISPKI" },	/* The URL of an SPKI certificate */
	{ 6, "IPGP" },	/* The fingerprint and URL of an OpenPGP packet */
	{ 7, "ACPKIX" },	/* Attribute Certificate */
	{ 8, "IACPKIX" },	/* The URL of an Attribute Certificate */
	{ 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
/*	255 		Reserved */
/* 	256-65279	Available for IANA assignment */
/*	65280-65534	Experimental */
/*	65535		Reserved */
	{ 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
lookup_table_type dns_algorithms[] = {
	{ 1, "RSAMD5" },	/* RFC 2537 */
	{ 2, "DH" },		/* RFC 2539 */
	{ 3, "DSA" },		/* RFC 2536 */
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* RFC 3110 */
	{ 6, "DSA-NSEC3-SHA1" },	/* RFC 5155 */
	{ 7, "RSASHA1-NSEC3-SHA1" },	/* RFC 5155 */
	{ 8, "RSASHA256" },		/* RFC 5702 */
	{ 10, "RSASHA512" },		/* RFC 5702 */
	{ 12, "ECC-GOST" },		/* RFC 5933 */
	{ 13, "ECDSAP256SHA256" },	/* RFC 6605 */
	{ 14, "ECDSAP384SHA384" },	/* RFC 6605 */
	{ 15, "ED25519" },		/* RFC 8080 */
	{ 16, "ED448" },		/* RFC 8080 */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

const char *svcparamkey_strs[] = {
		"mandatory", "alpn", "no-default-alpn", "port",
		"ipv4hint", "ech", "ipv6hint", "dohpath"
	};

typedef int (*rdata_to_string_type)(buffer_type *output,
				    rdata_atom_type rdata,
				    rr_type *rr);

static int
rdata_dname_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	buffer_printf(output,
		      "%s",
		      dname_to_string(domain_dname(rdata_atom_domain(rdata)),
				      NULL));
	return 1;
}

static int
rdata_dns_name_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	const uint8_t *data = rdata_atom_data(rdata);
	size_t offset = 0;
	uint8_t length = data[offset];
	size_t i;

	while (length > 0)
	{
		if (offset) /* concat label */
			buffer_printf(output, ".");

		for (i = 1; i <= length; ++i) {
			uint8_t ch = data[i+offset];

			if (ch=='.' || ch==';' || ch=='(' || ch==')' || ch=='\\') {
				buffer_printf(output, "\\%c", (char) ch);
			} else if (!isgraph((unsigned char) ch)) {
				buffer_printf(output, "\\%03u", (unsigned int) ch);
			} else if (isprint((unsigned char) ch)) {
				buffer_printf(output, "%c", (char) ch);
			} else {
				buffer_printf(output, "\\%03u", (unsigned int) ch);
			}
		}
		/* next label */
		offset = offset+length+1;
		length = data[offset];
	}

	/* root label */
	buffer_printf(output, ".");
	return 1;
}

static int
rdata_text_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint8_t length = rdata[offset];

	buffer_printf(output, "\"");
	for (size_t i = offset + 1; i <= length; ++i) {
		char ch = (char) data[i];
		if (isprint((unsigned char)ch)) {
			if (ch == '"' || ch == '\\') {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u", (unsigned) rdata[i]);
		}
	}
	buffer_printf(output, "\"");
	return 1;
}

static int
rdata_texts_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint16_t pos = offset;

	while (pos < rdlength && pos + rdata[pos] < rdlength) {
		buffer_printf(output, "\"");
		for (size_t i = 1; i <= data[pos]; ++i) {
			char ch = (char) data[pos + i];
			if (isprint((unsigned char)ch)) {
				if (ch == '"' || ch == '\\') {
					buffer_printf(output, "\\");
				}
				buffer_printf(output, "%c", ch);
			} else {
				buffer_printf(output, "\\%03u", (unsigned) data[pos+i]);
			}
		}
		pos += data[pos]+1;
		buffer_printf(output, pos < length?"\" ":"\"");
	}
	return pos - offset;
}

static int
rdata_long_text_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	buffer_printf(output, "\"");
	for (size_t i = offset; i < length; ++i) {
		char ch = (char) rdata[i];
		if (isprint((unsigned char)ch)) {
			if (ch == '"' || ch == '\\') {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u", (unsigned) rdata[i]);
		}
	}
	buffer_printf(output, "\"");
	return rdlength - offset;
}

static int
rdata_tag_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	size_t length = offset + rdata[offset];
	for (size_t i = offset; i <= length; ++i) {
		char ch = (char) rdata[i];
		if (isdigit((unsigned char)ch) || islower((unsigned char)ch))
			buffer_printf(output, "%c", ch);
		else	return -1;
	}
	return 1 + rdata[offset];
}

static int
rdata_byte_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	buffer_printf(output, "%lu", (unsigned long) rdata[offset]);
	return 1;
}

static int
rdata_short_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint16_t data = read_uint16(rdata + offset);
	buffer_printf(output, "%lu", (unsigned long) data);
	return 2;
}

static int
rdata_long_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint32_t data = read_uint32(rdata + offset);
	buffer_printf(output, "%lu", (unsigned long) data);
	return 4;
}

static int
rdata_a_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	char str[200];
	if (inet_ntop(AF_INET, rdata + offset, str, sizeof(str))) {
		buffer_printf(output, "%s", str);
		return 4;
	}
	return -1;
}

static int
rdata_aaaa_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	int result = 0;
	char str[200];
	if (inet_ntop(AF_INET6, rdata_atom_data(rdata), str, sizeof(str))) {
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_ilnp64_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint16_t a1 = read_uint16(rdata + offset);
	uint16_t a2 = read_uint16(rdata + offset + 2);
	uint16_t a3 = read_uint16(rdata + offset + 4);
	uint16_t a4 = read_uint16(rdata + offset + 6);

	buffer_printf(output, "%.4x:%.4x:%.4x:%.4x", a1, a2, a3, a4);
	return 8;
}

static int
rdata_eui48_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint8_t a1 = rdata[offset];
	uint8_t a2 = rdata[offset+1];
	uint8_t a3 = rdata[offset+2];
	uint8_t a4 = rdata[offset+3];
	uint8_t a5 = rdata[offset+4];
	uint8_t a6 = rdata[offset+5];

	buffer_printf(output, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		a1, a2, a3, a4, a5, a6);
	return 6;
}

static int
rdata_eui64_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint8_t a1 = rdata[offset];
	uint8_t a2 = rdata[offset+1];
	uint8_t a3 = rdata[offset+2];
	uint8_t a4 = rdata[offset+3];
	uint8_t a5 = rdata[offset+4];
	uint8_t a6 = rdata[offset+5];
	uint8_t a7 = rdata[offset+6];
	uint8_t a8 = rdata[offset+7];

	buffer_printf(output, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		a1, a2, a3, a4, a5, a6, a7, a8);
	return 8;
}

static int
rdata_rrtype_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint16_t type = read_uint16(rdata + offset);
	buffer_printf(output, "%s", rrtype_to_string(type));
	return 2;
}

static int
rdata_algorithm_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	buffer_printf(output, "%u", (unsigned)rdata[offset]);
	return 1;
}

static int
rdata_certificate_type_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint16_t id = read_uint16(rdata + offset);
	lookup_table_type *type
		= lookup_by_id(dns_certificate_types, id);
	if (type) {
		buffer_printf(output, "%s", type->name);
	} else {
		buffer_printf(output, "%u", (unsigned) id);
	}
	return 2;
}

static int
rdata_period_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	uint32_t period = read_uint32(rdata + offset);
	buffer_printf(output, "%lu", (unsigned long) period);
	return 4;
}

static int
rdata_time_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	time_t time = (time_t) read_uint32(rdata + offset);
	struct tm *tm = gmtime(&time);
	char buf[15];
	if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm)) {
		buffer_printf(output, "%s", buf);
		return 4;
	}
	return -1;
}

static int
rdata_base32_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	int length;
	size_t size = rdata[offset];
	if(size == 0) {
		buffer_write(output, "-", 1);
		return 1;
	}
	buffer_reserve(output, size * 2 + 1);
	length = b32_ntop(rdata + offset + 1, size,
			  (char *)buffer_current(output), size * 2);
	if (length == -1)
		return -1;
	buffer_skip(output, length);
	return 1 + size;
}

static int
rdata_base64_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	int length;
	size_t size = rdlength - offset;
	if(size == 0) {
		/* single zero represents empty buffer */
		buffer_write(output, "0", 1);
		return 0;
	}
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(rdata + offset, size,
			  (char *) buffer_current(output), size * 2);
	if (length == -1)
		return -1;
	buffer_skip(output, length);
	return size;
}

static void
hex_to_string(buffer_type *output, const uint8_t *data, size_t size)
{ 
	static const char hexdigits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	size_t i;

	buffer_reserve(output, size * 2);
	for (i = 0; i < size; ++i) {
		uint8_t octet = *data++;
		buffer_write_u8(output, hexdigits[octet >> 4]);
		buffer_write_u8(output, hexdigits[octet & 0x0f]);
	}
}

static int
rdata_hex_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	if(rdata_atom_size(rdata) == 0) {
		/* single zero represents empty buffer, such as CDS deletes */
		buffer_printf(output, "0");
	} else {
		hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
	}
	return 1;
}

static int
rdata_hexlen_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	size_t size = rdata[offset];
	if(size == 0) {
		/* NSEC3 salt hex can be empty */
		buffer_printf(output, "-");
		return 1;
	}
	hex_to_string(output, rdata + offset + 1, size);
	return 1 + size;
}

static int
rdata_nsap_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	buffer_printf(output, "0x");
	hex_to_string(output, rdata + offset, rdlength - offset);
	return rdlength - offset;
}

static int
rdata_apl_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	size_t size = rdlength - offset;

	if (size >= 4) {
		uint16_t address_family = read_uin16(rdata + offset);
		uint8_t prefix = rdata[offset + 2];
		uint8_t length = rdata[offset + 3];
		int negated = length & APL_NEGATION_MASK;
		int af = -1;

		length &= APL_LENGTH_MASK;
		switch (address_family) {
		case 1: af = AF_INET; break;
		case 2: af = AF_INET6; break;
		}
		if (af != -1 && (size - 4) >= length) {
			char text_address[1000];
			uint8_t address[128];
			memset(address, 0, sizeof(address));
			memmove(address, rdata + offset + 4, length);
			if (inet_ntop(af, address, text_address, sizeof(text_address))) {
				buffer_printf(output, "%s%d:%s/%d",
					      negated ? "!" : "",
					      (int) address_family,
					      text_address,
					      (int) prefix);
				return 4 + length;
			}
		}
	}
	return -1;
}

/*
 * Print protocol and service numbers rather than names for Well-Know Services
 * (WKS) RRs. WKS RRs are deprecated, though not technically, and should not
 * be used. The parser supports tcp/udp for protocols and a small subset of
 * services because getprotobyname and/or getservbyname are marked MT-Unsafe
 * and locale. getprotobyname_r and getservbyname_r exist on some platforms,
 * but are still marked locale (meaning the locale object is used without
 * synchonization, which is a problem for a library). Failure to load a zone
 * on a primary server because of an unknown protocol or service name is
 * acceptable as the operator can opt to use the numeric value. Failure to
 * load a zone on a secondary server is problematic because "unsupported"
 * protocols and services might be written. Print the numeric value for
 * maximum compatibility.
 *
 * (see simdzone/generic/wks.h for details).
 */
static int
rdata_services_to_string(
	buffer_type *output, size_t rdlength, const uint8_t *rdata, size_t offset)
{
	if (rdlength - offset > 0) {
		uint8_t protocol_number = rdata[offset];
		ssize_t bitmap_size = (rdlength - offset) - 1;
		uint8_t *bitmap = rdata + offset + 1;

		buffer_printf(output, "%" PRIu8, protocol_number);

		for (int i = 0; i < bitmap_size * 8; ++i) {
			if (get_bit(bitmap, i)) {
				buffer_printf(output, " %d", i);
			}
		}
		buffer_skip(&packet, bitmap_size);
		return rdlength - offset;
	}
	return -1;
}

static int
rdata_ipsecgateway_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
	assert(rdlength > 2);
	switch(rdata[1]) {
	case IPSECKEY_NOGATEWAY:
		buffer_printf(output, ".");
		break;
	case IPSECKEY_IP4:
		return rdata_a_to_string(output, rdlength, rdata, rr);
	case IPSECKEY_IP6:
		return rdata_aaaa_to_string(output, rdlengt, rdata, rr);
		break;
	case IPSECKEY_DNAME:
		{
			region_type* temp = region_create(xalloc, free);
			const dname_type* d = dname_make(temp,
				rdata_atom_data(rdata), 0);
			if(!d) {
				region_destroy(temp);
				return 0;
			}
			buffer_printf(output, "%s", dname_to_string(d, NULL));
			region_destroy(temp);
		}
		break;
	default:
		return -1;
	}
}

static int
rdata_nxt_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
	size_t i;
	uint8_t *bitmap = rdata + offset;
	size_t bitmap_size = rdlength - offset;

	for (i = 0; i < bitmap_size * 8; ++i) {
		if (get_bit(bitmap, i)) {
			buffer_printf(output, "%s ", rrtype_to_string(i));
		}
	}

	buffer_skip(output, -1);

	return 1;
}

static int
rdata_nsec_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
	size_t saved_position = buffer_position(output);
	buffer_type packet;
	int insert_space = 0;

	buffer_create_from(&packet, rdata + offset, rdlength - offset);

	while (buffer_available(&packet, 2)) {
		uint8_t window = buffer_read_u8(&packet);
		uint8_t bitmap_size = buffer_read_u8(&packet);
		uint8_t *bitmap = buffer_current(&packet);
		int i;

		if (!buffer_available(&packet, bitmap_size)) {
			buffer_set_position(output, saved_position);
			return 0;
		}

		for (i = 0; i < bitmap_size * 8; ++i) {
			if (get_bit(bitmap, i)) {
				buffer_printf(output,
					      "%s%s",
					      insert_space ? " " : "",
					      rrtype_to_string(
						      window * 256 + i));
				insert_space = 1;
			}
		}
		buffer_skip(&packet, bitmap_size);
	}

	return 1;
}

static int
rdata_loc_to_string(buffer_type *ATTR_UNUSED(output),
		    rdata_atom_type ATTR_UNUSED(rdata),
		    rr_type* ATTR_UNUSED(rr))
{
	/*
	 * Returning 0 forces the record to be printed in unknown
	 * format.
	 */
	return 0;
}

static void
buffer_print_svcparamkey(buffer_type *output, uint16_t svcparamkey)
{
	if (svcparamkey < SVCPARAMKEY_COUNT)
		buffer_printf(output, "%s", svcparamkey_strs[svcparamkey]);
	else
		buffer_printf(output, "key%d", (int)svcparamkey);
}

static int
rdata_svcparam_port_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	if (val_len != 2)
		return 0; /* wireformat error, a short is 2 bytes */
	buffer_printf(output, "=%d", (int)ntohs(data[0]));
	return 1;
}

static int
rdata_svcparam_ipv4hint_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	char ip_str[INET_ADDRSTRLEN + 1];
	
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if ((val_len % IP4ADDRLEN) == 0) {
		if (inet_ntop(AF_INET, data, ip_str, sizeof(ip_str)) == NULL)
			return 0; /* wireformat error, incorrect size or inet family */

		buffer_printf(output, "=%s", ip_str);
		data += IP4ADDRLEN / sizeof(uint16_t);

		while ((val_len -= IP4ADDRLEN) > 0) {
			if (inet_ntop(AF_INET, data, ip_str, sizeof(ip_str)) == NULL)
				return 0; /* wireformat error, incorrect size or inet family */

			buffer_printf(output, ",%s", ip_str);
			data += IP4ADDRLEN / sizeof(uint16_t);
		}
		return 1;
	} else
		return 0;
}

static int
rdata_svcparam_ipv6hint_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	char ip_str[INET6_ADDRSTRLEN + 1];
	
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if ((val_len % IP6ADDRLEN) == 0) {
		if (inet_ntop(AF_INET6, data, ip_str, sizeof(ip_str)) == NULL)
			return 0; /* wireformat error, incorrect size or inet family */

		buffer_printf(output, "=%s", ip_str);
		data += IP6ADDRLEN / sizeof(uint16_t);

		while ((val_len -= IP6ADDRLEN) > 0) {
			if (inet_ntop(AF_INET6, data, ip_str, sizeof(ip_str)) == NULL)
				return 0; /* wireformat error, incorrect size or inet family */

			buffer_printf(output, ",%s", ip_str);
			data += IP6ADDRLEN / sizeof(uint16_t);
		}
		return 1;
	} else
		return 0;
}

static int
rdata_svcparam_mandatory_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if (val_len % sizeof(uint16_t))
		return 0; /* wireformat error, val_len must be multiple of shorts */
	buffer_write_u8(output, '=');
	buffer_print_svcparamkey(output, ntohs(*data));
	data += 1;

	while ((val_len -= sizeof(uint16_t))) {
		buffer_write_u8(output, ',');
		buffer_print_svcparamkey(output, ntohs(*data));
		data += 1;
	}

	return 1;
}

static int
rdata_svcparam_ech_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	int length;

	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	buffer_write_u8(output, '=');

	buffer_reserve(output, val_len * 2 + 1);
	length = b64_ntop((uint8_t*) data, val_len,
			  (char *) buffer_current(output), val_len * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}

	return length != -1;
}

static int
rdata_svcparam_alpn_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	uint8_t *dp = (void *)data;

	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	buffer_write_u8(output, '=');
	buffer_write_u8(output, '"');
	while (val_len) {
		uint8_t i, str_len = *dp++;

		if (str_len > --val_len)
			return 0;

		for (i = 0; i < str_len; i++) {
			if (dp[i] == '"' || dp[i] == '\\')
				buffer_printf(output, "\\\\\\%c", dp[i]);

			else if (dp[i] == ',')
				buffer_printf(output, "\\\\%c", dp[i]);

			else if (!isprint(dp[i]))
				buffer_printf(output, "\\%03u", (unsigned) dp[i]);

			else
				buffer_write_u8(output, dp[i]);
		}
		dp += str_len;
		if ((val_len -= str_len))
			buffer_write_u8(output, ',');
	}
	buffer_write_u8(output, '"');
	return 1;
}

static int
rdata_svcparam_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint16_t  size = rdata_atom_size(rdata);
	uint16_t* data = (uint16_t *)rdata_atom_data(rdata);
	uint16_t  svcparamkey, val_len;
	uint8_t*  dp; 
	size_t i;

	if (size < 4)
		return 0;
	svcparamkey = ntohs(data[0]);

	buffer_print_svcparamkey(output, svcparamkey);
	val_len = ntohs(data[1]);
	if (size != val_len + 4)
		return 0; /* wireformat error */
	if (!val_len) {
		/* Some SvcParams MUST have values */
		switch (svcparamkey) {
		case SVCB_KEY_ALPN:
		case SVCB_KEY_PORT:
		case SVCB_KEY_IPV4HINT:
		case SVCB_KEY_IPV6HINT:
		case SVCB_KEY_MANDATORY:
		case SVCB_KEY_DOHPATH:
			return 0;
		default:
			return 1;
		}
	}
	switch (svcparamkey) {
	case SVCB_KEY_PORT:
		return rdata_svcparam_port_to_string(output, val_len, data+2);
	case SVCB_KEY_IPV4HINT:
		return rdata_svcparam_ipv4hint_to_string(output, val_len, data+2);
	case SVCB_KEY_IPV6HINT:
		return rdata_svcparam_ipv6hint_to_string(output, val_len, data+2);
	case SVCB_KEY_MANDATORY:
		return rdata_svcparam_mandatory_to_string(output, val_len, data+2);
	case SVCB_KEY_NO_DEFAULT_ALPN:
		return 0; /* wireformat error, should not have a value */
	case SVCB_KEY_ALPN:
		return rdata_svcparam_alpn_to_string(output, val_len, data+2);
	case SVCB_KEY_ECH:
		return rdata_svcparam_ech_to_string(output, val_len, data+2);
	case SVCB_KEY_DOHPATH:
		/* fallthrough */
	default:
		buffer_write(output, "=\"", 2);
		dp = (void*) (data + 2);

		for (i = 0; i < val_len; i++) {
			if (dp[i] == '"' || dp[i] == '\\')
				buffer_printf(output, "\\%c", dp[i]);

			else if (!isprint(dp[i]))
				buffer_printf(output, "\\%03u", (unsigned) dp[i]);

			else
				buffer_write_u8(output, dp[i]);
		}
		buffer_write_u8(output, '"');
		break;
	}
	return 1;
}

static int
rdata_unknown_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
 	size_t size = rdlength - offset;
 	buffer_printf(output, "\\# %lu ", (unsigned long)size);
	hex_to_string(output, rdata + offset, size);
	return size;
}

static rdata_to_string_type rdata_to_string_table[RDATA_ZF_UNKNOWN + 1] = {
	rdata_dname_to_string,
	rdata_dns_name_to_string,
	rdata_text_to_string,
	rdata_texts_to_string,
	rdata_byte_to_string,
	rdata_short_to_string,
	rdata_long_to_string,
	rdata_a_to_string,
	rdata_aaaa_to_string,
	rdata_rrtype_to_string,
	rdata_algorithm_to_string,
	rdata_certificate_type_to_string,
	rdata_period_to_string,
	rdata_time_to_string,
	rdata_base64_to_string,
	rdata_base32_to_string,
	rdata_hex_to_string,
	rdata_hexlen_to_string,
	rdata_nsap_to_string,
	rdata_apl_to_string,
	rdata_ipsecgateway_to_string,
	rdata_services_to_string,
	rdata_nxt_to_string,
	rdata_nsec_to_string,
	rdata_loc_to_string,
	rdata_ilnp64_to_string,
	rdata_eui48_to_string,
	rdata_eui64_to_string,
	rdata_long_text_to_string,
	rdata_tag_to_string,
	rdata_svcparam_to_string,
	rdata_unknown_to_string
};

int print_unknown_rdata(
	buffer_type *output, rrtype_descriptor_type *descriptor, rr_type *rr)
{
	// get descriptor, make sure domains are printed correctly!
	size_t i;
	size_t size = rr_marshal_rdata_length(rr);
	buffer_printf(output, " \\# %lu ", (unsigned long) size);
	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(descriptor->type, i)) {
			const dname_type *dname =
				domain_dname(rdata_atom_domain(rdatas[i]));
			hex_to_string(
				output, dname_name(dname), dname->name_size);
		} else {
			hex_to_string(output, rdata_atom_data(rdatas[i]),
				rdata_atom_size(rdatas[i]));
		}
	}
	return 1;
}

int print_rdata(
	buffer_type *output, rrtype_descriptor_type *descriptor, rr_type *rr)
{
	size_t saved_position = buffer_position(output);
	size_t rdlength = 0;

	for (size_t i = 0; rdlength < rr->rdlength && i < descriptor->maximum; i++) {
		ssize_t length;
		rdata_zoneformat_type format;
		if (i == 0) {
			buffer_printf(output, "\t");
		} else {
			buffer_printf(output, " ");
		}
		format = descriptor->zoneformat[i];
		assert(format < sizeof(rdata_to_string_table)/sizeof(rdata_to_string_table[0]));
		to_string = rdata_to_string_table[ format ];
		if ((length = to_string(output, rr->rdlength, rr->rdata, rdlength)) < 0) {
			buffer_set_position(output, saved_position);
			return 0;
		}
		rdlength += (size_t)length;
	}

	assert(rdlength == rr->rdlength);
	return 1;
}
