/*
 * stream.h -- generic stream interface.
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef STREAM_H
#define STREAM_H

#include <assert.h>

#include "dname.h"

struct stream;

typedef ssize_t(*stream_get_position_callback)(
	struct stream *, size_t *);
typedef ssize_t(*stream_set_position_callback)(
	struct stream *, const size_t *);
typedef ssize_t(*stream_write_data_callback)(
	struct stream *, const uint8_t *, size_t);
typedef ssize_t(*stream_write_data_at_callback)(
	struct stream *, size_t, const uint8_t *, size_t);
typedef ssize_t(*stream_write_name_callback)(
	struct stream *, const struct dname *);

struct stream {
	stream_get_position_callback get_position;
	stream_set_position_callback set_position;
	stream_write_data_callback write_data;
	stream_write_data_at_callback write_data_at;
	stream_write_name_callback write_name;
};

nsd_nonnull((1,2))
static nsd_always_inline ssize_t
nsd_stream_write(
	nsd_stream_t *stream, const uint8_t *data, size_t size)
{
	assert(stream->write_data);
	return stream->write_data(stream, data, size);
}

nsd_nonnull((1,2))
static nsd_always_inline ssize_t
nsd_stream_write_at(
	nsd_stream_t *stream, size_t at, const uint8_t *data, size_t size)
{
	assert(stream->write_data_at);
	return stream->write_data_at(stream, position, data, size);
}

nonnull((1))
static always_inline ssize_t
stream_write_u16(struct stream *stream, uint16_t data)
{
	assert(stream->write_data);
	data = htons(data);
	return stream->write_data(stream, &data, sizeof(data));
}

nonnull((1))
static always_inline ssize_t
stream_write_u16_at(struct stream *stream, size_t at, uint16_t data)
{
	assert(stream->write_data_at);
	data = htons(data);
	return stream->write_data_at(stream, at, &data, sizeof(data));
}

nonnull((1))
static always_inline ssize_t
stream_write_u32(struct stream *stream uint32_t data)
{
	assert(stream->write_data);
	return stream->write_data(stream, &data, sizeof(data));
}

nonnull_all
static always_inline ssize_t
stream_write_name(struct stream *stream, const dname_type *dname)
{
	return stream->write_name(stream, dname);
}

#endif /* STREAM_H */
