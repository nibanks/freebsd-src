/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/eventlog_decode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode.h"

struct dvalue {
	uint32_t	value;
	char	       *name;
};

/* enum or flag table */
struct dtable {
	char	       *name;
	uint16_t	count;
	struct dvalue  *values;
};

struct dfield {
	char	       *name;
	uint8_t		type;		/* EVENTLOG_DECODE_TYPE_* */
	uint8_t		annotation;	/* EVENTLOG_DECODE_ANNOT_* */
	uint16_t	annot_index;	/* 1-based enum/flag index, else 0 */
	uint16_t	char_len;
	uint16_t	offset;
	uint8_t		flags;
	uint16_t	varlen_count_index;
	uint16_t	varlen_max;
};

struct dstruct {
	char	       *name;
	uint16_t	field_count;
	struct dfield  *fields;
};

struct devent {
	uint32_t	id;
	char	       *name;
	uint8_t		level;
	uint32_t	keywords;
	uint16_t	struct_index;	/* 1-based, 0 == no payload */
	char	       *format;
};

struct dkeyword {
	char	       *name;
	uint32_t	value;
};

struct decode_provider {
	char	       *name;
	uint16_t	version;
	uint8_t		word_size;	/* producer pointer width in bytes */
	uint8_t		endianness;	/* EVENTLOG_DECODE_ENDIAN_* */
	uint16_t	nkeywords;
	uint16_t	nenums;
	uint16_t	nflags;
	uint16_t	nstructs;
	uint16_t	nevents;
	struct dkeyword *keywords;
	struct dtable  *enums;
	struct dtable  *flags;
	struct dstruct *structs;
	struct devent  *events;
};

/* Forward-only blob reader with bounds checking. */
struct rdr {
	const unsigned char    *p;
	const unsigned char    *end;
	bool			err;
};

static uint8_t
rd_u8(struct rdr *r)
{
	if (r->err || r->p + 1 > r->end) {
		r->err = true;
		return (0);
	}
	return (*r->p++);
}

static uint16_t
rd_u16(struct rdr *r)
{
	uint16_t v;

	if (r->err || r->p + 2 > r->end) {
		r->err = true;
		return (0);
	}
	v = (uint16_t)r->p[0] | ((uint16_t)r->p[1] << 8);
	r->p += 2;
	return (v);
}

static uint32_t
rd_u32(struct rdr *r)
{
	uint32_t v;

	if (r->err || r->p + 4 > r->end) {
		r->err = true;
		return (0);
	}
	v = (uint32_t)r->p[0] | ((uint32_t)r->p[1] << 8) |
	    ((uint32_t)r->p[2] << 16) | ((uint32_t)r->p[3] << 24);
	r->p += 4;
	return (v);
}

/* Read a uint16 length-prefixed string into a freshly allocated NUL string. */
static char *
rd_str(struct rdr *r)
{
	uint16_t len;
	char *s;

	len = rd_u16(r);
	if (r->err || r->p + len > r->end) {
		r->err = true;
		return (NULL);
	}
	s = malloc((size_t)len + 1);
	if (s == NULL) {
		r->err = true;
		return (NULL);
	}
	memcpy(s, r->p, len);
	s[len] = '\0';
	r->p += len;
	return (s);
}

static void
free_table(struct dtable *t, uint16_t n)
{
	uint16_t i, j;

	if (t == NULL)
		return;
	for (i = 0; i < n; i++) {
		free(t[i].name);
		if (t[i].values != NULL) {
			for (j = 0; j < t[i].count; j++)
				free(t[i].values[j].name);
			free(t[i].values);
		}
	}
	free(t);
}

void
decode_provider_free(struct decode_provider *dp)
{
	uint16_t i, j;

	if (dp == NULL)
		return;
	free(dp->name);
	if (dp->keywords != NULL) {
		for (i = 0; i < dp->nkeywords; i++)
			free(dp->keywords[i].name);
		free(dp->keywords);
	}
	free_table(dp->enums, dp->nenums);
	free_table(dp->flags, dp->nflags);
	if (dp->structs != NULL) {
		for (i = 0; i < dp->nstructs; i++) {
			free(dp->structs[i].name);
			if (dp->structs[i].fields != NULL) {
				for (j = 0; j < dp->structs[i].field_count; j++)
					free(dp->structs[i].fields[j].name);
				free(dp->structs[i].fields);
			}
		}
		free(dp->structs);
	}
	if (dp->events != NULL) {
		for (i = 0; i < dp->nevents; i++) {
			free(dp->events[i].name);
			free(dp->events[i].format);
		}
		free(dp->events);
	}
	free(dp);
}

static struct dtable *
parse_tables(struct rdr *r, uint16_t n)
{
	struct dtable *t;
	uint16_t i, j;

	if (n == 0)
		return (NULL);
	t = calloc(n, sizeof(*t));
	if (t == NULL) {
		r->err = true;
		return (NULL);
	}
	for (i = 0; i < n; i++) {
		t[i].name = rd_str(r);
		t[i].count = rd_u16(r);
		if (r->err)
			return (t);
		if (t[i].count > 0) {
			t[i].values = calloc(t[i].count, sizeof(struct dvalue));
			if (t[i].values == NULL) {
				r->err = true;
				return (t);
			}
			for (j = 0; j < t[i].count; j++) {
				t[i].values[j].value = rd_u32(r);
				t[i].values[j].name = rd_str(r);
			}
		}
	}
	return (t);
}

/*
 * Validate that every cross-reference in the parsed blob is in range, so the
 * formatting paths can index enum/flag/struct/field tables without bounds
 * checks.  Returns false on any out-of-range index (a malformed or hostile
 * blob).  Indices in the blob are 1-based with 0 meaning "none".
 */
static bool
validate_provider(const struct decode_provider *dp)
{
	uint16_t i, j;

	for (i = 0; i < dp->nstructs; i++) {
		const struct dstruct *st = &dp->structs[i];

		for (j = 0; j < st->field_count; j++) {
			const struct dfield *f = &st->fields[j];

			if (f->annotation == EVENTLOG_DECODE_ANNOT_ENUM &&
			    (f->annot_index == 0 || f->annot_index > dp->nenums))
				return (false);
			if (f->annotation == EVENTLOG_DECODE_ANNOT_FLAG &&
			    (f->annot_index == 0 || f->annot_index > dp->nflags))
				return (false);
			if ((f->flags & EVENTLOG_DECODE_FIELD_VARLEN) != 0 &&
			    (f->varlen_count_index == 0 ||
			    f->varlen_count_index > st->field_count))
				return (false);
		}
	}
	for (i = 0; i < dp->nevents; i++) {
		if (dp->events[i].struct_index > dp->nstructs)
			return (false);
	}
	return (true);
}

struct decode_provider *
decode_provider_parse(const unsigned char *blob, size_t len)
{
	struct decode_provider *dp;
	struct rdr rdr, *r = &rdr;
	uint16_t i, j;

	if (blob == NULL || len < EVENTLOG_DECODE_MAGIC_LEN + 2)
		return (NULL);
	if (memcmp(blob, EVENTLOG_DECODE_MAGIC, EVENTLOG_DECODE_MAGIC_LEN) != 0)
		return (NULL);

	dp = calloc(1, sizeof(*dp));
	if (dp == NULL)
		return (NULL);

	r->p = blob + EVENTLOG_DECODE_MAGIC_LEN;
	r->end = blob + len;
	r->err = false;

	dp->version = rd_u16(r);
	if (dp->version != EVENTLOG_DECODE_VERSION)
		goto fail;
	dp->word_size = rd_u8(r);
	dp->endianness = rd_u8(r);
	(void)rd_u16(r);		/* reserved */
	if (r->err)
		goto fail;
	/*
	 * The interpreter reads little-endian payloads directly; a big-endian
	 * producer would need byte-swapping we do not implement.
	 */
	if (dp->endianness != EVENTLOG_DECODE_ENDIAN_LE)
		goto fail;
	dp->name = rd_str(r);
	dp->nkeywords = rd_u16(r);
	dp->nenums = rd_u16(r);
	dp->nflags = rd_u16(r);
	dp->nstructs = rd_u16(r);
	dp->nevents = rd_u16(r);
	if (r->err)
		goto fail;

	if (dp->nkeywords > 0) {
		dp->keywords = calloc(dp->nkeywords, sizeof(struct dkeyword));
		if (dp->keywords == NULL)
			goto fail;
		for (i = 0; i < dp->nkeywords; i++) {
			dp->keywords[i].name = rd_str(r);
			dp->keywords[i].value = rd_u32(r);
		}
	}

	dp->enums = parse_tables(r, dp->nenums);
	dp->flags = parse_tables(r, dp->nflags);
	if (r->err)
		goto fail;

	if (dp->nstructs > 0) {
		dp->structs = calloc(dp->nstructs, sizeof(struct dstruct));
		if (dp->structs == NULL)
			goto fail;
		for (i = 0; i < dp->nstructs; i++) {
			struct dstruct *st = &dp->structs[i];

			st->name = rd_str(r);
			st->field_count = rd_u16(r);
			if (r->err)
				goto fail;
			if (st->field_count == 0)
				continue;
			st->fields = calloc(st->field_count,
			    sizeof(struct dfield));
			if (st->fields == NULL)
				goto fail;
			for (j = 0; j < st->field_count; j++) {
				struct dfield *f = &st->fields[j];

				f->name = rd_str(r);
				f->type = rd_u8(r);
				f->annotation = rd_u8(r);
				f->annot_index = rd_u16(r);
				f->char_len = rd_u16(r);
				f->offset = rd_u16(r);
				f->flags = rd_u8(r);
				f->varlen_count_index = rd_u16(r);
				f->varlen_max = rd_u16(r);
			}
		}
	}

	if (dp->nevents > 0) {
		dp->events = calloc(dp->nevents, sizeof(struct devent));
		if (dp->events == NULL)
			goto fail;
		for (i = 0; i < dp->nevents; i++) {
			dp->events[i].id = rd_u32(r);
			dp->events[i].name = rd_str(r);
			dp->events[i].level = rd_u8(r);
			dp->events[i].keywords = rd_u32(r);
			dp->events[i].struct_index = rd_u16(r);
			dp->events[i].format = rd_str(r);
		}
	}

	if (r->err)
		goto fail;

	if (!validate_provider(dp))
		goto fail;

	return (dp);

fail:
	decode_provider_free(dp);
	return (NULL);
}

const char *
decode_provider_name(const struct decode_provider *dp)
{
	return (dp->name != NULL ? dp->name : "?");
}

static const struct devent *
find_event(const struct decode_provider *dp, uint32_t event_id)
{
	uint16_t i;

	for (i = 0; i < dp->nevents; i++) {
		if (dp->events[i].id == event_id)
			return (&dp->events[i]);
	}
	return (NULL);
}

const char *
decode_event_id_to_name(const struct decode_provider *dp, uint32_t event_id)
{
	const struct devent *ev = find_event(dp, event_id);

	return (ev != NULL ? ev->name : NULL);
}

uint32_t
decode_keyword_from_string(const struct decode_provider *dp, const char *name)
{
	uint16_t i;

	for (i = 0; i < dp->nkeywords; i++) {
		if (strcasecmp(dp->keywords[i].name, name) == 0)
			return (dp->keywords[i].value);
	}
	return (0);
}

/* Byte width of a field's element in the payload. */
static uint16_t
field_size(const struct dfield *f)
{
	switch (f->type) {
	case EVENTLOG_DECODE_TYPE_U8:
	case EVENTLOG_DECODE_TYPE_I8:
		return (1);
	case EVENTLOG_DECODE_TYPE_U16:
	case EVENTLOG_DECODE_TYPE_I16:
		return (2);
	case EVENTLOG_DECODE_TYPE_U32:
	case EVENTLOG_DECODE_TYPE_I32:
	case EVENTLOG_DECODE_TYPE_IN_ADDR:
		return (4);
	case EVENTLOG_DECODE_TYPE_U64:
	case EVENTLOG_DECODE_TYPE_I64:
	case EVENTLOG_DECODE_TYPE_PTR:
		return (8);
	case EVENTLOG_DECODE_TYPE_IN6_ADDR:
		return (16);
	case EVENTLOG_DECODE_TYPE_CHAR_ARRAY:
		return (f->char_len);
	default:
		return (0);
	}
}

static bool
field_is_signed(const struct dfield *f)
{
	switch (f->type) {
	case EVENTLOG_DECODE_TYPE_I8:
	case EVENTLOG_DECODE_TYPE_I16:
	case EVENTLOG_DECODE_TYPE_I32:
	case EVENTLOG_DECODE_TYPE_I64:
		return (true);
	default:
		return (false);
	}
}

/* Read a field's little-endian integer value (sign-extended if signed). */
static bool
load_uint(const struct dfield *f, const void *payload, size_t payload_size,
    uint64_t *out)
{
	const unsigned char *p;
	uint16_t sz = field_size(f);
	uint64_t v = 0;
	int i;

	if (sz == 0 || sz > 8)
		return (false);
	if ((size_t)f->offset + sz > payload_size)
		return (false);
	/* Only form the pointer once offset+sz is known to be in bounds. */
	p = (const unsigned char *)payload + f->offset;
	for (i = 0; i < sz; i++)
		v |= (uint64_t)p[i] << (8 * i);
	if (field_is_signed(f) && sz < 8) {
		uint64_t signbit = (uint64_t)1 << (sz * 8 - 1);
		if (v & signbit)
			v |= ~((signbit << 1) - 1);
	}
	*out = v;
	return (true);
}

static const struct dfield *
find_field(const struct decode_provider *dp, const struct devent *ev,
    const char *field_name, const struct dstruct **st_out)
{
	const struct dstruct *st;
	uint16_t j;

	if (ev->struct_index == 0 || ev->struct_index > dp->nstructs)
		return (NULL);
	st = &dp->structs[ev->struct_index - 1];
	for (j = 0; j < st->field_count; j++) {
		if (strcmp(st->fields[j].name, field_name) == 0) {
			if (st_out != NULL)
				*st_out = st;
			return (&st->fields[j]);
		}
	}
	return (NULL);
}

bool
decode_get_field(const struct decode_provider *dp, uint32_t event_id,
    const char *field_name, const void *payload, size_t payload_size,
    struct decode_value *out)
{
	const struct devent *ev = find_event(dp, event_id);
	const struct dfield *f;

	if (ev == NULL)
		return (false);
	f = find_field(dp, ev, field_name, NULL);
	if (f == NULL)
		return (false);

	memset(out, 0, sizeof(*out));
	out->type = f->type;
	out->annotation = f->annotation;

	if (f->type == EVENTLOG_DECODE_TYPE_IN_ADDR ||
	    f->type == EVENTLOG_DECODE_TYPE_IN6_ADDR ||
	    f->type == EVENTLOG_DECODE_TYPE_CHAR_ARRAY) {
		uint16_t sz = field_size(f);

		if ((size_t)f->offset + sz > payload_size)
			return (false);
		out->ptr = (const unsigned char *)payload + f->offset;
		out->len = sz;
		return (true);
	}
	return (load_uint(f, payload, payload_size, &out->u));
}

/* Append into buf at *pos with snprintf semantics; *pos tracks intended len. */
static void
appendf(char *buf, size_t bufsize, size_t *pos, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t avail;

	avail = (*pos < bufsize) ? bufsize - *pos : 0;
	va_start(ap, fmt);
	n = vsnprintf(buf + (*pos < bufsize ? *pos : bufsize), avail, fmt, ap);
	va_end(ap);
	if (n > 0)
		*pos += (size_t)n;
}

static const struct dtable *
table_at(const struct dtable *t, uint16_t n, uint16_t idx1)
{
	if (idx1 == 0 || idx1 > n)
		return (NULL);
	return (&t[idx1 - 1]);
}

/* Append the string form of an enum/flag/address/char field. */
static void
append_field_string(char *buf, size_t bufsize, size_t *pos,
    const struct decode_provider *dp, const struct dfield *f,
    const void *payload, size_t payload_size)
{
	uint64_t v = 0;

	if (f->type == EVENTLOG_DECODE_TYPE_IN_ADDR) {
		char tmp[INET_ADDRSTRLEN];
		if ((size_t)f->offset + 4 > payload_size ||
		    inet_ntop(AF_INET,
		    (const unsigned char *)payload + f->offset, tmp,
		    sizeof(tmp)) == NULL)
			appendf(buf, bufsize, pos, "<invalid>");
		else
			appendf(buf, bufsize, pos, "%s", tmp);
		return;
	}
	if (f->type == EVENTLOG_DECODE_TYPE_IN6_ADDR) {
		char tmp[INET6_ADDRSTRLEN];
		if ((size_t)f->offset + 16 > payload_size ||
		    inet_ntop(AF_INET6,
		    (const unsigned char *)payload + f->offset, tmp,
		    sizeof(tmp)) == NULL)
			appendf(buf, bufsize, pos, "<invalid>");
		else
			appendf(buf, bufsize, pos, "%s", tmp);
		return;
	}
	if (f->type == EVENTLOG_DECODE_TYPE_CHAR_ARRAY) {
		if ((size_t)f->offset + f->char_len > payload_size)
			appendf(buf, bufsize, pos, "<invalid>");
		else
			appendf(buf, bufsize, pos, "%.*s", (int)f->char_len,
			    (const char *)payload + f->offset);
		return;
	}

	if (!load_uint(f, payload, payload_size, &v)) {
		appendf(buf, bufsize, pos, "<?>");
		return;
	}

	if (f->annotation == EVENTLOG_DECODE_ANNOT_ENUM) {
		const struct dtable *t = table_at(dp->enums, dp->nenums,
		    f->annot_index);
		uint16_t k;

		if (t != NULL) {
			for (k = 0; k < t->count; k++) {
				if (t->values[k].value == (uint32_t)v) {
					appendf(buf, bufsize, pos, "%s",
					    t->values[k].name);
					return;
				}
			}
		}
		appendf(buf, bufsize, pos, "%llu", (unsigned long long)v);
		return;
	}

	if (f->annotation == EVENTLOG_DECODE_ANNOT_FLAG) {
		const struct dtable *t = table_at(dp->flags, dp->nflags,
		    f->annot_index);
		bool first = true;
		uint16_t k;

		if (t != NULL && v != 0) {
			for (k = 0; k < t->count; k++) {
				if ((v & t->values[k].value) ==
				    t->values[k].value &&
				    t->values[k].value != 0) {
					appendf(buf, bufsize, pos, "%s%s",
					    first ? "" : "|",
					    t->values[k].name);
					first = false;
				}
			}
		}
		if (first)
			appendf(buf, bufsize, pos, "%llu",
			    (unsigned long long)v);
		return;
	}

	/* Fallback: plain numeric. */
	appendf(buf, bufsize, pos, "%llu", (unsigned long long)v);
}

/* Append a field formatted by its own type/annotation (positional %N). */
static void
append_field_positional(char *buf, size_t bufsize, size_t *pos,
    const struct decode_provider *dp, const struct dstruct *st,
    const struct dfield *f, const void *payload, size_t payload_size)
{
	uint64_t v = 0;

	if ((f->flags & EVENTLOG_DECODE_FIELD_VARLEN) != 0 &&
	    f->type == EVENTLOG_DECODE_TYPE_U8 && st != NULL &&
	    f->varlen_count_index > 0 &&
	    f->varlen_count_index <= st->field_count) {
		const struct dfield *cf;
		uint64_t n = 0;

		cf = &st->fields[f->varlen_count_index - 1];
		if (!load_uint(cf, payload, payload_size, &n)) {
			appendf(buf, bufsize, pos, "<?>");
			return;
		}
		if (n > f->varlen_max)
			n = f->varlen_max;
		if ((size_t)f->offset >= payload_size) {
			appendf(buf, bufsize, pos, "<?>");
			return;
		}
		if (f->offset + n > payload_size)
			n = payload_size - f->offset;
		appendf(buf, bufsize, pos, "%.*s", (int)n,
		    (const char *)payload + f->offset);
		return;
	}

	switch (f->type) {
	case EVENTLOG_DECODE_TYPE_IN_ADDR:
	case EVENTLOG_DECODE_TYPE_IN6_ADDR:
	case EVENTLOG_DECODE_TYPE_CHAR_ARRAY:
		append_field_string(buf, bufsize, pos, dp, f, payload,
		    payload_size);
		return;
	}
	if (f->annotation == EVENTLOG_DECODE_ANNOT_ENUM ||
	    f->annotation == EVENTLOG_DECODE_ANNOT_FLAG) {
		append_field_string(buf, bufsize, pos, dp, f, payload,
		    payload_size);
		return;
	}
	if (!load_uint(f, payload, payload_size, &v)) {
		appendf(buf, bufsize, pos, "<?>");
		return;
	}
	switch (f->annotation) {
	case EVENTLOG_DECODE_ANNOT_HEX:
		appendf(buf, bufsize, pos, "0x%llx", (unsigned long long)v);
		return;
	case EVENTLOG_DECODE_ANNOT_NTOHS:
		appendf(buf, bufsize, pos, "%u", ntohs((uint16_t)v));
		return;
	}
	if (f->type == EVENTLOG_DECODE_TYPE_PTR) {
		appendf(buf, bufsize, pos, "%p",
		    (void *)(uintptr_t)v);
		return;
	}
	if (field_is_signed(f))
		appendf(buf, bufsize, pos, "%lld", (long long)v);
	else
		appendf(buf, bufsize, pos, "%llu", (unsigned long long)v);
}

/* The k-th (1-based) field that is not a trailing variable-length array. */
static const struct dfield *
nth_scalar_field(const struct dstruct *st, int k)
{
	int seen = 0;
	uint16_t j;

	for (j = 0; j < st->field_count; j++) {
		if (st->fields[j].flags & EVENTLOG_DECODE_FIELD_VARLEN)
			continue;
		if (++seen == k)
			return (&st->fields[j]);
	}
	return (NULL);
}

/*
 * Append a field formatted to a printf conversion taken from the schema's
 * format string (direct %u/%s/%x/... style).  Address/enum/flag/char fields
 * always render as their string form; numeric fields honor the conversion.
 */
static void
append_field_spec(char *buf, size_t bufsize, size_t *pos,
    const struct decode_provider *dp, const struct dfield *f,
    const void *payload, size_t payload_size, const char *flagswidth,
    char conv)
{
	char spec[32];
	uint64_t v = 0;

	switch (f->type) {
	case EVENTLOG_DECODE_TYPE_IN_ADDR:
	case EVENTLOG_DECODE_TYPE_IN6_ADDR:
	case EVENTLOG_DECODE_TYPE_CHAR_ARRAY:
		append_field_string(buf, bufsize, pos, dp, f, payload,
		    payload_size);
		return;
	}
	if (conv == 's' || f->annotation == EVENTLOG_DECODE_ANNOT_ENUM ||
	    f->annotation == EVENTLOG_DECODE_ANNOT_FLAG) {
		append_field_string(buf, bufsize, pos, dp, f, payload,
		    payload_size);
		return;
	}
	if (!load_uint(f, payload, payload_size, &v)) {
		appendf(buf, bufsize, pos, "<?>");
		return;
	}
	if (conv == 'p') {
		appendf(buf, bufsize, pos, "%p", (void *)(uintptr_t)v);
		return;
	}
	if (conv == 'c') {
		appendf(buf, bufsize, pos, "%c", (int)v);
		return;
	}
	if (conv == 'd' || conv == 'i') {
		snprintf(spec, sizeof(spec), "%%%slld", flagswidth);
		appendf(buf, bufsize, pos, spec, (long long)v);
		return;
	}
	/* u, o, x, X */
	snprintf(spec, sizeof(spec), "%%%sll%c", flagswidth, conv);
	appendf(buf, bufsize, pos, spec, (unsigned long long)v);
}

/*
 * Recognized printf conversion specifiers.  %n is deliberately excluded: a
 * decode blob's format strings can come from an untrusted source (a capture
 * file, or a provider built elsewhere), and honoring %n would turn the
 * formatter's vsnprintf into an arbitrary memory write.  An unrecognized
 * conversion is emitted literally instead.
 */
static bool
is_conv_char(char c)
{
	return (c != '\0' && strchr("diouxXpsc", c) != NULL);
}

/*
 * Upper bound on a printf field width taken from a decode blob's format
 * string.  No real field needs more than a couple dozen columns; without a
 * cap, a hostile blob's "%999999999d" would hand vsnprintf(3) a width large
 * enough to burn significant CPU computing the padded length, even though
 * the actual write is bounded by the output buffer.
 */
#define	EVENTLOG_DECODE_MAX_FIELD_WIDTH	256

/*
 * Upper bound on the number of %-placeholders formatted per event. Every
 * placeholder triggers at least one linear scan (nth_scalar_field() rescans
 * the struct's fields from the start each time, and an enum/flag field on
 * top of that scans its value table), so cost is O(placeholders * field or
 * table size) -- quadratic in a hostile blob that pairs a huge format string
 * with a huge struct/table (both can be up to 65535 per the wire format).
 * Real schemas format a handful of fields per event, never close to this;
 * placeholders beyond it render as "<?>" without doing the lookup.
 */
#define	EVENTLOG_DECODE_MAX_FORMAT_FIELDS	256

int
decode_format_payload(const struct decode_provider *dp, uint32_t event_id,
    const void *payload, size_t payload_size, char *buf, size_t bufsize)
{
	const struct devent *ev = find_event(dp, event_id);
	const struct dstruct *st = NULL;
	const char *f;
	size_t pos = 0;
	int seq = 0;
	int nplaceholders = 0;

	if (ev == NULL)
		return (-1);

	/* SESSION_CREATE with no payload is rendered without the tp pointer. */
	if (payload_size == 0 && ev->name != NULL &&
	    strcmp(ev->name, "SESSION_CREATE") == 0) {
		snprintf(buf, bufsize, "Session created");
		return ((int)strlen(buf));
	}

	if (ev->struct_index != 0 && ev->struct_index <= dp->nstructs)
		st = &dp->structs[ev->struct_index - 1];

	if (bufsize > 0)
		buf[0] = '\0';

	f = ev->format != NULL ? ev->format : "";
	while (*f != '\0') {
		const struct dfield *fld;
		char flagswidth[24];
		size_t fw = 0;
		const char *q;
		int field_idx;
		char conv;

		if (*f != '%') {
			appendf(buf, bufsize, &pos, "%c", *f);
			f++;
			continue;
		}
		if (f[1] == '%') {
			appendf(buf, bufsize, &pos, "%%");
			f += 2;
			continue;
		}

		/* Parse a conversion. */
		q = f + 1;
		/* flags */
		while (*q != '\0' && strchr("-+ #0", *q) != NULL) {
			if (fw < sizeof(flagswidth) - 1)
				flagswidth[fw++] = *q;
			q++;
		}
		/* width digits, clamped (see EVENTLOG_DECODE_MAX_FIELD_WIDTH) */
		if (isdigit((unsigned char)*q)) {
			unsigned long width = 0;
			int wn;

			while (isdigit((unsigned char)*q)) {
				width = width * 10 + (unsigned)(*q - '0');
				q++;
			}
			if (width > EVENTLOG_DECODE_MAX_FIELD_WIDTH)
				width = EVENTLOG_DECODE_MAX_FIELD_WIDTH;
			if (fw < sizeof(flagswidth) - 1) {
				wn = snprintf(flagswidth + fw,
				    sizeof(flagswidth) - fw, "%lu", width);
				if (wn > 0)
					fw += (size_t)wn;
			}
		}
		flagswidth[fw] = '\0';

		/*
		 * Skip any length modifiers; integer fields are reformatted
		 * with an explicit "ll" width based on the field's real type.
		 */
		while (*q == 'l' || *q == 'h' || *q == 'j' || *q == 'z' ||
		    *q == 't' || *q == 'q' || *q == 'L')
			q++;

		if (is_conv_char(*q)) {
			/* Direct printf-style placeholder: next scalar field. */
			conv = *q;
			fld = (st != NULL &&
			    ++nplaceholders <= EVENTLOG_DECODE_MAX_FORMAT_FIELDS) ?
			    nth_scalar_field(st, ++seq) : NULL;
			if (fld == NULL)
				appendf(buf, bufsize, &pos, "<?>");
			else
				append_field_spec(buf, bufsize, &pos, dp, fld,
				    payload, payload_size, flagswidth, conv);
			f = q + 1;
			continue;
		}

		/*
		 * Positional placeholder %N (no length modifier / conversion
		 * letter, no flags): the digits are a 1-based field index.
		 */
		if (fw > 0 && flagswidth[0] >= '0' && flagswidth[0] <= '9') {
			field_idx = atoi(flagswidth);
			fld = (st != NULL &&
			    ++nplaceholders <= EVENTLOG_DECODE_MAX_FORMAT_FIELDS &&
			    field_idx >= 1 && field_idx <= st->field_count) ?
			    &st->fields[field_idx - 1] : NULL;
			if (fld == NULL)
				appendf(buf, bufsize, &pos, "<?>");
			else
				append_field_positional(buf, bufsize, &pos, dp,
				    st, fld, payload, payload_size);
			f = q;
			continue;
		}

		/* Not a recognized conversion; emit literally. */
		appendf(buf, bufsize, &pos, "%c", *f);
		f++;
	}

	return ((int)pos);
}
