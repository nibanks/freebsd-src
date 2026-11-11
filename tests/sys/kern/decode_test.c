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

/*
 * Unit tests for the elog decode-blob interpreter (usr.bin/elog/decode.c).
 *
 * decode.c parses a flat binary "decode blob" (see sys/sys/eventlog_decode.h)
 * and formats event payloads from it.  Both the blob and the payloads can come
 * from an untrusted source (a capture file, or a provider built on a different
 * kernel), so the parser and formatter are hardened.  These tests build blobs
 * byte-for-byte to exercise that hardening directly - the live elog_test.py
 * suite only ever feeds it well-formed, in-tree blobs.
 */

#include <sys/types.h>
#include <sys/eventlog_decode.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "decode.h"

/* ------------------------------------------------------------------ */
/* Blob builder: append primitives in the EDB1 wire format.           */
/* ------------------------------------------------------------------ */

struct bb {
	unsigned char  *p;
	size_t		len;
	size_t		cap;
};

static void
bb_need(struct bb *b, size_t n)
{
	if (b->len + n <= b->cap)
		return;
	if (b->cap == 0)
		b->cap = 256;
	while (b->len + n > b->cap)
		b->cap *= 2;
	b->p = realloc(b->p, b->cap);
	ATF_REQUIRE(b->p != NULL);
}

static void
bb_u8(struct bb *b, uint8_t v)
{
	bb_need(b, 1);
	b->p[b->len++] = v;
}

static void
bb_u16(struct bb *b, uint16_t v)
{
	bb_u8(b, (uint8_t)(v & 0xff));
	bb_u8(b, (uint8_t)((v >> 8) & 0xff));
}

static void
bb_u32(struct bb *b, uint32_t v)
{
	bb_u16(b, (uint16_t)(v & 0xffff));
	bb_u16(b, (uint16_t)((v >> 16) & 0xffff));
}

static void
bb_bytes(struct bb *b, const void *d, size_t n)
{
	bb_need(b, n);
	memcpy(b->p + b->len, d, n);
	b->len += n;
}

static void
bb_str(struct bb *b, const char *s)
{
	size_t n = strlen(s);

	ATF_REQUIRE(n <= 0xffff);
	bb_u16(b, (uint16_t)n);
	bb_bytes(b, s, n);
}

static void
bb_free(struct bb *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

static void
bb_header(struct bb *b, const char *name, uint16_t nk, uint16_t ne,
    uint16_t nf, uint16_t ns, uint16_t nev)
{
	bb_bytes(b, EVENTLOG_DECODE_MAGIC, EVENTLOG_DECODE_MAGIC_LEN);
	bb_u16(b, EVENTLOG_DECODE_VERSION);
	bb_u8(b, 8);				/* word_size */
	bb_u8(b, EVENTLOG_DECODE_ENDIAN_LE);
	bb_u16(b, 0);				/* reserved */
	bb_str(b, name);
	bb_u16(b, nk);
	bb_u16(b, ne);
	bb_u16(b, nf);
	bb_u16(b, ns);
	bb_u16(b, nev);
}

static void
bb_field(struct bb *b, const char *name, uint8_t type, uint8_t annot,
    uint16_t annot_index, uint16_t char_len, uint16_t offset, uint8_t flags,
    uint16_t vci, uint16_t vmax)
{
	bb_str(b, name);
	bb_u8(b, type);
	bb_u8(b, annot);
	bb_u16(b, annot_index);
	bb_u16(b, char_len);
	bb_u16(b, offset);
	bb_u8(b, flags);
	bb_u16(b, vci);
	bb_u16(b, vmax);
}

static void
bb_event(struct bb *b, uint32_t id, const char *name, uint8_t level,
    uint32_t keywords, uint16_t struct_index, const char *fmt)
{
	bb_u32(b, id);
	bb_str(b, name);
	bb_u8(b, level);
	bb_u32(b, keywords);
	bb_u16(b, struct_index);
	bb_str(b, fmt);
}

/*
 * uint8_t varlen tails render as a string under positional %N (nginx URI).
 *
 * struct layout: u32 id @0, u8 cnt @4, uint8_t tail @5 (count field 2).
 */
static void
make_varlen_u8_blob(struct bb *b, uint16_t vmax, const char *fmt)
{
	bb_header(b, "p", 0, 0, 0, 1, 1);
	bb_str(b, "s"); bb_u16(b, 3);
	bb_field(b, "id", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 0, 0, 0, 0);
	bb_field(b, "cnt", EVENTLOG_DECODE_TYPE_U8,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 4, 0, 0, 0);
	bb_field(b, "uri", EVENTLOG_DECODE_TYPE_U8,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 5,
	    EVENTLOG_DECODE_FIELD_VARLEN, 2, vmax);
	bb_event(b, 1, "E", 3, 0, 1, fmt);
}

/* Event ids used by the canonical blob. */
#define	EV_POS		1	/* positional format over struct "s" */
#define	EV_CONV		2	/* printf-style %u/%d/%x over struct "s" */
#define	EV_V6		3	/* char-array + IPv6 over struct "s2" */
#define	EV_SESSION	4	/* no payload; SESSION_CREATE special-case */
#define	EV_LITERAL	5	/* %% and out-of-range positional */
#define	EV_PCTN		6	/* %n must be neutralized */

/*
 * Build the canonical, well-formed provider blob shared by most tests.
 *
 * struct "s" payload layout (20 bytes):
 *   off 0  u32  a
 *   off 4  i32  b
 *   off 8  u32  h   (HEX)
 *   off 12 u8   e   (ENUM "state")
 *   off 13 u8   f   (FLAG "fl")
 *   off 16 in_addr  ip
 * struct "s2" payload layout (20 bytes):
 *   off 0  char[4] name
 *   off 4  in6_addr ip6
 */
static unsigned char *
make_good(size_t *lenp)
{
	struct bb b = { 0 };
	unsigned char *out;

	bb_header(&b, "testp", 2, 1, 1, 2, 6);

	/* keywords */
	bb_str(&b, "RX"); bb_u32(&b, 0x01);
	bb_str(&b, "TX"); bb_u32(&b, 0x02);

	/* enum "state": 0 CLOSED, 1 OPEN */
	bb_str(&b, "state"); bb_u16(&b, 2);
	bb_u32(&b, 0); bb_str(&b, "CLOSED");
	bb_u32(&b, 1); bb_str(&b, "OPEN");

	/* flag "fl": 1 A, 2 B, 4 C */
	bb_str(&b, "fl"); bb_u16(&b, 3);
	bb_u32(&b, 0x1); bb_str(&b, "A");
	bb_u32(&b, 0x2); bb_str(&b, "B");
	bb_u32(&b, 0x4); bb_str(&b, "C");

	/* struct 1: "s" with 6 fields */
	bb_str(&b, "s"); bb_u16(&b, 6);
	bb_field(&b, "a", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 0, 0, 0, 0);
	bb_field(&b, "b", EVENTLOG_DECODE_TYPE_I32,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 4, 0, 0, 0);
	bb_field(&b, "h", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_HEX, 0, 0, 8, 0, 0, 0);
	bb_field(&b, "e", EVENTLOG_DECODE_TYPE_U8,
	    EVENTLOG_DECODE_ANNOT_ENUM, 1, 0, 12, 0, 0, 0);
	bb_field(&b, "f", EVENTLOG_DECODE_TYPE_U8,
	    EVENTLOG_DECODE_ANNOT_FLAG, 1, 0, 13, 0, 0, 0);
	bb_field(&b, "ip", EVENTLOG_DECODE_TYPE_IN_ADDR,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 16, 0, 0, 0);

	/* struct 2: "s2" with 2 fields */
	bb_str(&b, "s2"); bb_u16(&b, 2);
	bb_field(&b, "name", EVENTLOG_DECODE_TYPE_CHAR_ARRAY,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 4, 0, 0, 0, 0);
	bb_field(&b, "ip6", EVENTLOG_DECODE_TYPE_IN6_ADDR,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 4, 0, 0, 0);

	/* events */
	bb_event(&b, EV_POS, "EV", 3, 0, 1, "%1 %2 %3 %4 %5 %6");
	bb_event(&b, EV_CONV, "EVCONV", 3, 0, 1, "u=%u d=%d x=%x");
	bb_event(&b, EV_V6, "EV6", 3, 0, 2, "%1 %2");
	bb_event(&b, EV_SESSION, "SESSION_CREATE", 3, 0, 0, "");
	bb_event(&b, EV_LITERAL, "EVLIT", 3, 0, 1, "lit%% %9 end");
	bb_event(&b, EV_PCTN, "EVN", 3, 0, 1, "A%nB");

	out = b.p;
	*lenp = b.len;
	return (out);	/* caller frees */
}

static void
put_u32le(unsigned char *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* Canonical struct "s" payload (20 bytes), with overridable e/f bytes. */
static void
fill_s_payload(unsigned char pl[20], uint8_t e, uint8_t f)
{
	memset(pl, 0, 20);
	put_u32le(pl + 0, 100);
	put_u32le(pl + 4, (uint32_t)(-5));
	put_u32le(pl + 8, 0xabcd);
	pl[12] = e;
	pl[13] = f;
	pl[16] = 127; pl[17] = 0; pl[18] = 0; pl[19] = 1;	/* 127.0.0.1 */
}

/* ------------------------------------------------------------------ */
/* Parse: well-formed blob.                                           */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(parse_good);
ATF_TC_BODY(parse_good, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp;

	dp = decode_provider_parse(blob, len);
	ATF_REQUIRE_MSG(dp != NULL, "well-formed blob failed to parse");

	ATF_CHECK_STREQ("testp", decode_provider_name(dp));

	ATF_CHECK_STREQ("EV", decode_event_id_to_name(dp, EV_POS));
	ATF_CHECK_STREQ("SESSION_CREATE",
	    decode_event_id_to_name(dp, EV_SESSION));
	ATF_CHECK(decode_event_id_to_name(dp, 9999) == NULL);

	/* Keyword lookup is case-insensitive; unknown -> 0. */
	ATF_CHECK_EQ(0x01, decode_keyword_from_string(dp, "rx"));
	ATF_CHECK_EQ(0x02, decode_keyword_from_string(dp, "TX"));
	ATF_CHECK_EQ(0u, decode_keyword_from_string(dp, "nope"));

	decode_provider_free(dp);
	free(blob);
	/* Freeing NULL is a no-op. */
	decode_provider_free(NULL);
}

ATF_TC_WITHOUT_HEAD(parse_minimal);
ATF_TC_BODY(parse_minimal, tc)
{
	struct bb b = { 0 };
	struct decode_provider *dp;

	/* All counts zero: valid, but nothing to decode. */
	bb_header(&b, "empty", 0, 0, 0, 0, 0);
	dp = decode_provider_parse(b.p, b.len);
	ATF_REQUIRE_MSG(dp != NULL, "empty-but-valid blob failed to parse");
	ATF_CHECK_STREQ("empty", decode_provider_name(dp));
	ATF_CHECK(decode_event_id_to_name(dp, 1) == NULL);
	decode_provider_free(dp);
	bb_free(&b);
}

/* ------------------------------------------------------------------ */
/* Parse: reject malformed headers.                                   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(parse_reject_header);
ATF_TC_BODY(parse_reject_header, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	unsigned char tmp[64];

	/* NULL / too-short inputs. */
	ATF_CHECK(decode_provider_parse(NULL, len) == NULL);
	ATF_CHECK(decode_provider_parse(blob, 0) == NULL);
	ATF_CHECK(decode_provider_parse(blob,
	    EVENTLOG_DECODE_MAGIC_LEN + 1) == NULL);

	/* Bad magic. */
	memcpy(tmp, blob, sizeof(tmp));
	tmp[0] = 'X';
	ATF_CHECK(decode_provider_parse(tmp, sizeof(tmp)) == NULL);

	/* Wrong version. */
	memcpy(tmp, blob, sizeof(tmp));
	tmp[EVENTLOG_DECODE_MAGIC_LEN] =
	    (uint8_t)(EVENTLOG_DECODE_VERSION + 1);
	ATF_CHECK(decode_provider_parse(tmp, sizeof(tmp)) == NULL);

	/* Big-endian producer is rejected (interpreter is LE-only). */
	memcpy(tmp, blob, sizeof(tmp));
	tmp[EVENTLOG_DECODE_MAGIC_LEN + 3] = EVENTLOG_DECODE_ENDIAN_BE;
	ATF_CHECK(decode_provider_parse(tmp, sizeof(tmp)) == NULL);

	free(blob);
}

/*
 * Truncating a valid blob at every length must fail cleanly (NULL, no crash,
 * no read past the buffer - run under ASAN to make the bounds checks bite).
 */
ATF_TC_WITHOUT_HEAD(parse_reject_truncated);
ATF_TC_BODY(parse_reject_truncated, tc)
{
	size_t len, n;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp;

	for (n = 0; n < len; n++) {
		dp = decode_provider_parse(blob, n);
		ATF_CHECK_MSG(dp == NULL,
		    "truncated blob of %zu/%zu bytes parsed", n, len);
		decode_provider_free(dp);
	}
	/* The full blob still parses. */
	dp = decode_provider_parse(blob, len);
	ATF_CHECK(dp != NULL);
	decode_provider_free(dp);
	free(blob);
}

/* ------------------------------------------------------------------ */
/* Parse: reject out-of-range cross-references (validate_provider).   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(parse_reject_bad_enum_index);
ATF_TC_BODY(parse_reject_bad_enum_index, tc)
{
	struct bb b = { 0 };

	/* One struct/field annotated ENUM idx 1, but zero enum tables. */
	bb_header(&b, "p", 0, 0, 0, 1, 0);
	bb_str(&b, "s"); bb_u16(&b, 1);
	bb_field(&b, "x", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_ENUM, 1, 0, 0, 0, 0, 0);
	ATF_CHECK(decode_provider_parse(b.p, b.len) == NULL);
	bb_free(&b);
}

ATF_TC_WITHOUT_HEAD(parse_reject_bad_flag_index);
ATF_TC_BODY(parse_reject_bad_flag_index, tc)
{
	struct bb b = { 0 };

	bb_header(&b, "p", 0, 0, 0, 1, 0);
	bb_str(&b, "s"); bb_u16(&b, 1);
	bb_field(&b, "x", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_FLAG, 1, 0, 0, 0, 0, 0);
	ATF_CHECK(decode_provider_parse(b.p, b.len) == NULL);
	bb_free(&b);
}

ATF_TC_WITHOUT_HEAD(parse_reject_bad_struct_index);
ATF_TC_BODY(parse_reject_bad_struct_index, tc)
{
	struct bb b = { 0 };

	/* Event references struct 2, but only one struct exists. */
	bb_header(&b, "p", 0, 0, 0, 1, 1);
	bb_str(&b, "s"); bb_u16(&b, 0);
	bb_event(&b, 1, "E", 3, 0, 2, "");
	ATF_CHECK(decode_provider_parse(b.p, b.len) == NULL);
	bb_free(&b);
}

ATF_TC_WITHOUT_HEAD(parse_reject_bad_varlen_index);
ATF_TC_BODY(parse_reject_bad_varlen_index, tc)
{
	struct bb b = { 0 };

	/* Varlen field names a count field index past the struct. */
	bb_header(&b, "p", 0, 0, 0, 1, 0);
	bb_str(&b, "s"); bb_u16(&b, 1);
	bb_field(&b, "x", EVENTLOG_DECODE_TYPE_U8,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 0,
	    EVENTLOG_DECODE_FIELD_VARLEN, 9, 4);
	ATF_CHECK(decode_provider_parse(b.p, b.len) == NULL);
	bb_free(&b);
}

/* ------------------------------------------------------------------ */
/* Format: well-formed payloads.                                      */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(format_positional);
ATF_TC_BODY(format_positional, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[256];
	int n;

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);	/* e=OPEN, f=A|B */
	n = decode_format_payload(dp, EV_POS, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK(n > 0);
	ATF_CHECK_STREQ("100 -5 0xabcd OPEN A|B 127.0.0.1", out);

	decode_provider_free(dp);
	free(blob);
}

ATF_TC_WITHOUT_HEAD(format_printf_conv);
ATF_TC_BODY(format_printf_conv, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[256];

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);
	(void)decode_format_payload(dp, EV_CONV, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK_STREQ("u=100 d=-5 x=abcd", out);

	decode_provider_free(dp);
	free(blob);
}

ATF_TC_WITHOUT_HEAD(format_char_and_v6);
ATF_TC_BODY(format_char_and_v6, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[256];

	ATF_REQUIRE(dp != NULL);
	memset(pl, 0, sizeof(pl));
	memcpy(pl, "eth0", 4);
	pl[19] = 1;			/* ::1 */
	(void)decode_format_payload(dp, EV_V6, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK_STREQ("eth0 ::1", out);

	decode_provider_free(dp);
	free(blob);
}

ATF_TC_WITHOUT_HEAD(format_enum_flag_edges);
ATF_TC_BODY(format_enum_flag_edges, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[256];

	ATF_REQUIRE(dp != NULL);

	/* enum miss -> numeric; flag 0 -> "0"; */
	fill_s_payload(pl, 7, 0);
	(void)decode_format_payload(dp, EV_POS, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK_STREQ("100 -5 0xabcd 7 0 127.0.0.1", out);

	/* single known flag bit, then an unknown bit -> numeric fallback. */
	fill_s_payload(pl, 0, 4);	/* e=CLOSED, f=C */
	(void)decode_format_payload(dp, EV_POS, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK_STREQ("100 -5 0xabcd CLOSED C 127.0.0.1", out);

	fill_s_payload(pl, 0, 8);	/* f has no matching bit */
	(void)decode_format_payload(dp, EV_POS, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK_STREQ("100 -5 0xabcd CLOSED 8 127.0.0.1", out);

	decode_provider_free(dp);
	free(blob);
}

ATF_TC_WITHOUT_HEAD(format_session_create_special);
ATF_TC_BODY(format_session_create_special, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	char out[256];

	ATF_REQUIRE(dp != NULL);
	(void)decode_format_payload(dp, EV_SESSION, NULL, 0, out, sizeof(out));
	ATF_CHECK_STREQ("Session created", out);

	decode_provider_free(dp);
	free(blob);
}

ATF_TC_WITHOUT_HEAD(format_unknown_event);
ATF_TC_BODY(format_unknown_event, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	char out[64];

	ATF_REQUIRE(dp != NULL);
	ATF_CHECK_EQ(-1, decode_format_payload(dp, 9999, NULL, 0, out,
	    sizeof(out)));

	decode_provider_free(dp);
	free(blob);
}

ATF_TC_WITHOUT_HEAD(format_literal_and_oob_positional);
ATF_TC_BODY(format_literal_and_oob_positional, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[256];

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);
	/* format "lit%% %9 end": %% -> literal %, %9 -> out of range -> <?> */
	(void)decode_format_payload(dp, EV_LITERAL, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK_STREQ("lit% <?> end", out);

	decode_provider_free(dp);
	free(blob);
}

/* ------------------------------------------------------------------ */
/* Format: payload-bounds hardening.                                  */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(format_short_payload);
ATF_TC_BODY(format_short_payload, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[256];

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);
	/*
	 * Only 6 bytes available: "a" (off 0) fits; everything past it runs
	 * off the end and must render as <?> (numeric/enum/flag) or <invalid>
	 * (address), never read past the buffer.
	 */
	(void)decode_format_payload(dp, EV_POS, pl, 6, out, sizeof(out));
	ATF_CHECK_STREQ("100 <?> <?> <?> <?> <invalid>", out);

	/* Zero-length payload: every field is out of range. */
	(void)decode_format_payload(dp, EV_POS, pl, 0, out, sizeof(out));
	ATF_CHECK_STREQ("<?> <?> <?> <?> <?> <invalid>", out);

	decode_provider_free(dp);
	free(blob);
}

/*
 * decode_format_payload uses snprintf semantics: it never overflows buf, the
 * result stays NUL-terminated, and the return value is the length the output
 * would have had.  Verify with a guarded buffer.
 */
ATF_TC_WITHOUT_HEAD(format_truncation);
ATF_TC_BODY(format_truncation, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char full[256];
	char small[8];
	int n_full, n_small;

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);

	n_full = decode_format_payload(dp, EV_POS, pl, sizeof(pl), full,
	    sizeof(full));

	memset(small, 0x7f, sizeof(small));
	n_small = decode_format_payload(dp, EV_POS, pl, sizeof(pl), small,
	    sizeof(small) - 1);
	/* sentinel byte after the advertised buffer must be untouched. */
	ATF_CHECK_EQ((char)0x7f, small[sizeof(small) - 1]);
	/* NUL-terminated within the buffer. */
	ATF_CHECK(memchr(small, '\0', sizeof(small) - 1) != NULL);
	/* Same intended length regardless of buffer size. */
	ATF_CHECK_EQ(n_full, n_small);
	/* Truncated prefix matches. */
	ATF_CHECK(strncmp(full, small, strlen(small)) == 0);

	decode_provider_free(dp);
	free(blob);
}

/*
 * A %n in a (potentially untrusted) format string must NOT be honored: it is
 * rendered literally.  Before the fix this drove vsnprintf("%lln", ...) with a
 * payload-derived value as the pointer - an arbitrary write.
 */
ATF_TC_WITHOUT_HEAD(format_percent_n_neutralized);
ATF_TC_BODY(format_percent_n_neutralized, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	char out[64];
	int n;

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);
	n = decode_format_payload(dp, EV_PCTN, pl, sizeof(pl), out,
	    sizeof(out));
	ATF_CHECK(n > 0);
	ATF_CHECK_STREQ("A%nB", out);

	decode_provider_free(dp);
	free(blob);
}

/*
 * A hostile format-string width (e.g. "%999999999d") must be clamped rather
 * than hitting vsnprintf(3) with the raw value: an unbounded width lets the
 * decoded output's *intended* length (the snprintf-semantics return value)
 * balloon even though nothing beyond bufsize is ever written, which is
 * itself the CPU-cost concern (vsnprintf still has to compute/pad out to the
 * requested width). Tracks decode.c's EVENTLOG_DECODE_MAX_FIELD_WIDTH (256);
 * update this test if that constant changes.
 */
ATF_TC_WITHOUT_HEAD(format_width_clamped);
ATF_TC_BODY(format_width_clamped, tc)
{
	struct bb b = { 0 };
	struct decode_provider *dp;
	unsigned char pl[4];
	char out[1024];
	int n;

	bb_header(&b, "p", 0, 0, 0, 1, 1);
	bb_str(&b, "s"); bb_u16(&b, 1);
	bb_field(&b, "a", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 0, 0, 0, 0);
	bb_event(&b, 1, "E", 3, 0, 1, "%999999999d");
	dp = decode_provider_parse(b.p, b.len);
	ATF_REQUIRE(dp != NULL);

	put_u32le(pl, 5);
	n = decode_format_payload(dp, 1, pl, sizeof(pl), out, sizeof(out));
	ATF_CHECK_MSG(n == 256, "expected width clamped to 256, got %d", n);
	ATF_CHECK_EQ((size_t)n, strlen(out));

	decode_provider_free(dp);
	bb_free(&b);
}

/*
 * A format string with more %-placeholders than
 * EVENTLOG_DECODE_MAX_FORMAT_FIELDS (256) must stop doing real field lookups
 * beyond the cap and render "<?>" instead, so a hostile blob pairing a huge
 * format string with a huge struct/table can't force unbounded lookup work.
 * Uses positional (%1) placeholders repeated 300 times over a one-field
 * struct so the expected output is fully deterministic.
 */
ATF_TC_WITHOUT_HEAD(format_placeholder_count_clamped);
ATF_TC_BODY(format_placeholder_count_clamped, tc)
{
#define	NPLACEHOLDERS	300
#define	NCLAMPED	256
	struct bb b = { 0 };
	struct decode_provider *dp;
	unsigned char pl[4];
	char fmt[NPLACEHOLDERS * 2 + 1];
	char expected[NPLACEHOLDERS * 4 + 1];
	char out[NPLACEHOLDERS * 4 + 1];
	size_t i, pos;
	int n;

	for (i = 0, pos = 0; i < NPLACEHOLDERS; i++, pos += 2)
		memcpy(fmt + pos, "%1", 2);
	fmt[pos] = '\0';

	bb_header(&b, "p", 0, 0, 0, 1, 1);
	bb_str(&b, "s"); bb_u16(&b, 1);
	bb_field(&b, "a", EVENTLOG_DECODE_TYPE_U32,
	    EVENTLOG_DECODE_ANNOT_NONE, 0, 0, 0, 0, 0, 0);
	bb_event(&b, 1, "E", 3, 0, 1, fmt);
	dp = decode_provider_parse(b.p, b.len);
	ATF_REQUIRE(dp != NULL);

	put_u32le(pl, 100);
	n = decode_format_payload(dp, 1, pl, sizeof(pl), out, sizeof(out));

	for (i = 0, pos = 0; i < NPLACEHOLDERS; i++) {
		const char *piece = (i < NCLAMPED) ? "100" : "<?>";
		size_t plen = strlen(piece);

		memcpy(expected + pos, piece, plen);
		pos += plen;
	}
	expected[pos] = '\0';

	ATF_CHECK_EQ((size_t)n, pos);
	ATF_CHECK_STREQ(expected, out);

	decode_provider_free(dp);
	bb_free(&b);
#undef	NPLACEHOLDERS
#undef	NCLAMPED
}

ATF_TC_WITHOUT_HEAD(format_varlen_u8_positional);
ATF_TC_BODY(format_varlen_u8_positional, tc)
{
	struct bb b = { 0 };
	struct decode_provider *dp;
	unsigned char pl[5 + 16];
	char out[64];

	make_varlen_u8_blob(&b, 2048, "[%1] cnt=%2 %3");
	dp = decode_provider_parse(b.p, b.len);
	ATF_REQUIRE(dp != NULL);

	memset(pl, 0, sizeof(pl));
	put_u32le(pl, 42);
	pl[4] = 5;
	memcpy(pl + 5, "/fast", 5);
	(void)decode_format_payload(dp, 1, pl, 5 + 5, out, sizeof(out));
	ATF_CHECK_STREQ("[42] cnt=5 /fast", out);

	/* cnt=0 with one extra payload byte past the URI offset. */
	pl[4] = 0;
	(void)decode_format_payload(dp, 1, pl, 6, out, sizeof(out));
	ATF_CHECK_STREQ("[42] cnt=0 ", out);

	decode_provider_free(dp);
	bb_free(&b);
}

ATF_TC_WITHOUT_HEAD(format_varlen_u8_clamp_and_short);
ATF_TC_BODY(format_varlen_u8_clamp_and_short, tc)
{
	struct bb b = { 0 };
	struct decode_provider *dp;
	unsigned char pl[5 + 8];
	char out[64];

	make_varlen_u8_blob(&b, 4, "%3");
	dp = decode_provider_parse(b.p, b.len);
	ATF_REQUIRE(dp != NULL);

	memset(pl, 0, sizeof(pl));
	put_u32le(pl, 1);
	pl[4] = 8;
	memset(pl + 5, 'x', 8);
	(void)decode_format_payload(dp, 1, pl, 5 + 8, out, sizeof(out));
	ATF_CHECK_STREQ("xxxx", out);

	/* cnt claims 5 bytes; only 2 remain after the tail offset. */
	pl[4] = 5;
	(void)decode_format_payload(dp, 1, pl, 5 + 2, out, sizeof(out));
	ATF_CHECK_STREQ("xx", out);

	/* Tail offset sits at the end of the payload. */
	(void)decode_format_payload(dp, 1, pl, 5, out, sizeof(out));
	ATF_CHECK_STREQ("<?>", out);

	/* Truncated before the count field. */
	(void)decode_format_payload(dp, 1, pl, 2, out, sizeof(out));
	ATF_CHECK_STREQ("<?>", out);

	decode_provider_free(dp);
	bb_free(&b);
}

/* ------------------------------------------------------------------ */
/* decode_get_field.                                                  */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(get_field);
ATF_TC_BODY(get_field, tc)
{
	size_t len;
	unsigned char *blob = make_good(&len);
	struct decode_provider *dp = decode_provider_parse(blob, len);
	unsigned char pl[20];
	struct decode_value v;

	ATF_REQUIRE(dp != NULL);
	fill_s_payload(pl, 1, 3);

	/* Known scalar field. */
	ATF_REQUIRE(decode_get_field(dp, EV_POS, "a", pl, sizeof(pl), &v));
	ATF_CHECK_EQ(EVENTLOG_DECODE_TYPE_U32, v.type);
	ATF_CHECK_EQ(100u, (uint32_t)v.u);

	/* Signed field is sign-extended. */
	ATF_REQUIRE(decode_get_field(dp, EV_POS, "b", pl, sizeof(pl), &v));
	ATF_CHECK_EQ((int64_t)-5, (int64_t)v.u);

	/* Address field exposes a bounded pointer into the payload. */
	ATF_REQUIRE(decode_get_field(dp, EV_POS, "ip", pl, sizeof(pl), &v));
	ATF_CHECK_EQ(4, v.len);

	/* Unknown event / field -> false. */
	ATF_CHECK(!decode_get_field(dp, 9999, "a", pl, sizeof(pl), &v));
	ATF_CHECK(!decode_get_field(dp, EV_POS, "nope", pl, sizeof(pl), &v));

	/* Field past the (short) payload -> false. */
	ATF_CHECK(!decode_get_field(dp, EV_POS, "ip", pl, 10, &v));

	decode_provider_free(dp);
	free(blob);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, parse_good);
	ATF_TP_ADD_TC(tp, parse_minimal);
	ATF_TP_ADD_TC(tp, parse_reject_header);
	ATF_TP_ADD_TC(tp, parse_reject_truncated);
	ATF_TP_ADD_TC(tp, parse_reject_bad_enum_index);
	ATF_TP_ADD_TC(tp, parse_reject_bad_flag_index);
	ATF_TP_ADD_TC(tp, parse_reject_bad_struct_index);
	ATF_TP_ADD_TC(tp, parse_reject_bad_varlen_index);
	ATF_TP_ADD_TC(tp, format_positional);
	ATF_TP_ADD_TC(tp, format_printf_conv);
	ATF_TP_ADD_TC(tp, format_char_and_v6);
	ATF_TP_ADD_TC(tp, format_enum_flag_edges);
	ATF_TP_ADD_TC(tp, format_session_create_special);
	ATF_TP_ADD_TC(tp, format_unknown_event);
	ATF_TP_ADD_TC(tp, format_literal_and_oob_positional);
	ATF_TP_ADD_TC(tp, format_short_payload);
	ATF_TP_ADD_TC(tp, format_truncation);
	ATF_TP_ADD_TC(tp, format_percent_n_neutralized);
	ATF_TP_ADD_TC(tp, format_width_clamped);
	ATF_TP_ADD_TC(tp, format_placeholder_count_clamped);
	ATF_TP_ADD_TC(tp, format_varlen_u8_positional);
	ATF_TP_ADD_TC(tp, format_varlen_u8_clamp_and_short);
	ATF_TP_ADD_TC(tp, get_field);

	return (atf_no_error());
}
