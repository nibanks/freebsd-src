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

#ifndef _ELOG_DECODE_H_
#define _ELOG_DECODE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Runtime interpreter for eventlog decode blobs (see
 * sys/sys/eventlog_decode.h).  A decode_provider is the parsed, in-memory
 * form of one provider's blob; it replaces the per-provider C decoders that
 * elog used to compile in.
 */
struct decode_provider;

/*
 * Parse a decode blob into a decode_provider.  The blob bytes are copied, so
 * the caller may free the input afterwards.  Returns NULL on malformed input.
 */
struct decode_provider *decode_provider_parse(const unsigned char *blob,
    size_t len);
void decode_provider_free(struct decode_provider *dp);

/* The provider name recorded in the blob. */
const char *decode_provider_name(const struct decode_provider *dp);

/*
 * Format an event payload into buf as human-readable text.  Returns the
 * number of characters that would have been written (snprintf semantics), or
 * -1 if the event id is unknown to this provider.
 */
int decode_format_payload(const struct decode_provider *dp, uint32_t event_id,
    const void *payload, size_t payload_size, char *buf, size_t bufsize);

/* Map an event id to its name, or NULL if unknown. */
const char *decode_event_id_to_name(const struct decode_provider *dp,
    uint32_t event_id);

/* Resolve a keyword name (case-insensitive) to its bitmask, or 0 if unknown. */
uint32_t decode_keyword_from_string(const struct decode_provider *dp,
    const char *name);

/*
 * A single decoded field value.  For integer/pointer fields, "u" holds the
 * raw little-endian value (sign-extended for signed types); for address and
 * char-array fields, "ptr"/"len" point into the supplied payload.
 */
struct decode_value {
	int		type;		/* EVENTLOG_DECODE_TYPE_* */
	int		annotation;	/* EVENTLOG_DECODE_ANNOT_* */
	uint64_t	u;
	const void     *ptr;
	uint16_t	len;
};

/*
 * Extract a named field from an event payload.  Returns false if the event or
 * field is unknown, or the field lies outside the payload.
 */
bool decode_get_field(const struct decode_provider *dp, uint32_t event_id,
    const char *field_name, const void *payload, size_t payload_size,
    struct decode_value *out);

#endif /* _ELOG_DECODE_H_ */
