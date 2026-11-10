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

#ifndef _SYS_EVENTLOG_DECODE_H_
#define _SYS_EVENTLOG_DECODE_H_

/*
 * Eventlog "decode blob" wire format.
 *
 * A decode blob is a flat, self-describing binary image of one provider's
 * schema: enough information to turn a raw event payload into human-readable
 * text without any provider-specific generated C code. Each provider generates
 * its blob at build time (eventlog_gen.awk -h embeds it in the producer header)
 * and registers a pointer to it (no copy) with the framework; consumers such as
 * elog(1) fetch the blob over
 * the EVENTLOG_IOCTL_GET_DECODE_BLOB ioctl (or read it back from a captured
 * .elog file) and interpret it at runtime.
 *
 * Encoding rules (prototype):
 *   - All multi-byte integers are little-endian.
 *   - Strings are stored as a uint16_t length followed by that many bytes,
 *     with no NUL terminator.
 *   - Records appear sequentially in the order documented below; there are no
 *     absolute offsets, so the image is parsed in a single forward pass.
 *   - Field byte offsets within a payload are precomputed by the generator
 *     as a cumulative sum of preceding field sizes, matching the producer's
 *     __packed C struct layout (no alignment padding; described by the
 *     word_size and endianness header bytes; 64-bit little-endian for the
 *     prototype).
 *   - The blob bytes must be reproducible for a given schema build (no
 *     timestamps, paths, pointers, or nondeterministic ordering): a provider's
 *     "schema_id" is the SHA-256 of these bytes truncated to
 *     EVENTLOG_DECODE_SCHEMA_ID_LEN, used as a content-addressed key for decode
 *     and fleet-wide dedup, so identical schemas must hash identically.  The
 *     schema_id is computed by the registrar (see eventlog_provider_create())
 *     and is NOT stored inside the blob itself.
 *
 * Top-level layout:
 *   char     magic[4];        "EDB1"
 *   uint16_t version;         EVENTLOG_DECODE_VERSION
 *   uint8_t  word_size;       producer pointer width in bytes (8 == 64-bit)
 *   uint8_t  endianness;      EVENTLOG_DECODE_ENDIAN_* (0 == little-endian)
 *   uint16_t reserved;        0
 *   string   provider_name;
 *   uint16_t keyword_count;
 *   uint16_t enum_count;
 *   uint16_t flag_count;
 *   uint16_t struct_count;
 *   uint16_t event_count;
 *   keyword[keyword_count]
 *   enum[enum_count]
 *   flag[flag_count]
 *   struct[struct_count]
 *   event[event_count]
 *
 * keyword:  string name; uint32_t value
 * enum:     string name; uint16_t value_count; { uint32_t value; string name }*
 * flag:     string name; uint16_t value_count; { uint32_t value; string name }*
 * struct:   string name; uint16_t field_count; field[field_count]
 * field:    string   name;
 *           uint8_t  type;        EVENTLOG_DECODE_TYPE_*
 *           uint8_t  annotation;  EVENTLOG_DECODE_ANNOT_*
 *           uint16_t annot_index; 1-based enum/flag index, else 0
 *           uint16_t char_len;    array length for TYPE_CHAR_ARRAY, else 0
 *           uint16_t offset;      byte offset of the field within the payload
 *           uint8_t  flags;       EVENTLOG_DECODE_FIELD_* bits
 *           uint16_t varlen_count_index; 1-based field index holding the count
 *           uint16_t varlen_max;  max element count for a varlen tail
 *   event:  uint32_t id;
 *           string   name;
 *           uint8_t  level;       enum eventlog_level
 *           uint32_t keywords;
 *           uint16_t struct_index; 1-based struct index, 0 == no payload (NONE)
 *           string   format;      original positional (%1, %2, ...) format
 */

#define	EVENTLOG_DECODE_MAGIC		"EDB1"
#define	EVENTLOG_DECODE_MAGIC_LEN	4
#define	EVENTLOG_DECODE_VERSION		1

/* Producer word size / endianness descriptor (see top-level layout). */
#define	EVENTLOG_DECODE_ENDIAN_LE	0
#define	EVENTLOG_DECODE_ENDIAN_BE	1

/*
 * Upper bound on a single decode blob, used to bound allocations and copies of
 * blobs that originate outside the trusted build (e.g. read back from a capture
 * file or, in future, registered by a userspace provider).
 */
#define	EVENTLOG_DECODE_BLOB_MAX	(16u * 1024u * 1024u)

/*
 * A provider's schema_id is the SHA-256 of its decode blob, truncated to this
 * many bytes.  It is the durable, content-addressed key for decode (events
 * carry a runtime provider_id that maps to a schema_id; see eventlog(9)).
 */
#define	EVENTLOG_DECODE_SCHEMA_ID_LEN	16

/* Field element type codes. */
#define	EVENTLOG_DECODE_TYPE_U8		1
#define	EVENTLOG_DECODE_TYPE_U16	2
#define	EVENTLOG_DECODE_TYPE_U32	3
#define	EVENTLOG_DECODE_TYPE_U64	4
#define	EVENTLOG_DECODE_TYPE_I8		5
#define	EVENTLOG_DECODE_TYPE_I16	6
#define	EVENTLOG_DECODE_TYPE_I32	7
#define	EVENTLOG_DECODE_TYPE_I64	8
#define	EVENTLOG_DECODE_TYPE_PTR	9	/* void *, displayed as %p */
#define	EVENTLOG_DECODE_TYPE_IN_ADDR	10	/* in_addr_t / struct in_addr */
#define	EVENTLOG_DECODE_TYPE_IN6_ADDR	11	/* in6_addr_t / struct in6_addr */
#define	EVENTLOG_DECODE_TYPE_CHAR_ARRAY	12	/* char[char_len], shown as %s */

/* Field display annotations. */
#define	EVENTLOG_DECODE_ANNOT_NONE	0
#define	EVENTLOG_DECODE_ANNOT_HEX	1
#define	EVENTLOG_DECODE_ANNOT_NTOHS	2
#define	EVENTLOG_DECODE_ANNOT_ENUM	3	/* annot_index -> enum table */
#define	EVENTLOG_DECODE_ANNOT_FLAG	4	/* annot_index -> flag table */

/* Field flag bits. */
#define	EVENTLOG_DECODE_FIELD_VARLEN	0x01	/* trailing variable-length array */

#endif /* _SYS_EVENTLOG_DECODE_H_ */
