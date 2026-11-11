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
 * Manual fuzz target for the elog decode-blob interpreter.  It drives a single
 * untrusted byte string through decode_provider_parse() and, on a successful
 * parse, sweeps decode_format_payload()/decode_get_field() so the formatting
 * paths run against attacker-controlled offsets and indices.  This is not
 * wired into the test suite; it is meant to be built and run by hand (or under
 * a coverage-guided fuzzer) when touching decode.c.
 *
 * Run-by-hand (reads one input from stdin):
 *
 *     cc -g -O1 -fsanitize=address,undefined -I${SRCTOP}/sys \
 *         decode_fuzz.c ../decode.c -o decode_fuzz
 *     ./decode_fuzz < some-blob.bin
 *
 * Coverage-guided (libFuzzer, builds the LLVMFuzzerTestOneInput entry point):
 *
 *     cc -g -O1 -DELOG_DECODE_LIBFUZZER \
 *         -fsanitize=fuzzer,address,undefined -I${SRCTOP}/sys \
 *         decode_fuzz.c ../decode.c -o decode_fuzz
 *     ./decode_fuzz corpus/
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../decode.h"

static void
exercise(const unsigned char *data, size_t len)
{
	struct decode_provider *dp;
	char out[4096];
	uint32_t id;

	dp = decode_provider_parse(data, len);
	if (dp == NULL)
		return;

	/*
	 * Sweep a range of event ids, formatting with the same untrusted bytes
	 * as the payload (and an empty payload) to flex offset/length handling
	 * in the formatter and field extractor.
	 */
	for (id = 0; id < 512; id++) {
		struct decode_value v;

		(void)decode_format_payload(dp, id, data, len, out,
		    sizeof(out));
		(void)decode_format_payload(dp, id, NULL, 0, out, sizeof(out));
		(void)decode_event_id_to_name(dp, id);
		(void)decode_get_field(dp, id, "x", data, len, &v);
	}
	(void)decode_provider_name(dp);
	decode_provider_free(dp);
}

#ifdef ELOG_DECODE_LIBFUZZER
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	exercise(data, size);
	return (0);
}
#else
int
main(void)
{
	unsigned char *buf = NULL;
	size_t cap = 0, len = 0;
	size_t n;

	for (;;) {
		if (len == cap) {
			cap = cap ? cap * 2 : 65536;
			buf = realloc(buf, cap);
			if (buf == NULL) {
				perror("realloc");
				return (1);
			}
		}
		n = fread(buf + len, 1, cap - len, stdin);
		len += n;
		if (n == 0)
			break;
	}
	exercise(buf, len);
	free(buf);
	return (0);
}
#endif
