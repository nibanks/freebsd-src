/*-
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_HISTOGRAM_H_
#define _SYS_HISTOGRAM_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/libkern.h>
#endif

/*
 * Macro to define a histogram structure.
 * Usage: HISTOGRAM_DECLARE(name, 64);
 *        HISTOGRAM_LIN_GENERATE(name);
 *        struct name variable_name;
 *        bzero(&variable_name, sizeof(variable_name));
 *        name##_inc(&variable_name, value);
 *        name##_inc_weighted(&variable_name, value, weight);
 * Note: max_buckets is determined from the struct size in GENERATE macros.
 */
#define HISTOGRAM_DECLARE(name, max_buckets) \
struct name { \
	uint64_t buckets[max_buckets]; \
}

/*
 * Macro to generate linear histogram functions.
 * Usage: HISTOGRAM_LIN_GENERATE(name);
 * Note: max_buckets is determined from sizeof(struct name).
 */
#define HISTOGRAM_LIN_GENERATE(name) \
static inline void name##_inc(struct name *hist_ptr, uint64_t value) { \
	const uint32_t max_buckets = sizeof(hist_ptr->buckets) / sizeof(hist_ptr->buckets[0]); \
	if (__predict_false(value >= max_buckets)) \
		value = max_buckets - 1; \
	hist_ptr->buckets[value]++; \
} \
static inline void name##_inc_weighted(struct name *hist_ptr, uint64_t value, uint64_t weight) { \
	const uint32_t max_buckets = sizeof(hist_ptr->buckets) / sizeof(hist_ptr->buckets[0]); \
	if (__predict_false(value >= max_buckets)) \
		value = max_buckets - 1; \
	hist_ptr->buckets[value] += weight; \
}

/*
 * Macro to generate exponential (log2) histogram functions.
 * Usage: HISTOGRAM_EXP_GENERATE(name);
 * Note: max_buckets is determined from sizeof(struct name).
 */
#define HISTOGRAM_EXP_GENERATE(name) \
static inline void name##_inc(struct name *hist_ptr, uint64_t value) { \
	const uint32_t max_buckets = sizeof(hist_ptr->buckets) / sizeof(hist_ptr->buckets[0]); \
	uint32_t bucket = flsll(value); \
	if (__predict_false(bucket >= max_buckets)) \
		bucket = max_buckets - 1; \
	hist_ptr->buckets[bucket]++; \
} \
static inline void name##_inc_weighted(struct name *hist_ptr, uint64_t value, uint64_t weight) { \
	const uint32_t max_buckets = sizeof(hist_ptr->buckets) / sizeof(hist_ptr->buckets[0]); \
	uint32_t bucket = flsll(value); \
	if (__predict_false(bucket >= max_buckets)) \
		bucket = max_buckets - 1; \
	hist_ptr->buckets[bucket] += weight; \
}

#endif /* _SYS_HISTOGRAM_H_ */
