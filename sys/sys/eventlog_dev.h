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

#ifndef _SYS_EVENTLOG_DEV_H_
#define _SYS_EVENTLOG_DEV_H_

/*
 * /dev/eventlog wire ABI: ioctl numbers, request/response structs, the
 * user-space producer submission ring, control channel, and shared
 * enablement page.  This is the low-level kernel<->user contract and is not
 * meant to be included directly: producers use libeventlog via
 * <sys/eventlog.h>, consumers use elog(8).  See eventlog(9) and
 * eventlog_user(3).
 */

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/eventlog.h>
#include <sys/ioccom.h>

/* Event header structure (naturally aligned, 32 bytes) */
struct eventlog_event_header {
	uint16_t	event_length;	/* Total size of event including this header */
	uint16_t	cpu;		/* CPU ID */
	uint16_t	provider_id;	/* Provider's unique ID */
	uint16_t	RESERVED;	/* Write to zero, do not read */
	uint64_t	timestamp;	/* Timestamp in microseconds */
	uint64_t	session_id;	/* Session ID */
	uint32_t	event_id;	/* Event ID */
	lwpid_t		thread_id;	/* Thread ID */
};

/* Per-subscription flags; unknown bits return EINVAL.  See eventlog(9). */
#define EVENTLOG_SUBSCRIPTION_DUMP_STATE	0x00000001
#define EVENTLOG_SUBSCRIPTION_FLAGS_VALID	\
	(EVENTLOG_SUBSCRIPTION_DUMP_STATE)

/* Subscription request structure (for CREATE). */
struct eventlog_subscription_req {
	enum eventlog_level level;
	uint32_t keywords;
	uint32_t flags;
	char provider_name[EVENTLOG_PROVIDER_NAME_MAX];
};

/*
 * Per-CPU ring buffer size limits.  The kernel rounds the requested size
 * up to a power of two (ring cursors are masked), so the allocated ring
 * may be larger than requested, up to 1 GB.
 */
#define EVENTLOG_BUFFER_SIZE_MIN	(64 * 1024)		/* 64 KB */
#define EVENTLOG_BUFFER_SIZE_MAX	(1 << 30)		/* 1 GB */

/* CREATE request: creates subscriber and subscribes to providers */
struct eventlog_create_req {
	uint32_t buffer_size_per_cpu;	/* Buffer size per CPU */
	uint32_t count;			/* Number of subscriptions */
	struct eventlog_subscription_req subscriptions[];	/* Variable length array */
};

/* Stats structure for GET_STATS IOCTL */
struct eventlog_stats {
	uint64_t dropped_events;	/* Events dropped due to buffer full */
	uint64_t user_dropped_full;	/* User events dropped: stream buffer full */
	uint64_t user_dropped_prejoin;	/* User events dropped: older than join point */
	uint64_t user_dropped_late;	/* User events dropped: past the lateness ceiling */
};

/*
 * User-space provider registration (EVENTLOG_IOCTL_REGISTER_PROVIDER).  A
 * single fd may register many providers (records carry provider_id); the
 * kernel assigns provider_id and the enable_offset of this provider's slot in
 * the mmap'd enable page.  See eventlog_user(3).
 */
struct eventlog_provider_reg_req {
	char		name[EVENTLOG_PROVIDER_NAME_MAX];
	int		default_enabled;	/* Seed kern.eventlog.<name>.default */
	uint32_t	flags;			/* Reserved; write zero */
	uint64_t	expected_cadence_us;	/* Hint: max interval between pushes
						 * (0 => use the global ceiling) */
	uint64_t	decode_blob;		/* IN: user address of the schema
						 * decode blob, or 0 for none.
						 * The kernel copies it in and
						 * owns the copy (see
						 * sys/sys/eventlog_decode.h). */
	uint32_t	decode_blob_size;	/* IN: decode blob length in bytes
						 * (0 => no blob) */
	uint16_t	provider_id;		/* OUT: kernel-assigned id */
	uint16_t	enable_offset;		/* OUT: byte offset of this
						 * provider's enable slot in the
						 * mmap'd page */
	uint32_t	RESERVED;		/* Write to zero */
};

/*
 * One submitted event (shared ring or EVENTLOG_IOCTL_PUSH_DUMP), followed by
 * payload_len payload bytes.  Timestamps are microseconds on CLOCK_UPTIME and
 * must be non-decreasing within a stream.  level/keywords are used only for
 * per-subscriber filtering and are not stored in the wire header.
 */
struct eventlog_push_record {
	uint64_t	timestamp_us;
	uint64_t	session_id;
	uint32_t	event_id;
	uint32_t	keywords;
	int32_t		thread_id;
	uint16_t	payload_len;
	uint16_t	provider_id;	/* Registered provider that emitted this */
	uint8_t		level;		/* enum eventlog_level */
	uint8_t		RESERVED1;	/* Write to zero */
	uint16_t	cpu;		/* Producer's CPU at emit time */
	uint8_t		RESERVED[4];	/* Write to zero */
};

/*
 * Shared submission ring (EVENTLOG_IOCTL_SETUP_RING), mapped at
 * EVENTLOG_RING_MMAP_OFFSET + n * EVENTLOG_RING_MMAP_STRIDE.  SETUP_RING may
 * be called more than once per fd; each call allocates another ring up to
 * EVENTLOG_USER_RINGS_MAX.  The kernel writes a unique stream_id into the
 * header (0, then 2, 3, …; 1 is EVENTLOG_DUMP_STREAM_ID).  head/tail are
 * free-running 64-bit byte offsets into a power-of-two data region (slot for
 * offset o is data[o & (data_size - 1)]); a record may straddle the wrap.
 * head/watermark_us/dropped are producer-owned, tail/flags kernel-owned, on
 * separate cache lines.  See eventlog_user(3).
 */
/*
 * Ring header version.  Bump when the kernel-visible ring ABI changes in a
 * way a producer can detect from the header.  Version 3 is the first to
 * support more than one submission ring per provider fd (repeatable
 * EVENTLOG_IOCTL_SETUP_RING); version 2 fds are limited to a single ring
 * (a second SETUP_RING fails with EEXIST).  A producer can read the version
 * from the first ring's header to learn which model it is on.
 */
#define	EVENTLOG_RING_VERSION		3
#define	EVENTLOG_RING_VERSION_MULTI	3	/* first multi-ring version */
#define	EVENTLOG_RING_CACHELINE		64
#define	EVENTLOG_RING_SIZE_MIN		(64U * 1024)		/* 64 KB */
#define	EVENTLOG_RING_SIZE_MAX		(64U * 1024 * 1024)	/* 64 MB */
#define	EVENTLOG_RING_SIZE_DEFAULT	(1U * 1024 * 1024)	/* 1 MB */

/* mmap() offset of the first submission ring (enable page is offset 0). */
#define	EVENTLOG_RING_MMAP_OFFSET	0x10000
/*
 * Spacing between rings' mmap offsets.  Sized at 2*MAX so a max-sized ring
 * (header + data, page-rounded) cannot overlap the next slot.
 */
#define	EVENTLOG_RING_MMAP_STRIDE	((uint64_t)EVENTLOG_RING_SIZE_MAX * 2)
#define	EVENTLOG_USER_RINGS_MAX		256

/* stream_id 1 is EVENTLOG_DUMP_STREAM_ID; live rings use 0, then 2, 3, … */
#define	EVENTLOG_LIVE_STREAM_ID		0
#define	EVENTLOG_DUMP_STREAM_ID		1

/*
 * Kernel-published hint bits in eventlog_ring_hdr.flags (read-only to the
 * producer, plain acquire load, no syscall).  They tell libeventlog when an
 * EVENTLOG_IOCTL_KICK is worthwhile so the steady state stays zero-syscall.
 */
#define	EVENTLOG_RING_F_NEED_WAKEUP	0x1	/* A reader is blocked on this ring */
#define	EVENTLOG_RING_F_CONSUMER_PRESENT 0x2	/* >=1 subscriber consumes this ring */

/* Producer kicks when ring fill reaches capacity >> this shift (half full). */
#define	EVENTLOG_RING_KICK_HIWATER_SHIFT 1

struct eventlog_ring_hdr {
	uint32_t	version;	/* EVENTLOG_RING_VERSION */
	uint32_t	data_size;	/* power-of-two byte capacity of data[] */
	uint32_t	data_offset;	/* byte offset of data[] from this header */
	uint32_t	RESERVED0;	/* Write to zero */

	/* Producer-owned cache line (written by the user process). */
	volatile uint64_t __aligned(EVENTLOG_RING_CACHELINE) head;
	volatile uint64_t watermark_us;
	volatile uint64_t dropped;	/* records dropped: ring full */
	uint16_t	stream_id;
	uint16_t	RESERVED1;	/* Write to zero */
	uint32_t	RESERVED2;	/* Write to zero */

	/* Kernel-owned cache line. */
	volatile uint64_t __aligned(EVENTLOG_RING_CACHELINE) tail;
	volatile uint32_t flags;	/* EVENTLOG_RING_F_* wakeup hints */
	uint32_t	RESERVED3;	/* Write to zero */
};

/*
 * EVENTLOG_IOCTL_SETUP_RING: allocate one submission ring on the provider
 * fd.  May be called repeatedly (up to EVENTLOG_USER_RINGS_MAX); ENOSPC when
 * the fd is full.  size is rounded to a power of two and clamped to
 * [MIN, MAX]; 0 selects DEFAULT.  mmap_offset/mmap_size (OUT) describe the
 * region to mmap.  stream_id is in the mapped header.
 */
struct eventlog_ring_setup_req {
	uint32_t	size;		/* IN: requested data bytes; OUT: granted */
	uint32_t	flags;		/* Reserved; write zero */
	uint64_t	mmap_offset;	/* OUT: offset to pass to mmap() */
	uint64_t	mmap_size;	/* OUT: total bytes to mmap */
};

/*
 * Control channel (kernel -> user-space provider).  A provider's background
 * thread blocks in EVENTLOG_IOCTL_WAIT_CONTROL to receive dump-state,
 * subscriber-transition, and default-changed events that the passive enable
 * gate cannot express.  See eventlog_user(3).
 */
#define	EVENTLOG_CONTROL_NONE			0
#define	EVENTLOG_CONTROL_DUMP_REQUEST		1 /* replay state for subscriber_id */
#define	EVENTLOG_CONTROL_SUBSCRIBERS_CHANGED	2 /* value = has_subscribers */
#define	EVENTLOG_CONTROL_DEFAULT_CHANGED		3 /* value = raw sysctl value */

struct eventlog_control_event {
	uint16_t	type;		/* EVENTLOG_CONTROL_* */
	uint16_t	provider_id;	/* Provider this event concerns */
	int32_t		value;		/* Per-type scalar (see above) */
	uint64_t	subscriber_id;	/* DUMP_REQUEST: dump target; else 0 */
};

/*
 * EVENTLOG_IOCTL_WAIT_CONTROL: block up to timeout_us for control events.
 * count is IN capacity / OUT events returned (0 on timeout); size the buffer
 * with EVENTLOG_IOCTL_WAIT_CONTROL_SIZE(capacity).
 */
struct eventlog_wait_control_req {
	uint64_t	timeout_us;	/* IN: max blocking time (0 = poll) */
	uint32_t	count;		/* IN: capacity; OUT: events returned */
	uint32_t	RESERVED;	/* Write to zero */
	struct eventlog_control_event events[];
};

/*
 * EVENTLOG_IOCTL_PUSH_DUMP: the same packed eventlog_push_record stream as the
 * ring, routed only to subscriber_id.  Used by a provider's dump_callback.
 */
struct eventlog_push_dump_req {
	uint64_t	subscriber_id;	/* IN: dump target (from DUMP_REQUEST) */
	uint16_t	stream_id;
	uint16_t	flags;		/* Reserved; write zero */
	uint32_t	count;		/* Number of records */
	uint64_t	watermark_us;	/* Stream watermark */
	uint32_t	bytes;		/* Total size of packed records + payloads */
	uint32_t	RESERVED;	/* Write to zero */
	uint8_t		data[];		/* Packed eventlog_push_record entries */
};

/*
 * EVENTLOG_IOCTL_DUMP_DONE: the provider finished replaying state for a
 * DUMP_REQUEST; the kernel synthesises DUMP_COMPLETE and releases the dump.
 */
struct eventlog_dump_done_req {
	uint64_t	subscriber_id;	/* Target from the DUMP_REQUEST */
	uint16_t	provider_id;	/* Provider that was dumped */
	uint16_t	RESERVED16;	/* Write to zero */
	uint32_t	RESERVED;	/* Write to zero */
};

/*
 * GET_PROVIDERS response (variable length).  count is IN capacity / OUT total
 * available; the kernel writes min(capacity, total) entries.  count > capacity
 * signals truncation: retry larger.  Size with
 * EVENTLOG_IOCTL_GET_PROVIDERS_SIZE(capacity).
 *
 * The ioctl length rides the 13-bit IOCPARM_LEN field, so capacity is capped
 * at roughly 163 providers.  Prefer EVENTLOG_IOCTL_GET_PROVIDERS2 (pointer-
 * based, unlimited) for new code; this form is kept for older consumers.
 */
struct eventlog_provider_info {
	uint16_t	provider_id;
	char		name[EVENTLOG_PROVIDER_NAME_MAX];
	/* SHA-256(decode blob) truncated; all-zero if no decode blob. */
	uint8_t		schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
} __packed;
struct eventlog_get_providers_resp {
	uint32_t	count;		/* IN: capacity; OUT: total available */
	uint32_t	RESERVED;	/* Write to zero */
	struct eventlog_provider_info providers[];	/* min(capacity, total) */
};

/*
 * GET_PROVIDERS2: pointer-based provider list (no IOCPARM_LEN cap).
 * Two-call size probe, same pattern as GET_DECODE_BLOB: issue with buf == 0
 * (or buf_size == 0) to learn count, allocate count * sizeof(provider_info),
 * reissue.  ENOSPC if the buffer is too small for the current total; the
 * kernel still reports count so the caller can grow and retry.
 */
struct eventlog_get_providers2_req {
	uint64_t	buf;		/* IN: user buffer for provider_info[] */
	uint32_t	buf_size;	/* IN: buffer capacity in bytes */
	uint32_t	count;		/* OUT: total subscribed providers */
};

/*
 * EVENTLOG_IOCTL_REPORT_STATS: a producer periodically reports its
 * per-provider session counts so the kernel can publish them under
 * kern.eventlog.<provider>.* (user sessions are invisible to the kernel
 * otherwise).
 */
struct eventlog_provider_stat {
	uint16_t	provider_id;		/* registered on this fd */
	uint16_t	RESERVED;		/* Write to zero */
	uint32_t	RESERVED2;		/* Write to zero */
	uint64_t	sessions_created;	/* cumulative opened (monotonic) */
	uint64_t	sessions_active;	/* currently live */
	uint64_t	sessions_enabled;	/* live while enabled, else 0 */
};
struct eventlog_report_stats_req {
	uint32_t	count;			/* number of reports that follow */
	uint32_t	RESERVED;		/* Write to zero */
	struct eventlog_provider_stat stats[];
};

/*
 * Wire-ABI pins: libeventlog is statically linked into producers (ELLA), so
 * a field inserted or resized above must break the build, not silently shift
 * offsets for an old producer talking to a new kernel.
 */
_Static_assert(sizeof(struct eventlog_provider_stat) == 32,
    "eventlog_provider_stat wire ABI changed");
_Static_assert(__builtin_offsetof(struct eventlog_provider_stat,
    sessions_enabled) == 24, "eventlog_provider_stat wire ABI changed");
_Static_assert(__builtin_offsetof(struct eventlog_report_stats_req,
    stats) == 8, "eventlog_report_stats_req wire ABI changed");

/* GET_DECODE_BLOB lookup_kind values. */
#define EVENTLOG_DECODE_LOOKUP_NAME	0	/* match on provider_name */
#define EVENTLOG_DECODE_LOOKUP_SCHEMA_ID 1	/* match on schema_id */

/*
 * GET_DECODE_BLOB request: fetch a provider's decode blob (see
 * sys/sys/eventlog_decode.h) without an active subscription.  Two-call size
 * probe: issue with buf == 0 to learn blob_size, then allocate and reissue.
 * lookup_kind selects the match key (provider_name or content-addressed
 * schema_id).
 */
struct eventlog_get_decode_blob_req {
	char		provider_name[EVENTLOG_PROVIDER_NAME_MAX]; /* in */
	uint8_t		schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];  /* in */
	uint8_t		lookup_kind;	/* in: EVENTLOG_DECODE_LOOKUP_* */
	uint64_t	buf;		/* in: user buffer address */
	uint32_t	buf_size;	/* in: buffer capacity in bytes */
	uint32_t	blob_size;	/* out: actual blob size in bytes */
};

/*
 * SET_SUBSCRIPTION_KEYWORDS request: replace the keyword mask on this
 * subscriber fd's existing subscription to provider_name.  Used to narrow a
 * subscription made by keyword name, whose names only become resolvable when
 * the provider publishes its decode blob.
 */
struct eventlog_set_subscription_keywords_req {
	char		provider_name[EVENTLOG_PROVIDER_NAME_MAX];
	uint32_t	keywords;
};

/* IOCTL definitions */
#define EVENTLOG_IOC_MAGIC	'E'
#define EVENTLOG_IOCTL_CREATE_BASE	_IOW(EVENTLOG_IOC_MAGIC, 1, struct eventlog_create_req)
#define EVENTLOG_IOCTL_DESTROY		_IO(EVENTLOG_IOC_MAGIC, 2)
#define EVENTLOG_IOCTL_GET_STATS		_IOR(EVENTLOG_IOC_MAGIC, 3, struct eventlog_stats)
#define EVENTLOG_IOCTL_GET_PROVIDERS_BASE	_IOWR(EVENTLOG_IOC_MAGIC, 4, struct eventlog_get_providers_resp)
#define EVENTLOG_IOCTL_REGISTER_PROVIDER	_IOWR(EVENTLOG_IOC_MAGIC, 5, struct eventlog_provider_reg_req)
#define EVENTLOG_IOCTL_GET_DECODE_BLOB		_IOWR(EVENTLOG_IOC_MAGIC, 6, struct eventlog_get_decode_blob_req)
#define EVENTLOG_IOCTL_WAIT_CONTROL_BASE	_IOWR(EVENTLOG_IOC_MAGIC, 7, struct eventlog_wait_control_req)
#define EVENTLOG_IOCTL_PUSH_DUMP_BASE		_IOW(EVENTLOG_IOC_MAGIC, 8, struct eventlog_push_dump_req)
#define EVENTLOG_IOCTL_DUMP_DONE			_IOW(EVENTLOG_IOC_MAGIC, 9, struct eventlog_dump_done_req)
#define EVENTLOG_IOCTL_SETUP_RING		_IOWR(EVENTLOG_IOC_MAGIC, 10, struct eventlog_ring_setup_req)
#define EVENTLOG_IOCTL_REPORT_STATS_BASE	_IOW(EVENTLOG_IOC_MAGIC, 11, struct eventlog_report_stats_req)
/*
 * EVENTLOG_IOCTL_KICK: drain this provider's submission ring now and wake any
 * blocked subscriber reader.  No payload; libeventlog issues it only when the
 * ring's kernel-published flags warrant it (see EVENTLOG_RING_F_*).
 */
#define EVENTLOG_IOCTL_KICK		_IO(EVENTLOG_IOC_MAGIC, 12)
/*
 * EVENTLOG_IOCTL_TRIGGER_DUMP_STATE: re-trigger a dump_state replay for every
 * dump-capable provider this subscriber fd is already subscribed to, without
 * adding or changing any subscription. No payload.
 */
#define EVENTLOG_IOCTL_TRIGGER_DUMP_STATE	_IO(EVENTLOG_IOC_MAGIC, 13)
#define EVENTLOG_IOCTL_SET_SUBSCRIPTION_KEYWORDS \
	_IOW(EVENTLOG_IOC_MAGIC, 14, struct eventlog_set_subscription_keywords_req)
/*
 * EVENTLOG_IOCTL_GET_PROVIDERS2: pointer-based provider list (see
 * struct eventlog_get_providers2_req). Unlimited count; preferred over
 * EVENTLOG_IOCTL_GET_PROVIDERS for new consumers.
 */
#define EVENTLOG_IOCTL_GET_PROVIDERS2 \
	_IOWR(EVENTLOG_IOC_MAGIC, 15, struct eventlog_get_providers2_req)

#define EVENTLOG_IOCTL_CREATE_SIZE(count) \
	_IOC_NEWLEN(EVENTLOG_IOCTL_CREATE_BASE, \
	    __builtin_offsetof(struct eventlog_create_req, subscriptions) + \
	    (count) * sizeof(struct eventlog_subscription_req))

#define EVENTLOG_IOCTL_GET_PROVIDERS_SIZE(count) \
	_IOC_NEWLEN(EVENTLOG_IOCTL_GET_PROVIDERS_BASE, \
	    __builtin_offsetof(struct eventlog_get_providers_resp, providers) + \
	    (count) * sizeof(struct eventlog_provider_info))

#define EVENTLOG_IOCTL_WAIT_CONTROL_SIZE(count) \
	_IOC_NEWLEN(EVENTLOG_IOCTL_WAIT_CONTROL_BASE, \
	    __builtin_offsetof(struct eventlog_wait_control_req, events) + \
	    (count) * sizeof(struct eventlog_control_event))

#define EVENTLOG_IOCTL_PUSH_DUMP_SIZE(bytes) \
	_IOC_NEWLEN(EVENTLOG_IOCTL_PUSH_DUMP_BASE, \
	    __builtin_offsetof(struct eventlog_push_dump_req, data) + (bytes))

#define EVENTLOG_IOCTL_REPORT_STATS_SIZE(count) \
	_IOC_NEWLEN(EVENTLOG_IOCTL_REPORT_STATS_BASE, \
	    __builtin_offsetof(struct eventlog_report_stats_req, stats) + \
	    (count) * sizeof(struct eventlog_provider_stat))

/*
 * Shared enablement page (mmap'd at offset 0): an array of 16-byte slots, one
 * per provider registered on the fd.  The kernel publishes a provider's
 * aggregated subscriber interest into its slot; the generated _ENABLED() macro
 * reads it with no system call.  generation is bumped on every update.
 */
struct eventlog_enable_page {
	volatile uint32_t	effective_level;	/* enum eventlog_level */
	volatile uint32_t	effective_keywords;
	volatile uint32_t	generation;
	uint32_t		RESERVED;		/* Write to zero */
};

#endif /* _SYS_EVENTLOG_DEV_H_ */
