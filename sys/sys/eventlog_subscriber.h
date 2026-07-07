/*
 * Copyright (c) 2026 Netflix, Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_EVENTLOG_SUBSCRIBER_H_
#define _SYS_EVENTLOG_SUBSCRIBER_H_

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/eventlog.h>
#include <sys/ioccom.h>

/* Event header structure (naturally aligned, 32 bytes) */
struct eventlog_event_header {
	uint16_t	event_length;	/* Total size including this header */
	uint16_t	cpu;		/* CPU ID */
	uint16_t	provider_id;	/* Provider's unique ID */
	uint16_t	RESERVED;	/* Write to zero, do not read */
	uint64_t	timestamp;	/* Timestamp in microseconds */
	uint64_t	session_id;	/* Session ID */
	uint32_t	event_id;	/* Event ID */
	lwpid_t		thread_id;	/* Thread ID */
};

/* Subscriber type enum */
enum eventlog_subscriber_type {
	EVENTLOG_SUBSCRIBER_TYPE_DEVICE,
	EVENTLOG_SUBSCRIBER_TYPE_CALLBACK
};

/*
 * Per-subscription flags. Unknown bits are rejected with EINVAL by
 * eventlog_subscriber_add_subscription() so new flags can be added
 * later without silent breakage on old kernels.
 *
 * EVENTLOG_SUBSCRIPTION_DUMP_STATE: opt in to a replay of the
 * provider's current state. The framework enqueues an asynchronous
 * dump task for each newly-subscribed provider with a dump_callback;
 * events flow on the normal delivery path. See
 * eventlog_subscriber_drain_dumps() to wait for completion.
 */
#define EVENTLOG_SUBSCRIPTION_DUMP_STATE	0x00000001
#define EVENTLOG_SUBSCRIPTION_FLAGS_VALID	\
	(EVENTLOG_SUBSCRIPTION_DUMP_STATE)

/* Subscription request structure (for ioctl) */
struct eventlog_subscription_req {
	enum eventlog_level level;
	uint32_t keywords;
	uint32_t flags;
	char provider_name[EVENTLOG_PROVIDER_NAME_MAX];
};

/* Per-CPU buffer size limits (30-bit commit_pos in packed_state) */
#define EVENTLOG_BUFFER_SIZE_MIN	(64 * 1024)		/* 64 KB */
#define EVENTLOG_BUFFER_SIZE_MAX	((1 << 30) - 1)		/* ~1 GB */

/* CREATE request: creates subscriber and subscribes to providers */
struct eventlog_create_req {
	uint32_t buffer_size_per_cpu;	/* Buffer size per CPU */
	uint32_t count;			/* Number of subscriptions */
	/* Variable-length array of subscription requests. */
	struct eventlog_subscription_req subscriptions[];
};

/* Stats structure for GET_STATS IOCTL */
struct eventlog_stats {
	uint64_t dropped_events;	/* Events dropped due to buffer full */
};

/*
 * Provider info for GET_PROVIDERS IOCTL - returns subscribed providers with
 * their ids.
 */
#define EVENTLOG_MAX_PROVIDERS	32
struct eventlog_provider_info {
	uint16_t	provider_id;
	char		name[EVENTLOG_PROVIDER_NAME_MAX];
} __packed;
struct eventlog_get_providers_resp {
	uint32_t	count;
	struct eventlog_provider_info providers[EVENTLOG_MAX_PROVIDERS];
} __packed;

/* IOCTL definitions */
#define EVENTLOG_IOC_MAGIC	'E'
#define EVENTLOG_IOCTL_CREATE_BASE \
	_IOW(EVENTLOG_IOC_MAGIC, 1, struct eventlog_create_req)
#define EVENTLOG_IOCTL_DESTROY		_IO(EVENTLOG_IOC_MAGIC, 2)
#define EVENTLOG_IOCTL_GET_STATS \
	_IOR(EVENTLOG_IOC_MAGIC, 3, struct eventlog_stats)
#define EVENTLOG_IOCTL_GET_PROVIDERS \
	_IOR(EVENTLOG_IOC_MAGIC, 4, struct eventlog_get_providers_resp)

#define EVENTLOG_IOCTL_CREATE_SIZE(count) \
	_IOC_NEWLEN(EVENTLOG_IOCTL_CREATE_BASE, \
	    __builtin_offsetof(struct eventlog_create_req, subscriptions) + \
	    (count) * sizeof(struct eventlog_subscription_req))

#ifdef _KERNEL

#include <sys/conf.h>
#include <sys/uio.h>

/* Forward declarations */
struct eventlog_subscriber;
struct eventlog_subscription;

/*
 * Create a new device-based subscriber with per-CPU buffers.
 * buffer_size_per_cpu: Size of buffer to allocate per CPU
 *     (EVENTLOG_BUFFER_SIZE_MIN to EVENTLOG_BUFFER_SIZE_MAX).
 * The subscriber is automatically added to the global subscribers list.
 * Returns NULL on failure, subscriber pointer on success.
 */
struct eventlog_subscriber *eventlog_subscriber_create_device(
    uint32_t buffer_size_per_cpu);

/*
 * Callback function type for callback-based subscribers.
 *
 * The payload is delivered as a scatter/gather iovec; iovcnt == 1 for
 * scalar writes and may be > 1 for variable-length events. Callbacks
 * that need a flat payload compact the iov themselves. The iov and
 * iov[*].iov_base pointers are only valid for the duration of the call.
 *
 * Parameters (in order):
 * - hdr: Event header
 * - provider_name: Provider name string
 * - provider_name_len: Length of provider name (excluding null terminator)
 * - session_id: Session ID (uint64_t, displayed as decimal)
 * - iov, iovcnt: Payload segments. iovcnt == 0 means no payload.
 * - payload_size: Sum of iov[*].iov_len (redundant, provided for ease)
 * - callback_arg: User-provided callback argument
 */
typedef void (*eventlog_callback_t)(const struct eventlog_event_header *hdr,
    const char *provider_name, uint8_t provider_name_len, uint64_t session_id,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg);

/*
 * Create a new callback-based subscriber.
 * callback: Function to call when events arrive.
 * callback_arg: Argument to pass to callback function.
 * The subscriber is automatically added to the global subscribers list.
 * Returns NULL on failure, subscriber pointer on success.
 */
struct eventlog_subscriber *eventlog_subscriber_create_callback(
    eventlog_callback_t callback, void *callback_arg);

/*
 * Destroy a subscriber and update provider enablement.
 * Removes all subscriptions, drains any in-flight dump_state tasks,
 * and frees resources.
 */
void eventlog_subscriber_destroy(struct eventlog_subscriber *subscriber);

/*
 * Add a subscription to a subscriber. flags is a bitmask of
 * EVENTLOG_SUBSCRIPTION_* values; unknown bits return EINVAL. Pass 0
 * for no flags. Returns 0 on success, error code on failure.
 */
int eventlog_subscriber_add_subscription(struct eventlog_subscriber *subscriber,
    const char *provider_name, enum eventlog_level level, uint32_t keywords,
    uint32_t flags);

/*
 * Wait for every dump_state task this subscriber has outstanding
 * (queued or running) to finish. Safe to call from any sleepable
 * context.
 */
void eventlog_subscriber_drain_dumps(struct eventlog_subscriber *subscriber);

/*
 * Read events from a device subscriber's buffer.
 * Handles both user-space (UIO_USERSPACE) and kernel (UIO_SYSSPACE) uio.
 *
 * Parameters:
 * - subscriber: The subscriber to read from
 * - uio: Scatter/gather I/O structure (must have uio_td set for user space)
 * - flags: Read flags (e.g. FNONBLOCK for non-blocking)
 *
 * Returns 0 on success, or an error code on failure.
 */
int eventlog_subscriber_read(struct eventlog_subscriber *subscriber,
    struct uio *uio, int flags);

/*
 * Query subscriber statistics.
 * Fills stats with current values (e.g. dropped_events).
 */
void eventlog_subscriber_get_stats(struct eventlog_subscriber *subscriber,
    struct eventlog_stats *stats);

#endif /* _KERNEL */

#endif /* _SYS_EVENTLOG_SUBSCRIBER_H_ */
