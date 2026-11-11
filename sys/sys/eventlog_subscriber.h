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

#ifndef _SYS_EVENTLOG_SUBSCRIBER_H_
#define _SYS_EVENTLOG_SUBSCRIBER_H_

/*
 * In-kernel subscriber API.  The /dev/eventlog wire ABI consumed by elog(8)
 * and libeventlog lives in <sys/eventlog_dev.h>, included below.
 */
#include <sys/eventlog_dev.h>

#ifdef _KERNEL

#include <sys/conf.h>
#include <sys/uio.h>

/* Forward declarations */
struct eventlog_subscriber;
struct eventlog_subscription;

/* Subscriber type enum */
enum eventlog_subscriber_type {
	EVENTLOG_SUBSCRIBER_TYPE_DEVICE,
	EVENTLOG_SUBSCRIBER_TYPE_CALLBACK
};

/*
 * Create a new device-based subscriber with per-CPU buffers.
 * buffer_size_per_cpu: Size of buffer to allocate per CPU
 *     (EVENTLOG_BUFFER_SIZE_MIN to EVENTLOG_BUFFER_SIZE_MAX).
 * The subscriber is automatically added to the global subscribers list.
 * Returns NULL on failure, subscriber pointer on success.
 */
struct eventlog_subscriber *eventlog_subscriber_create_device(uint32_t buffer_size_per_cpu);

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
 * Replace the keyword mask on an existing subscription to provider_name,
 * leaving its level alone. The retained spec is updated too, so a same-named
 * provider binding later comes up with the new mask. Returns ENOENT if this
 * subscriber has no subscription to that name.
 */
int eventlog_subscriber_set_subscription_keywords(
    struct eventlog_subscriber *subscriber, const char *provider_name,
    uint32_t keywords);

/*
 * Wait for every dump_state task this subscriber has outstanding
 * (queued or running) to finish. Safe to call from any sleepable
 * context.
 */
void eventlog_subscriber_drain_dumps(struct eventlog_subscriber *subscriber);

/*
 * Re-trigger a dump_state replay for every dump-capable provider this
 * subscriber is subscribed to, without adding or changing any
 * subscription. This is what EVENTLOG_IOCTL_TRIGGER_DUMP_STATE
 * dispatches to.
 */
void eventlog_subscriber_trigger_dump_state(struct eventlog_subscriber *subscriber);

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
