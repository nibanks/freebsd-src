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

#ifndef _SYS_EVENTLOG_H_
#define _SYS_EVENTLOG_H_

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/eventlog_decode.h>
#ifndef _KERNEL
#include <stdbool.h>		/* bool for the producer callbacks/session_create */
#endif

/* Maximum provider name length */
#define EVENTLOG_PROVIDER_NAME_MAX	32

/* Keyword for session lifecycle events (reserved; provider schemas use KEYWORD SESSION 1) */
#define EVENTLOG_KEYWORD_SESSION	0x80000000

/*
 * Reserved event IDs (all providers). SESSION_CREATE / SESSION_END mark
 * each session's lifetime; DUMP_COMPLETE is synthesised once per
 * (subscriber, provider) at the end of an async dump_state replay,
 * with session_id == EVENTLOG_SESSION_ID_NONE. PROVIDER_INFO / PROVIDER_BLOB
 * announce a late-bound provider's identity (and optional decode blob) into
 * a subscriber's stream at bind time so a capture remains self-describing
 * even when the provider unregisters before the next GET_PROVIDERS poll;
 * elog(1) also synthesises the same records when writing a binary file.
 */
#define EVENTLOG_SESSION_END_ID		((uint32_t)-1)   /* UINT32_MAX */
#define EVENTLOG_SESSION_CREATE_ID	((uint32_t)-2)   /* UINT32_MAX - 1 */
#define EVENTLOG_DUMP_COMPLETE_ID	((uint32_t)-3)   /* UINT32_MAX - 2 */
#define EVENTLOG_PROVIDER_INFO_ID	((uint32_t)-4)   /* UINT32_MAX - 3 */
#define EVENTLOG_PROVIDER_BLOB_ID	((uint32_t)-5)   /* UINT32_MAX - 4 */

/* Sentinel session_id for framework events not tied to a session. */
#define EVENTLOG_SESSION_ID_NONE	((uint64_t)-1)   /* UINT64_MAX */

/* Event log levels */
enum eventlog_level {
	EVENTLOG_LEVEL_NONE,
	EVENTLOG_LEVEL_ERROR,
	EVENTLOG_LEVEL_WARN,
	EVENTLOG_LEVEL_INFO,
	EVENTLOG_LEVEL_VERBOSE,
	EVENTLOG_LEVEL_TRACE
};

/* Event log provider structure */
struct eventlog_provider;

/*
 * Optional provider notification callbacks.  Identical on both runtimes: the
 * kernel invokes them on its dump taskqueue / sysctl paths; libeventlog
 * invokes them on its private control thread.  Semantics (dump-state replay,
 * default-changed values, subscriber transitions) are documented in
 * eventlog(9) and eventlog_user(3).
 */
typedef void (*eventlog_provider_dump_state_t)(
    struct eventlog_provider *provider, void *arg);
typedef void (*eventlog_default_changed_t)(
    struct eventlog_provider *provider, int value, void *arg);
typedef void (*eventlog_subscribers_changed_t)(
    struct eventlog_provider *provider, bool has_subscribers, void *arg);

/*
 * eventlog_provider_config.flags bits.
 *
 * EVENTLOG_PROVIDER_AUTO_RATIO opts the provider name into
 * kern.eventlog.<name>.auto_ratio (1-in-N auto-enable of new sessions when
 * the default isn't already 1); only the first provider registered for a
 * given name matters, same as default_enabled.
 *
 * EVENTLOG_PROVIDER_EXTERNAL_CONTROL (libeventlog) has the caller invoke
 * eventlog_provider_poll (~100ms) so dump/subscribers/default callbacks
 * and session-count reports run on that thread.
 *
 * EVENTLOG_PROVIDER_PER_THREAD_RINGS gives each writing thread its own
 * SPSC submission ring on the process channel (SETUP_RING per thread,
 * default 64 KB).  The first registered provider's bit wins for the
 * process channel.
 */
#define EVENTLOG_PROVIDER_AUTO_RATIO		0x0001
#define EVENTLOG_PROVIDER_EXTERNAL_CONTROL	0x0002
#define EVENTLOG_PROVIDER_PER_THREAD_RINGS	0x0004

/*
 * Optional configuration for eventlog_provider_create().  NULL or a
 * zero-initialised struct yields no callbacks and disabled-by-default
 * sessions.  default_enabled seeds kern.eventlog.<name>.default; an explicit
 * tunable still wins.  decode_blob is an optional flat schema blob (see
 * sys/sys/eventlog_decode.h) that subscribers fetch via
 * EVENTLOG_IOCTL_GET_DECODE_BLOB to decode events at runtime; the kernel keeps
 * the pointer (the generated blob has static storage) while libeventlog copies
 * it to the kernel at registration.  flags is a bitmask of
 * EVENTLOG_PROVIDER_* above.
 */
struct eventlog_provider_config {
	int				default_enabled;
	uint32_t			flags;
	const void		       *decode_blob;
	size_t				decode_blob_size;
	eventlog_provider_dump_state_t	dump_callback;
	void			       *dump_callback_arg;
	eventlog_default_changed_t	default_changed;
	void			       *default_changed_arg;
	eventlog_subscribers_changed_t	subscribers_changed;
	void			       *subscribers_changed_arg;
};

#ifdef _KERNEL
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <vm/uma.h>
#include <sys/mutex.h>
#include <machine/atomic.h>
#else
#include <sys/eventlog_dev.h>	/* enable page + /dev/eventlog wire ABI */
#endif

/*
 * The session handle the generated _ENABLED()/_LOG() macros operate on.  The
 * kernel caches the effective level/keywords inline; libeventlog reads them
 * through ->eff, a pointer into the mmap'd enable page.  The
 * EVENTLOG_SESSION_EFFECTIVE_* accessors below hide the difference; the rest
 * of the object (definition in the runtime) is opaque to the caller.
 */
#ifndef EVENTLOG_INTERNAL
struct eventlog_session {
#ifdef _KERNEL
	enum eventlog_level	effective_level;
	uint32_t		effective_keywords;
#else
	const struct eventlog_enable_page *eff;
#endif
};
#else
struct eventlog_session;	/* Full definition in the runtime */
#endif

#ifndef EVENTLOG_INTERNAL
#ifdef _KERNEL
#define	EVENTLOG_SESSION_EFFECTIVE_LEVEL(__s)		((__s)->effective_level)
#define	EVENTLOG_SESSION_EFFECTIVE_KEYWORDS(__s)	((__s)->effective_keywords)
#else
#define	EVENTLOG_SESSION_EFFECTIVE_LEVEL(__s)		((__s)->eff->effective_level)
#define	EVENTLOG_SESSION_EFFECTIVE_KEYWORDS(__s)	((__s)->eff->effective_keywords)
#endif
#endif

struct iovec;

__BEGIN_DECLS

/*
 * Provider/session lifecycle and event writes.  These are identical for the
 * kernel and libeventlog -- only the runtime behind them differs -- so a
 * provider's setup code compiles for either side with no source changes.
 */

/*
 * Create and register a new eventlog provider.
 * config: Optional; NULL is equivalent to a zero-initialised config.
 */
struct eventlog_provider *eventlog_provider_create(const char *name,
    const struct eventlog_provider_config *config);

/* Unregister and destroy an eventlog provider. */
void eventlog_provider_destroy(struct eventlog_provider *provider);

/*
 * Create a new eventlog session.
 * session_id: Unique identifier (e.g., inp_gencnt for TCP per-connection sessions).
 * waitok: If true, use M_WAITOK for allocations, else M_NOWAIT (kernel only;
 *   ignored by libeventlog).
 * create_payload / create_payload_size: Optional provider-specific
 *   SESSION_CREATE payload; NULL/0 uses the default (no payload).
 *
 * The session's initial enabled state is derived from the provider's
 * default_enabled.  SESSION_CREATE is only emitted when enabled.
 */
struct eventlog_session *eventlog_session_create(struct eventlog_provider *provider,
    uint64_t session_id, bool waitok, void *create_payload,
    size_t create_payload_size);

/* Destroy an eventlog session. */
void eventlog_session_destroy(struct eventlog_session *session);

/*
 * Enable or disable a session.  When disabled the _ENABLED() check fails;
 * when enabled the effective level/keywords are restored from the provider
 * (or a per-session override set with eventlog_session_set_filter).
 */
void eventlog_session_set_enabled(struct eventlog_session *session, int enabled);

/*
 * Set a per-session level/keywords override.  Call
 * eventlog_session_set_enabled(s, true) afterwards to apply.  Level NONE or
 * keywords 0 disables the session.
 */
void eventlog_session_set_filter(struct eventlog_session *session,
    enum eventlog_level level, uint32_t keywords);

/* Write an event to all relevant subscribers. */
void eventlog_event_write(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length);

/*
 * As eventlog_event_write but with a caller-supplied timestamp (microseconds
 * since boot).
 */
void eventlog_event_write_at(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length,
    uint64_t timestamp_us);

/*
 * Scatter/gather variants.  The payload is the concatenation of iovcnt iovec
 * entries (zero-length entries and iovcnt == 0 are legal).
 */
void eventlog_event_write_gather(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt);
void eventlog_event_write_gather_at(struct eventlog_session *session,
    uint32_t id, enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt, uint64_t timestamp_us);

#ifndef _KERNEL
/*
 * With EVENTLOG_PROVIDER_EXTERNAL_CONTROL, drain WAIT_CONTROL (non-blocking)
 * and dispatch dump/subscribers/default callbacks on the calling thread.
 * Also reports session counts about once a second.  Call about every 100ms.
 * Returns the number of control events dispatched, or -1.
 */
int eventlog_provider_poll(struct eventlog_provider *provider);

/*
 * Probe whether the running kernel supports per-thread submission rings
 * (EVENTLOG_PROVIDER_PER_THREAD_RINGS), i.e. a repeatable
 * EVENTLOG_IOCTL_SETUP_RING.  Returns non-zero if supported, 0 if not.
 *
 * A producer that statically links libeventlog and may run on a kernel
 * predating multi-ring support should call this once at startup and only set
 * EVENTLOG_PROVIDER_PER_THREAD_RINGS when it returns non-zero.  (libeventlog
 * also falls back to the shared ring automatically if a per-thread ring
 * setup is rejected, so the probe is an optimization, not a correctness
 * requirement.)
 */
int eventlog_user_per_thread_rings_supported(void);
#endif /* !_KERNEL */

#ifdef _KERNEL
/* Query provider level and keywords (for testing/debugging). */
enum eventlog_level eventlog_provider_get_level(struct eventlog_provider *provider);
uint32_t eventlog_provider_get_keywords(struct eventlog_provider *provider);

/*
 * Return the provider's registered decode blob (or NULL). *sizep is set to the
 * blob size when non-NULL. The framework does not own the storage.
 */
const void *eventlog_provider_get_decode_blob(struct eventlog_provider *provider,
    size_t *sizep);

/*
 * Return a pointer to the provider's schema_id: SHA-256 of its decode blob
 * truncated to EVENTLOG_DECODE_SCHEMA_ID_LEN bytes, or all-zero if the provider
 * registered no decode blob. The storage is owned by the provider.
 */
const uint8_t *eventlog_provider_get_schema_id(
    struct eventlog_provider *provider);

/*
 * Provider lookup matching EVENTLOG_IOCTL_GET_DECODE_BLOB's semantics (see
 * sys/eventlog_subscriber.h), exposed for unit testing without going through
 * /dev/eventlog. lookup_kind is one of EVENTLOG_DECODE_LOOKUP_NAME/
 * _SCHEMA_ID; the other of provider_name/schema_id is ignored. On success
 * (0), *blob_out and *sizep_out are the provider's borrowed blob and its
 * size -- only safe for callers whose blobs are static/immortal, like
 * in-kernel providers; the ioctl handler itself copies under providers_lock
 * instead, since a user-space provider can free its blob on exit. Duplicate
 * provider names (e.g. multiple TCP stacks) resolve to whichever is first
 * on the provider list. Returns ENOENT if no matching provider has a decode
 * blob, EFBIG if its recorded size exceeds EVENTLOG_DECODE_BLOB_MAX, EINVAL
 * for an unknown lookup_kind.
 */
int eventlog_lookup_decode_blob(uint8_t lookup_kind,
    const char *provider_name,
    const uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN],
    const void **blob_out, size_t *sizep_out);

/*
 * Query/set the provider's default_enabled (kern.eventlog.<name>.default).
 * set_default does NOT iterate existing sessions; only affects future session
 * creates.
 */
int eventlog_provider_get_default(struct eventlog_provider *provider);
void eventlog_provider_set_default(struct eventlog_provider *provider, int value);

/*
 * Return the provider's auto-generated kern.eventlog.<name> sysctl node and
 * its context list. Providers may attach children (e.g. kern.eventlog.cpu.hz);
 * the framework owns the storage so children must not outlive the provider.
 */
struct sysctl_oid;
struct sysctl_ctx_list;
struct sysctl_oid *eventlog_provider_get_sysctl_node(struct eventlog_provider *provider);
struct sysctl_ctx_list *eventlog_provider_get_sysctl_ctx(struct eventlog_provider *provider);

/*
 * Returns non-zero if session is enabled, 0 if disabled or NULL. The
 * kernel-native write path always captures its timestamp at write time (see
 * kern_eventlog.c for why callers can't supply their own without
 * reintroducing a per-CPU ordering race); eventlog_event_write_at above
 * remains available for libeventlog producers, which drain into subscriber
 * streams through a different path.
 */
int eventlog_session_is_enabled(struct eventlog_session *session);

/* Test hook: expose internal reentrancy drop/stash counters. */
u_long eventlog_get_reentrant_drops(void);
u_long eventlog_get_reentrant_stashed(void);

/* Test hooks: drain/restore the provider_id pool; see
 * eventlog_test_drain_provider_ids() in kern_eventlog.c. */
u_int eventlog_test_drain_provider_ids(void);
void eventlog_test_release_provider_ids(void);

#endif /* _KERNEL */

__END_DECLS

#endif /* _SYS_EVENTLOG_H_ */
