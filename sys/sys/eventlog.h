/*
 * Copyright (c) 2026 Netflix, Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_EVENTLOG_H_
#define _SYS_EVENTLOG_H_

#include <sys/types.h>
#include <sys/cdefs.h>

/* Maximum provider name length */
#define EVENTLOG_PROVIDER_NAME_MAX	32

/*
 * Keyword for session lifecycle events (reserved; provider schemas use
 * KEYWORD SESSION 1).
 */
#define EVENTLOG_KEYWORD_SESSION	0x80000000

/*
 * Reserved event IDs (all providers). SESSION_CREATE / SESSION_END mark
 * each session's lifetime; DUMP_COMPLETE is synthesised once per
 * (subscriber, provider) at the end of an async dump_state replay,
 * with session_id == EVENTLOG_SESSION_ID_NONE.
 */
#define EVENTLOG_SESSION_END_ID		((uint32_t)-1)   /* UINT32_MAX */
#define EVENTLOG_SESSION_CREATE_ID	((uint32_t)-2)   /* UINT32_MAX - 1 */
#define EVENTLOG_DUMP_COMPLETE_ID	((uint32_t)-3)   /* UINT32_MAX - 2 */

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

#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/sysctl.h>
#include <vm/uma.h>
#include <sys/mutex.h>
#include <machine/atomic.h>

/* Event log provider structure */
struct eventlog_provider;

/* Session with exposed level/keywords for _ENABLED checks */
#ifndef EVENTLOG_INTERNAL
struct eventlog_session {
	enum eventlog_level effective_level;	/* Cached for _ENABLED macro */
	uint32_t effective_keywords;		/* Cached for _ENABLED macro */
};
#else
struct eventlog_session;	/* Full definition in kern_eventlog.c */
#endif

/*
 * Optional callback invoked when a subscriber subscribes with
 * EVENTLOG_SUBSCRIPTION_DUMP_STATE. The provider should emit current
 * state for all its sessions using the normal event write APIs; the
 * framework routes those writes to the requesting subscriber only.
 *
 * Runs asynchronously on the eventlog dump taskqueue after the
 * subscribe call has returned. The taskqueue is single-threaded, so
 * concurrent invocations of the same callback never overlap. Callers
 * that need to observe the post-dump state can call
 * eventlog_subscriber_drain_dumps().
 */
typedef void (*eventlog_provider_dump_state_t)(
    struct eventlog_provider *provider, void *arg);

/*
 * Optional callback invoked when the provider's default_enabled sysctl changes.
 * value is the raw sysctl value: 0, 1, -1 (disable all then set 0),
 * or 2 (enable all then set 1).
 * When value is -1 or 2, the framework does NOT iterate sessions for this
 * provider; the callback is responsible for enabling/disabling sessions itself.
 * When value is 0 or 1, this is informational only (default changed).
 */
typedef void (*eventlog_default_changed_t)(
    struct eventlog_provider *provider, int value, void *arg);

/*
 * Optional callback invoked when a provider transitions between "no
 * subscribers" and "at least one subscriber". has_subscribers is the
 * new state. Useful for gating expensive setup that only needs to run
 * while a consumer is listening. May sleep and take other locks; must
 * not re-enter the eventlog framework.
 */
typedef void (*eventlog_subscribers_changed_t)(
    struct eventlog_provider *provider, bool has_subscribers, void *arg);

/*
 * Optional configuration for eventlog_provider_create. NULL or a
 * zero-initialised struct yields no callbacks and disabled-by-default
 * sessions. default_enabled seeds kern.eventlog.<name>.default; an
 * explicit tunable still wins.
 */
struct eventlog_provider_config {
	eventlog_provider_dump_state_t	dump_callback;
	void			       *dump_callback_arg;
	eventlog_default_changed_t	default_changed;
	void			       *default_changed_arg;
	eventlog_subscribers_changed_t	subscribers_changed;
	void			       *subscribers_changed_arg;
	int				default_enabled;
};

/*
 * Create and register a new eventlog provider.
 * config: Optional; NULL is equivalent to a zero-initialised config.
 */
struct eventlog_provider *eventlog_provider_create(const char *name,
    const struct eventlog_provider_config *config);

/*
 * Unregister and destroy an eventlog provider.
 */
void eventlog_provider_destroy(struct eventlog_provider *provider);

/*
 * Query provider level and keywords (for testing/debugging).
 */
enum eventlog_level eventlog_provider_get_level(
    struct eventlog_provider *provider);
uint32_t eventlog_provider_get_keywords(struct eventlog_provider *provider);

/*
 * Query the provider's default_enabled setting (from
 * kern.eventlog.<name>.default). Returns 0 (sessions start disabled) or 1
 * (sessions start enabled).
 */
int eventlog_provider_get_default(struct eventlog_provider *provider);

/*
 * Set the provider's default_enabled value programmatically. This does NOT
 * iterate existing sessions; only affects future session creates.
 */
void eventlog_provider_set_default(struct eventlog_provider *provider,
    int value);

/*
 * Return the provider's auto-generated kern.eventlog.<name> sysctl node and
 * its context list. Providers may attach children (e.g. kern.eventlog.cpu.hz);
 * the framework owns the storage so children must not outlive the provider.
 */
struct sysctl_oid;
struct sysctl_ctx_list;
struct sysctl_oid *eventlog_provider_get_sysctl_node(
    struct eventlog_provider *provider);
struct sysctl_ctx_list *eventlog_provider_get_sysctl_ctx(
    struct eventlog_provider *provider);

/*
 * Create a new eventlog session.
 * session_id: Unique identifier (e.g., inp_gencnt for TCP per-connection
 *   sessions).
 * waitok: If true, use M_WAITOK for allocations; else M_NOWAIT.
 * create_payload: Optional provider-specific payload for SESSION_CREATE. If
 *   NULL, uses default (created_at only). Otherwise must match provider's
 *   SESSION_CREATE struct.
 * create_payload_size: Size of create_payload, or 0 if NULL.
 *
 * The session's initial enabled state is derived from the provider's
 * default_enabled sysctl (kern.eventlog.<name>.default). SESSION_CREATE is
 * only emitted when enabled.
 */
struct eventlog_session *eventlog_session_create(
    struct eventlog_provider *provider, uint64_t session_id, bool waitok,
    void *create_payload, size_t create_payload_size);

/*
 * Destroy an eventlog session.
 */
void eventlog_session_destroy(struct eventlog_session *session);

/*
 * Enable or disable a session. When disabled, effective_level is set to
 * EVENTLOG_LEVEL_NONE so the _ENABLED check fails. When enabled, effective
 * values are restored from provider (or session override).
 */
void eventlog_session_set_enabled(struct eventlog_session *session,
    int enabled);

/*
 * Returns non-zero if session is enabled, 0 if disabled or NULL.
 */
int eventlog_session_is_enabled(struct eventlog_session *session);

/*
 * Set per-session level/keywords override. When set, effective values use
 * this instead of provider. Use eventlog_session_set_enabled(s, true) after
 * to apply. Level NONE or keywords 0 disables the session.
 */
void eventlog_session_set_filter(struct eventlog_session *session,
    enum eventlog_level level, uint32_t keywords);

/*
 * Write an event directly to all relevant subscribers.
 */
void eventlog_event_write(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length);

/*
 * Same as eventlog_event_write but use a pre-computed timestamp (microseconds
 * since boot). Use when the caller already queried time (e.g.
 * session->created_at for SESSION_CREATE).
 */
void eventlog_event_write_at(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length,
    uint64_t timestamp_us);

/*
 * Scatter/gather variants. The payload is the concatenation of iovcnt
 * iovec entries (zero-length entries and iovcnt == 0 legal). Avoids an
 * intermediate copy when the event has a variable-length tail.
 */
struct iovec;
void eventlog_event_write_gather(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt);
void eventlog_event_write_gather_at(struct eventlog_session *session,
    uint32_t id, enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt, uint64_t timestamp_us);

#endif /* _KERNEL */

#endif /* _SYS_EVENTLOG_H_ */
