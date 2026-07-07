/*
 * Copyright (c) 2026 Netflix, Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * MEMORY ACCESS AND SYNCHRONIZATION MODEL
 * =======================================
 * Per-CPU double-buffering: Two buffers per CPU. Writers use "active" buffer;
 * readers use "reader" buffer (1 - active). Swap when reader is empty and
 * active has data.
 *
 * Invariant: There is NEVER partial data in either buffer. Each buffer
 * contains zero or more complete events (header + payload).
 *
 * Per-CPU writer concurrency: All write paths enter via smr_enter() which
 * calls critical_enter(), disabling thread preemption.  Thread-level
 * writer-vs-writer contention is therefore impossible.  Hardware NMIs are
 * NOT blocked by critical sections, however, so an NMI-context writer can
 * nest inside an in-progress thread-level writer on the same CPU.  The
 * protocol tolerates this: every state-changing step (try_swap, commit-CAS)
 * re-derives active and commit_pos from the post-CAS state and re-checks
 * capacity, so an NMI's intervening commit (with or without a buffer swap)
 * is preserved.
 *
 * Packed state: reader_len (30 bits), commit_pos (30 bits), active_buf, and
 * swap_allowed are packed into a single 64-bit word (packed_state).  A
 * single CAS atomically publishes any state transition (writer commit,
 * buffer swap, reader drain).
 *
 * Writer:
 *   (1) Load packed_state to get commit_pos and active_buf.
 *   (2) Check capacity: if commit_pos + event_len > buffer_size, attempt a
 *       proactive swap if swap_allowed.  After try_swap, re-derive active
 *       and commit_pos from the post-CAS state and re-check capacity (an
 *       NMI on this CPU may have already swapped or partially filled the
 *       new active buffer).  Drops only if swap is not allowed (reader
 *       still draining) or no room remains after the swap.
 *   (3) Write: memcpy event data to buffer at commit_pos offset.
 *   (4) Commit: CAS packed_state to advance commit_pos.  On CAS failure,
 *       re-derive active and commit_pos from the updated state.  If either
 *       changed (peer reader swap, NMI commit, or NMI swap-and-commit),
 *       redo the write at the new offset; otherwise just recompute the
 *       desired packed_state value and retry the CAS.
 *
 * Reader: Single reader only. Reads from reader buffer. No lock needed for
 * reads. Advances read_pos by full event lengths. When fully drained, zeros
 * read_pos/reader_len then eagerly sets swap_allowed (giving writers the
 * earliest possible permission to proactively swap on buffer-full).
 *
 * Swap publication:
 *   reader_len is packed into the upper 32 bits of packed_state and the
 *   swap is a single transition that flips active_buf, zeros commit_pos,
 *   clears swap_allowed, and publishes reader_len = old commit_pos.  Two
 *   concurrent try_swap callers cannot clobber each other: exactly one
 *   wins; the loser sees the post-swap state and reader_len = winner's
 *   commit_pos.
 *
 *   On targets where the MI atomic_*_64 API is available (__LP64__, i.e.
 *   every 64-bit FreeBSD architecture) the swap is a single
 *   atomic_fcmpset_64; the path is lock-free and NMI-safe by construction.
 *
 *   On 32-bit targets that do not provide atomic_*_64 (FreeBSD's MI
 *   atomic_load_64 is itself gated on __LP64__),
 *   the same 64-bit packed_state is used but every state operation (load,
 *   commit, swap, drain) takes a per-pcpu_buf MTX_SPIN that serialises
 *   access to the otherwise non-atomic 64-bit field.  No atomics are
 *   needed inside the helpers; the lock provides both serialisation and
 *   visibility.  NMI-safety is provided up-front: the writer entry point
 *   checks mtx_owned(&pcpu_buf->swap_lock) and drops the event if true
 *   (in NMI context curthread is the interrupted thread, so mtx_owned()
 *   being true means we would mtx_lock_spin against ourselves and
 *   deadlock).  No caller-visible flag or per-helper trylock is needed.
 *
 *   Key properties (both implementations):
 *   - Writers NEVER spin waiting for the reader. They perform the swap
 *     themselves or drop if swap is not allowed.
 *   - No critical_enter needed: the writer's commit CAS detects and
 *     handles concurrent reader swaps by retrying.
 *   - Writer can proactively swap on buffer-full when swap_allowed is set,
 *     reducing event drops.
 *   - swap_allowed=0 implies reader_len > 0 (try_swap is only invoked with
 *     commit_pos > 0, and the swap publishes reader_len = commit_pos).
 */

#define EVENTLOG_INTERNAL
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/condvar.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/jail.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/ck.h>
#include <sys/smr.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/counter.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/eventlog.h>
#include <sys/eventlog_subscriber.h>
#include <sys/smp.h>
#include <sys/time.h>
#include <sys/limits.h>
#include <machine/cpu.h>
#include <machine/atomic.h>
#include <sys/conf.h>
#include <fs/devfs/devfs.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/libkern.h>
#include <sys/ioccom.h>
#include <sys/time.h>
#include <vm/vm.h>
#include <vm/uma.h>

/* Used to disable inlining to help debug performance issues via flamegraphs. */
#define EVENTLOG_INLINING	//__noinline

MALLOC_DEFINE(M_EVENTLOG, "eventlog", "eventlog subsystem");

/*
 * Full definition of eventlog_session - private to this file; header
 * has partial/forward only.
 */
struct eventlog_session {
	enum eventlog_level effective_level;
	uint32_t effective_keywords;
	/* Private fields - only visible in this file */
	struct eventlog_provider *provider;
	LIST_ENTRY(eventlog_session) link;
	uint64_t session_id;	/* Unique id (e.g., inp_gencnt for TCP) */
	uint64_t created_at;	/* us since boot when session was created */
	enum eventlog_level override_level;
	uint32_t override_keywords;
	uint8_t disabled;
	uint8_t has_override;
};

/*
 * Shared statistics for all providers with the same name.
 * Reference-counted: created on first provider, freed when last is destroyed.
 * Protected by evl.providers_lock.
 */
struct eventlog_provider_stats {
	int refcount;
	int default_enabled;
	LIST_ENTRY(eventlog_provider_stats) link;
	counter_u64_t sessions_created;
	counter_u64_t sessions_active;
	counter_u64_t sessions_enabled;
	struct sysctl_ctx_list sysctl_ctx;
	/*
	 * kern.eventlog.<name>; exposed to providers via
	 * eventlog_provider_get_sysctl_node().
	 */
	struct sysctl_oid *sysctl_node;
	char name[EVENTLOG_PROVIDER_NAME_MAX];
};

/* Full definition of eventlog_provider */
struct eventlog_provider {
	struct mtx sessions_lock;
	LIST_HEAD(, eventlog_session) sessions;
	LIST_ENTRY(eventlog_provider) link;
	struct eventlog_provider_stats *stats;
	eventlog_provider_dump_state_t dump_callback;
	void *dump_callback_arg;
	eventlog_default_changed_t default_changed;
	void *default_changed_arg;
	eventlog_subscribers_changed_t subscribers_changed;
	void *subscribers_changed_arg;
	enum eventlog_level level;
	uint32_t keywords;
	bool has_subscribers;		/* tracked under sessions_lock */
	uint16_t provider_id;		/* Unique ID assigned on registration */
	uint8_t name_len;		/* excluding null terminator */
	char name[EVENTLOG_PROVIDER_NAME_MAX];
};

/*
 * Full definition of eventlog_subscription. CK_SLIST for lock-free traversal
 * in SMR read path.
 */
struct eventlog_subscription {
	CK_SLIST_ENTRY(eventlog_subscription) link;
	struct eventlog_provider *provider;
	enum eventlog_level level;
	uint32_t keywords;
};

/*
 * Per-CPU buffer structure for double-buffering.  See "MEMORY ACCESS AND
 * SYNCHRONIZATION MODEL" at the top of this file for the protocol; this
 * block documents only the data layout.
 *
 * packed_state layout:
 *   [63:32] reader_len    - bytes in reader buffer (set at swap)
 *   [31:2]  commit_pos    - bytes committed to active buffer (= write cursor)
 *   [1]     swap_allowed  - reader buffer is empty, writer may proactively swap
 *   [0]     active_buf    - which buffer (0 or 1) is the active writer buffer
 *
 * 30-bit commit_pos and 30-bit reader_len each support buffers up to 1 GB
 * (the enforced maximum).  Initialised with swap_allowed=1.  Because
 * commit_pos lives in [31:2], a writer commit can simply add
 * (event_len << 2) to packed_state without disturbing the upper bits
 * (commit_pos + event_len <= buffer_size <= 1 GB rules out overflow).
 * The SMR critical section pins the writer to one CPU, so commit_pos
 * also serves as the writer's reservation cursor.
 *
 * EVENTLOG_FORCE_SWAP_LOCK overrides the LP64 detection so the fallback
 * path can be compile- and run-tested on 64-bit hosts.
 */
#if defined(__LP64__) && !defined(EVENTLOG_FORCE_SWAP_LOCK)
#define EVENTLOG_HAS_ATOMIC64 1
#endif

#define EVTLOG_ACTIVE_BUF	0x1U
#define EVTLOG_SWAP_ALLOWED	0x2U
#define EVTLOG_COMMIT_SHIFT	2

#define EVTLOG_READER_LEN_SHIFT	32
#define EVTLOG_PACK_READER_LEN(rl) \
	(((uint64_t)(uint32_t)(rl)) << EVTLOG_READER_LEN_SHIFT)
#define EVTLOG_READER_LEN_MASK \
	(((uint64_t)UINT32_MAX) << EVTLOG_READER_LEN_SHIFT)

struct eventlog_percpu_buffer {
	void *buffers[2];		/* Two buffers: [0] and [1] */
	uint32_t buffer_size;
	uint32_t read_pos;		/* Read cursor in reader buffer */
#ifndef EVENTLOG_HAS_ATOMIC64
	struct mtx swap_lock;		/* MTX_SPIN; covers all state ops */
#endif
	volatile uint64_t packed_state;	/* See layout above */
} __aligned(CACHE_LINE_SIZE);

/*
 * Atomic state abstraction.  evtlog_state_t carries the entire per-CPU
 * buffer state observable by callers as a single uint64_t with the layout
 * documented above.  Both implementations operate on the same word; only
 * the synchronisation primitive (atomic_*_64 vs spin-mutex) differs.
 */
typedef uint64_t evtlog_state_t;

static inline int
evtlog_state_active(evtlog_state_t s)
{
	return ((int)(s & EVTLOG_ACTIVE_BUF));
}

static inline uint32_t
evtlog_state_commit_pos(evtlog_state_t s)
{
	return (((uint32_t)s) >> EVTLOG_COMMIT_SHIFT);
}

static inline bool
evtlog_state_swap_allowed(evtlog_state_t s)
{
	return ((s & EVTLOG_SWAP_ALLOWED) != 0);
}

static inline uint32_t
evtlog_state_reader_len(evtlog_state_t s)
{
	return ((uint32_t)(s >> EVTLOG_READER_LEN_SHIFT));
}

static inline evtlog_state_t
evtlog_load_state(struct eventlog_percpu_buffer *pcpu)
{
#ifdef EVENTLOG_HAS_ATOMIC64
	return (atomic_load_acq_64(&pcpu->packed_state));
#else
	evtlog_state_t s;

	mtx_lock_spin(&pcpu->swap_lock);
	s = pcpu->packed_state;
	mtx_unlock_spin(&pcpu->swap_lock);
	return (s);
#endif
}

/*
 * Atomically advance commit_pos by event_len.  Returns true on success;
 * on failure, *state is updated to the current packed state so the caller
 * can re-derive active and commit_pos and decide whether to redo the write.
 */
static inline bool
evtlog_try_commit(struct eventlog_percpu_buffer *pcpu,
    evtlog_state_t *state, uint32_t event_len)
{
	evtlog_state_t new_state;
#ifndef EVENTLOG_HAS_ATOMIC64
	bool ok;
#endif

	new_state = *state + ((uint64_t)event_len << EVTLOG_COMMIT_SHIFT);
#ifdef EVENTLOG_HAS_ATOMIC64
	return (atomic_fcmpset_64(&pcpu->packed_state, state, new_state));
#else
	mtx_lock_spin(&pcpu->swap_lock);
	if (pcpu->packed_state == *state) {
		pcpu->packed_state = new_state;
		*state = new_state;
		ok = true;
	} else {
		*state = pcpu->packed_state;
		ok = false;
	}
	mtx_unlock_spin(&pcpu->swap_lock);
	return (ok);
#endif
}

/*
 * Try to perform a buffer swap atomically.  See "Swap publication" in the
 * SYNC MODEL at the top of this file for the protocol and the per-impl
 * synchronisation primitive.
 *
 * On success returns true and *old_state is updated to the post-swap
 * state (active_buf flipped, commit_pos=0, swap_allowed clear, reader_len
 * = pre-swap commit_pos).  On failure returns false and *old_state is
 * refreshed with the latest observed packed state so the caller can
 * re-check capacity after a peer swap.
 *
 * Precondition: commit_pos > 0 in *old_state.
 */
static inline bool
evtlog_try_swap(struct eventlog_percpu_buffer *pcpu,
    evtlog_state_t *old_state)
{
	evtlog_state_t state = *old_state;
	evtlog_state_t new_state;
	uint32_t commit;
#ifndef EVENTLOG_HAS_ATOMIC64
	bool ok;
#endif

	commit = evtlog_state_commit_pos(state);
	MPASS(commit > 0);
	new_state = ((state & EVTLOG_ACTIVE_BUF) ^ EVTLOG_ACTIVE_BUF) |
	    EVTLOG_PACK_READER_LEN(commit);

#ifdef EVENTLOG_HAS_ATOMIC64
	if (!atomic_fcmpset_64(&pcpu->packed_state, old_state, new_state))
		return (false);
#else
	mtx_lock_spin(&pcpu->swap_lock);
	if (pcpu->packed_state == *old_state) {
		pcpu->packed_state = new_state;
		ok = true;
	} else {
		*old_state = pcpu->packed_state;
		ok = false;
	}
	mtx_unlock_spin(&pcpu->swap_lock);
	if (!ok)
		return (false);
#endif
	*old_state = new_state;
	return (true);
}

/*
 * Mark the reader buffer empty: clear reader_len and set swap_allowed.
 * Caller must have just consumed all bytes in the reader buffer
 * (read_pos == reader_len) and runs in the single reader thread (never
 * NMI), so blocking on the swap lock in the fallback path is safe.
 */
static inline void
evtlog_drain_complete(struct eventlog_percpu_buffer *pcpu_buf)
{
#ifdef EVENTLOG_HAS_ATOMIC64
	uint64_t state, new_state;

	pcpu_buf->read_pos = 0;
	state = atomic_load_acq_64(&pcpu_buf->packed_state);
	do {
		new_state = (state & ~EVTLOG_READER_LEN_MASK) |
		    EVTLOG_SWAP_ALLOWED;
	} while (!atomic_fcmpset_64(&pcpu_buf->packed_state, &state,
	    new_state));
#else
	mtx_lock_spin(&pcpu_buf->swap_lock);
	pcpu_buf->read_pos = 0;
	pcpu_buf->packed_state = (pcpu_buf->packed_state &
	    ~EVTLOG_READER_LEN_MASK) | EVTLOG_SWAP_ALLOWED;
	mtx_unlock_spin(&pcpu_buf->swap_lock);
#endif
}

/*
 * Validate that a buffer contains only complete events (no partial data).
 * buffer: pointer to buffer, buffer_size: capacity, start: offset to begin,
 * written_len: bytes of data. Call with __LINE__ for panic diagnostics.
 */
#ifdef INVARIANTS
static inline void
eventlog_validate_buffer(void *buffer, size_t buffer_size, size_t start,
    size_t written_len, int line)
{
	size_t offset = start;
	struct eventlog_event_header hdr;

	KASSERT(start <= written_len,
	    ("%s: start %zu > written_len %zu (caller line %d)",
	    __func__, start, written_len, line));
	KASSERT(written_len <= buffer_size,
	    ("%s: written_len %zu > buffer_size %zu (caller line %d)",
	    __func__, written_len, buffer_size, line));
	if (written_len == 0)
		return;
	KASSERT(written_len >= sizeof(struct eventlog_event_header),
	    ("%s: partial data, written_len %zu < header (line %d)",
	    __func__, written_len, line));
	while (offset < written_len) {
		KASSERT(
		    offset + sizeof(struct eventlog_event_header) <=
		    written_len,
		    ("%s: truncated header at offset %zu (line %d)",
		    __func__, offset, line));
		memcpy(&hdr, (const uint8_t *)buffer + offset,
		    sizeof(struct eventlog_event_header));
		KASSERT(hdr.event_length >=
		    sizeof(struct eventlog_event_header),
		    ("%s: invalid event_length %u at offset %zu (line %d)",
		    __func__, hdr.event_length, offset, line));
		KASSERT(offset + hdr.event_length <= written_len,
		    ("%s: event overrun at offset %zu len %u (line %d)",
		    __func__, offset, hdr.event_length, line));
		offset += hdr.event_length;
	}
	KASSERT(offset == written_len,
	    ("%s: partial event at end, offset %zu != written_len %zu"
	    " (caller line %d)",
	    __func__, offset, written_len, line));
}

#define EVENTLOG_VALIDATE_READER(pcpu_buf) do {				\
	evtlog_state_t _vs = evtlog_load_state(pcpu_buf);		\
	eventlog_validate_buffer(					\
	    (pcpu_buf)->buffers[1 - evtlog_state_active(_vs)],		\
	    (pcpu_buf)->buffer_size, (pcpu_buf)->read_pos,		\
	    evtlog_state_reader_len(_vs), __LINE__);			\
} while (0)
#define EVENTLOG_VALIDATE_WRITER(pcpu_buf) do {				\
	evtlog_state_t _vs = evtlog_load_state(pcpu_buf);		\
	eventlog_validate_buffer(					\
	    (pcpu_buf)->buffers[evtlog_state_active(_vs)],		\
	    (pcpu_buf)->buffer_size, 0,					\
	    evtlog_state_commit_pos(_vs), __LINE__);			\
} while (0)
#else
#define EVENTLOG_VALIDATE_READER(pcpu_buf) do { } while (0)
#define EVENTLOG_VALIDATE_WRITER(pcpu_buf) do { } while (0)
#endif

static inline uint64_t
eventlog_read_timestamp(const void *buf)
{
	return (((const struct eventlog_event_header *)buf)->timestamp);
}

/*
 * Peek at the next event's timestamp from a CPU buffer's reader buffer.
 * Does not advance the buffer read position.
 */
static EVENTLOG_INLINING uint64_t
eventlog_peek_next_timestamp(struct eventlog_percpu_buffer *pcpu_buf)
{
	const uint8_t *ptr;
	int reader = 1 - evtlog_state_active(evtlog_load_state(pcpu_buf));

	EVENTLOG_VALIDATE_READER(pcpu_buf);
	ptr = (const uint8_t *)pcpu_buf->buffers[reader] + pcpu_buf->read_pos;
	return (eventlog_read_timestamp(ptr));
}

/* Sentinel for timestamp: no next-event timestamp. */
#define EVENTLOG_TIMESTAMP_NONE	UINT64_MAX
/* CPU already checked by resweep during this read (skip next time). */
#define EVENTLOG_TIMESTAMP_SWEPT (UINT64_MAX - 1)

/* Full definition of eventlog_subscriber (internal only) */
CK_LIST_HEAD(eventlog_subscriber_head, eventlog_subscriber);
struct eventlog_subscriber {
	CK_LIST_ENTRY(eventlog_subscriber) link;
	CK_SLIST_HEAD(, eventlog_subscription) subscriptions;
	enum eventlog_subscriber_type type;

	union {
		/* Device-based subscriber: per-CPU buffers */
		struct {
			struct eventlog_percpu_buffer *percpu_buffers;
			uint32_t buffer_size_per_cpu;
			/* Atomic: non-zero if reader is waiting. */
			volatile uint32_t reader_waiting;
			/* [maxcpu] next-event timestamp per CPU. */
			uint64_t *cpu_timestamps;
			/* Min-heap of CPU indices by timestamp. */
			uint16_t *heap_cpus;
			uint16_t heap_size;	/* Number of CPUs in heap */
		} device;
		/* Callback-based subscriber: callback function */
		struct {
			eventlog_callback_t callback;
			void *callback_arg;
		} callback;
	} u;

	/*
	 * Async dump_state coordination. dump_pending counts queued +
	 * in-flight dump tasks targeting this subscriber; destroy/drain
	 * waits on the cv until it hits zero. The mtx covers both fields.
	 */
	struct mtx dump_pending_mtx;
	struct cv dump_pending_cv;
	u_int dump_pending;

	/* Statistics */
	volatile u_long dropped_events;
};

/*
 * Min-heap of CPU indices ordered by next-event timestamp.
 * heap_cpus[0] is the CPU with minimum timestamp when heap_size > 0.
 * Stored as implicit binary heap: parent at i, children at 2*i+1 and 2*i+2.
 */

/*
 * Insert (cpu, timestamp) into the min-heap. O(log n).
 */
static EVENTLOG_INLINING void
eventlog_heap_insert(struct eventlog_subscriber *subscriber, uint16_t cpu,
    uint64_t timestamp)
{
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint16_t *heap_cpus = subscriber->u.device.heap_cpus;
	uint16_t *heap_size = &subscriber->u.device.heap_size;
	size_t i;

	timestamps[cpu] = timestamp;

	if (*heap_size == 0) {
		heap_cpus[0] = cpu;
		*heap_size = 1;
		return;
	}

	/* Add at end, bubble up */
	i = (*heap_size)++;
	heap_cpus[i] = cpu;
	while (i > 0) {
		size_t parent = (i - 1) / 2;
		if (timestamps[heap_cpus[parent]] <= timestamps[cpu])
			break;
		heap_cpus[i] = heap_cpus[parent];
		i = parent;
	}
	heap_cpus[i] = cpu;
}

/*
 * Extract the CPU with minimum timestamp from the heap. Caller must ensure
 * heap_size > 0. O(log n).
 */
static inline void
eventlog_heap_extract_min(struct eventlog_subscriber *subscriber)
{
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint16_t *heap_cpus = subscriber->u.device.heap_cpus;
	uint16_t *heap_size = &subscriber->u.device.heap_size;
	uint16_t replaced;
	size_t i, smallest;

	MPASS(*heap_size > 0);

	timestamps[heap_cpus[0]] = EVENTLOG_TIMESTAMP_NONE;

	if (*heap_size == 1) {
		*heap_size = 0;
		return;
	}

	replaced = heap_cpus[--*heap_size];
	heap_cpus[0] = replaced;
	i = 0;

	/* Heapify down */
	while (1) {
		size_t left = 2 * i + 1;
		size_t right = 2 * i + 2;

		smallest = i;
		if (left < *heap_size &&
		    timestamps[heap_cpus[left]] <
		    timestamps[heap_cpus[smallest]])
			smallest = left;
		if (right < *heap_size &&
		    timestamps[heap_cpus[right]] <
		    timestamps[heap_cpus[smallest]])
			smallest = right;

		if (smallest == i)
			break;

		heap_cpus[i] = heap_cpus[smallest];
		i = smallest;
	}
	heap_cpus[i] = replaced;
}

/*
 * Update the root's timestamp (root key increased) and restore heap property.
 * Replaces extract_min + heap_insert when we only need to update the root CPU.
 * Caller must ensure heap_size > 0.
 */
static inline void
eventlog_heap_update_root(struct eventlog_subscriber *subscriber,
    uint64_t new_timestamp)
{
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint16_t *heap_cpus = subscriber->u.device.heap_cpus;
	uint16_t *heap_size = &subscriber->u.device.heap_size;
	uint16_t root_cpu;
	size_t i, smallest;

	MPASS(*heap_size > 0);

	root_cpu = heap_cpus[0];
	timestamps[root_cpu] = new_timestamp;
	i = 0;

	/* Sift down from root */
	while (1) {
		size_t left = 2 * i + 1;
		size_t right = 2 * i + 2;

		smallest = i;
		if (left < *heap_size &&
		    timestamps[heap_cpus[left]] <
		    timestamps[heap_cpus[smallest]])
			smallest = left;
		if (right < *heap_size &&
		    timestamps[heap_cpus[right]] <
		    timestamps[heap_cpus[smallest]])
			smallest = right;

		if (smallest == i)
			break;

		heap_cpus[i] = heap_cpus[smallest];
		i = smallest;
	}
	heap_cpus[i] = root_cpu;
}

/*
 * Return the second-smallest timestamp (for max_timestamp bound), or UINT64_MAX
 * if heap has fewer than 2 elements.
 */
static inline uint64_t
eventlog_heap_second_min_timestamp(struct eventlog_subscriber *subscriber)
{
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint16_t *heap_cpus = subscriber->u.device.heap_cpus;
	uint16_t heap_size = subscriber->u.device.heap_size;

	if (heap_size < 2)
		return (UINT64_MAX);
	if (heap_size == 2)
		return (timestamps[heap_cpus[1]]);
	return (MIN(timestamps[heap_cpus[1]], timestamps[heap_cpus[2]]));
}

/* Global eventlog state structure */
struct eventlog_state {
	/* Provider registry */
	LIST_HEAD(, eventlog_provider) providers;
	LIST_HEAD(, eventlog_provider_stats) provider_stats;
	struct mtx providers_lock;	/* Protects providers/stats lists */
	uint16_t next_provider_id;	/* Next ID to assign (1-based) */

	/* System-wide device */
	struct cdev *device;
	smr_t smr;			/* SMR domain for subscriber iter. */
	struct mtx subscribers_mtx;	/* Writer-writer add/remove excl. */
	struct eventlog_subscriber_head subscribers;

	/* UMA zones */
	uma_zone_t session_zone;

	/*
	 * Dump state. dump_tq is single-threaded so dump callbacks
	 * serialize naturally. While the TQ thread runs a callback it
	 * publishes (dump_thread, dump_target) so eventlog_event_write_impl
	 * can route the callback's events to just the requesting subscriber.
	 * No lock is held: only the TQ thread reads its own publication
	 * (curthread == dump_thread); the destroy barrier is
	 * taskqueue_drain_all() in eventlog_provider_destroy().
	 */
	struct thread *dump_thread;	/* Thread running dump callback */
	/* Subscriber receiving dump events. */
	struct eventlog_subscriber *dump_target;
	struct taskqueue *dump_tq;
};

/* Single instance of global eventlog state */
static struct eventlog_state evl = {
	.providers = LIST_HEAD_INITIALIZER(evl.providers),
	.provider_stats = LIST_HEAD_INITIALIZER(evl.provider_stats),
	.device = NULL,
	.subscribers = CK_LIST_HEAD_INITIALIZER(evl.subscribers),
};

/* Initialize mutexes and SMR */
static void
eventlog_state_init(void *unused)
{
	mtx_init(&evl.providers_lock, "eventlog providers", NULL, MTX_DEF);
	evl.smr = smr_create("eventlog", 0, 0);
	mtx_init(&evl.subscribers_mtx, "eventlog subscribers", NULL, MTX_DEF);
}
SYSINIT(eventlog_state_init, SI_SUB_LOCK, SI_ORDER_ANY,
    eventlog_state_init, NULL);

/*
 * Start the single-threaded dump taskqueue. Serializing dump callbacks
 * lets the (dump_thread, dump_target) publication stay lock-free.
 */
static void
eventlog_dump_tq_init(void *unused)
{
	int err;

	evl.dump_tq = taskqueue_create("eventlog_dump", M_WAITOK,
	    taskqueue_thread_enqueue, &evl.dump_tq);
	err = taskqueue_start_threads(&evl.dump_tq, 1, PWAIT,
	    "eventlog_dump taskq");
	if (err != 0)
		panic("eventlog: taskqueue_start_threads failed: %d", err);
}
SYSINIT(eventlog_dump_tq_init, SI_SUB_TASKQ, SI_ORDER_SECOND,
    eventlog_dump_tq_init, NULL);

/* Initialize UMA zone for sessions */
static void
eventlog_session_zone_init(void *unused)
{
	evl.session_zone = uma_zcreate("eventlog_session",
	    sizeof(struct eventlog_session), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
}
SYSINIT(eventlog_session_zone, SI_SUB_KMEM, SI_ORDER_ANY,
    eventlog_session_zone_init, NULL);

/* Forward declarations */
static void eventlog_session_update_effective(struct eventlog_session *session,
    struct eventlog_provider *provider);
static void eventlog_update_provider_enablement(
    struct eventlog_provider *provider);
static void eventlog_subscriber_write_event(
    struct eventlog_subscriber *subscriber,
    struct eventlog_session *session, struct eventlog_event_header *hdr,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    uint16_t event_length, enum eventlog_level level, uint32_t keywords);
static void eventlog_copy_events_from_cpu(
    struct eventlog_subscriber *subscriber,
    struct eventlog_percpu_buffer *pcpu_buf, struct uio *uio,
    uint64_t max_timestamp, uint64_t *next_timestamp_out,
    bool *uio_out_of_space_out);
static void eventlog_read_merged(struct eventlog_subscriber *subscriber,
    struct uio *uio, uint64_t read_timestamp);
static void eventlog_resweep_idle_cpus(struct eventlog_subscriber *subscriber,
    uint64_t read_timestamp);

/* Kernel sysctl node definitions */
SYSCTL_DECL(_kern_eventlog);
SYSCTL_NODE(_kern, OID_AUTO, eventlog, CTLFLAG_RD | CTLFLAG_MPSAFE, NULL,
    "Event log subsystem");

/*
 * Find existing shared statistics for a provider name.
 * Caller must hold evl.providers_lock.
 * Returns NULL if no stats exist for this name.
 */
static struct eventlog_provider_stats *
eventlog_provider_stats_find(const char *name)
{
	struct eventlog_provider_stats *stats;

	LIST_FOREACH(stats, &evl.provider_stats, link) {
		if (strcmp(stats->name, name) == 0) {
			stats->refcount++;
			return (stats);
		}
	}
	return (NULL);
}

/*
 * Enable or disable all sessions for a single provider instance.
 * Holds provider->sessions_lock for the entire iteration.
 */
static void
eventlog_provider_set_all_sessions(struct eventlog_provider *provider,
    int enabled)
{
	struct eventlog_session *session;

	mtx_lock(&provider->sessions_lock);
	LIST_FOREACH(session, &provider->sessions, link) {
		if (session->disabled == (enabled == 0 ? 1 : 0))
			continue;
		counter_u64_add(provider->stats->sessions_enabled,
		    (enabled != 0) ? 1 : -1);
		session->disabled = (enabled == 0) ? 1 : 0;
		eventlog_session_update_effective(session, provider);
	}
	mtx_unlock(&provider->sessions_lock);
}

/*
 * Sysctl handler for kern.eventlog.<name>.default.
 * Values: 0=disabled, 1=enabled, -1=disable all active (set 0),
 *         2=enable all disabled (set 1).
 */
static int
sysctl_eventlog_default(SYSCTL_HANDLER_ARGS)
{
	struct eventlog_provider_stats *stats = arg1;
	struct eventlog_provider *provider;
	struct eventlog_provider *matched[16];
	int nmatched, i, error, val, new_default;

	val = stats->default_enabled;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	switch (val) {
	case -1:
		new_default = 0;
		break;
	case 0:
	case 1:
		new_default = val;
		break;
	case 2:
		new_default = 1;
		break;
	default:
		return (EINVAL);
	}

	stats->default_enabled = new_default;

	nmatched = 0;
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link) {
		if (provider->stats == stats && nmatched < 16)
			matched[nmatched++] = provider;
	}
	mtx_unlock(&evl.providers_lock);

	for (i = 0; i < nmatched; i++) {
		if (matched[i]->default_changed != NULL) {
			matched[i]->default_changed(matched[i], val,
			    matched[i]->default_changed_arg);
		} else if (val == -1 || val == 2) {
			eventlog_provider_set_all_sessions(matched[i],
			    (val == 2) ? 1 : 0);
		}
	}

	return (0);
}

/*
 * Allocate a new shared statistics structure.  Does not insert into the
 * global list — caller must do that under evl.providers_lock after
 * re-checking for a concurrent creation.  All sleeping allocations
 * (malloc, counter_u64_alloc, sysctl) happen here, outside any lock.
 */
static struct eventlog_provider_stats *
eventlog_provider_stats_alloc(const char *name, int default_enabled)
{
	struct eventlog_provider_stats *stats;
	struct sysctl_oid *stats_node;
	char tunable_name[64];

	stats = malloc(sizeof(*stats), M_EVENTLOG, M_WAITOK | M_ZERO);
	strlcpy(stats->name, name, EVENTLOG_PROVIDER_NAME_MAX);
	stats->refcount = 1;
	stats->default_enabled = default_enabled;
	/*
	 * Apply the kern.eventlog.<name>.default tunable on top of the
	 * config default. TUNABLE_INT_FETCH leaves the field alone if the
	 * tunable is absent.
	 */
	snprintf(tunable_name, sizeof(tunable_name),
	    "kern.eventlog.%s.default", name);
	TUNABLE_INT_FETCH(tunable_name, &stats->default_enabled);
	stats->sessions_created = counter_u64_alloc(M_WAITOK);
	stats->sessions_active = counter_u64_alloc(M_WAITOK);
	stats->sessions_enabled = counter_u64_alloc(M_WAITOK);

	sysctl_ctx_init(&stats->sysctl_ctx);
	stats_node = SYSCTL_ADD_NODE(&stats->sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_kern_eventlog), OID_AUTO, name,
	    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
	    "Event log provider statistics");
	stats->sysctl_node = stats_node;
	SYSCTL_ADD_COUNTER_U64(&stats->sysctl_ctx, SYSCTL_CHILDREN(stats_node),
	    OID_AUTO, "sessions_created", CTLFLAG_RD, &stats->sessions_created,
	    "Total sessions ever created successfully");
	SYSCTL_ADD_COUNTER_U64(&stats->sysctl_ctx, SYSCTL_CHILDREN(stats_node),
	    OID_AUTO, "sessions_active", CTLFLAG_RD, &stats->sessions_active,
	    "Current active session count");
	SYSCTL_ADD_COUNTER_U64(&stats->sysctl_ctx, SYSCTL_CHILDREN(stats_node),
	    OID_AUTO, "sessions_enabled", CTLFLAG_RD, &stats->sessions_enabled,
	    "Active sessions that are not disabled");
	SYSCTL_ADD_PROC(&stats->sysctl_ctx, SYSCTL_CHILDREN(stats_node),
	    OID_AUTO, "default", CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    stats, 0, sysctl_eventlog_default, "I",
	    "Default enabled: 0=disabled, 1=enabled, -1=disable all active, 2=enable all disabled");

	return (stats);
}

/*
 * Free a provider_stats that was never inserted into the global list
 * (used when a concurrent creator won the race).
 */
static void
eventlog_provider_stats_free(struct eventlog_provider_stats *stats)
{
	sysctl_ctx_free(&stats->sysctl_ctx);
	counter_u64_free(stats->sessions_created);
	counter_u64_free(stats->sessions_active);
	counter_u64_free(stats->sessions_enabled);
	free(stats, M_EVENTLOG);
}

/*
 * Release a reference to shared provider statistics.
 * Removes from the global list when refcount reaches zero, but does NOT
 * free — caller must free outside the lock via eventlog_provider_stats_free.
 * Caller must hold evl.providers_lock.
 * Returns the stats pointer if it should be freed, NULL otherwise.
 */
static struct eventlog_provider_stats *
eventlog_provider_stats_release(struct eventlog_provider_stats *stats)
{
	if (--stats->refcount > 0)
		return (NULL);

	LIST_REMOVE(stats, link);
	return (stats);
}

/*
 * Create and register a new eventlog provider.
 */
struct eventlog_provider*
eventlog_provider_create(const char *name,
    const struct eventlog_provider_config *config)
{
	static const struct eventlog_provider_config empty_config;
	struct eventlog_provider *provider;
	struct eventlog_provider_stats *new_stats = NULL;

	MPASS(name != NULL);
	MPASS(strlen(name) < EVENTLOG_PROVIDER_NAME_MAX);

	if (config == NULL)
		config = &empty_config;

	/* Allocate provider structure */
	provider = malloc(sizeof(*provider), M_EVENTLOG, M_WAITOK | M_ZERO);
	strlcpy(provider->name, name, EVENTLOG_PROVIDER_NAME_MAX);
	provider->name_len = strlen(provider->name);
	provider->dump_callback = config->dump_callback;
	provider->dump_callback_arg = config->dump_callback_arg;
	provider->default_changed = config->default_changed;
	provider->default_changed_arg = config->default_changed_arg;
	provider->subscribers_changed = config->subscribers_changed;
	provider->subscribers_changed_arg = config->subscribers_changed_arg;
	mtx_init(&provider->sessions_lock, "eventlog sessions", NULL, MTX_DEF);
	LIST_INIT(&provider->sessions);

	/* Fast path: check if stats already exist for this name. */
	mtx_lock(&evl.providers_lock);
	provider->stats = eventlog_provider_stats_find(name);
	if (provider->stats != NULL)
		goto insert;
	mtx_unlock(&evl.providers_lock);

	/*
	 * Slow path: allocate stats outside the lock, then re-check.
	 * The first provider for a given name seeds default_enabled;
	 * later providers reuse the existing stats record (the sysctl
	 * surface is shared by name).
	 */
	new_stats = eventlog_provider_stats_alloc(name,
	    config->default_enabled);

	mtx_lock(&evl.providers_lock);
	provider->stats = eventlog_provider_stats_find(name);
	if (provider->stats != NULL) {
		/* Another thread created it while we were allocating. */
		mtx_unlock(&evl.providers_lock);
		eventlog_provider_stats_free(new_stats);
		mtx_lock(&evl.providers_lock);
	} else {
		LIST_INSERT_HEAD(&evl.provider_stats, new_stats, link);
		provider->stats = new_stats;
	}

insert:
	/* Assign unique provider_id (1-based; 0 reserved for invalid) */
	if (evl.next_provider_id == 0)
		evl.next_provider_id = 1;
	provider->provider_id = evl.next_provider_id++;
	LIST_INSERT_HEAD(&evl.providers, provider, link);
	mtx_unlock(&evl.providers_lock);

	return (provider);
}

/*
 * Unregister and cleanup an eventlog provider.
 */
void
eventlog_provider_destroy(struct eventlog_provider *provider)
{
	struct eventlog_provider_stats *dead_stats;

	if (provider == NULL)
		return;

	MPASS(LIST_EMPTY(&provider->sessions));

	/*
	 * Remove from the provider list first so no new subscription
	 * (and therefore no new dump task) can find us.
	 */
	mtx_lock(&evl.providers_lock);
	LIST_REMOVE(provider, link);
	dead_stats = eventlog_provider_stats_release(provider->stats);
	mtx_unlock(&evl.providers_lock);

	/*
	 * Drain the dump taskqueue: queued or in-flight tasks may still
	 * reference this provider.
	 */
	taskqueue_drain_all(evl.dump_tq);

	if (dead_stats != NULL)
		eventlog_provider_stats_free(dead_stats);

	mtx_destroy(&provider->sessions_lock);
	free(provider, M_EVENTLOG);
}

/*
 * Create a new eventlog session.
 * Initial enabled state is derived from the provider's default_enabled.
 */
struct eventlog_session*
eventlog_session_create(struct eventlog_provider *provider,
    uint64_t session_id, bool waitok,
    void *create_payload, size_t create_payload_size)
{
	struct bintime bt;
	struct eventlog_session *session;
	bool enabled;

	if (provider == NULL)
		return (NULL);

	session = uma_zalloc(evl.session_zone,
	    (waitok ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (session == NULL)
		return (NULL);

	enabled = (provider->stats->default_enabled != 0);

	binuptime(&bt);
	session->created_at = bintime2us(&bt);
	session->provider = provider;
	session->session_id = session_id;
	session->disabled = enabled ? 0 : 1;

	counter_u64_add(provider->stats->sessions_created, 1);
	counter_u64_add(provider->stats->sessions_active, 1);
	if (enabled)
		counter_u64_add(provider->stats->sessions_enabled, 1);

	/* Add session to provider's list */
	mtx_lock(&provider->sessions_lock);
	LIST_INSERT_HEAD(&provider->sessions, session, link);
	eventlog_session_update_effective(session, provider);
	mtx_unlock(&provider->sessions_lock);

	/* Emit SESSION_CREATE only when enabled. */
	if (enabled && provider->level != EVENTLOG_LEVEL_NONE) {
		eventlog_event_write_at(session, EVENTLOG_SESSION_CREATE_ID,
		    EVENTLOG_LEVEL_INFO, EVENTLOG_KEYWORD_SESSION,
		    create_payload, create_payload_size,
		    session->created_at);
	}

	return (session);
}

/*
 * Destroy an eventlog session.
 */
void
eventlog_session_destroy(struct eventlog_session *session)
{
	struct eventlog_provider *provider;

	if (session == NULL)
		return;

	provider = session->provider;
	MPASS(provider != NULL);

	if (session->disabled == 0) {
		counter_u64_add(provider->stats->sessions_enabled, -1);
		eventlog_event_write(session, EVENTLOG_SESSION_END_ID,
		    EVENTLOG_LEVEL_INFO, EVENTLOG_KEYWORD_SESSION, NULL, 0);
	}

	counter_u64_add(provider->stats->sessions_active, -1);

	/* Remove session from provider's list */
	mtx_lock(&provider->sessions_lock);
	LIST_REMOVE(session, link);
	mtx_unlock(&provider->sessions_lock);

	/* Wait for SMR readers before freeing */
	smr_synchronize(evl.smr);
	uma_zfree(evl.session_zone, session);
}

/*
 * Query provider level and keywords.
 */
enum eventlog_level
eventlog_provider_get_level(struct eventlog_provider *provider)
{
	MPASS(provider != NULL);
	return (provider->level);
}

uint32_t
eventlog_provider_get_keywords(struct eventlog_provider *provider)
{
	MPASS(provider != NULL);
	return (provider->keywords);
}

int
eventlog_provider_get_default(struct eventlog_provider *provider)
{
	if (provider == NULL)
		return (0);
	return (provider->stats->default_enabled);
}

void
eventlog_provider_set_default(struct eventlog_provider *provider, int value)
{

	MPASS(provider != NULL);
	provider->stats->default_enabled = value;
}

/*
 * Return the auto-generated kern.eventlog.<name> sysctl node and its
 * context list. Children attached by providers are freed with the
 * node, so they must not outlive the provider.
 */
struct sysctl_oid *
eventlog_provider_get_sysctl_node(struct eventlog_provider *provider)
{
	MPASS(provider != NULL);
	return (provider->stats->sysctl_node);
}

struct sysctl_ctx_list *
eventlog_provider_get_sysctl_ctx(struct eventlog_provider *provider)
{
	MPASS(provider != NULL);
	return (&provider->stats->sysctl_ctx);
}

/*
 * Update session's effective_level and effective_keywords from
 * disabled/override/provider.
 * Caller must hold provider->sessions_lock.
 */
static void
eventlog_session_update_effective(struct eventlog_session *session,
    struct eventlog_provider *provider)
{
	if (session->disabled) {
		session->effective_level = EVENTLOG_LEVEL_NONE;
		session->effective_keywords = 0;
	} else if (session->has_override) {
		session->effective_level = session->override_level;
		session->effective_keywords = session->override_keywords;
	} else {
		session->effective_level = provider->level;
		session->effective_keywords = provider->keywords;
	}
}

/*
 * Enable or disable a session.
 */
void
eventlog_session_set_enabled(struct eventlog_session *session, int enabled)
{
	struct eventlog_provider *provider;

	if (session == NULL)
		return;

	/* No change - nothing to do */
	if (session->disabled == (enabled == 0 ? 1 : 0))
		return;

	provider = session->provider;
	MPASS(provider != NULL);

	counter_u64_add(provider->stats->sessions_enabled,
	    (enabled != 0) ? 1 : -1);
	session->disabled = (enabled == 0) ? 1 : 0;

	mtx_lock(&provider->sessions_lock);
	eventlog_session_update_effective(session, provider);
	mtx_unlock(&provider->sessions_lock);
}

int
eventlog_session_is_enabled(struct eventlog_session *session)
{
	return (session != NULL && session->disabled == 0);
}

/*
 * Set per-session level/keywords override.
 */
void
eventlog_session_set_filter(struct eventlog_session *session,
    enum eventlog_level level, uint32_t keywords)
{
	struct eventlog_provider *provider;

	if (session == NULL)
		return;

	provider = session->provider;
	MPASS(provider != NULL);

	session->has_override =
	    (level != EVENTLOG_LEVEL_NONE || keywords != 0) ? 1 : 0;
	session->override_level = level;
	session->override_keywords = keywords;

	mtx_lock(&provider->sessions_lock);
	eventlog_session_update_effective(session, provider);
	mtx_unlock(&provider->sessions_lock);
}

/*
 * Write an event directly to all relevant subscribers (internal, with
 * explicit timestamp). The payload is a scatter/gather iovec; scalar
 * callers pass a 1-element iov. payload_size must equal the sum of
 * iov[*].iov_len; the caller is responsible for computing it so the
 * hot path doesn't need to walk the iov twice.
 */
static void
eventlog_event_write_impl(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt,
    size_t payload_size, uint64_t timestamp_us)
{
	struct eventlog_event_header hdr;
	struct eventlog_provider *provider;
	struct eventlog_subscriber *subscriber;
	size_t total_size;

	MPASS(session != NULL);
	if (__predict_false(session == NULL))
		return;

	provider = session->provider;
	MPASS(provider != NULL);

	MPASS(iovcnt >= 0);
	MPASS(iovcnt == 0 || iov != NULL);

	total_size = sizeof(struct eventlog_event_header) + payload_size;

	if (__predict_false(total_size > UINT16_MAX))
		return;

	hdr.event_length = (uint16_t)total_size;
	hdr.RESERVED = 0;
	hdr.timestamp = timestamp_us;
	hdr.thread_id = (curthread != NULL) ? curthread->td_tid : 0;
	hdr.provider_id = provider->provider_id;
	hdr.session_id = session->session_id;
	hdr.event_id = id;

	smr_enter(evl.smr);
	hdr.cpu = PCPU_GET(cpuid);

	/*
	 * BUGBUG: It's possible other events raced on a different thread
	 * with a later timestamp and have already been written.
	 */

	if (__predict_false(evl.dump_target != NULL &&
	    curthread == evl.dump_thread)) {
		eventlog_subscriber_write_event(evl.dump_target, session,
		    &hdr, iov, iovcnt, payload_size,
		    (uint16_t)total_size, level, keywords);
	} else {
		CK_LIST_FOREACH(subscriber, &evl.subscribers, link) {
			eventlog_subscriber_write_event(subscriber, session,
			    &hdr, iov, iovcnt, payload_size,
			    (uint16_t)total_size, level, keywords);
		}
	}

	smr_exit(evl.smr);
}

void
eventlog_event_write(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length)
{
	struct iovec iov = { .iov_base = buffer, .iov_len = length };
	struct bintime bt;

	binuptime(&bt);
	eventlog_event_write_impl(session, id, level, keywords,
	    &iov, 1, length, bintime2us(&bt));
}

void
eventlog_event_write_at(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length,
    uint64_t timestamp_us)
{
	struct iovec iov = { .iov_base = buffer, .iov_len = length };

	eventlog_event_write_impl(session, id, level, keywords,
	    &iov, 1, length, timestamp_us);
}

void
eventlog_event_write_gather(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt)
{
	struct bintime bt;
	size_t payload_size = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		payload_size += iov[i].iov_len;
	binuptime(&bt);
	eventlog_event_write_impl(session, id, level, keywords,
	    iov, iovcnt, payload_size, bintime2us(&bt));
}

void
eventlog_event_write_gather_at(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt, uint64_t timestamp_us)
{
	size_t payload_size = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		payload_size += iov[i].iov_len;
	eventlog_event_write_impl(session, id, level, keywords,
	    iov, iovcnt, payload_size, timestamp_us);
}

/*
 * Create a new device-based subscriber with per-CPU buffers.
 * buffer_size_per_cpu: Size of buffer to allocate per CPU.
 * The subscriber is automatically added to the global subscribers list.
 * Returns NULL on failure, subscriber pointer on success.
 */
struct eventlog_subscriber *
eventlog_subscriber_create_device(uint32_t buffer_size_per_cpu)
{
	struct eventlog_subscriber *subscriber;
	struct eventlog_percpu_buffer *percpu_buffers;
	int cpu, maxcpu;

	if (buffer_size_per_cpu < EVENTLOG_BUFFER_SIZE_MIN ||
	    buffer_size_per_cpu > EVENTLOG_BUFFER_SIZE_MAX)
		return (NULL);

	/* Allocate subscriber structure */
	subscriber = malloc(sizeof(*subscriber), M_EVENTLOG, M_ZERO | M_WAITOK);
	MPASS(subscriber != NULL);

	CK_SLIST_INIT(&subscriber->subscriptions);
	subscriber->type = EVENTLOG_SUBSCRIBER_TYPE_DEVICE;
	subscriber->u.device.buffer_size_per_cpu = buffer_size_per_cpu;
	subscriber->u.device.reader_waiting = 0;
	subscriber->u.device.heap_size = 0;
	mtx_init(&subscriber->dump_pending_mtx, "eventlog dump pending",
	    NULL, MTX_DEF);
	cv_init(&subscriber->dump_pending_cv, "evl_dump");

	/* Allocate per-CPU buffers */
	maxcpu = mp_maxid + 1;
	percpu_buffers = malloc(sizeof(*percpu_buffers) * maxcpu,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(percpu_buffers != NULL);
	subscriber->u.device.percpu_buffers = percpu_buffers;

	/* Allocate cpu_timestamps and heap for merge ordering */
	subscriber->u.device.cpu_timestamps = malloc(sizeof(uint64_t) * maxcpu,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(subscriber->u.device.cpu_timestamps != NULL);
	subscriber->u.device.heap_cpus = malloc(sizeof(uint16_t) * maxcpu,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(subscriber->u.device.heap_cpus != NULL);
	for (cpu = 0; cpu < maxcpu; cpu++)
		subscriber->u.device.cpu_timestamps[cpu] =
		    EVENTLOG_TIMESTAMP_NONE;

	/* Allocate reader/writer buffers for each CPU */
	for (cpu = 0; cpu < maxcpu; cpu++) {
		percpu_buffers[cpu].buffer_size = buffer_size_per_cpu;
		percpu_buffers[cpu].packed_state = EVTLOG_SWAP_ALLOWED;
#ifndef EVENTLOG_HAS_ATOMIC64
		mtx_init(&percpu_buffers[cpu].swap_lock,
		    "eventlog swap", NULL, MTX_SPIN);
#endif
		percpu_buffers[cpu].buffers[0] = malloc(buffer_size_per_cpu,
		    M_EVENTLOG, M_WAITOK | M_ZERO);
		MPASS(percpu_buffers[cpu].buffers[0] != NULL);
		percpu_buffers[cpu].buffers[1] = malloc(buffer_size_per_cpu,
		    M_EVENTLOG, M_WAITOK | M_ZERO);
		MPASS(percpu_buffers[cpu].buffers[1] != NULL);
	}

	/* Add subscriber to global list */
	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_INSERT_HEAD(&evl.subscribers, subscriber, link);
	mtx_unlock(&evl.subscribers_mtx);

	return (subscriber);
}

/*
 * Create a new callback-based subscriber.
 * callback: Function to call when events arrive.
 * callback_arg: Argument to pass to callback function.
 * The subscriber is automatically added to the global subscribers list.
 * Returns NULL on failure, subscriber pointer on success.
 */
struct eventlog_subscriber *
eventlog_subscriber_create_callback(eventlog_callback_t callback,
    void *callback_arg)
{
	struct eventlog_subscriber *subscriber;

	MPASS(callback != NULL);

	/* Allocate subscriber structure */
	subscriber = malloc(sizeof(*subscriber), M_EVENTLOG, M_ZERO | M_WAITOK);
	MPASS(subscriber != NULL);

	CK_SLIST_INIT(&subscriber->subscriptions);
	subscriber->type = EVENTLOG_SUBSCRIBER_TYPE_CALLBACK;
	subscriber->u.callback.callback = callback;
	subscriber->u.callback.callback_arg = callback_arg;
	mtx_init(&subscriber->dump_pending_mtx, "eventlog dump pending",
	    NULL, MTX_DEF);
	cv_init(&subscriber->dump_pending_cv, "evl_dump");

	/* Add subscriber to global list */
	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_INSERT_HEAD(&evl.subscribers, subscriber, link);
	mtx_unlock(&evl.subscribers_mtx);

	return (subscriber);
}

/*
 * Async dump_state machinery. One eventlog_dump_task per (subscriber,
 * provider) pair is enqueued on evl.dump_tq; the TQ thread publishes
 * (dump_thread, dump_target), invokes provider->dump_callback, then
 * decrements subscriber->dump_pending and signals dump_pending_cv.
 *
 * Subscriber and provider pointers in the task are kept alive by their
 * destroy paths draining the TQ before freeing memory.
 */
struct eventlog_dump_task {
	struct task task;
	struct eventlog_subscriber *subscriber;
	struct eventlog_provider *provider;
};

/*
 * Forward declarations for eventlog_emit_dump_complete(); definitions
 * are further down with the rest of the subscriber write path.
 */
static void eventlog_subscriber_write_event_device(
    struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, uint64_t session_id,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size);
static void eventlog_subscriber_write_event_callback(
    struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, uint64_t session_id,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size);

/*
 * Synthesise an EVENTLOG_DUMP_COMPLETE_ID event for `subscriber` once
 * `provider`'s dump_callback has finished. session_id is
 * EVENTLOG_SESSION_ID_NONE; the level/keyword filter matches
 * SESSION_CREATE/SESSION_END.
 */
static void
eventlog_emit_dump_complete(struct eventlog_provider *provider,
    struct eventlog_subscriber *subscriber)
{
	struct eventlog_event_header hdr;
	struct eventlog_subscription *sub;
	struct iovec iov = { .iov_base = NULL, .iov_len = 0 };
	struct bintime bt;
	bool match = false;

	binuptime(&bt);
	hdr.event_length = (uint16_t)sizeof(hdr);
	hdr.RESERVED = 0;
	hdr.timestamp = bintime2us(&bt);
	hdr.thread_id = (curthread != NULL) ? curthread->td_tid : 0;
	hdr.provider_id = provider->provider_id;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = EVENTLOG_DUMP_COMPLETE_ID;

	smr_enter(evl.smr);
	hdr.cpu = PCPU_GET(cpuid);

	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (sub->provider == provider) {
			if (EVENTLOG_LEVEL_INFO <= sub->level &&
			    (sub->keywords & EVENTLOG_KEYWORD_SESSION) != 0)
				match = true;
			break;
		}
	}

	if (match) {
		if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE) {
			eventlog_subscriber_write_event_device(subscriber,
			    provider, EVENTLOG_SESSION_ID_NONE, &hdr, &iov, 0,
			    0);
		} else {
			eventlog_subscriber_write_event_callback(subscriber,
			    provider, EVENTLOG_SESSION_ID_NONE, &hdr, &iov, 0,
			    0);
		}
	}

	smr_exit(evl.smr);
}

static void
eventlog_dump_task_handler(void *context, int pending __unused)
{
	struct eventlog_dump_task *dt = context;
	struct eventlog_subscriber *subscriber = dt->subscriber;
	struct eventlog_provider *provider = dt->provider;

	/*
	 * No lock around the publication: the single-threaded TQ is the
	 * only writer; other threads' curthread != dump_thread so they
	 * always take the normal subscriber-fanout path regardless of
	 * any torn read.
	 */
	evl.dump_thread = curthread;
	evl.dump_target = subscriber;
	provider->dump_callback(provider, provider->dump_callback_arg);
	eventlog_emit_dump_complete(provider, subscriber);
	evl.dump_target = NULL;
	evl.dump_thread = NULL;

	mtx_lock(&subscriber->dump_pending_mtx);
	KASSERT(subscriber->dump_pending > 0,
	    ("eventlog: dump_pending underflow on %p", subscriber));
	if (--subscriber->dump_pending == 0)
		cv_broadcast(&subscriber->dump_pending_cv);
	mtx_unlock(&subscriber->dump_pending_mtx);

	free(dt, M_EVENTLOG);
}

/*
 * Block until every dump_state task outstanding for this subscriber
 * (queued or running) has finished.
 */
void
eventlog_subscriber_drain_dumps(struct eventlog_subscriber *subscriber)
{

	if (subscriber == NULL)
		return;

	mtx_lock(&subscriber->dump_pending_mtx);
	while (subscriber->dump_pending > 0)
		cv_wait(&subscriber->dump_pending_cv,
		    &subscriber->dump_pending_mtx);
	mtx_unlock(&subscriber->dump_pending_mtx);
}

/*
 * Destroy a subscriber and update provider enablement.
 */
void
eventlog_subscriber_destroy(struct eventlog_subscriber *subscriber)
{
	struct eventlog_subscription *sub, *sub_next;

	if (subscriber == NULL)
		return;

	/*
	 * Drain dump tasks first; they reference this subscriber's
	 * buffers and would UAF if we freed them mid-callback.
	 */
	eventlog_subscriber_drain_dumps(subscriber);

	/* Remove subscriber from global list */
	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_REMOVE(subscriber, link);
	mtx_unlock(&evl.subscribers_mtx);

	/* Update all provider enablements (we're no longer visible) */
	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		eventlog_update_provider_enablement(sub->provider);
	}

	/* Wait for all SMR readers before freeing */
	smr_synchronize(evl.smr);

	/* Free subscriptions, buffers, and subscriber */
	CK_SLIST_FOREACH_SAFE(sub, &subscriber->subscriptions, link, sub_next) {
		free(sub, M_EVENTLOG);
	}

	/* Clean up subscriber based on type */
	if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE) {
		int cpu, maxcpu = mp_maxid + 1;
		struct eventlog_percpu_buffer *percpu_buffers =
		    subscriber->u.device.percpu_buffers;

		if (percpu_buffers != NULL) {
			for (cpu = 0; cpu < maxcpu; cpu++) {
				if (percpu_buffers[cpu].buffers[0] != NULL)
					free(percpu_buffers[cpu].buffers[0],
					    M_EVENTLOG);
				if (percpu_buffers[cpu].buffers[1] != NULL)
					free(percpu_buffers[cpu].buffers[1],
					    M_EVENTLOG);
#ifndef EVENTLOG_HAS_ATOMIC64
				mtx_destroy(&percpu_buffers[cpu].swap_lock);
#endif
			}
			free(percpu_buffers, M_EVENTLOG);
		}
		if (subscriber->u.device.cpu_timestamps != NULL)
			free(subscriber->u.device.cpu_timestamps, M_EVENTLOG);
		if (subscriber->u.device.heap_cpus != NULL)
			free(subscriber->u.device.heap_cpus, M_EVENTLOG);
	}
	/* Callback subscribers don't need cleanup */

	cv_destroy(&subscriber->dump_pending_cv);
	mtx_destroy(&subscriber->dump_pending_mtx);
	free(subscriber, M_EVENTLOG);
}

/*
 * Subscribe to a single provider. Handles both new subscriptions and
 * updating existing ones.
 *
 * On a brand-new subscription (not an in-place update) and only when
 * the provider has a dump_callback, enqueue one task on evl.dump_tq
 * so the provider can replay current state. Re-subscribing does not
 * re-fire the dump.
 */
static void
eventlog_subscriber_add_subscription_one(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, enum eventlog_level level,
    uint32_t keywords, uint32_t flags)
{
	struct eventlog_subscription *sub, *new_sub;
	struct eventlog_dump_task *dt;
	bool newly_subscribed = false;

	new_sub = malloc(sizeof(*new_sub), M_EVENTLOG, M_WAITOK);
	MPASS(new_sub != NULL);
	new_sub->provider = provider;
	new_sub->level = level;
	new_sub->keywords = keywords;

	mtx_lock(&evl.subscribers_mtx);

	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (sub->provider == provider) {
			/* Already subscribed; update in place. */
			sub->level = level;
			sub->keywords = keywords;
			mtx_unlock(&evl.subscribers_mtx);
			free(new_sub, M_EVENTLOG);
			goto update_enablement;
		}
	}

	CK_SLIST_INSERT_HEAD(&subscriber->subscriptions, new_sub, link);
	newly_subscribed = true;

	mtx_unlock(&evl.subscribers_mtx);

update_enablement:

	/* Update provider enablement */
	eventlog_update_provider_enablement(provider);

	if (!newly_subscribed || provider->dump_callback == NULL ||
	    (flags & EVENTLOG_SUBSCRIPTION_DUMP_STATE) == 0)
		return;

	/*
	 * First-time subscribe + dump_callback + DUMP_STATE flag:
	 * enqueue an async dump. Bumping dump_pending under the
	 * subscriber's mtx ensures a racing destroy() either sees the
	 * pending count and waits, or finds none yet and our task is
	 * still scheduled to fire after subscribe returns.
	 *
	 * M_NOWAIT: on failure skip the dump rather than block subscribe;
	 * the live event stream is still delivered.
	 */
	dt = malloc(sizeof(*dt), M_EVENTLOG, M_NOWAIT);
	if (dt == NULL)
		return;
	TASK_INIT(&dt->task, 0, eventlog_dump_task_handler, dt);
	dt->subscriber = subscriber;
	dt->provider = provider;

	mtx_lock(&subscriber->dump_pending_mtx);
	subscriber->dump_pending++;
	mtx_unlock(&subscriber->dump_pending_mtx);

	taskqueue_enqueue(evl.dump_tq, &dt->task);
}

/*
 * Add a subscription to a subscriber.
 * Subscribes to ALL providers matching provider_name (multiple providers
 * may share the same name, e.g., different TCP stacks each registering "tcp").
 * Returns 0 on success, error code on failure.
 *
 * `flags` is a bitmask of EVENTLOG_SUBSCRIPTION_* values; unknown bits
 * return EINVAL. With EVENTLOG_SUBSCRIPTION_DUMP_STATE set, every
 * newly-subscribed provider with a dump_callback gets an asynchronous
 * dump enqueued; eventlog_subscriber_drain_dumps() waits for them.
 */
int
eventlog_subscriber_add_subscription(struct eventlog_subscriber *subscriber,
    const char *provider_name, enum eventlog_level level, uint32_t keywords,
    uint32_t flags)
{
	struct eventlog_provider *provider;
	struct eventlog_provider *matched[EVENTLOG_MAX_PROVIDERS];
	int nmatched = 0;
	int i;

	MPASS(subscriber != NULL);
	MPASS(provider_name != NULL);

	if ((flags & ~EVENTLOG_SUBSCRIPTION_FLAGS_VALID) != 0)
		return (EINVAL);

	/* Find all providers matching the name */
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link) {
		if (strcmp(provider->name, provider_name) == 0 &&
		    nmatched < EVENTLOG_MAX_PROVIDERS)
			matched[nmatched++] = provider;
	}
	mtx_unlock(&evl.providers_lock);

	if (nmatched == 0)
		/* TODO: Support subscribing before provider is registered. */
		return (ENOENT);

	for (i = 0; i < nmatched; i++)
		eventlog_subscriber_add_subscription_one(subscriber,
		    matched[i], level, keywords, flags);

	return (0);
}

/*
 * Update provider enablement based on all active subscribers.
 * Keywords are OR'ed, level is MAX (most verbose) of all subscribers.
 *
 * sessions_lock is held across the recount and per-session update so
 * the subscribers_changed callback fires exactly once per real 0<->N
 * edge. The callback runs after the lock is dropped.
 */
static void
eventlog_update_provider_enablement(struct eventlog_provider *provider)
{
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_subscription *sub;
	enum eventlog_level max_level = EVENTLOG_LEVEL_NONE;
	uint32_t or_keywords = 0;
	bool has_subscribers = false;
	bool transitioned = false;

	MPASS(provider != NULL);

	mtx_lock(&provider->sessions_lock);

	smr_enter(evl.smr);
	CK_LIST_FOREACH(subscriber, &evl.subscribers, link) {
		CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
			if (sub->provider == provider) {
				has_subscribers = true;
				or_keywords |= sub->keywords;
				if (sub->level > max_level)
					max_level = sub->level;
			}
		}
	}
	smr_exit(evl.smr);

	if (provider->has_subscribers != has_subscribers) {
		provider->has_subscribers = has_subscribers;
		transitioned = true;
	}

	/* Update provider enablement */
	if (has_subscribers) {
		provider->keywords = or_keywords;
		provider->level = max_level;
	} else {
		/* No subscribers - disable provider */
		provider->keywords = 0;
		provider->level = EVENTLOG_LEVEL_NONE;
	}

	/* Update all sessions' effective values */
	LIST_FOREACH(session, &provider->sessions, link) {
		eventlog_session_update_effective(session, provider);
	}
	mtx_unlock(&provider->sessions_lock);

	if (transitioned && provider->subscribers_changed != NULL) {
		provider->subscribers_changed(provider, has_subscribers,
		    provider->subscribers_changed_arg);
	}
}

/*
 * Swap buffers for a single CPU if the reader buffer is empty and the
 * active buffer has data.  Returns true if data is available in the
 * reader buffer (either from a swap we performed or a proactive writer
 * swap that already completed); false if there is nothing to read.
 *
 * The swap can lose its CAS to a concurrent writer commit or proactive
 * swap, so we loop, re-checking swap_allowed and commit_pos each time.
 */
static EVENTLOG_INLINING bool
eventlog_swap_cpu_buffer_if_needed(struct eventlog_percpu_buffer *pcpu_buf,
    int cpu)
{
	evtlog_state_t state;

	state = evtlog_load_state(pcpu_buf);
	while (1) {
		if (!evtlog_state_swap_allowed(state)) {
			MPASS(evtlog_state_reader_len(state) > 0);
			return (true);
		}

		if (evtlog_state_commit_pos(state) == 0)
			return (false);

		if (evtlog_try_swap(pcpu_buf, &state))
			return (true);
		/* Lost the swap CAS to a peer; *state is refreshed, retry. */
	}
}

/*
 * Swap buffers for all CPUs if reader buffer is empty and active buffer
 * has data. Builds/preserves the merge heap (min-heap by timestamp) of
 * CPUs that have data. CPUs already in the list from a previous call
 * have data and are skipped (no swap,
 * no reinsert).
 */
static void
eventlog_swap_buffers_if_needed(struct eventlog_subscriber *subscriber)
{
	int cpu;
	struct eventlog_percpu_buffer *pcpu_buf;
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;

	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);

	for (cpu = 0; cpu <= mp_maxid; cpu++) {
		if (timestamps[cpu] < EVENTLOG_TIMESTAMP_SWEPT)
			continue;	/* In heap */
		pcpu_buf = &subscriber->u.device.percpu_buffers[cpu];
		if (eventlog_swap_cpu_buffer_if_needed(pcpu_buf, cpu))
			eventlog_heap_insert(subscriber, (uint16_t)cpu,
			    eventlog_peek_next_timestamp(pcpu_buf));
		else
			timestamps[cpu] = EVENTLOG_TIMESTAMP_NONE;
	}
}

/*
 * Read events from a device subscriber's buffer.
 * Handles both user-space (UIO_USERSPACE) and kernel (UIO_SYSSPACE) uio.
 */
int
eventlog_subscriber_read(struct eventlog_subscriber *subscriber,
    struct uio *uio, int flags)
{
	struct bintime bt;
	uint64_t read_timestamp;
	int error = 0;

	MPASS(subscriber != NULL);
	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);
	MPASS(uio != NULL);

	if (uio->uio_iovcnt != 1 || uio->uio_resid == 0)
		return (EOPNOTSUPP); /* Only one iovec supported */

	/* Swap to get latest data, then check if we have anything to read. */
	eventlog_swap_buffers_if_needed(subscriber);

	if (subscriber->u.device.heap_size == 0) {
		if (flags & FNONBLOCK)
			return (EAGAIN);

		/* Wait for writers to produce data. */
		atomic_store_rel_32(&subscriber->u.device.reader_waiting, 1);
		error = tsleep(subscriber, PCATCH, "evtlogrd", hz);
		atomic_store_rel_32(&subscriber->u.device.reader_waiting, 0);
		if (error != 0 && error != EWOULDBLOCK)
			return (error);

		eventlog_swap_buffers_if_needed(subscriber);
		if (subscriber->u.device.heap_size == 0)
			return (EAGAIN);
	}

	binuptime(&bt);
	read_timestamp = bintime2us(&bt);

	eventlog_read_merged(subscriber, uio, read_timestamp);
	return (0);
}

/*
 * Re-sweep CPUs not in the heap after hitting a timestamp boundary.
 * Picks up events from preempted writers that committed before read_timestamp
 * but whose CPU was previously extracted (no data at extraction time).
 */
static void
eventlog_resweep_idle_cpus(struct eventlog_subscriber *subscriber,
    uint64_t read_timestamp)
{
	int cpu;
	struct eventlog_percpu_buffer *pcpu_buf;
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;

	for (cpu = 0; cpu <= mp_maxid; cpu++) {
		if (timestamps[cpu] != EVENTLOG_TIMESTAMP_NONE)
			continue;	/* In heap or already swept */
		pcpu_buf = &subscriber->u.device.percpu_buffers[cpu];
		if (eventlog_swap_cpu_buffer_if_needed(pcpu_buf, cpu)) {
			uint64_t ts = eventlog_peek_next_timestamp(pcpu_buf);
			if (ts <= read_timestamp) {
				eventlog_heap_insert(subscriber, (uint16_t)cpu,
				    ts);
				continue;
			}
		}
		timestamps[cpu] = EVENTLOG_TIMESTAMP_SWEPT;
	}
}

/*
 * Merge events from all CPUs in timestamp order, copying via uio.
 * Events with timestamps beyond read_timestamp are deferred to the next read.
 * Caller must have called eventlog_swap_buffers_if_needed beforehand.
 */
static EVENTLOG_INLINING void
eventlog_read_merged(struct eventlog_subscriber *subscriber, struct uio *uio,
    uint64_t read_timestamp)
{
	struct eventlog_percpu_buffer *pcpu_buf;
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;

	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);
	MPASS(subscriber->u.device.heap_size > 0);

	/* Take lowest timestamp, copy from that CPU, reinsert when drained. */
	while (uio->uio_resid > 0 && subscriber->u.device.heap_size > 0) {
		uint16_t current_cpu = subscriber->u.device.heap_cpus[0];
		uint64_t max_timestamp, effective_max, next_timestamp;
		bool uio_out_of_space;

		pcpu_buf = &subscriber->u.device.percpu_buffers[current_cpu];
		max_timestamp = eventlog_heap_second_min_timestamp(subscriber);
		effective_max = (max_timestamp < read_timestamp) ?
		    max_timestamp : read_timestamp;

		eventlog_copy_events_from_cpu(subscriber, pcpu_buf, uio,
		    effective_max, &next_timestamp, &uio_out_of_space);

		if (uio_out_of_space)
			break;

		EVENTLOG_VALIDATE_READER(pcpu_buf);
		if (evtlog_state_reader_len(evtlog_load_state(pcpu_buf)) ==
		    pcpu_buf->read_pos) {
			MPASS(next_timestamp == 0);

			/*
			 * Reader buffer fully drained. Atomically clear
			 * reader_len and set swap_allowed in one CAS so
			 * the upper-32-bit and lower-32-bit updates are
			 * inseparable from concurrent writer commits.
			 */
			evtlog_drain_complete(pcpu_buf);

			if (eventlog_swap_cpu_buffer_if_needed(pcpu_buf,
			    current_cpu)) {
				/*
				 * Single CPU swapped; update timestamp and
				 * possibly reinsert.
				 */
				next_timestamp =
				    eventlog_peek_next_timestamp(pcpu_buf);
				if (next_timestamp > read_timestamp) {
					eventlog_heap_extract_min(subscriber);
					eventlog_resweep_idle_cpus(subscriber,
					    read_timestamp);
					continue;
				}
				if (next_timestamp <= max_timestamp) {
					timestamps[current_cpu] =
					    next_timestamp;
					continue;
				}
				/* No longer min; update root and sift down. */
				eventlog_heap_update_root(subscriber,
				    next_timestamp);
			} else {
				/* Buffer drained, no swap: remove from heap. */
				eventlog_heap_extract_min(subscriber);
			}
			continue;
		}

		if (next_timestamp > read_timestamp) {
			/* Remaining events are past the epoch boundary. */
			eventlog_heap_extract_min(subscriber);
			eventlog_resweep_idle_cpus(subscriber, read_timestamp);
			continue;
		}

		/* Buffer has more data within epoch: update root and sift. */
		MPASS(next_timestamp != 0);
		eventlog_heap_update_root(subscriber, next_timestamp);
	}
}

/*
 * Copy events from a CPU buffer up to a given timestamp threshold.
 * UIO_USERSPACE uses copyout; UIO_SYSSPACE uses bcopy directly.
 * Stops if we run out of space.
 */
static EVENTLOG_INLINING void
eventlog_copy_events_from_cpu(
    struct eventlog_subscriber *subscriber,
    struct eventlog_percpu_buffer *pcpu_buf, struct uio *uio,
    uint64_t max_timestamp, uint64_t *next_timestamp_out,
    bool *uio_out_of_space_out)
{
	uint32_t bytes_consumed = 0;
	uint64_t next_timestamp;
	evtlog_state_t cur_state = evtlog_load_state(pcpu_buf);
	int reader = 1 - evtlog_state_active(cur_state);
	size_t space_avail = uio->uio_resid;
	uint32_t available = evtlog_state_reader_len(cur_state) -
	    pcpu_buf->read_pos;

	MPASS(pcpu_buf != NULL);
	MPASS(uio != NULL);
	MPASS(next_timestamp_out != NULL);
	MPASS(uio_out_of_space_out != NULL);
	EVENTLOG_VALIDATE_READER(pcpu_buf);

	*uio_out_of_space_out = false;

	/* Scan events to compute contiguous batch within max_timestamp. */
	do {
		struct eventlog_event_header hdr;
		uint32_t offset = pcpu_buf->read_pos + bytes_consumed;

		MPASS((available - bytes_consumed) >=
		    sizeof(struct eventlog_event_header));
		MPASS(offset < pcpu_buf->buffer_size);
		memcpy(&hdr, (uint8_t *)pcpu_buf->buffers[reader] + offset,
		    sizeof(struct eventlog_event_header));

		MPASS(hdr.event_length >= sizeof(struct eventlog_event_header));
		MPASS(hdr.event_length <= (available - bytes_consumed));
		MPASS(offset + hdr.event_length <= pcpu_buf->buffer_size);
		MPASS((available - bytes_consumed - hdr.event_length) == 0 ||
		    (available - bytes_consumed - hdr.event_length)
		    >= sizeof(struct eventlog_event_header));

		next_timestamp = hdr.timestamp;

		if (next_timestamp > max_timestamp)
			break;

		if (bytes_consumed + hdr.event_length > space_avail) {
			*uio_out_of_space_out = true;
			break;
		}

		bytes_consumed += hdr.event_length;

	} while (available > bytes_consumed);

	/* Copy the data into the uio buffer. */
	if (bytes_consumed > 0) {
		const char *src;

		src = (char *)((uint8_t *)pcpu_buf->buffers[reader] +
		    pcpu_buf->read_pos);

		if (uio->uio_segflg == UIO_USERSPACE) {
			KASSERT(THREAD_CAN_SLEEP(),
			    ("eventlog copyout in non-sleepable context"));
			if (copyout(src, uio->uio_iov[0].iov_base,
			    bytes_consumed) != 0) {
				*uio_out_of_space_out = true;
				goto out;
			}
			uioadvance(uio, bytes_consumed);
		} else {
			bcopy(src, uio->uio_iov[0].iov_base, bytes_consumed);
			uioadvance(uio, bytes_consumed);
		}

		pcpu_buf->read_pos += bytes_consumed;
		EVENTLOG_VALIDATE_READER(pcpu_buf);

		if (pcpu_buf->read_pos ==
		    evtlog_state_reader_len(evtlog_load_state(pcpu_buf)))
			next_timestamp = 0;
	}

out:
	*next_timestamp_out = next_timestamp;
}

/*
 * Write an event to a device-based subscriber's per-CPU buffer.  Format:
 * header (includes provider_id, session_id, event_id) + payload.
 *
 * Implements the writer side of the SYNC MODEL at the top of this file;
 * the four numbered steps below correspond to (1)-(4) in that comment.
 *
 * Wakes the reader only after a proactive swap (a full buffer's worth of
 * data just moved into the reader buffer).  Normal commits do not wake;
 * the reader is woken in batches.
 */
static EVENTLOG_INLINING void
eventlog_subscriber_write_event_device(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, uint64_t session_id,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size)
{
	struct eventlog_percpu_buffer *pcpu_buf;
	uint8_t *buf;
	int active;
	uint32_t commit_pos;
	evtlog_state_t state;
	size_t event_len = hdr->event_length;
	bool did_swap = false;
	int i;

	MPASS(subscriber != NULL);
	MPASS(provider != NULL);
	MPASS(hdr != NULL);
	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);
	MPASS(hdr->cpu >= 0 && hdr->cpu <= mp_maxid);
#ifdef INVARIANTS
	size_t expected_length = sizeof(struct eventlog_event_header) +
	    payload_size;
	MPASS(hdr->event_length == expected_length);
#endif

	pcpu_buf = &subscriber->u.device.percpu_buffers[hdr->cpu];
	MPASS(event_len <= pcpu_buf->buffer_size);

#ifndef EVENTLOG_HAS_ATOMIC64
	/* NMI-on-lock-holder deadlock guard; see SYNC MODEL. */
	if (__predict_false(mtx_owned(&pcpu_buf->swap_lock))) {
		atomic_add_long(&subscriber->dropped_events, 1);
		return;
	}
#endif

	/* (1) Load state to get active buffer and write offset. */
	state = evtlog_load_state(pcpu_buf);
	active = evtlog_state_active(state);
	commit_pos = evtlog_state_commit_pos(state);

write:
	/*
	 * (2) Check capacity (re-derived every retry: an NMI or peer may
	 * have advanced commit_pos since we last loaded it).
	 */
	if (__predict_false(commit_pos + event_len > pcpu_buf->buffer_size)) {
		if (!did_swap && evtlog_state_swap_allowed(state)) {
			evtlog_try_swap(pcpu_buf, &state);
			/*
			 * *state holds the post-swap packed state regardless
			 * of who won; re-derive active/commit_pos from it so
			 * we never write at offset 0 over a peer's event.
			 */
			active = evtlog_state_active(state);
			commit_pos = evtlog_state_commit_pos(state);
			did_swap = true;
			if (__predict_false(commit_pos + event_len >
			    pcpu_buf->buffer_size)) {
				/*
				 * No room after the swap; a same-CPU NMI
				 * writer filled the new buffer.  Drop.
				 */
				atomic_add_long(&subscriber->dropped_events, 1);
				return;
			}
		} else {
			atomic_add_long(&subscriber->dropped_events, 1);
			return;
		}
	}

	/* (3) Write: copy header then iov segments at commit_pos. */
	buf = (uint8_t *)pcpu_buf->buffers[active] + commit_pos;
	memcpy(buf, hdr, sizeof(struct eventlog_event_header));
	buf += sizeof(struct eventlog_event_header);
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf, iov[i].iov_base, iov[i].iov_len);
			buf += iov[i].iov_len;
		}
	}

	/*
	 * (4) Commit: CAS to advance commit_pos.  If active or commit_pos
	 * moved (peer swap or NMI commit), our memcpy is at a stale
	 * offset and we redo the write via `goto write`.  Reader drain
	 * only moves the upper bits or swap_allowed; the memcpy stays
	 * valid and we just retry the CAS.
	 */
	while (__predict_false(!evtlog_try_commit(pcpu_buf, &state,
	    (uint32_t)event_len))) {
		if (evtlog_state_active(state) != active ||
		    evtlog_state_commit_pos(state) != commit_pos) {
			active = evtlog_state_active(state);
			commit_pos = evtlog_state_commit_pos(state);
			goto write;
		}
	}

	/*
	 * Wake reader only after a proactive swap - a full buffer's worth
	 * of data is now in the reader buffer.
	 */
	if (did_swap &&
	    atomic_cmpset_32(&subscriber->u.device.reader_waiting, 1, 0))
		wakeup(subscriber);
}

/*
 * Deliver an event to a callback subscriber. The payload is passed as
 * the same scatter/gather iovec the write path carries internally;
 * callbacks that need a flat payload compact it themselves.
 */
static EVENTLOG_INLINING void
eventlog_subscriber_write_event_callback(
    struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, uint64_t session_id,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size)
{
	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_CALLBACK);
	MPASS(subscriber->u.callback.callback != NULL);

	subscriber->u.callback.callback(hdr, provider->name,
	    provider->name_len, session_id, iov, iovcnt, payload_size,
	    subscriber->u.callback.callback_arg);
}

/*
 * Write an event to a subscriber.
 * Checks if subscriber has matching subscription and level/keywords match.
 * Routes to device or callback handler based on subscriber type.
 */
static void
eventlog_subscriber_write_event(struct eventlog_subscriber *subscriber,
    struct eventlog_session *session, struct eventlog_event_header *hdr,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    uint16_t event_length, enum eventlog_level level, uint32_t keywords)
{
	struct eventlog_subscription *sub;
	struct eventlog_provider *provider;

	MPASS(subscriber != NULL);
	MPASS(session != NULL);
	MPASS(session->provider != NULL);
	MPASS(hdr != NULL);
	MPASS(event_length <= UINT16_MAX);

	provider = session->provider;

	/* Note: Called within SMR read section. */
	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (sub->provider != provider)
			continue;
		/*
		 * Only one subscription per provider per subscriber: return
		 * unconditionally below, even if the filter doesn't match.
		 */
		if (level <= sub->level &&
		    (keywords & sub->keywords) != 0) {
			if (subscriber->type ==
			    EVENTLOG_SUBSCRIBER_TYPE_DEVICE)
				eventlog_subscriber_write_event_device(
				    subscriber, provider,
				    session->session_id, hdr, iov, iovcnt,
				    payload_size);
			else
				eventlog_subscriber_write_event_callback(
				    subscriber, provider,
				    session->session_id, hdr, iov, iovcnt,
				    payload_size);
		}
		return;
	}
}

/*
 * Query subscriber statistics.
 */
void
eventlog_subscriber_get_stats(struct eventlog_subscriber *subscriber,
    struct eventlog_stats *stats)
{
	MPASS(subscriber != NULL);
	MPASS(stats != NULL);

	stats->dropped_events = (uint64_t)atomic_load_acq_long(
	    &subscriber->dropped_events);
}

/*
 * Device operations
 */

/*
 * Device open handler. Subscriber is created via CREATE IOCTL.
 * Only prison0 (the host) may open: the eventlog framework is host-global
 * and not safe to expose to jailed processes.
 */
static int
eventlog_dev_open(struct cdev *dev, int flags, int devtype __unused,
    struct thread *td)
{
	if (jailed(td->td_ucred))
		return (EPERM);

	/* Only allow read access */
	if (flags & (FWRITE | FEXEC | FAPPEND | O_TRUNC))
		return (ENODEV);
	return (0);
}

/*
 * Device close handler.
 */
static int
eventlog_dev_close(struct cdev *dev __unused, int flags __unused,
    int devtype __unused, struct thread *td __unused)
{
	return (0); /* Cleanup is handled by eventlog_dev_clear_cdevpriv */
}

/*
 * Cleanup cdevpriv data when device is closed.
 */
static void
eventlog_dev_clear_cdevpriv(void *data)
{
	/* Handle case where CREATE failed and no subscriber was created */
	if (data == NULL)
		return;

	eventlog_subscriber_destroy((struct eventlog_subscriber *)data);
}

/*
 * Device ioctl handler.
 */
static int
eventlog_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	struct eventlog_subscriber *subscriber;
	struct eventlog_subscription_req *sub_req;
	uint32_t i;
	int error;

	switch (IOCBASECMD(cmd)) {
	case IOCBASECMD(EVENTLOG_IOCTL_CREATE_BASE): {
		size_t base_size;

		base_size = __builtin_offsetof(
		    struct eventlog_create_req, subscriptions);
		u_int ioctl_len = IOCPARM_LEN(cmd);
		struct eventlog_create_req *req =
		    (struct eventlog_create_req *)data;

		/* Check if subscriber already exists */
		error = devfs_get_cdevpriv((void **)&subscriber);
		if (error == 0)
			return (EEXIST); /* Subscriber already exists */
		if (error != ENOENT)
			return (error);  /* Something weird is going on */

		/* Validate request size */
		if (ioctl_len < base_size + sizeof(uint32_t) ||
		    ioctl_len < (base_size + req->count *
		    sizeof(struct eventlog_subscription_req)))
			return (EINVAL);

		if (req->buffer_size_per_cpu < EVENTLOG_BUFFER_SIZE_MIN ||
		    req->buffer_size_per_cpu > EVENTLOG_BUFFER_SIZE_MAX)
			return (EINVAL);

		/* Create subscriber with specified buffer size */
		subscriber = eventlog_subscriber_create_device(
		    req->buffer_size_per_cpu);
		MPASS(subscriber != NULL);

		/* Process each subscription before setting cdevpriv. */
		for (i = 0; i < req->count; i++) {
			sub_req = &req->subscriptions[i];
			error = eventlog_subscriber_add_subscription(
			    subscriber, sub_req->provider_name, sub_req->level,
			    sub_req->keywords, sub_req->flags);
			if (error != 0) {
				eventlog_subscriber_destroy(subscriber);
				return (error);
			}
		}

		/* Only store subscriber after all subscriptions succeed. */
		error = devfs_set_cdevpriv(subscriber,
		    eventlog_dev_clear_cdevpriv);
		if (error != 0) {
			eventlog_subscriber_destroy(subscriber);
			return (error);
		}

		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_DESTROY): {
		error = devfs_get_cdevpriv((void **)&subscriber);
		if (error != 0)
			return (error);

		eventlog_subscriber_destroy(subscriber);
		devfs_set_cdevpriv(NULL, NULL);

		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_GET_STATS): {
		u_int ioctl_len = IOCPARM_LEN(cmd);
		if (ioctl_len < sizeof(struct eventlog_stats))
			return (EINVAL);

		error = devfs_get_cdevpriv((void **)&subscriber);
		if (error != 0)
			return (error);

		eventlog_subscriber_get_stats(subscriber,
		    (struct eventlog_stats *)data);

		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_GET_PROVIDERS): {
		struct eventlog_get_providers_resp *resp;
		struct eventlog_subscription *sub;
		uint32_t count = 0;

		error = devfs_get_cdevpriv((void **)&subscriber);
		if (error != 0)
			return (error);

		resp = (struct eventlog_get_providers_resp *)data;
		memset(resp, 0, sizeof(*resp));

		smr_enter(evl.smr);
		CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
			if (count >= EVENTLOG_MAX_PROVIDERS)
				break;
			resp->providers[count].provider_id =
			    sub->provider->provider_id;
			strlcpy(resp->providers[count].name,
			    sub->provider->name,
			    EVENTLOG_PROVIDER_NAME_MAX);
			count++;
		}
		smr_exit(evl.smr);
		resp->count = count;

		return (0);
	}

	default:
		return (ENOTTY);
	}
}

/*
 * Device read handler - reads from subscriber's per-CPU buffers.
 */
static int
eventlog_dev_read(struct cdev *dev, struct uio *uio, int flags)
{
	int error;
	struct eventlog_subscriber *subscriber;

	error = devfs_get_cdevpriv((void **)&subscriber);
	if (error != 0)
		return (error);

	return (eventlog_subscriber_read(subscriber, uio, flags));
}

static struct cdevsw eventlog_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	eventlog_dev_open,
	.d_close =	eventlog_dev_close,
	.d_read =	eventlog_dev_read,
	.d_ioctl =	eventlog_dev_ioctl,
	.d_name =	"eventlog",
};

/* Initialize single system-wide eventlog device */
static void
eventlog_device_init(void *unused)
{
	struct make_dev_args mda;
	int error;

	make_dev_args_init(&mda);
	mda.mda_devsw = &eventlog_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_OPERATOR;
	mda.mda_mode = 0640;
	mda.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	error = make_dev_s(&mda, &evl.device, "eventlog");
	if (error != 0) {
		printf("eventlog: failed to create device: %d\n", error);
		return;
	}
}
SYSINIT(eventlog_device, SI_SUB_DRIVERS, SI_ORDER_MIDDLE,
    eventlog_device_init, NULL);
