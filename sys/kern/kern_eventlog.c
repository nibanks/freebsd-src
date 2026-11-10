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
 *
 * MEMORY ACCESS AND SYNCHRONIZATION MODEL
 * =======================================
 * Per-CPU single-producer / single-consumer (SPSC) ring buffer: one ring
 * per CPU with two independent byte cursors, head (producer) and tail
 * (consumer), that increase monotonically mod 2^32.  The physical slot for
 * a cursor is (cursor & buffer_mask); buffer_size is a power of two.
 * (head - tail) is the number of bytes held (0 == empty, buffer_size ==
 * full) -- unambiguous because the cursors are monotonic, not wrapped.
 *
 * Concurrency: exactly one producer per CPU and one consumer.  The write
 * path enters via smr_enter() (critical_enter()), which disables preemption
 * and pins the writer to one CPU; the subsystem does not support re-entrant
 * logging on a CPU (a nested eventlog_event_write() would recurse into
 * smr_enter()).  So head has a single writer (the producer) and tail has a
 * single writer (the reader).  Because each cursor has exactly one writer,
 * publication needs only word-sized release stores and acquire loads -- no
 * CAS, no read-modify-write, no 64-bit atomic, and no lock, on every
 * architecture.  head and tail live on separate cache lines, so the
 * producer and consumer never write-share a line.
 *
 * Writer:
 *   (1) Load head (own copy) and acquire-load tail; used = head - tail.
 *   (2) If the record would straddle the physical end, plan to skip the
 *       remaining tail bytes (a PAD record when a header fits, else an
 *       implicit sub-header gap) and place the record at offset 0.
 *   (3) If used + reservation > buffer_size, drop.  Writers NEVER block or
 *       spin on the reader.
 *   (4) memcpy the header + payload at the slot, then publish with a single
 *       release store of the new head.  The reader observes either the old
 *       head (no new data) or the new head (record fully written).
 *
 * Reader (single consumer): acquire-load head; walk complete records from
 * tail in timestamp order (merged across CPUs), copying them out and
 * advancing tail with a release store.  A leading wrap PAD (or sub-header
 * end gap) is skipped by advancing tail to the next buffer boundary.  No
 * swap, no drain handshake: draining is simply tail catching up to head.
 *
 * The cross-CPU timestamp merge (min-heap + epoch/resweep) operates above
 * this layer and is independent of the per-CPU ring mechanics.
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
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/jail.h>
#include <sys/proc.h>
#include <sys/priv.h>
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
#include <sys/pcpu.h>	/* zpcpu_get() for the write-path re-entrancy guard */
#include <sys/time.h>
#include <sys/limits.h>
#include <machine/cpu.h>
#include <machine/atomic.h>
#include <sys/conf.h>
#include <fs/devfs/devfs.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/libkern.h>
#include <sys/ioccom.h>
#include <sys/filio.h>
#include <sys/time.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_param.h>
#include <vm/vm_radix.h>
#include <vm/uma.h>
#include <crypto/sha2/sha256.h>

/* Used to disable inlining to help debug performance issues via flamegraphs. */
#define EVENTLOG_INLINING	//__noinline

MALLOC_DEFINE(M_EVENTLOG, "eventlog", "eventlog subsystem");

/* Full definition of eventlog_session - private to this file; header has partial/forward only */
struct eventlog_session {
	enum eventlog_level effective_level;
	uint32_t effective_keywords;
	/* Private fields - only visible in this file */
	struct eventlog_provider *provider;
	LIST_ENTRY(eventlog_session) link;
	uint64_t session_id;	/* Unique identifier (e.g., inp_gencnt for TCP) */
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
	u_long auto_ratio;		/* kern.eventlog.<name>.auto_ratio, if capable */
	volatile u_long auto_ratio_cur;
	LIST_ENTRY(eventlog_provider_stats) link;
	counter_u64_t sessions_created;
	counter_u64_t sessions_active;
	counter_u64_t sessions_enabled;
	struct sysctl_ctx_list sysctl_ctx;
	struct sysctl_oid *sysctl_node;	/* kern.eventlog.<name>; exposed
					 * via eventlog_provider_get_sysctl_node(). */
	char name[EVENTLOG_PROVIDER_NAME_MAX];
};

struct eventlog_user_channel;	/* user-space provider channel (defined below) */

/*
 * One outstanding state-dump request delegated to a user-space provider.
 * Linked on the target subscriber's user_dumps list (under its
 * dump_pending_mtx); identifies the owning channel/provider so the request
 * can be matched by DUMP_DONE or cancelled on channel/subscriber teardown.
 */
struct eventlog_user_dump {
	TAILQ_ENTRY(eventlog_user_dump) link;
	struct eventlog_user_channel *chan;
	uint16_t provider_id;
};

/* Full definition of eventlog_provider */
struct eventlog_provider {
	struct mtx sessions_lock;
	LIST_HEAD(, eventlog_session) sessions;
	LIST_ENTRY(eventlog_provider) link;
	struct eventlog_provider_stats *stats;
	/* For is_userspace providers: owning fd channel (control queue). */
	struct eventlog_user_channel *chan;
	eventlog_provider_dump_state_t dump_callback;
	void *dump_callback_arg;
	eventlog_default_changed_t default_changed;
	void *default_changed_arg;
	eventlog_subscribers_changed_t subscribers_changed;
	void *subscribers_changed_arg;
	enum eventlog_level level;
	uint32_t keywords;
	const void *decode_blob;	/* see eventlog_provider_config */
	size_t decode_blob_size;
	/* SHA-256(decode_blob) truncated; content-addressed decode key. */
	uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	bool has_subscribers;		/* tracked under sessions_lock */
	bool is_userspace;		/* registered by a user-space process */
	/*
	 * decode_blob points at a kernel copy this provider owns and must free
	 * on destroy (true for user-space providers, whose blob is copied in
	 * from userland); false when the blob is borrowed immortal static
	 * storage handed in by an in-kernel provider.
	 */
	bool decode_blob_owned;
	/* uid charged decode_blob_size bytes at registration (see
	 * eventlog_ring_quota); refunded on destroy. */
	uid_t blob_charge_uid;
	/*
	 * For user-space providers only: kernel mapping of this provider's
	 * enablement slot within the channel's mmap'd page (NULL otherwise).
	 * eventlog_update_provider_enablement() publishes the aggregated
	 * level/keywords here so the generated _ENABLED() macro can gate
	 * without a system call.  Owned by the fd's struct
	 * eventlog_user_channel, which outlives the window in which this
	 * pointer is dereferenced.
	 */
	struct eventlog_enable_page *user_enable;
	/*
	 * For user-space providers: the session counts this fd last reported
	 * via EVENTLOG_IOCTL_REPORT_STATS.  The handler folds the delta from
	 * these into the shared stats counters; the dtor backs out the last
	 * active/enabled contribution (created stays, being monotonic).
	 */
	uint64_t reported_created;
	uint64_t reported_active;
	uint64_t reported_enabled;
	uint16_t provider_id;		/* Unique ID assigned on registration */
	uint8_t name_len;		/* excluding null terminator */
	char name[EVENTLOG_PROVIDER_NAME_MAX];
};

/* Full definition of eventlog_subscription.
 * CK_SLIST for lock-free traversal in SMR read path. */
struct eventlog_subscription {
	CK_SLIST_ENTRY(eventlog_subscription) link;
	struct eventlog_provider *provider;
	enum eventlog_level level;
	uint32_t keywords;
};

/*
 * Per-CPU single-producer / single-consumer ring buffer.  See "MEMORY
 * ACCESS AND SYNCHRONIZATION MODEL" at the top of this file; this block
 * documents only the data layout.
 *
 * head/tail are byte cursors that increase monotonically mod 2^32; the
 * physical slot for a cursor is (cursor & buffer_mask), so buffer_size
 * must be a power of two.  (head - tail) is the number of bytes currently
 * held (0 == empty, buffer_size == full); this is unambiguous because the
 * cursors are monotonic rather than wrapped, and buffer_size <= 1 GB keeps
 * the fill level well under 2^31.
 *
 * Exactly one producer per CPU (the SMR critical section pins the writer
 * and disables preemption) and one consumer (the reader).  The producer
 * owns head and only reads tail; the consumer owns tail and only reads
 * head.  Each cursor has a single writer, so publication needs only
 * word-sized release stores / acquire loads -- no CAS, no 64-bit atomic,
 * no lock.  head and tail sit on separate cache lines.
 */

struct eventlog_percpu_buffer {
	uint8_t *buffer;		/* single ring, buffer_size bytes */
	uint32_t buffer_size;		/* power of two */
	uint32_t buffer_mask;		/* buffer_size - 1 */
	volatile uint32_t head;		/* producer cursor (bytes, monotonic) */
	volatile uint32_t __aligned(CACHE_LINE_SIZE) tail; /* consumer cursor */
} __aligned(CACHE_LINE_SIZE);
CTASSERT(offsetof(struct eventlog_percpu_buffer, tail) % CACHE_LINE_SIZE == 0);

/* Round up to a power of two, capped at the 1 GB buffer maximum. */
static inline uint32_t
eventlog_ring_pow2(uint32_t v)
{
	uint32_t p = 1;

	while (p < v && p < (1U << 30))
		p <<= 1;
	return (p);
}

/*
 * Reader-only: advance tail past a leading wrap pad (a zero-length header,
 * or a sub-header gap at the physical end left when a record could not fit).
 * After this returns, the ring is either empty (head == tail) or tail
 * points at a real event that does not straddle the buffer end.  At most
 * one pad sits in [tail, head): the writer never pads at offset 0.
 *
 * Returns the acquire-loaded head observed for this skip, so callers that
 * need head do not have to load it again.
 */
static EVENTLOG_INLINING uint32_t
eventlog_ring_skip_pad(struct eventlog_percpu_buffer *pcpu_buf)
{
	uint32_t size = pcpu_buf->buffer_size;
	uint32_t mask = pcpu_buf->buffer_mask;
	uint32_t head = atomic_load_acq_32(&pcpu_buf->head);
	uint32_t tail = pcpu_buf->tail;
	uint32_t offset = tail & mask;
	struct eventlog_event_header hdr;

	if (head == tail)
		return (head);
	if (size - offset < sizeof(hdr))
		atomic_store_rel_32(&pcpu_buf->tail, tail + (size - offset));
	else {
		memcpy(&hdr, pcpu_buf->buffer + offset, sizeof(hdr));
		if (hdr.event_length == 0)
			atomic_store_rel_32(&pcpu_buf->tail,
			    tail + (size - offset));
	}
	return (head);
}

/*
 * INVARIANTS validation: walk the committed region [tail, head) and verify
 * every record parses cleanly -- valid length, no straddle of the physical
 * end, wrap pads/sub-header gaps accounted for -- and that the walk lands
 * exactly on head.  O(bytes held), so INVARIANTS-only.
 */
#ifdef INVARIANTS
static inline void
eventlog_validate_ring(struct eventlog_percpu_buffer *pcpu, int line)
{
	uint32_t size = pcpu->buffer_size;
	uint32_t mask = pcpu->buffer_mask;
	uint32_t head = atomic_load_acq_32(&pcpu->head);
	uint32_t tail = pcpu->tail;
	uint32_t pos = tail;
	struct eventlog_event_header hdr;

	KASSERT((head - tail) <= size,
	    ("eventlog_validate_ring: used %u > size %u (line %d)",
	    head - tail, size, line));

	while (pos != head) {
		uint32_t offset = pos & mask;
		uint32_t remain = head - pos;

		if (size - offset < sizeof(hdr)) {
			/* Sub-header end gap == implicit wrap. */
			KASSERT((size - offset) <= remain,
			    ("eventlog_validate_ring: gap %u > remain %u (line %d)",
			    size - offset, remain, line));
			pos += (size - offset);
			continue;
		}
		memcpy(&hdr, pcpu->buffer + offset, sizeof(hdr));
		if (hdr.event_length == 0) {
			/* Wrap pad extends to the physical end. */
			KASSERT((size - offset) <= remain,
			    ("eventlog_validate_ring: pad %u > remain %u (line %d)",
			    size - offset, remain, line));
			pos += (size - offset);
			continue;
		}
		KASSERT(hdr.event_length >= sizeof(hdr),
		    ("eventlog_validate_ring: bad event_length %u at %u (line %d)",
		    hdr.event_length, offset, line));
		KASSERT(offset + hdr.event_length <= size,
		    ("eventlog_validate_ring: event straddles end at %u len %u (line %d)",
		    offset, hdr.event_length, line));
		KASSERT(hdr.event_length <= remain,
		    ("eventlog_validate_ring: event overruns head at %u len %u (line %d)",
		    offset, hdr.event_length, line));
		pos += hdr.event_length;
	}
	KASSERT(pos == head,
	    ("eventlog_validate_ring: walk ended at %u != head %u (line %d)",
	    pos, head, line));
}
#define EVENTLOG_VALIDATE_READER(pcpu_buf) \
	eventlog_validate_ring((pcpu_buf), __LINE__)
#else
#define EVENTLOG_VALIDATE_READER(pcpu_buf) do { } while (0)
#endif

static inline uint64_t
eventlog_read_timestamp(const void *buf)
{
	return (((const struct eventlog_event_header *)buf)->timestamp);
}

/* Sentinel for timestamp: no next-event timestamp. */
#define EVENTLOG_TIMESTAMP_NONE	UINT64_MAX
/* Sentinel: CPU already checked by resweep during this read (skip next time). */
#define EVENTLOG_TIMESTAMP_SWEPT (UINT64_MAX - 1)

/*
 * Skip any leading wrap pad and report the oldest unread event's timestamp.
 * Returns EVENTLOG_TIMESTAMP_NONE when the ring is empty.
 */
static EVENTLOG_INLINING uint64_t
eventlog_ring_peek(struct eventlog_percpu_buffer *pcpu_buf)
{
	uint32_t head = eventlog_ring_skip_pad(pcpu_buf);
	uint32_t tail = pcpu_buf->tail;

	if (head == tail)
		return (EVENTLOG_TIMESTAMP_NONE);
	return (eventlog_read_timestamp(
	    pcpu_buf->buffer + (tail & pcpu_buf->buffer_mask)));
}

/*
 * Per-subscriber bookkeeping for one user-space producer channel.
 *
 * A "stream" is one producer channel's (independent, internally
 * time-ordered) ring.  Its events are buffered in a dedicated
 * pseudo-CPU ring at percpu_buffers[maxcpu + slot] so the
 * normal per-CPU merge machinery handles ordering for free; this
 * struct holds only the watermark/join state the merge needs.
 *
 * armed/join_wc implement the late-join protocol: when a stream first
 * delivers events to a subscriber that is already reading, the
 * subscriber's consumer watermark (consumer_wc) is already ahead of the
 * stream's data.  We record join_wc, drop events older than it
 * (unorderable), and hold the merge boundary at join_wc until the
 * stream's ws catches up, then "arm" it into the normal merge.
 *
 * Protected by subscriber->u.device.user_lock.
 */
struct eventlog_user_stream {
	bool		active;		/* Slot in use */
	bool		armed;		/* Participating in the normal merge */
	uint32_t	channel_id;	/* Owning producer channel */
	uint16_t	stream_id;	/* Producer substream id */
	uint16_t	active_idx;	/* Index into user_active[] while active */
	int16_t		hnext;		/* Next slot in hash bucket, or -1 */
	uint64_t	ws;		/* Watermark: delivered through this ts */
	uint64_t	join_wc;	/* consumer_wc when the stream joined */
	uint64_t	last_ts;	/* Highest ts buffered (monotonicity check) */
	uint64_t	last_push_us;	/* Uptime us of the last push (liveness) */
};

/*
 * Remembered subscription request, used to (re)bind providers that
 * register after the subscriber subscribed.  Recorded for every
 * add_subscription call; consulted by eventlog_provider_create.
 * Protected by evl.subscribers_mtx.
 */
struct eventlog_sub_spec {
	STAILQ_ENTRY(eventlog_sub_spec) link;
	enum eventlog_level level;
	uint32_t keywords;
	uint32_t flags;
	char name[EVENTLOG_PROVIDER_NAME_MAX];
};

/* Full definition of eventlog_subscriber (internal only) */
CK_LIST_HEAD(eventlog_subscriber_head, eventlog_subscriber);
struct eventlog_subscriber {
	CK_LIST_ENTRY(eventlog_subscriber) link;
	CK_SLIST_HEAD(, eventlog_subscription) subscriptions;
	STAILQ_HEAD(, eventlog_sub_spec) specs;	/* For late provider binding */
	enum eventlog_subscriber_type type;

	union {
		/* Device-based subscriber: per-CPU buffers */
		struct {
			struct eventlog_percpu_buffer *percpu_buffers;
			uint32_t buffer_size_per_cpu;
			volatile uint32_t reader_waiting;	/* Atomic: non-zero if reader is waiting */
			uint64_t *cpu_timestamps;	/* [total_sources] next-event timestamp per source */
			uint16_t *heap_cpus;	/* Min-heap of source indices by timestamp */
			uint16_t heap_size;	/* Number of sources in heap */
			/*
			 * User-space provider support.  Real CPUs occupy
			 * source indices [0, maxcpu); user streams occupy
			 * [maxcpu, total_sources).  Metadata arrays are sized
			 * to the kern.eventlog.max_user_streams cap at CREATE,
			 * but per-stream ring buffers (in percpu_buffers[] at
			 * the user-stream sources) are allocated lazily on
			 * first push and freed when a stream is reclaimed.  A
			 * compact active-slot list and a (provider,stream)->slot
			 * hash keep push assignment and read-side sweeps O(live
			 * streams), not O(cap).
			 */
			uint16_t maxcpu;		/* mp_maxid + 1 */
			uint16_t total_sources;		/* maxcpu + user_stream_cap */
			uint16_t user_stream_cap;	/* Capacity of user_streams[] (KMAX) */
			uint16_t user_stream_active;	/* Live entries in user_active[] */
			uint32_t user_buffer_size;	/* Per-user-stream buffer size */
			struct eventlog_user_stream *user_streams; /* [user_stream_cap] */
			uint16_t *user_active;		/* [cap] compact live-slot indices */
			int16_t *user_hash;		/* [hash_size] bucket heads, -1 empty */
			uint32_t user_hash_mask;	/* hash_size - 1 */
			struct mtx user_lock;	/* Protects user_streams[] metadata */
			uint64_t consumer_wc;	/* Boundary delivered to consumer so far */
			uint64_t commit_seq;	/* Bumped on empty->nonempty publish */
			uint64_t swept_seq;		/* commit_seq at last resweep */
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
	/*
	 * Outstanding state-dump requests delegated to user-space providers,
	 * one per (channel, provider).  Protected by dump_pending_mtx.  The
	 * producer's DUMP_DONE, its channel teardown, or this subscriber's
	 * own teardown clears each entry and drops a dump_pending reference.
	 */
	TAILQ_HEAD(, eventlog_user_dump) user_dumps;
	uint64_t subscriber_id;		/* Stable id echoed in control events */

	/* Statistics */
	volatile u_long dropped_events;
	volatile u_long user_dropped_full;	/* user stream buffer full */
	volatile u_long user_dropped_prejoin;	/* older than join point */
	volatile u_long user_dropped_late;	/* past the lateness ceiling */
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
		    timestamps[heap_cpus[left]] < timestamps[heap_cpus[smallest]])
			smallest = left;
		if (right < *heap_size &&
		    timestamps[heap_cpus[right]] < timestamps[heap_cpus[smallest]])
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
		    timestamps[heap_cpus[left]] < timestamps[heap_cpus[smallest]])
			smallest = left;
		if (right < *heap_size &&
		    timestamps[heap_cpus[right]] < timestamps[heap_cpus[smallest]])
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

/*
 * Per-uid wired ring-memory accounting.  Producing is unprivileged, so an
 * untrusted process could otherwise wire arbitrary kernel memory by setting
 * up many large rings; each uid's total is capped (root exempt).
 */
struct eventlog_ring_quota {
	LIST_ENTRY(eventlog_ring_quota) link;
	uid_t uid;
	uint64_t bytes;		/* currently wired ring bytes for this uid */
};

/* Global eventlog state structure */
struct eventlog_user_channel;
struct eventlog_state {
	/* Provider registry */
	LIST_HEAD(, eventlog_provider) providers;
	LIST_HEAD(, eventlog_provider_stats) provider_stats;
	struct mtx providers_lock;	/* Protects providers and provider_stats lists */
	/* provider_id allocator, range [1, UINT16_MAX]; reclaimed on
	 * eventlog_provider_destroy() instead of an ever-incrementing
	 * counter. provider_id_lock is owned by the unrhdr (subr_unit.c). */
	struct unrhdr *provider_ids;
	struct mtx provider_id_lock;

	/*
	 * User-space provider submission-ring channels, enumerated by the
	 * subscriber read path to drain each producer's ring.  Protected by
	 * user_channels_lock; channels carry a refcount so a drain can run
	 * with the list lock dropped while teardown waits for it.
	 */
	LIST_HEAD(, eventlog_user_channel) user_channels;
	struct mtx user_channels_lock;
	uint32_t next_channel_id;	/* Monotonic; 0 reserved as "none" */
	u_int blocked_readers;		/* Device readers asleep awaiting data */

	/* Per-uid wired ring-memory accounting (see eventlog_ring_quota). */
	LIST_HEAD(, eventlog_ring_quota) ring_quotas;
	struct mtx ring_quota_lock;

	/* System-wide device */
	struct cdev *device;
	smr_t smr;				/* SMR domain for lock-free subscriber iteration */
	u_long reentrant_drops;			/* nested (NMI/interrupt) writes dropped */
	u_long reentrant_stashed;		/* nested writes stashed via scratch and delivered */
	struct mtx subscribers_mtx;		/* Writer-writer exclusion for add/remove */
	struct eventlog_subscriber_head subscribers;
	uint64_t next_subscriber_id;		/* Monotonic; 0 reserved as "none" */

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
	struct thread *dump_thread;		/* Thread running the dump callback */
	struct eventlog_subscriber *dump_target;	/* Subscriber receiving dump events */
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
	mtx_init(&evl.provider_id_lock, "eventlog provider ids", NULL, MTX_DEF);
	evl.provider_ids = new_unrhdr(1, UINT16_MAX, &evl.provider_id_lock);
	evl.smr = smr_create("eventlog", 0, 0);
	mtx_init(&evl.subscribers_mtx, "eventlog subscribers", NULL, MTX_DEF);
	LIST_INIT(&evl.user_channels);
	mtx_init(&evl.user_channels_lock, "eventlog channels", NULL, MTX_DEF);
	LIST_INIT(&evl.ring_quotas);
	mtx_init(&evl.ring_quota_lock, "eventlog ring quota", NULL, MTX_DEF);
}
SYSINIT(eventlog_state_init, SI_SUB_LOCK, SI_ORDER_ANY, eventlog_state_init, NULL);

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
static void eventlog_dev_clear_cdevpriv(void *data);
static int eventlog_channel_enqueue_control(struct eventlog_user_channel *chan,
    uint16_t type, uint16_t provider_id, int32_t value,
    uint64_t subscriber_id);
static void eventlog_user_dump_request(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider);
static void eventlog_user_dump_done(struct eventlog_user_channel *chan,
    uint64_t subscriber_id, uint16_t provider_id);
static void eventlog_bind_provider_to_subscribers(struct eventlog_provider *provider);
static void eventlog_unbind_provider_from_subscribers(struct eventlog_provider *provider);
static void eventlog_session_update_effective(struct eventlog_session *session,
    struct eventlog_provider *provider);
static void eventlog_update_provider_enablement(struct eventlog_provider *provider);
static void eventlog_subscriber_write_event(struct eventlog_subscriber *subscriber,
    struct eventlog_session *session, struct eventlog_event_header *hdr,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    uint16_t event_length, enum eventlog_level level, uint32_t keywords);
static void eventlog_copy_events_from_cpu(
    struct eventlog_subscriber *subscriber,
    struct eventlog_percpu_buffer *pcpu_buf, struct uio *uio,
    uint64_t max_timestamp, uint64_t *next_timestamp_out,
    bool *uio_out_of_space_out, bool *announcements_only);
static bool eventlog_read_merged(struct eventlog_subscriber *subscriber,
    struct uio *uio, uint64_t read_timestamp);
static void eventlog_resweep_idle_cpus(struct eventlog_subscriber *subscriber,
    uint64_t read_timestamp);
static void eventlog_drain_user_channels(void);
static void eventlog_reader_block_enter(void);
static void eventlog_reader_block_exit(void);
static void eventlog_ring_quota_refund(uid_t uid, uint64_t bytes);
static void eventlog_channel_publish_consumer(struct eventlog_user_channel *chan);

/* Kernel sysctl node definitions */
SYSCTL_DECL(_kern_eventlog);
SYSCTL_NODE(_kern, OID_AUTO, eventlog, CTLFLAG_RD | CTLFLAG_MPSAFE, NULL,
    "Event log subsystem");

SYSCTL_ULONG(_kern_eventlog, OID_AUTO, reentrant_drops, CTLFLAG_RD,
    &evl.reentrant_drops, 0,
    "Nested (NMI/interrupt/callout) event writes dropped: scratch slot busy "
    "or payload too large to stash");

SYSCTL_ULONG(_kern_eventlog, OID_AUTO, reentrant_stashed, CTLFLAG_RD,
    &evl.reentrant_stashed, 0,
    "Nested (NMI/interrupt/callout) event writes stashed in the per-CPU "
    "scratch slot and delivered when the outer write exits");

/*
 * Global safety ceiling (L_max) on how long a subscriber's merged stream
 * may be held back waiting for a lagging user-space provider.  The
 * steady-state hold-back self-tunes to the slowest live producer's actual
 * lag; this only bounds the pathological case (a slow or dead producer).
 * Beyond this, the laggard's late events are dropped so the stream
 * progresses.  It is NOT the normal operating latency.
 */
static u_long eventlog_max_holdback_us = 500000;	/* 500 ms */
SYSCTL_ULONG(_kern_eventlog, OID_AUTO, max_holdback_us,
    CTLFLAG_RWTUN, &eventlog_max_holdback_us, 0,
    "Max microseconds the merged stream is held back for a lagging "
    "user-space provider before its late events are dropped");

/*
 * Hard ceiling (KMAX) on concurrent user-space provider streams a single
 * subscriber may buffer.  Per-subscriber metadata arrays are sized to this
 * at CREATE (cheap); the ring buffers themselves are allocated lazily as
 * streams go live and reclaimed when they go idle, so typical memory tracks
 * the active working set, not the cap.  Raise it if a busy subscriber sees
 * user-stream drops climb.
 */
static u_int eventlog_max_user_streams = 1024;
SYSCTL_UINT(_kern_eventlog, OID_AUTO, max_user_streams,
    CTLFLAG_RWTUN, &eventlog_max_user_streams, 0,
    "Per-subscriber ceiling on concurrent buffered user-space provider "
    "streams (metadata sized to this at subscribe time; ring buffers "
    "allocated on demand)");

/*
 * Per-user-stream ring buffer size.  Each live user stream gets one
 * power-of-two ring of this size, allocated on first push and freed when
 * the stream is reclaimed.  Worst-case user-stream memory is
 * max_user_streams * this.
 */
static u_int eventlog_user_buffer_size = 512 * 1024;	/* 512 KB */
SYSCTL_UINT(_kern_eventlog, OID_AUTO, user_buffer_size,
    CTLFLAG_RWTUN, &eventlog_user_buffer_size, 0,
    "Per-user-stream ring buffer size in bytes (one per live stream, read "
    "at subscribe time)");

/*
 * A user stream idle for longer than this is fully reclaimed: deactivated
 * and its ring buffers freed.  Must exceed max_holdback_us so a merely
 * lagging stream is not torn down underneath the merge.
 */
static u_long eventlog_user_idle_reclaim_us = 5000000;	/* 5 s */
SYSCTL_ULONG(_kern_eventlog, OID_AUTO, user_idle_reclaim_us,
    CTLFLAG_RWTUN, &eventlog_user_idle_reclaim_us, 0,
    "Microseconds of inactivity after which an idle user stream's buffers "
    "are reclaimed");

/*
 * How often a subscriber blocked in read() wakes to drain user-space
 * submission rings when any producer channel exists.  Producers do zero
 * syscalls to submit, so this bounds idle-reader delivery latency (the
 * holdback ceiling, max_holdback_us, still bounds ordering separately).
 */
static u_long eventlog_user_drain_poll_us = 100000;	/* 100 ms */
SYSCTL_ULONG(_kern_eventlog, OID_AUTO, user_drain_poll_us,
    CTLFLAG_RWTUN, &eventlog_user_drain_poll_us, 0,
    "Max microseconds a blocked subscriber waits before re-draining "
    "user-space submission rings");

/*
 * Ceiling on the total wired submission-ring memory a single non-root uid may
 * hold across all its provider channels.  Producing is unprivileged, so this
 * bounds the kernel memory an untrusted process can pin.  Root is exempt.
 */
static u_long eventlog_user_ring_max_per_uid = 256UL * 1024 * 1024; /* 256 MB */
SYSCTL_ULONG(_kern_eventlog, OID_AUTO, user_ring_max_bytes_per_uid,
    CTLFLAG_RWTUN, &eventlog_user_ring_max_per_uid, 0,
    "Max wired submission-ring bytes a single non-root uid may hold");

/*
 * Max submission rings per provider fd.  >1 means the kernel supports
 * per-thread rings (repeatable EVENTLOG_IOCTL_SETUP_RING); a producer can
 * read this to decide whether EVENTLOG_PROVIDER_PER_THREAD_RINGS is usable.
 * Absent (ENOENT) on kernels predating multi-ring support.
 */
static u_int eventlog_user_rings_max = EVENTLOG_USER_RINGS_MAX;
SYSCTL_UINT(_kern_eventlog, OID_AUTO, user_rings_max, CTLFLAG_RD,
    &eventlog_user_rings_max, 0,
    "Max submission rings per provider fd (>1 = per-thread rings supported)");

/*
 * Holdback applied to the read epoch boundary: hold back the last N
 * microseconds of "now" before treating anything as safe to deliver, so a
 * CPU whose commit only becomes visible a few microseconds after another
 * CPU's (ordinary cross-CPU clock/commit-visibility skew) still gets
 * discovered before we've delivered past it. That skew is long-tailed
 * rather than a fixed few microseconds; 20us is the smallest value that
 * reliably eliminates it against cross_cpu_merge_order. Relies on elog(1)
 * sizing its buffer for the symbols/process dump-on-subscribe burst (see
 * ELOG_AUTO_BUFFER_SIZE_FOR_DUMP_PROVIDERS in elog.c) to stay free of
 * added drops. Does not address the much larger buffer-backpressure
 * violations under sustained overload, which remain unfixed.
 */
static u_int eventlog_read_watermark_us = 20;
SYSCTL_UINT(_kern_eventlog, OID_AUTO, read_watermark_us, CTLFLAG_RWTUN,
    &eventlog_read_watermark_us, 0,
    "Microseconds of holdback applied to the read epoch boundary to absorb "
    "cross-CPU clock/commit-visibility skew");

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
eventlog_provider_set_all_sessions(struct eventlog_provider *provider, int enabled)
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
		} else if (matched[i]->is_userspace && matched[i]->chan != NULL) {
			(void)eventlog_channel_enqueue_control(matched[i]->chan,
			    EVENTLOG_CONTROL_DEFAULT_CHANGED,
			    matched[i]->provider_id, val, 0);
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
eventlog_provider_stats_alloc(const char *name, int default_enabled,
    uint32_t flags)
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
	if ((flags & EVENTLOG_PROVIDER_AUTO_RATIO) != 0) {
		SYSCTL_ADD_ULONG(&stats->sysctl_ctx, SYSCTL_CHILDREN(stats_node),
		    OID_AUTO, "auto_ratio", CTLFLAG_RW, &stats->auto_ratio,
		    "Auto-enable a random 1 out of N new sessions when not "
		    "already default-enabled (0=off)");
	}

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
	int id;

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
	provider->decode_blob = config->decode_blob;
	provider->decode_blob_size = config->decode_blob_size;
	/*
	 * Derive the content-addressed schema_id from the (trusted, in-tree)
	 * decode blob.  Oversize blobs are a build error; drop the blob rather
	 * than register an unbounded one.  No blob => schema_id stays zeroed.
	 */
	if (provider->decode_blob != NULL) {
		if (provider->decode_blob_size > EVENTLOG_DECODE_BLOB_MAX) {
			printf("eventlog: provider '%s' decode blob too large "
			    "(%zu > %u), ignoring\n", provider->name,
			    provider->decode_blob_size, EVENTLOG_DECODE_BLOB_MAX);
			provider->decode_blob = NULL;
			provider->decode_blob_size = 0;
		} else {
			uint8_t digest[SHA256_DIGEST_LENGTH];
			SHA256_CTX ctx;

			SHA256_Init(&ctx);
			SHA256_Update(&ctx, provider->decode_blob,
			    provider->decode_blob_size);
			SHA256_Final(digest, &ctx);
			memcpy(provider->schema_id, digest,
			    EVENTLOG_DECODE_SCHEMA_ID_LEN);
		}
	}
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
	 * The first provider for a given name seeds default_enabled and
	 * flags; later providers reuse the existing stats record (the
	 * sysctl surface is shared by name).
	 */
	new_stats = eventlog_provider_stats_alloc(name, config->default_enabled,
	    config->flags);

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
	/* Assign from the reclaimable pool; alloc_unr() manages its own
	 * lock internally, so calling it under providers_lock is fine. */
	id = alloc_unr(evl.provider_ids);
	if (id == -1) {
		struct eventlog_provider_stats *dead_stats;

		dead_stats = eventlog_provider_stats_release(provider->stats);
		mtx_unlock(&evl.providers_lock);
		if (dead_stats != NULL)
			eventlog_provider_stats_free(dead_stats);
		mtx_destroy(&provider->sessions_lock);
		free(provider, M_EVENTLOG);
		return (NULL);
	}
	provider->provider_id = (uint16_t)id;
	LIST_INSERT_HEAD(&evl.providers, provider, link);
	mtx_unlock(&evl.providers_lock);

	/*
	 * Late binding: attach to any subscriber that already expressed
	 * interest in this name (e.g. a deferred subscription waiting for
	 * a user-space provider to register). Done after dropping
	 * providers_lock to respect lock ordering.
	 */
	eventlog_bind_provider_to_subscribers(provider);

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
	 * Back out this fd's last-reported user-session contribution (see
	 * EVENTLOG_IOCTL_REPORT_STATS) so the shared active/enabled gauges
	 * drop when the producer goes away.  created is monotonic and kept.
	 */
	if (provider->reported_active != 0)
		counter_u64_add(provider->stats->sessions_active,
		    -(int64_t)provider->reported_active);
	if (provider->reported_enabled != 0)
		counter_u64_add(provider->stats->sessions_enabled,
		    -(int64_t)provider->reported_enabled);

	/*
	 * Remove from the provider list first so no new subscription
	 * (and therefore no new dump task) can find us.
	 */
	mtx_lock(&evl.providers_lock);
	LIST_REMOVE(provider, link);
	dead_stats = eventlog_provider_stats_release(provider->stats);
	mtx_unlock(&evl.providers_lock);

	/* Return the id to the pool now that no lookup can find us. */
	free_unr(evl.provider_ids, provider->provider_id);

	/*
	 * Drop any subscriptions still pointing at us so no subscriber
	 * dereferences a freed provider. Subscribers keep their specs, so
	 * a re-registered provider of the same name rebinds automatically.
	 */
	eventlog_unbind_provider_from_subscribers(provider);

	/*
	 * Drain the dump taskqueue: queued or in-flight tasks may still
	 * reference this provider.
	 */
	taskqueue_drain_all(evl.dump_tq);

	if (dead_stats != NULL)
		eventlog_provider_stats_free(dead_stats);

	/*
	 * Free a user-space provider's copied-in decode blob.  Safe here: the
	 * provider is off evl.providers (so GET_DECODE_BLOB can no longer find
	 * it) and has no subscribers, and GET_DECODE_BLOB copies the blob under
	 * providers_lock rather than holding the bare pointer across copyout.
	 */
	if (provider->decode_blob_owned && provider->decode_blob != NULL) {
		free(__DECONST(void *, provider->decode_blob), M_EVENTLOG);
		eventlog_ring_quota_refund(provider->blob_charge_uid,
		    provider->decode_blob_size);
	}

	mtx_destroy(&provider->sessions_lock);
	free(provider, M_EVENTLOG);
}

/*
 * Auto-ratio selection: 1-in-N counter-modulo sampling, mirroring
 * tcp_log_buf.c's log_auto_ratio. Deliberately a plain counter rather than a
 * hash of session_id, since a hash would bias toward whichever identities
 * happen to land in the selected bucket rather than sampling at random.
 * auto_ratio is 0 unless the provider opted in via EVENTLOG_PROVIDER_AUTO_RATIO,
 * so this is a no-op for every other provider.
 */
static __inline bool
eventlog_provider_selectauto(struct eventlog_provider_stats *stats)
{

	return (stats->auto_ratio != 0 &&
	    (atomic_fetchadd_long(&stats->auto_ratio_cur, 1) %
	    stats->auto_ratio) == 0);
}

/*
 * Create a new eventlog session.
 * Initial enabled state is derived from the provider's default_enabled,
 * falling back to auto_ratio selection when not already default-enabled.
 */
struct eventlog_session*
eventlog_session_create(struct eventlog_provider *provider, uint64_t session_id, bool waitok,
    void *create_payload, size_t create_payload_size)
{
	struct eventlog_session *session;
	bool enabled;

	if (provider == NULL)
		return (NULL);

	session = uma_zalloc(evl.session_zone, (waitok ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (session == NULL)
		return (NULL);

	enabled = (provider->stats->default_enabled != 0);
	if (!enabled)
		enabled = eventlog_provider_selectauto(provider->stats);

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

	/* Emit SESSION_CREATE only when enabled (disabled sessions don't need it) */
	if (enabled && provider->level != EVENTLOG_LEVEL_NONE) {
		eventlog_event_write(session, EVENTLOG_SESSION_CREATE_ID,
		    EVENTLOG_LEVEL_INFO, EVENTLOG_KEYWORD_SESSION,
		    create_payload, create_payload_size);
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

const void *
eventlog_provider_get_decode_blob(struct eventlog_provider *provider,
    size_t *sizep)
{
	MPASS(provider != NULL);
	if (sizep != NULL)
		*sizep = provider->decode_blob_size;
	return (provider->decode_blob);
}

const uint8_t *
eventlog_provider_get_schema_id(struct eventlog_provider *provider)
{
	MPASS(provider != NULL);
	return (provider->schema_id);
}

/*
 * See sys/eventlog.h. Exposes the EVENTLOG_IOCTL_GET_DECODE_BLOB lookup logic
 * (name/schema_id matching, first-match-wins, ENOENT/EFBIG) for unit testing
 * without going through /dev/eventlog. The ioctl handler itself does not call
 * this: a user-space provider can free its blob on exit, so it copies under
 * providers_lock instead of retaining a pointer past the unlock as this does.
 * Only safe for callers whose blobs are static/immortal, like in-kernel
 * providers.
 */
int
eventlog_lookup_decode_blob(uint8_t lookup_kind, const char *provider_name,
    const uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN],
    const void **blob_out, size_t *sizep_out)
{
	struct eventlog_provider *provider;
	const void *blob = NULL;
	size_t blob_size = 0;

	if (lookup_kind != EVENTLOG_DECODE_LOOKUP_NAME &&
	    lookup_kind != EVENTLOG_DECODE_LOOKUP_SCHEMA_ID)
		return (EINVAL);

	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link) {
		bool match;

		if (provider->decode_blob == NULL)
			continue;
		if (lookup_kind == EVENTLOG_DECODE_LOOKUP_SCHEMA_ID)
			match = memcmp(provider->schema_id, schema_id,
			    EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0;
		else
			match = strcmp(provider->name, provider_name) == 0;
		if (match) {
			blob = provider->decode_blob;
			blob_size = provider->decode_blob_size;
			break;
		}
	}
	mtx_unlock(&evl.providers_lock);

	if (blob == NULL)
		return (ENOENT);
	if (blob_size > EVENTLOG_DECODE_BLOB_MAX)
		return (EFBIG);

	*blob_out = blob;
	*sizep_out = blob_size;
	return (0);
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
 * Update session's effective_level and effective_keywords from disabled/override/provider.
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

	counter_u64_add(provider->stats->sessions_enabled, (enabled != 0) ? 1 : -1);
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

	session->has_override = (level != EVENTLOG_LEVEL_NONE || keywords != 0) ? 1 : 0;
	session->override_level = level;
	session->override_keywords = keywords;

	mtx_lock(&provider->sessions_lock);
	eventlog_session_update_effective(session, provider);
	mtx_unlock(&provider->sessions_lock);
}

static inline uint64_t
eventlog_now_us(void)
{
	struct bintime bt;

	binuptime(&bt);
	return (bintime2us(&bt));
}

/*
 * Per-CPU scratch slot for a same-CPU reentrant write (NMI / interrupt
 * filter / C_DIRECT_EXEC callout landing on a CPU already inside
 * eventlog_event_write_impl()).  Stashed here instead of being dropped;
 * the outer call drains it just before its own smr_exit(), keeping the
 * stashed pointers SMR-protected and its commit after the outer event's.
 *
 * One slot per CPU: only helps a single level of nesting.  A second
 * nested write before the first drains, or a payload over
 * EVENTLOG_SCRATCH_MAX_PAYLOAD, still drops (reentrant_drops).
 */
#define EVENTLOG_SCRATCH_MAX_PAYLOAD	512

enum eventlog_scratch_state {
	EVTLOG_SCRATCH_EMPTY = 0,	/* slot free */
	EVTLOG_SCRATCH_READY,		/* holds a stashed event, awaiting drain */
	EVTLOG_SCRATCH_BUSY,		/* claimed: a fill or a drain is in flight */
};

struct eventlog_write_scratch {
	volatile u_int state;		/* enum eventlog_scratch_state */
	struct eventlog_session *session;
	struct eventlog_event_header hdr;
	enum eventlog_level level;
	uint32_t keywords;
	size_t payload_size;
	uint8_t payload[EVENTLOG_SCRATCH_MAX_PAYLOAD];
};
DPCPU_DEFINE_STATIC(struct eventlog_write_scratch, evl_scratch);

/*
 * Dispatch hdr/iov to evl.dump_target (if a dump is in progress on this
 * thread) or every subscriber.  Caller must hold evl.smr (smr_enter()) on
 * this CPU.
 */
static inline void
eventlog_deliver_event(struct eventlog_session *session,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size, enum eventlog_level level, uint32_t keywords)
{
	struct eventlog_subscriber *subscriber;

	if (__predict_false(evl.dump_target != NULL &&
	    curthread == evl.dump_thread)) {
		eventlog_subscriber_write_event(evl.dump_target, session,
		    hdr, iov, iovcnt, payload_size, hdr->event_length,
		    level, keywords);
	} else {
		CK_LIST_FOREACH(subscriber, &evl.subscribers, link) {
			eventlog_subscriber_write_event(subscriber, session,
			    hdr, iov, iovcnt, payload_size, hdr->event_length,
			    level, keywords);
		}
	}
}

/*
 * Try to stash a nested write into this CPU's scratch slot.  Returns false
 * (caller must count a drop) if the payload doesn't fit or the slot is
 * already occupied.  Flattens the iovec into the scratch's own buffer since
 * the caller's iov_base pointers (typically an interrupted NMI/callout's
 * locals) will not survive past this call.
 */
static bool
eventlog_scratch_stash(struct eventlog_session *session,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size, enum eventlog_level level, uint32_t keywords)
{
	struct eventlog_write_scratch *scratch = DPCPU_PTR(evl_scratch);
	uint8_t *dst;
	int i;

	if (__predict_false(payload_size > EVENTLOG_SCRATCH_MAX_PAYLOAD))
		return (false);

	if (!atomic_cmpset_int(&scratch->state, EVTLOG_SCRATCH_EMPTY,
	    EVTLOG_SCRATCH_BUSY))
		return (false);

	scratch->session = session;
	scratch->hdr = *hdr;
	scratch->level = level;
	scratch->keywords = keywords;
	scratch->payload_size = payload_size;
	dst = scratch->payload;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(dst, iov[i].iov_base, iov[i].iov_len);
			dst += iov[i].iov_len;
		}
	}

	atomic_store_rel_int(&scratch->state, EVTLOG_SCRATCH_READY);
	return (true);
}

/*
 * Drain this CPU's scratch slot if it holds a stashed event.  Must be
 * called after the outer call's own eventlog_deliver_event() and before its
 * smr_exit(), so the stashed pointers are still SMR-protected and the
 * drained event's commit lands after the outer event's own commit.
 */
static void
eventlog_scratch_drain(void)
{
	struct eventlog_write_scratch *scratch = DPCPU_PTR(evl_scratch);
	struct iovec iov;

	if (__predict_false(atomic_cmpset_acq_int(&scratch->state,
	    EVTLOG_SCRATCH_READY, EVTLOG_SCRATCH_BUSY))) {
		iov.iov_base = scratch->payload;
		iov.iov_len = scratch->payload_size;
		eventlog_deliver_event(scratch->session, &scratch->hdr, &iov, 1,
		    scratch->payload_size, scratch->level, scratch->keywords);

		atomic_store_rel_int(&scratch->state, EVTLOG_SCRATCH_EMPTY);
	}
}

/*
 * Write an event directly to all relevant subscribers (internal). The
 * payload is a scatter/gather iovec; scalar callers pass a 1-element iov.
 * payload_size must equal the sum of iov[*].iov_len; the caller is
 * responsible for computing it so the hot path doesn't need to walk the
 * iov twice.
 */
static void
eventlog_event_write_impl(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt, size_t payload_size)
{
	struct eventlog_event_header hdr;
	struct eventlog_provider *provider;
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
	hdr.thread_id = (curthread != NULL) ? curthread->td_tid : 0;
	hdr.provider_id = provider->provider_id;
	hdr.session_id = session->session_id;
	hdr.event_id = id;

	/*
	 * Re-entrancy guard.  smr_enter() cannot nest, so if an NMI, interrupt
	 * filter, or C_DIRECT_EXEC callout logs while this CPU is already in an
	 * eventlog SMR section, stash the nested event into the scratch slot.
	 * critical_enter() pins us so the c_seq check, the hdr.cpu/timestamp
	 * capture below, and smr_enter() all agree on the CPU -- which is also
	 * what keeps timestamps non-decreasing per CPU (see
	 * eventlog_read_merged()): nesting can only happen once the capture
	 * below has already run for the outer call, so a stashed event's
	 * timestamp is always later.
	 */
	critical_enter();
	hdr.cpu = PCPU_GET(cpuid);
	hdr.timestamp = eventlog_now_us();
	if (__predict_false(zpcpu_get(evl.smr)->c_seq != SMR_SEQ_INVALID)) {
		if (eventlog_scratch_stash(session, &hdr, iov, iovcnt,
		    payload_size, level, keywords))
			atomic_add_long(&evl.reentrant_stashed, 1);
		else
			atomic_add_long(&evl.reentrant_drops, 1);
		critical_exit();
		return;
	}

	smr_enter(evl.smr);

	eventlog_deliver_event(session, &hdr, iov, iovcnt, payload_size,
	    level, keywords);

	/*
	 * Drain any stashed nested write while still inside the SMR section.
	 */
	eventlog_scratch_drain();

	smr_exit(evl.smr);
	critical_exit();
}

void
eventlog_event_write(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length)
{
	struct iovec iov = { .iov_base = buffer, .iov_len = length };

	eventlog_event_write_impl(session, id, level, keywords, &iov, 1, length);
}

void
eventlog_event_write_gather(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords,
    const struct iovec *iov, int iovcnt)
{
	size_t payload_size = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		payload_size += iov[i].iov_len;
	eventlog_event_write_impl(session, id, level, keywords,
	    iov, iovcnt, payload_size);
}

u_long
eventlog_get_reentrant_drops(void)
{
	return (atomic_load_long(&evl.reentrant_drops));
}

u_long
eventlog_get_reentrant_stashed(void)
{
	return (atomic_load_long(&evl.reentrant_stashed));
}

/* Test hook: ids drained by eventlog_test_drain_provider_ids(). */
static uint16_t *eventlog_test_drained_ids;
static u_int eventlog_test_drained_count;

/*
 * Test hook: drain the provider_id pool to empty so a test can verify
 * exhaustion behavior without registering ~64K real providers. Pair with
 * eventlog_test_release_provider_ids() before anything else registers.
 */
u_int
eventlog_test_drain_provider_ids(void)
{
	uint16_t *ids;
	u_int n;
	int id;

	MPASS(eventlog_test_drained_ids == NULL);
	ids = malloc(UINT16_MAX * sizeof(*ids), M_EVENTLOG, M_WAITOK);
	n = 0;
	while ((id = alloc_unr(evl.provider_ids)) != -1)
		ids[n++] = (uint16_t)id;
	eventlog_test_drained_ids = ids;
	eventlog_test_drained_count = n;
	return (n);
}

/* Test hook: undo eventlog_test_drain_provider_ids(). */
void
eventlog_test_release_provider_ids(void)
{
	u_int i;

	for (i = 0; i < eventlog_test_drained_count; i++)
		free_unr(evl.provider_ids, eventlog_test_drained_ids[i]);
	free(eventlog_test_drained_ids, M_EVENTLOG);
	eventlog_test_drained_ids = NULL;
	eventlog_test_drained_count = 0;
}

/*
 * Create a device-based subscriber with per-CPU buffers plus an
 * auto-managed pool of pseudo-CPU sources for user-space provider streams.
 *
 * Source indices [0, maxcpu) are real CPUs and get their ring buffers
 * allocated up front here (sleepable context).  Indices [maxcpu,
 * total_sources) are user streams: their metadata is sized to the
 * kern.eventlog.max_user_streams cap (cheap), but their ring buffers are
 * allocated lazily on first push (eventlog_user_stream_get) and freed on
 * idle reclaim, so a subscriber pays only for the user streams actually in
 * flight.  The subscriber declares nothing about user streams.
 *
 * The subscriber is automatically added to the global subscribers list.
 * Returns NULL on failure, subscriber pointer on success.
 */
struct eventlog_subscriber *
eventlog_subscriber_create_device(uint32_t buffer_size_per_cpu)
{
	struct eventlog_subscriber *subscriber;
	struct eventlog_percpu_buffer *percpu_buffers;
	uint32_t user_buffer_size, hash_size;
	int src, maxcpu, total;
	u_int cap, i;

	if (buffer_size_per_cpu < EVENTLOG_BUFFER_SIZE_MIN ||
	    buffer_size_per_cpu > EVENTLOG_BUFFER_SIZE_MAX)
		return (NULL);

	maxcpu = mp_maxid + 1;

	/*
	 * Clamp the user-stream cap so that maxcpu + cap stays within the
	 * uint16_t source index space and a slot index still fits the signed
	 * 16-bit hash/active links (which use -1 as the empty sentinel), then
	 * derive a power-of-two hash table at least as large as the cap
	 * (min 64).
	 */
	cap = eventlog_max_user_streams;
	if (cap > (u_int)(UINT16_MAX - maxcpu))
		cap = UINT16_MAX - maxcpu;
	if (cap > INT16_MAX)
		cap = INT16_MAX;
	user_buffer_size = eventlog_user_buffer_size;
	if (user_buffer_size < EVENTLOG_BUFFER_SIZE_MIN)
		user_buffer_size = EVENTLOG_BUFFER_SIZE_MIN;
	else if (user_buffer_size > EVENTLOG_BUFFER_SIZE_MAX)
		user_buffer_size = EVENTLOG_BUFFER_SIZE_MAX;

	for (hash_size = 64; hash_size < cap; hash_size <<= 1)
		;

	/* Allocate subscriber structure */
	subscriber = malloc(sizeof(*subscriber), M_EVENTLOG, M_ZERO | M_WAITOK);
	MPASS(subscriber != NULL);

	CK_SLIST_INIT(&subscriber->subscriptions);
	STAILQ_INIT(&subscriber->specs);
	subscriber->type = EVENTLOG_SUBSCRIBER_TYPE_DEVICE;
	subscriber->u.device.buffer_size_per_cpu = buffer_size_per_cpu;
	subscriber->u.device.reader_waiting = 0;
	subscriber->u.device.heap_size = 0;
	mtx_init(&subscriber->dump_pending_mtx, "eventlog dump pending",
	    NULL, MTX_DEF);
	cv_init(&subscriber->dump_pending_cv, "evl_dump");
	TAILQ_INIT(&subscriber->user_dumps);

	total = maxcpu + cap;
	subscriber->u.device.maxcpu = (uint16_t)maxcpu;
	subscriber->u.device.total_sources = (uint16_t)total;
	subscriber->u.device.user_stream_cap = (uint16_t)cap;
	subscriber->u.device.user_stream_active = 0;
	subscriber->u.device.user_buffer_size = user_buffer_size;
	subscriber->u.device.user_hash_mask = hash_size - 1;
	subscriber->u.device.consumer_wc = 0;
	subscriber->u.device.commit_seq = 0;
	subscriber->u.device.swept_seq = 0;
	mtx_init(&subscriber->u.device.user_lock, "eventlog user streams",
	    NULL, MTX_DEF);

	/* Allocate source buffers (real CPUs + user-stream pseudo-CPUs) */
	percpu_buffers = malloc(sizeof(*percpu_buffers) * total,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(percpu_buffers != NULL);
	subscriber->u.device.percpu_buffers = percpu_buffers;

	/* Allocate cpu_timestamps and heap for merge ordering */
	subscriber->u.device.cpu_timestamps = malloc(sizeof(uint64_t) * total,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(subscriber->u.device.cpu_timestamps != NULL);
	subscriber->u.device.heap_cpus = malloc(sizeof(uint16_t) * total,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(subscriber->u.device.heap_cpus != NULL);
	for (src = 0; src < total; src++)
		subscriber->u.device.cpu_timestamps[src] = EVENTLOG_TIMESTAMP_NONE;

	/*
	 * User-stream metadata: sized to the cap, cheap, no ring buffers yet.
	 * user_active[] is a full permutation of slot indices; entries
	 * [0, user_stream_active) are live and [user_stream_active, cap) are
	 * free, with each slot's active_idx tracking its position.  This makes
	 * activation and reclaim O(1) and lets callers iterate only live slots.
	 */
	subscriber->u.device.user_streams = malloc(
	    sizeof(struct eventlog_user_stream) * cap,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(subscriber->u.device.user_streams != NULL);
	subscriber->u.device.user_active = malloc(sizeof(uint16_t) * cap,
	    M_EVENTLOG, M_WAITOK | M_ZERO);
	MPASS(subscriber->u.device.user_active != NULL);
	for (i = 0; i < cap; i++) {
		subscriber->u.device.user_streams[i].hnext = -1;
		subscriber->u.device.user_streams[i].active_idx = (uint16_t)i;
		subscriber->u.device.user_active[i] = (uint16_t)i;
	}
	subscriber->u.device.user_hash = malloc(sizeof(int16_t) * hash_size,
	    M_EVENTLOG, M_WAITOK);
	MPASS(subscriber->u.device.user_hash != NULL);
	for (i = 0; i < hash_size; i++)
		subscriber->u.device.user_hash[i] = -1;

	/*
	 * Allocate a single power-of-two ring buffer for each real CPU.
	 * User-stream pseudo-sources are left zeroed and populated lazily
	 * on first push.
	 */
	{
		uint32_t ring_size = eventlog_ring_pow2(buffer_size_per_cpu);

		for (src = 0; src < maxcpu; src++) {
			percpu_buffers[src].buffer_size = ring_size;
			percpu_buffers[src].buffer_mask = ring_size - 1;
			percpu_buffers[src].head = 0;
			percpu_buffers[src].tail = 0;
			percpu_buffers[src].buffer = malloc(ring_size,
			    M_EVENTLOG, M_WAITOK | M_ZERO);
			MPASS(percpu_buffers[src].buffer != NULL);
		}
	}

	/* Add subscriber to global list */
	mtx_lock(&evl.subscribers_mtx);
	subscriber->subscriber_id = ++evl.next_subscriber_id;
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
eventlog_subscriber_create_callback(eventlog_callback_t callback, void *callback_arg)
{
	struct eventlog_subscriber *subscriber;

	MPASS(callback != NULL);

	/* Allocate subscriber structure */
	subscriber = malloc(sizeof(*subscriber), M_EVENTLOG, M_ZERO | M_WAITOK);
	MPASS(subscriber != NULL);

	CK_SLIST_INIT(&subscriber->subscriptions);
	STAILQ_INIT(&subscriber->specs);
	subscriber->type = EVENTLOG_SUBSCRIBER_TYPE_CALLBACK;
	subscriber->u.callback.callback = callback;
	subscriber->u.callback.callback_arg = callback_arg;
	mtx_init(&subscriber->dump_pending_mtx, "eventlog dump pending",
	    NULL, MTX_DEF);
	cv_init(&subscriber->dump_pending_cv, "evl_dump");
	TAILQ_INIT(&subscriber->user_dumps);

	/* Add subscriber to global list */
	mtx_lock(&evl.subscribers_mtx);
	subscriber->subscriber_id = ++evl.next_subscriber_id;
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
    struct eventlog_provider *provider, uint64_t session_id, uint16_t src,
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
	bool match = false;

	hdr.event_length = (uint16_t)sizeof(hdr);
	hdr.RESERVED = 0;
	hdr.thread_id = (curthread != NULL) ? curthread->td_tid : 0;
	hdr.provider_id = provider->provider_id;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = EVENTLOG_DUMP_COMPLETE_ID;

	smr_enter(evl.smr);
	hdr.cpu = PCPU_GET(cpuid);

	/* Timestamp captured post-smr_enter(); see eventlog_event_write_impl(). */
	hdr.timestamp = eventlog_now_us();

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
			    provider, EVENTLOG_SESSION_ID_NONE, hdr.cpu, &hdr,
			    &iov, 0, 0);
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

static void
eventlog_subscriber_disable_task(void *context, int pending __unused)
{
	struct eventlog_subscriber *subscriber = context;
	struct eventlog_subscription *sub;

	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link)
		eventlog_update_provider_enablement(sub->provider);
}

struct eventlog_enable_task {
	struct task task;
	struct eventlog_provider *provider;
};

static void
eventlog_provider_enable_task(void *context, int pending __unused)
{
	struct eventlog_enable_task *et = context;

	eventlog_update_provider_enablement(et->provider);
}

/*
 * Destroy a subscriber and update provider enablement.
 */
void
eventlog_subscriber_destroy(struct eventlog_subscriber *subscriber)
{
	struct eventlog_subscription *sub, *sub_next;
	struct eventlog_user_dump *ud;
	struct task disable_task;

	if (subscriber == NULL)
		return;

	/*
	 * Remove from the global list (making us invisible to control-channel
	 * PUSH_DUMP/DUMP_DONE lookups, which run under subscribers_mtx) and
	 * cancel any outstanding user-provider dump requests in the same
	 * critical section.  Their DUMP_DONE may never arrive, so we drop the
	 * dump_pending references here rather than let drain block forever.
	 *
	 * Once unlisted, a destroyed provider's unbind can no longer drop our
	 * subscriptions, so the enablement walk is queued on dump_tq in the
	 * same critical section: eventlog_provider_destroy() either unbinds
	 * first or drains dump_tq before freeing.
	 */
	TASK_INIT(&disable_task, 0, eventlog_subscriber_disable_task,
	    subscriber);
	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_REMOVE(subscriber, link);
	mtx_lock(&subscriber->dump_pending_mtx);
	while ((ud = TAILQ_FIRST(&subscriber->user_dumps)) != NULL) {
		TAILQ_REMOVE(&subscriber->user_dumps, ud, link);
		if (subscriber->dump_pending > 0)
			subscriber->dump_pending--;
		free(ud, M_EVENTLOG);
	}
	mtx_unlock(&subscriber->dump_pending_mtx);
	taskqueue_enqueue(evl.dump_tq, &disable_task);
	mtx_unlock(&evl.subscribers_mtx);

	/*
	 * Drain kernel-provider dump tasks; they reference this subscriber's
	 * buffers and would UAF if we freed them mid-callback.
	 */
	eventlog_subscriber_drain_dumps(subscriber);

	/* Wait for the provider enablement updates (we're no longer visible) */
	taskqueue_drain(evl.dump_tq, &disable_task);

	/* Wait for all SMR readers before freeing */
	smr_synchronize(evl.smr);

	/* Free subscriptions, buffers, and subscriber */
	CK_SLIST_FOREACH_SAFE(sub, &subscriber->subscriptions, link, sub_next) {
		free(sub, M_EVENTLOG);
	}

	/* Free remembered subscription specs */
	{
		struct eventlog_sub_spec *spec, *spec_next;

		STAILQ_FOREACH_SAFE(spec, &subscriber->specs, link, spec_next)
			free(spec, M_EVENTLOG);
		STAILQ_INIT(&subscriber->specs);
	}

	/* Clean up subscriber based on type */
	if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE) {
		int src, total = subscriber->u.device.total_sources;
		struct eventlog_percpu_buffer *percpu_buffers = subscriber->u.device.percpu_buffers;

		if (percpu_buffers != NULL) {
			for (src = 0; src < total; src++) {
				if (percpu_buffers[src].buffer != NULL)
					free(percpu_buffers[src].buffer, M_EVENTLOG);
			}
			free(percpu_buffers, M_EVENTLOG);
		}
		if (subscriber->u.device.cpu_timestamps != NULL)
			free(subscriber->u.device.cpu_timestamps, M_EVENTLOG);
		if (subscriber->u.device.heap_cpus != NULL)
			free(subscriber->u.device.heap_cpus, M_EVENTLOG);
		if (subscriber->u.device.user_streams != NULL)
			free(subscriber->u.device.user_streams, M_EVENTLOG);
		if (subscriber->u.device.user_active != NULL)
			free(subscriber->u.device.user_active, M_EVENTLOG);
		if (subscriber->u.device.user_hash != NULL)
			free(subscriber->u.device.user_hash, M_EVENTLOG);
		mtx_destroy(&subscriber->u.device.user_lock);
	}
	/* Callback subscribers don't need cleanup */

	cv_destroy(&subscriber->dump_pending_cv);
	mtx_destroy(&subscriber->dump_pending_mtx);
	free(subscriber, M_EVENTLOG);
}

/*
 * Enqueue one async dump_state replay for (subscriber, provider).
 *
 * User-space providers replay state out of process: post a DUMP_REQUEST to
 * the owning channel's control queue and let the producer's background
 * thread call its dump callback and PUSH_DUMP the result back scoped to
 * this subscriber.
 *
 * In-kernel providers with a dump_callback get an async task on
 * evl.dump_tq instead. Bumping dump_pending under the subscriber's mtx
 * ensures a racing destroy() either sees the pending count and waits, or
 * finds none yet and our task is still scheduled to fire after the caller
 * returns.
 */
static void
eventlog_enqueue_dump_task(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider)
{
	struct eventlog_dump_task *dt;

	if (provider->is_userspace) {
		eventlog_user_dump_request(subscriber, provider);
		return;
	}

	if (provider->dump_callback == NULL)
		return;

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
 * Subscribe to a single provider. Handles both new subscriptions and
 * updating existing ones.
 *
 * On a brand-new subscription (not an in-place update) and only when
 * the provider has a dump_callback, enqueue one task on evl.dump_tq
 * so the provider can replay current state. Re-subscribing does not
 * re-fire the dump -- see EVENTLOG_IOCTL_TRIGGER_DUMP_STATE for an
 * explicit way to ask for a fresh replay on an existing subscription.
 */
static void
eventlog_subscriber_add_subscription_one(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, enum eventlog_level level,
    uint32_t keywords, uint32_t flags)
{
	struct eventlog_subscription *sub, *new_sub;
	struct eventlog_provider *p;
	struct eventlog_enable_task et = { .provider = provider };

	new_sub = malloc(sizeof(*new_sub), M_EVENTLOG, M_WAITOK);
	MPASS(new_sub != NULL);
	new_sub->provider = provider;
	new_sub->level = level;
	new_sub->keywords = keywords;
	TASK_INIT(&et.task, 0, eventlog_provider_enable_task, &et);

	mtx_lock(&evl.subscribers_mtx);

	/*
	 * provider came from an unlocked snapshot of evl.providers.  Bind only
	 * if it is still listed, so its unbind sees this subscription, and
	 * queue the enablement update on dump_tq (drained before the free).
	 */
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(p, &evl.providers, link)
		if (p == provider)
			break;
	mtx_unlock(&evl.providers_lock);
	if (p == NULL) {
		mtx_unlock(&evl.subscribers_mtx);
		free(new_sub, M_EVENTLOG);
		return;
	}

	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (sub->provider == provider) {
			/* Already subscribed - update in place */
			sub->level = level;
			sub->keywords = keywords;
			break;
		}
	}
	if (sub == NULL)
		CK_SLIST_INSERT_HEAD(&subscriber->subscriptions, new_sub, link);

	/* Enable the provider before its dump task runs on the same queue. */
	taskqueue_enqueue(evl.dump_tq, &et.task);
	if (sub == NULL && (flags & EVENTLOG_SUBSCRIPTION_DUMP_STATE) != 0)
		eventlog_enqueue_dump_task(subscriber, provider);

	mtx_unlock(&evl.subscribers_mtx);

	if (sub != NULL)
		free(new_sub, M_EVENTLOG);
	taskqueue_drain(evl.dump_tq, &et.task);
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
	struct eventlog_provider *small[16];
	struct eventlog_provider **matched;
	struct eventlog_sub_spec *spec;
	int nmatched, cap_matched;
	int i;

	MPASS(subscriber != NULL);
	MPASS(provider_name != NULL);

	if ((flags & ~EVENTLOG_SUBSCRIPTION_FLAGS_VALID) != 0)
		return (EINVAL);
	if (strlen(provider_name) >= EVENTLOG_PROVIDER_NAME_MAX)
		return (EINVAL);

	/*
	 * Remember the request so a provider that registers later (e.g. a
	 * user-space provider process) is bound automatically. Allocated
	 * before taking any lock since malloc may sleep.
	 */
	spec = malloc(sizeof(*spec), M_EVENTLOG, M_WAITOK | M_ZERO);
	strlcpy(spec->name, provider_name, EVENTLOG_PROVIDER_NAME_MAX);
	spec->level = level;
	spec->keywords = keywords;
	spec->flags = flags;

	/*
	 * Count matching providers, size a match array (no fixed cap, so all
	 * same-name providers bind), then collect into it.  A small on-stack
	 * array covers the common case without allocating.  Any provider that
	 * registers after the spec is armed binds via the late-binding path.
	 */
	cap_matched = 0;
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link)
		if (strcmp(provider->name, provider_name) == 0)
			cap_matched++;
	mtx_unlock(&evl.providers_lock);

	if (cap_matched <= (int)nitems(small))
		matched = small;
	else
		matched = malloc(cap_matched * sizeof(*matched), M_EVENTLOG,
		    M_WAITOK);

	nmatched = 0;
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link) {
		if (strcmp(provider->name, provider_name) == 0 &&
		    nmatched < cap_matched)
			matched[nmatched++] = provider;
	}
	mtx_unlock(&evl.providers_lock);

	/*
	 * Arm the spec (matched now, or deferred for a future provider) and
	 * bind any providers that already exist.  Subscribing to a name with
	 * no live provider always succeeds; the spec binds when one appears.
	 */
	mtx_lock(&evl.subscribers_mtx);
	STAILQ_INSERT_TAIL(&subscriber->specs, spec, link);
	mtx_unlock(&evl.subscribers_mtx);

	for (i = 0; i < nmatched; i++)
		eventlog_subscriber_add_subscription_one(subscriber,
		    matched[i], level, keywords, flags);

	if (matched != small)
		free(matched, M_EVENTLOG);

	return (0);
}

/*
 * Replace the keyword mask on an existing subscription, leaving its level
 * and dump-state history alone.  The retained spec is updated too, so a
 * same-named provider binding later comes up with the new mask.  Returns
 * ENOENT if this subscriber never subscribed to provider_name.
 */
int
eventlog_subscriber_set_subscription_keywords(
    struct eventlog_subscriber *subscriber, const char *provider_name,
    uint32_t keywords)
{
	struct eventlog_provider *provider;
	struct eventlog_provider *small[16];
	struct eventlog_provider **matched;
	struct eventlog_subscription *sub;
	struct eventlog_sub_spec *spec;
	int nmatched, cap_matched;
	int i;
	bool found = false;

	MPASS(subscriber != NULL);
	MPASS(provider_name != NULL);

	if (strlen(provider_name) >= EVENTLOG_PROVIDER_NAME_MAX)
		return (EINVAL);

	/* Size the match array before taking any lock, as malloc may sleep. */
	cap_matched = 0;
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link)
		if (strcmp(provider->name, provider_name) == 0)
			cap_matched++;
	mtx_unlock(&evl.providers_lock);

	if (cap_matched <= (int)nitems(small))
		matched = small;
	else
		matched = malloc(cap_matched * sizeof(*matched), M_EVENTLOG,
		    M_WAITOK);

	nmatched = 0;
	mtx_lock(&evl.providers_lock);
	LIST_FOREACH(provider, &evl.providers, link) {
		if (strcmp(provider->name, provider_name) == 0 &&
		    nmatched < cap_matched)
			matched[nmatched++] = provider;
	}
	mtx_unlock(&evl.providers_lock);

	mtx_lock(&evl.subscribers_mtx);
	STAILQ_FOREACH(spec, &subscriber->specs, link) {
		if (strcmp(spec->name, provider_name) == 0) {
			spec->keywords = keywords;
			found = true;
		}
	}
	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (strcmp(sub->provider->name, provider_name) == 0)
			sub->keywords = keywords;
	}
	mtx_unlock(&evl.subscribers_mtx);

	if (found) {
		for (i = 0; i < nmatched; i++)
			eventlog_update_provider_enablement(matched[i]);
	}

	if (matched != small)
		free(matched, M_EVENTLOG);

	return (found ? 0 : ENOENT);
}

/*
 * Synthesise EVENTLOG_PROVIDER_INFO_ID and (when the decode blob fits in
 * one record) EVENTLOG_PROVIDER_BLOB_ID into `subscriber`'s stream for a
 * just-bound provider.  Emitted at bind time so a capture is self-
 * describing even if the provider unregisters before the next
 * GET_PROVIDERS poll; elog(1) applies these records to its map/registry
 * and embeds them into the output file.  No level/keyword filter: the
 * subscriber just bound this provider, so it wants the announcement.
 */
static void
eventlog_emit_provider_announcement(struct eventlog_provider *provider,
    struct eventlog_subscriber *subscriber)
{
	struct eventlog_event_header hdr;
	struct eventlog_provider_info info;
	struct iovec iov;
	uint8_t *blob_payload;
	size_t blob_payload_len, max_blob;
	uint32_t blob_sz;

	memset(&info, 0, sizeof(info));
	info.provider_id = provider->provider_id;
	strlcpy(info.name, provider->name, sizeof(info.name));
	memcpy(info.schema_id, provider->schema_id,
	    EVENTLOG_DECODE_SCHEMA_ID_LEN);

	memset(&hdr, 0, sizeof(hdr));
	hdr.event_length = (uint16_t)(sizeof(hdr) + sizeof(info));
	hdr.thread_id = (curthread != NULL) ? curthread->td_tid : 0;
	hdr.provider_id = provider->provider_id;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = EVENTLOG_PROVIDER_INFO_ID;

	smr_enter(evl.smr);
	hdr.cpu = PCPU_GET(cpuid);
	hdr.timestamp = eventlog_now_us();
	iov.iov_base = &info;
	iov.iov_len = sizeof(info);
	if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE) {
		eventlog_subscriber_write_event_device(subscriber, provider,
		    EVENTLOG_SESSION_ID_NONE, hdr.cpu, &hdr, &iov, 1,
		    sizeof(info));
	} else {
		eventlog_subscriber_write_event_callback(subscriber, provider,
		    EVENTLOG_SESSION_ID_NONE, &hdr, &iov, 1, sizeof(info));
	}
	smr_exit(evl.smr);

	if (provider->decode_blob == NULL || provider->decode_blob_size == 0)
		return;
	max_blob = (size_t)UINT16_MAX - sizeof(hdr) -
	    EVENTLOG_DECODE_SCHEMA_ID_LEN - sizeof(uint32_t);
	if (provider->decode_blob_size > max_blob)
		return;

	blob_sz = (uint32_t)provider->decode_blob_size;
	blob_payload_len = EVENTLOG_DECODE_SCHEMA_ID_LEN + sizeof(blob_sz) +
	    blob_sz;
	blob_payload = malloc(blob_payload_len, M_EVENTLOG, M_NOWAIT);
	if (blob_payload == NULL)
		return;
	memcpy(blob_payload, provider->schema_id,
	    EVENTLOG_DECODE_SCHEMA_ID_LEN);
	memcpy(blob_payload + EVENTLOG_DECODE_SCHEMA_ID_LEN, &blob_sz,
	    sizeof(blob_sz));
	memcpy(blob_payload + EVENTLOG_DECODE_SCHEMA_ID_LEN + sizeof(blob_sz),
	    provider->decode_blob, blob_sz);

	memset(&hdr, 0, sizeof(hdr));
	hdr.event_length = (uint16_t)(sizeof(hdr) + blob_payload_len);
	hdr.thread_id = (curthread != NULL) ? curthread->td_tid : 0;
	hdr.provider_id = provider->provider_id;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = EVENTLOG_PROVIDER_BLOB_ID;

	smr_enter(evl.smr);
	hdr.cpu = PCPU_GET(cpuid);
	hdr.timestamp = eventlog_now_us();
	iov.iov_base = blob_payload;
	iov.iov_len = blob_payload_len;
	if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE) {
		eventlog_subscriber_write_event_device(subscriber, provider,
		    EVENTLOG_SESSION_ID_NONE, hdr.cpu, &hdr, &iov, 1,
		    blob_payload_len);
	} else {
		eventlog_subscriber_write_event_callback(subscriber, provider,
		    EVENTLOG_SESSION_ID_NONE, &hdr, &iov, 1, blob_payload_len);
	}
	smr_exit(evl.smr);
	free(blob_payload, M_EVENTLOG);
}

/*
 * Bind a freshly-registered provider to every subscriber that has a
 * remembered spec matching its name but is not yet subscribed to it.
 * Uses M_NOWAIT under evl.subscribers_mtx; on allocation failure the
 * binding is skipped (best effort).  After the lock is dropped, emit a
 * provider-announcement record into each newly-bound subscriber's stream
 * so the capture names the provider even if it unregisters before the
 * next GET_PROVIDERS poll.
 */
static void
eventlog_bind_provider_to_subscribers(struct eventlog_provider *provider)
{
	struct eventlog_subscriber *subscriber;
	struct eventlog_subscriber *targets_small[16];
	struct eventlog_subscriber **targets;
	struct eventlog_subscription *sub, *new_sub;
	struct eventlog_sub_spec *spec;
	uint32_t ntargets = 0, cap_targets = 0;
	bool bound_any = false;
	uint32_t i;

	/*
	 * Count matching unbound subscribers first so the target array can
	 * be sized without growing under the lock.  Over-count is fine (a
	 * concurrent subscribe may bind before we re-walk).
	 */
	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_FOREACH(subscriber, &evl.subscribers, link)
		cap_targets++;
	mtx_unlock(&evl.subscribers_mtx);

	if (cap_targets == 0)
		return;
	if (cap_targets <= nitems(targets_small))
		targets = targets_small;
	else {
		targets = malloc(cap_targets * sizeof(*targets), M_EVENTLOG,
		    M_NOWAIT);
		if (targets == NULL) {
			targets = targets_small;
			cap_targets = nitems(targets_small);
		}
	}

	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_FOREACH(subscriber, &evl.subscribers, link) {
		bool want = false, present = false;
		enum eventlog_level level = EVENTLOG_LEVEL_NONE;
		uint32_t keywords = 0;

		STAILQ_FOREACH(spec, &subscriber->specs, link) {
			if (strcmp(spec->name, provider->name) == 0) {
				want = true;
				level = spec->level;
				keywords = spec->keywords;
				break;
			}
		}
		if (!want)
			continue;

		CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
			if (sub->provider == provider) {
				present = true;
				break;
			}
		}
		if (present)
			continue;

		new_sub = malloc(sizeof(*new_sub), M_EVENTLOG, M_NOWAIT);
		if (new_sub == NULL)
			continue;
		new_sub->provider = provider;
		new_sub->level = level;
		new_sub->keywords = keywords;
		CK_SLIST_INSERT_HEAD(&subscriber->subscriptions, new_sub, link);
		bound_any = true;
		if (ntargets < cap_targets)
			targets[ntargets++] = subscriber;
	}
	mtx_unlock(&evl.subscribers_mtx);

	for (i = 0; i < ntargets; i++)
		eventlog_emit_provider_announcement(provider, targets[i]);

	if (targets != targets_small)
		free(targets, M_EVENTLOG);

	if (bound_any)
		eventlog_update_provider_enablement(provider);
}

/*
 * Remove all subscriptions pointing at a provider being destroyed, so no
 * subscriber dereferences freed memory. Subscribers keep their specs so a
 * re-registered provider of the same name rebinds.
 */
static void
eventlog_unbind_provider_from_subscribers(struct eventlog_provider *provider)
{
	struct eventlog_subscriber *subscriber;
	struct eventlog_subscription *sub, *tmp;
	CK_SLIST_HEAD(, eventlog_subscription) dead =
	    CK_SLIST_HEAD_INITIALIZER(dead);

	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_FOREACH(subscriber, &evl.subscribers, link) {
		CK_SLIST_FOREACH_SAFE(sub, &subscriber->subscriptions, link, tmp) {
			if (sub->provider != provider)
				continue;
			CK_SLIST_REMOVE(&subscriber->subscriptions, sub,
			    eventlog_subscription, link);
			CK_SLIST_INSERT_HEAD(&dead, sub, link);
		}
	}
	mtx_unlock(&evl.subscribers_mtx);

	/* Wait out SMR readers, then free the detached subscriptions. */
	if (!CK_SLIST_EMPTY(&dead)) {
		smr_synchronize(evl.smr);
		while ((sub = CK_SLIST_FIRST(&dead)) != NULL) {
			CK_SLIST_REMOVE_HEAD(&dead, link);
			free(sub, M_EVENTLOG);
		}
	}
}

/*
 * Re-trigger a dump_state replay for every dump-capable provider
 * `subscriber` is currently subscribed to, without adding or changing
 * any subscription. This is what EVENTLOG_IOCTL_TRIGGER_DUMP_STATE
 * dispatches to.
 */
void
eventlog_subscriber_trigger_dump_state(struct eventlog_subscriber *subscriber)
{
	struct eventlog_subscription *sub;
	struct eventlog_provider *small[16];
	struct eventlog_provider **dump_providers;
	uint32_t count, cap, i;

	MPASS(subscriber != NULL);

	/*
	 * Snapshot under evl.subscribers_mtx (the lock guarding
	 * subscriber->subscriptions), then enqueue after releasing it --
	 * eventlog_enqueue_dump_task() takes dump_pending_mtx, and no
	 * caller nests that under subscribers_mtx elsewhere; keep it that
	 * way.  Sized dynamically (a small on-stack array covers the common
	 * case) rather than a fixed cap, so a subscriber with many
	 * subscriptions never silently misses a re-trigger.
	 */
	cap = 0;
	mtx_lock(&evl.subscribers_mtx);
	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link)
		cap++;
	mtx_unlock(&evl.subscribers_mtx);

	if (cap == 0)
		return;

	if (cap <= nitems(small))
		dump_providers = small;
	else
		dump_providers = malloc(cap * sizeof(*dump_providers),
		    M_EVENTLOG, M_WAITOK);

	count = 0;
	mtx_lock(&evl.subscribers_mtx);
	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (count >= cap)
			break;
		dump_providers[count++] = sub->provider;
	}
	mtx_unlock(&evl.subscribers_mtx);

	for (i = 0; i < count; i++)
		eventlog_enqueue_dump_task(subscriber, dump_providers[i]);

	if (dump_providers != small)
		free(dump_providers, M_EVENTLOG);
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

	/*
	 * Publish the new enablement to a user-space provider's mmap'd page so
	 * its _ENABLED() macro sees the change with no system call.  Write
	 * keywords before level (release) so a lock-free reader never observes
	 * a higher level paired with stale keywords; the bumped generation
	 * lets readers detect updates.  A momentary mismatch only risks one
	 * spuriously (un)gated event, which the kernel re-filters on push.
	 */
	if (provider->user_enable != NULL) {
		provider->user_enable->effective_keywords = provider->keywords;
		atomic_store_rel_32(&provider->user_enable->effective_level,
		    (uint32_t)provider->level);
		atomic_add_32(&provider->user_enable->generation, 1);
	}

	/* Update all sessions' effective values */
	LIST_FOREACH(session, &provider->sessions, link) {
		eventlog_session_update_effective(session, provider);
	}
	mtx_unlock(&provider->sessions_lock);

	if (transitioned) {
		if (provider->subscribers_changed != NULL)
			provider->subscribers_changed(provider, has_subscribers,
			    provider->subscribers_changed_arg);
		else if (provider->is_userspace && provider->chan != NULL) {
			(void)eventlog_channel_enqueue_control(provider->chan,
			    EVENTLOG_CONTROL_SUBSCRIBERS_CHANGED,
			    provider->provider_id, has_subscribers ? 1 : 0, 0);
			eventlog_channel_publish_consumer(provider->chan);
		}
	}
}

/*
 * Fold newly-published sources into the merge heap: for each source not
 * already in the heap, insert it by its next-event timestamp, or mark it
 * EVENTLOG_TIMESTAMP_NONE if it has nothing committed.  Sources already in
 * the heap are known to have data and are skipped.
 *
 * Scans real CPUs [0, maxcpu) plus only the live user streams (via the
 * user_active[] permutation), not the full user_stream_cap tail: with the
 * default 1024-stream cap and no user providers attached, that tail is the
 * overwhelming majority of total_sources and is guaranteed inactive.
 * user_stream_active is an acquire load paired with the release store at
 * activation, so the new stream's ring state is visible with the count; a
 * stale-low read merely defers a just-activated stream to the next call,
 * and only the reader thread shrinks the count (reclaim runs under
 * user_lock in this same thread).
 */
static void
eventlog_discover_sources(struct eventlog_subscriber *subscriber)
{
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint16_t maxcpu = subscriber->u.device.maxcpu;
	uint16_t nuser;
	struct eventlog_percpu_buffer *pcpu_buf;
	uint16_t k;
	int src;

	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);

	nuser = atomic_load_acq_16(&subscriber->u.device.user_stream_active);
	for (k = 0; k < (uint16_t)(maxcpu + nuser); k++) {
		src = (k < maxcpu) ? k :
		    maxcpu + subscriber->u.device.user_active[k - maxcpu];
		if (timestamps[src] < EVENTLOG_TIMESTAMP_SWEPT)
			continue;	/* In heap */
		pcpu_buf = &subscriber->u.device.percpu_buffers[src];
		uint64_t ts = eventlog_ring_peek(pcpu_buf);
		if (ts != EVENTLOG_TIMESTAMP_NONE)
			eventlog_heap_insert(subscriber, (uint16_t)src, ts);
		else
			timestamps[src] = EVENTLOG_TIMESTAMP_NONE;
	}
}

/*
 * Read events from a device subscriber's buffer.
 * Handles both user-space (UIO_USERSPACE) and kernel (UIO_SYSSPACE) uio.
 */
/*
 * Compute the self-tuning emit boundary B for this read.
 *
 * B always starts at now - read_watermark_us, the small fixed holdback
 * that absorbs ordinary cross-CPU clock/commit-visibility skew (see
 * eventlog_event_write_impl()); with no user-provider streams that is
 * the final result.  Each armed user stream additionally lowers B to
 * its watermark (ws); an unarmed (just-joined) stream holds B at its
 * join point until it catches up (see the late-join protocol).  The
 * global ceiling eventlog_max_holdback_us (L_max) floors B at now -
 * L_max so a slow or dead producer can never stall the merged stream
 * indefinitely; past that, its late events are dropped.
 *
 * Also performs liveness eviction and arming as a side effect, so it is
 * called with user_lock held.
 */
static void eventlog_user_stream_reclaim(struct eventlog_subscriber *subscriber,
    int slot);

static uint64_t
eventlog_compute_boundary(struct eventlog_subscriber *subscriber, uint64_t now)
{
	struct eventlog_user_stream *us;
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint64_t floor, B;
	uint16_t k, slot, src;

	mtx_assert(&subscriber->u.device.user_lock, MA_OWNED);

	/*
	 * Hold back the last read_watermark_us of "now" even with no user
	 * streams: a CPU whose commit only becomes visible a few
	 * microseconds after another CPU's (ordinary cross-CPU clock/
	 * commit-visibility skew) must still be discovered before we
	 * deliver past it, or its event is silently skipped. See
	 * eventlog_event_write_impl()'s timestamp-capture comment.
	 */
	B = (now > eventlog_read_watermark_us) ?
	    now - eventlog_read_watermark_us : 0;

	floor = (now > eventlog_max_holdback_us) ?
	    now - eventlog_max_holdback_us : 0;

	/* Iterate only live streams via the active permutation. */
	k = 0;
	while (k < subscriber->u.device.user_stream_active) {
		slot = subscriber->u.device.user_active[k];
		us = &subscriber->u.device.user_streams[slot];
		src = subscriber->u.device.maxcpu + slot;

		/*
		 * Reclaim a stream that has been idle well past the holdback
		 * ceiling once its source holds no buffered events (so the
		 * merge cannot reference the freed buffers).  This returns its
		 * ring buffers and frees the slot for reuse.  reclaim swaps the
		 * last live entry into position k, so re-examine k.
		 */
		if (now - us->last_push_us > eventlog_user_idle_reclaim_us &&
		    timestamps[src] >= EVENTLOG_TIMESTAMP_SWEPT) {
			eventlog_user_stream_reclaim(subscriber, slot);
			continue;
		}

		/*
		 * Liveness: a stream that has gone quiet past the ceiling is
		 * declared caught-up to the floor so the stream can progress.
		 */
		if (now - us->last_push_us > eventlog_max_holdback_us) {
			us->armed = true;
			if (us->ws < floor)
				us->ws = floor;
		}

		if (!us->armed) {
			/* Hold at the join point until the stream catches up. */
			if (us->join_wc < B)
				B = us->join_wc;
			if (us->ws >= us->join_wc)
				us->armed = true;
		}
		if (us->armed && us->ws < B)
			B = us->ws;
		k++;
	}

	if (B < floor)
		B = floor;
	return (B);
}

/*
 * True if at least one buffered event is at or below the boundary B and
 * therefore emittable now.  The heap root holds the global minimum
 * head timestamp across all sources.
 */
static inline bool
eventlog_have_emittable(struct eventlog_subscriber *subscriber, uint64_t B)
{
	if (subscriber->u.device.heap_size == 0)
		return (false);
	return (subscriber->u.device.cpu_timestamps[
	    subscriber->u.device.heap_cpus[0]] <= B);
}

int
eventlog_subscriber_read(struct eventlog_subscriber *subscriber,
    struct uio *uio, int flags)
{
	uint64_t now, B;
	int error = 0;
	int tries;
	bool announcements_only;

	MPASS(subscriber != NULL);
	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);
	MPASS(uio != NULL);

	if (uio->uio_iovcnt != 1 || uio->uio_resid == 0)
		return (EOPNOTSUPP); /* Only one iovec supported */

	/*
	 * A blocking reader retries for up to ~1s total (matched to the old
	 * plain "hz" single sleep) in short increments, so a missed wakeup
	 * costs at most a short nap rather than a full second of
	 * stale-buffer discovery latency.
	 */
	for (tries = 0; ; tries++) {
		bool have_user;
		int to;

		/*
		 * Pull any records producers have published into their
		 * submission rings into subscriber buffers before we look
		 * for emittable events.
		 */
		eventlog_drain_user_channels();

		/* Pick up newly published data, then check if we have
		 * anything to read. */
		eventlog_discover_sources(subscriber);

		now = eventlog_now_us();
		mtx_lock(&subscriber->u.device.user_lock);
		B = eventlog_compute_boundary(subscriber, now);
		mtx_unlock(&subscriber->u.device.user_lock);

		if (eventlog_have_emittable(subscriber, B))
			break;

		have_user = !LIST_EMPTY(&evl.user_channels);

		if ((flags & FNONBLOCK) || tries >= 100)
			return (EAGAIN);

		/*
		 * Wait for writers to produce data, or for the boundary to
		 * advance (a lagging user stream catching up, or the L_max
		 * floor rising as time passes).  The short base timeout
		 * bounds how stale a missed wakeup can leave us; when
		 * user-space submission rings exist it is shortened further
		 * to user_drain_poll_us so a silently-publishing producer
		 * (zero submit syscalls) is still drained promptly.
		 */
		to = MAX(hz / 100, 1);
		if (have_user) {
			int pt = (int)((eventlog_user_drain_poll_us *
			    (uint64_t)hz) / 1000000ULL);
			if (pt < 1)
				pt = 1;
			if (pt < to)
				to = pt;
			/*
			 * Arm the producer-side kick: while we sleep, a newly
			 * published record wakes us immediately rather than
			 * waiting out the poll timeout.
			 */
			eventlog_reader_block_enter();
		}
		atomic_store_rel_32(&subscriber->u.device.reader_waiting, 1);
		error = tsleep(subscriber, PCATCH, "evtlogrd", to);
		atomic_store_rel_32(&subscriber->u.device.reader_waiting, 0);
		if (have_user)
			eventlog_reader_block_exit();
		if (error != 0 && error != EWOULDBLOCK)
			return (error);
	}

	announcements_only = eventlog_read_merged(subscriber, uio, B);

	/*
	 * Record the boundary the consumer is now guaranteed to have seen
	 * everything up to; a user stream joining later uses this as its
	 * join point. Announcements are not capture events, so a read that
	 * copied only them does not move the join point -- an announcement
	 * would otherwise make the next real user event unorderable.
	 */
	if (!announcements_only) {
		mtx_lock(&subscriber->u.device.user_lock);
		if (B > subscriber->u.device.consumer_wc)
			subscriber->u.device.consumer_wc = B;
		mtx_unlock(&subscriber->u.device.user_lock);
	}
	return (0);
}

/*
 * Re-sweep sources not in the heap. Called once per eventlog_read_merged()
 * loop iteration -- not just when a CPU is extracted from the heap --
 * because a continuously-busy CPU can stay root indefinitely (refreshed via
 * heap_update_root / direct timestamp writes) without ever being extracted,
 * which would otherwise starve discovery of an idle CPU that becomes
 * non-empty mid-call while other CPUs keep draining past its (older) next
 * timestamp.
 *
 * A CPU is only marked SWEPT (skip until the next read() call) once we've
 * actually peeked a committed timestamp beyond read_timestamp -- per-CPU
 * monotonicity then guarantees nothing earlier can ever land there for
 * this read_timestamp. A CPU with nothing committed yet (head == tail)
 * gives no such guarantee: its writer could commit an overdue event with
 * ts <= read_timestamp moments later, still within this same read() call,
 * so it must stay EVENTLOG_TIMESTAMP_NONE and keep getting re-checked by
 * every subsequent resweep. Marking it SWEPT here was the residual gap
 * that let a quiet CPU's overdue event slip behind busier CPUs' newer
 * ones within a single read().
 *
 * Two cheap outs keep this off the per-batch hot path:
 *
 *  - Sequence gate: a source outside the heap is by construction empty
 *    (NONE) or proven-fresh (SWEPT), and only the writer's
 *    empty->nonempty publish (which bumps commit_seq) can change that, so
 *    when no such publish has landed since the last sweep the full scan is
 *    skipped.  The acquire/release pairing with the writer's head publish
 *    means a sweep that observes a bumped seq also observes the data.
 *
 *  - Live-only scan: real CPUs [0, maxcpu) plus the live user streams
 *    (user_active[] permutation), not the full user_stream_cap tail, which
 *    is guaranteed inactive.  user_stream_active is an acquire load
 *    paired with the release store at activation, so the new stream's
 *    ring state is visible with the count; a stale-low read merely
 *    defers a just-activated stream to the next sweep, and only the
 *    reader thread shrinks the count.
 */
static void
eventlog_resweep_idle_cpus(struct eventlog_subscriber *subscriber,
    uint64_t read_timestamp)
{
	uint64_t *timestamps = subscriber->u.device.cpu_timestamps;
	uint16_t maxcpu = subscriber->u.device.maxcpu;
	uint16_t nuser;
	struct eventlog_percpu_buffer *pcpu_buf;
	uint64_t seq;
	uint16_t k;
	int src;

	seq = atomic_load_acq_64(&subscriber->u.device.commit_seq);
	if (seq == subscriber->u.device.swept_seq)
		return;		/* No empty->nonempty publish since last sweep. */

	nuser = atomic_load_acq_16(&subscriber->u.device.user_stream_active);
	for (k = 0; k < (uint16_t)(maxcpu + nuser); k++) {
		src = (k < maxcpu) ? k :
		    maxcpu + subscriber->u.device.user_active[k - maxcpu];
		if (timestamps[src] != EVENTLOG_TIMESTAMP_NONE)
			continue;	/* In heap or already swept */
		pcpu_buf = &subscriber->u.device.percpu_buffers[src];
		uint64_t ts = eventlog_ring_peek(pcpu_buf);
		if (ts == EVENTLOG_TIMESTAMP_NONE)
			continue;	/* Still nothing committed; recheck next resweep. */
		if (ts <= read_timestamp)
			eventlog_heap_insert(subscriber, (uint16_t)src, ts);
		else
			timestamps[src] = EVENTLOG_TIMESTAMP_SWEPT;
	}

	subscriber->u.device.swept_seq = seq;
}

/*
 * Merge events from all CPUs in timestamp order, copying via uio.
 * Events with timestamps beyond read_timestamp are deferred to the next read.
 * Every loop iteration resweeps idle CPUs (see eventlog_resweep_idle_cpus),
 * so a CPU that becomes non-empty mid-call is folded in before any other
 * CPU is allowed to drain past its next timestamp.
 * Caller must have called eventlog_discover_sources beforehand.
 */
static EVENTLOG_INLINING bool
eventlog_read_merged(struct eventlog_subscriber *subscriber, struct uio *uio,
    uint64_t read_timestamp)
{
	struct eventlog_percpu_buffer *pcpu_buf;
	bool announcements_only = true;

	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);
	MPASS(subscriber->u.device.heap_size > 0);

	/*
	 * A CPU can become non-empty in the gap between the previous read()
	 * call's last resweep and this call's fresh read_timestamp -- fold
	 * it in before copying anything, or the first batch below could
	 * drain another CPU past it untouched.
	 */
	eventlog_resweep_idle_cpus(subscriber, read_timestamp);

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
		    effective_max, &next_timestamp, &uio_out_of_space,
		    &announcements_only);

		if (uio_out_of_space)
			break;

		EVENTLOG_VALIDATE_READER(pcpu_buf);
		/* next_timestamp == 0 is copy_events()'s authoritative "this CPU
		 * was drained" signal.  It already re-checked head after the
		 * copy, so 0 means truly empty; anything else is the next
		 * event's timestamp. */
		if (next_timestamp == 0) {
			/* Ring drained and still empty: remove this CPU from
			 * the heap. */
			eventlog_heap_extract_min(subscriber);
		} else if (next_timestamp > read_timestamp) {
			/* Remaining events are past the epoch boundary. */
			eventlog_heap_extract_min(subscriber);
		} else {
			/* Buffer has more data within epoch: update root and sift. */
			MPASS(next_timestamp != 0);
			eventlog_heap_update_root(subscriber, next_timestamp);
		}

		/*
		 * Resweep every iteration, not just when a CPU is extracted
		 * from the heap. A continuously-busy CPU can stay root
		 * indefinitely via the heap_update_root / direct-timestamp-
		 * write paths above without ever being extracted; gating
		 * the resweep on extraction alone lets it monopolize the
		 * loop and starve discovery of an idle CPU that commits an
		 * overdue event mid-call -- the exact violation this heap
		 * is supposed to prevent.
		 */
		eventlog_resweep_idle_cpus(subscriber, read_timestamp);
	}
	return (announcements_only);
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
    bool *uio_out_of_space_out, bool *announcements_only)
{
	uint32_t size = pcpu_buf->buffer_size;
	uint32_t mask = pcpu_buf->buffer_mask;
	uint32_t head, tail, base_offset, avail, bytes_consumed = 0;
	size_t space_avail = uio->uio_resid;
	uint64_t next_timestamp = 0;

	MPASS(pcpu_buf != NULL);
	MPASS(uio != NULL);
	MPASS(next_timestamp_out != NULL);
	MPASS(uio_out_of_space_out != NULL);

	*uio_out_of_space_out = false;

	/* Ensure tail is at a real event (skip any leading wrap pad). */
	head = eventlog_ring_skip_pad(pcpu_buf);
	tail = pcpu_buf->tail;
	base_offset = tail & mask;
	avail = head - tail;

	/* Scan one contiguous run of real events (a batch never crosses the
	 * physical wrap) that fall within max_timestamp and fit in the uio. */
	while (bytes_consumed < avail &&
	    (base_offset + bytes_consumed) < size) {
		struct eventlog_event_header hdr;
		uint32_t offset = base_offset + bytes_consumed;

		/* Sub-header gap before the physical end == implicit wrap; the
		 * next batch's skip_pad reclaims it.  Must check before reading
		 * the header to avoid an out-of-bounds read at the end. */
		if (size - offset < sizeof(struct eventlog_event_header))
			break;

		memcpy(&hdr, pcpu_buf->buffer + offset,
		    sizeof(struct eventlog_event_header));
		if (hdr.event_length == 0)
			break;			/* wrap boundary */
		MPASS(hdr.event_length >= sizeof(struct eventlog_event_header));
		if (hdr.timestamp > max_timestamp)
			break;
		if (bytes_consumed + hdr.event_length > space_avail) {
			*uio_out_of_space_out = true;
			break;
		}
		if (hdr.event_id != EVENTLOG_PROVIDER_INFO_ID &&
		    hdr.event_id != EVENTLOG_PROVIDER_BLOB_ID &&
		    hdr.event_id != EVENTLOG_DUMP_COMPLETE_ID)
			*announcements_only = false;
		bytes_consumed += hdr.event_length;
	}

	/* Copy the contiguous batch into the uio buffer. */
	if (bytes_consumed > 0) {
		const char *src = (const char *)(pcpu_buf->buffer + base_offset);

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

		atomic_store_rel_32(&pcpu_buf->tail, tail + bytes_consumed);
	}

	/* Report the next event's timestamp (across any wrap) for the caller's
	 * heap bookkeeping; 0 means this CPU is now drained. */
	if (!*uio_out_of_space_out) {
		head = eventlog_ring_skip_pad(pcpu_buf);
		if (head != pcpu_buf->tail)
			next_timestamp = eventlog_read_timestamp(
			    pcpu_buf->buffer + (pcpu_buf->tail & mask));
		else
			next_timestamp = 0;
	}

out:
	*next_timestamp_out = next_timestamp;
}

/*
 * Account a dropped device write.  User-space provider streams live at
 * source indices >= maxcpu (the real per-CPU sources occupy [0, maxcpu));
 * attribute their buffer-full drops to user_dropped_full so a stalled
 * user producer is distinguishable from real kernel-CPU overruns.
 */
static inline void
eventlog_count_device_drop(struct eventlog_subscriber *subscriber, uint16_t cpu)
{
	if (cpu >= subscriber->u.device.maxcpu)
		atomic_add_long(&subscriber->user_dropped_full, 1);
	else
		atomic_add_long(&subscriber->dropped_events, 1);
}

/*
 * Write an event to a device-based subscriber's per-source ring (a real
 * per-CPU source, or a user-stream pseudo-source at maxcpu+slot -- see
 * `src` below).  Format: header (includes provider_id, session_id,
 * event_id) + payload.
 *
 * Single producer per source (the SMR critical section pins a real-CPU
 * writer and disables preemption; a user-stream source's user_lock gives
 * the same guarantee).  The producer owns head and only reads tail, so
 * publication is a single release store of head -- no CAS, no lock.  A
 * record never straddles the physical end: if it will not fit, the
 * remaining tail bytes are skipped (marked with a PAD when a header fits)
 * and the record is placed at offset 0.
 */
static EVENTLOG_INLINING void
eventlog_subscriber_write_event_device(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, uint64_t session_id, uint16_t src,
    struct eventlog_event_header *hdr, const struct iovec *iov, int iovcnt,
    size_t payload_size)
{
	struct eventlog_percpu_buffer *pcpu_buf;
	uint8_t *buf;
	uint32_t size, mask, head, head_old, tail, used, offset, to_end, total;
	uint32_t event_len = (uint32_t)hdr->event_length;
	bool wrap = false;
	int i;

	MPASS(subscriber != NULL);
	MPASS(provider != NULL);
	MPASS(hdr != NULL);
	MPASS(subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE);
	MPASS(src < subscriber->u.device.total_sources);
#ifdef INVARIANTS
	size_t expected_length = sizeof(struct eventlog_event_header) + payload_size;
	MPASS(hdr->event_length == expected_length);
	MPASS(hdr->RESERVED == 0);
#endif

	pcpu_buf = &subscriber->u.device.percpu_buffers[src];
	size = pcpu_buf->buffer_size;
	mask = pcpu_buf->buffer_mask;
	MPASS(event_len <= size);

	/* Single producer owns head; only tail is shared with the reader. */
	head = pcpu_buf->head;
	head_old = head;
	tail = atomic_load_acq_32(&pcpu_buf->tail);
	used = head - tail;
	offset = head & mask;
	to_end = size - offset;

	/* If the record would straddle the physical end, account for the
	 * skipped tail bytes as part of the reservation. */
	total = event_len;
	if (event_len > to_end) {
		wrap = true;
		total = to_end + event_len;
	}

	if (__predict_false(used + total > size)) {
		eventlog_count_device_drop(subscriber, src);
		return;
	}

	if (wrap) {
		if (to_end >= sizeof(struct eventlog_event_header)) {
			struct eventlog_event_header pad;

			memset(&pad, 0, sizeof(pad));
			memcpy(pcpu_buf->buffer + offset, &pad, sizeof(pad));
		}
		head += to_end;
		offset = 0;
	}

	/* Write header then payload segments at offset. */
	buf = pcpu_buf->buffer + offset;
	memcpy(buf, hdr, sizeof(struct eventlog_event_header));
	buf += sizeof(struct eventlog_event_header);
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf, iov[i].iov_base, iov[i].iov_len);
			buf += iov[i].iov_len;
		}
	}
	head += event_len;

	/* Publish: a single release store makes the pad (if any) and the
	 * record visible to the reader atomically. */
	atomic_store_rel_32(&pcpu_buf->head, head);

	/* If the ring is empty now that head is visible, this publish is the
	 * empty->nonempty transition the reader's resweep sequence gate keys
	 * on.  Re-check tail post-publish: the entry load can be stale if
	 * the reader drained the ring to empty between our tail load and
	 * the publish, and only a bump after the publish guarantees a
	 * resweep that runs from here on observes this record.  The release
	 * store above orders the record before the bump's release, so a
	 * reader that sees the bumped seq also sees the data. */
	if (__predict_false(atomic_load_acq_32(&pcpu_buf->tail) == head_old))
		atomic_add_rel_64(&subscriber->u.device.commit_seq, 1);

	/* The ring publishes each record immediately, so wake a blocked
	 * reader as soon as data is available (lower latency than the old
	 * batch-on-full wake). */
	if (__predict_false(
	    atomic_load_acq_32(&subscriber->u.device.reader_waiting) != 0) &&
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

	/* Note: Called within SMR read section */
	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (sub->provider == provider) {
			/* Ensure this subscriber wants this event */
			if (level <= sub->level && (keywords & sub->keywords) != 0) {
				if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_DEVICE) {
					eventlog_subscriber_write_event_device(
					    subscriber, provider,
					    session->session_id, hdr->cpu,
					    hdr, iov, iovcnt, payload_size);
				} else {
					eventlog_subscriber_write_event_callback(
					    subscriber, provider,
					    session->session_id,
					    hdr, iov, iovcnt, payload_size);
				}
			}
			return; /* Only one subscription per provider per subscriber */
		}
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
	stats->user_dropped_full = (uint64_t)atomic_load_acq_long(
	    &subscriber->user_dropped_full);
	stats->user_dropped_prejoin = (uint64_t)atomic_load_acq_long(
	    &subscriber->user_dropped_prejoin);
	stats->user_dropped_late = (uint64_t)atomic_load_acq_long(
	    &subscriber->user_dropped_late);
}

/*
 * Maximum providers a single fd (push channel) may register.  Each gets a
 * 16-byte struct eventlog_enable_page slot within the one mmap'd page
 * (PAGE_SIZE / 16 == 256 slots on a 4 KB page); cap well under that.
 */
#define	EVENTLOG_USER_PROVIDERS_PER_FD	64

/*
 * Upper bound on a decode blob copied in from an unprivileged user-space
 * provider at registration.  Well under EVENTLOG_DECODE_BLOB_MAX (which sizes
 * blobs read back from capture files): a real schema blob is a few KB, so this
 * caps the per-fd kernel memory a producer can pin (providers-per-fd * this)
 * without needing the ring quota.
 */
#define	EVENTLOG_USER_DECODE_BLOB_MAX	(64u * 1024u)

/*
 * Minimum spacing between consecutive submission-ring drains.  Drains fan a
 * producer's records out to every subscriber, so a drain triggered by one
 * reader serves them all; this collapses the stampede when many subscribers
 * read in lockstep without adding meaningful latency (well under the
 * holdback ceiling).
 */
#define	EVENTLOG_DRAIN_THROTTLE_US	200

/*
 * One submission ring on a user-space provider fd.  SETUP_RING appends
 * another; mmap looks it up by mmap_offset.
 */
struct eventlog_user_ring {
	vm_object_t obj;
	void *kva;
	uint32_t size;		/* data region capacity (power of two) */
	uint32_t data_off;	/* data offset; kernel-set, never re-read from hdr */
	uint32_t total;		/* total mapped bytes (header + data) */
	uint16_t stream_id;	/* kernel-assigned; also written into the header */
	uid_t uid;		/* uid charged for total wired bytes */
	uint64_t mmap_offset;
};

/*
 * User-space provider channel, owned by a /dev/eventlog fd that issued
 * EVENTLOG_IOCTL_REGISTER_PROVIDER. A single fd may register many providers
 * (records carry provider_id); push_lock serializes pushes from the fd so a
 * producer's per-stream timestamp ordering is preserved end to end.
 */
struct eventlog_user_channel {
	uint32_t channel_id;	/* Stable id; keys the subscriber merge stream */
	pid_t owner_pid;	/* Creating process; enforces one channel/pid */
	struct mtx push_lock;
	uint64_t expected_cadence_us;
	u_int nproviders;
	struct eventlog_provider *providers[EVENTLOG_USER_PROVIDERS_PER_FD];
	/*
	 * One-page enablement window shared with the provider process via
	 * mmap(), sliced into one struct eventlog_enable_page slot per
	 * registered provider.  enable_obj backs the user mapping; enable_kva
	 * is the kernel's permanent mapping of the same page, and each
	 * provider's ->user_enable points at its slot.  NULL/0 if allocation
	 * failed (providers still work; the library falls back to
	 * always-enabled).
	 */
	vm_object_t enable_obj;
	void *enable_kva;

	/*
	 * Control queue (kernel -> producer).  Low-frequency events the mmap
	 * gate cannot express: state-dump requests, 0<->N subscriber
	 * transitions, default-tunable changes.  The producer's background
	 * thread drains this via EVENTLOG_IOCTL_WAIT_CONTROL.  ctrl_closing
	 * is set during teardown to wake a blocked waiter and fail further
	 * waits.
	 */
	struct mtx ctrl_lock;
	TAILQ_HEAD(, eventlog_control_entry) ctrl_q;
	int ctrl_waiters;
	bool ctrl_closing;

	/*
	 * Submission rings (EVENTLOG_IOCTL_SETUP_RING).  The producer maps
	 * each ring_obj at its mmap_offset and writes records into it; the
	 * kernel drains [tail, head) under drain_lock into a private bounce
	 * snapshot (drain_buf, sized to the largest ring) and fans it out.
	 * rings is allocated on the first SETUP_RING (a fd may stay ring-less,
	 * e.g. dump-only); nrings counts the entries in use.
	 */
	struct mtx drain_lock;
	struct eventlog_user_ring *rings;
	u_int nrings;
	uint8_t *drain_buf;	/* snapshot bounce buffer (drain_buf_size bytes) */
	uint32_t drain_buf_size;

	/*
	 * Global channel list linkage + teardown sync (evl.user_channels_lock).
	 * refs counts in-flight drains; closing blocks new drains and the
	 * cdevpriv dtor waits for refs to reach zero before freeing.
	 */
	LIST_ENTRY(eventlog_user_channel) link;
	u_int refs;
	bool listed;
	bool closing;
};

/* A queued control event awaiting delivery via WAIT_CONTROL. */
struct eventlog_control_entry {
	TAILQ_ENTRY(eventlog_control_entry) link;
	struct eventlog_control_event ev;
};

/*
 * One /dev/eventlog fd is either a subscriber or a user-space provider,
 * decided by the first CREATE / REGISTER_PROVIDER ioctl. The tagged priv
 * is allocated at open and torn down via cdevpriv on close.
 */
enum eventlog_cdev_kind {
	EVENTLOG_CDEV_NONE,
	EVENTLOG_CDEV_SUBSCRIBER,
	EVENTLOG_CDEV_PROVIDER,
};
struct eventlog_cdev_priv {
	enum eventlog_cdev_kind kind;
	union {
		struct eventlog_subscriber *subscriber;
		struct eventlog_user_channel *chan;
	} u;
};

/* Hash a (channel_id, stream_id) pair into the user-stream bucket index. */
static inline uint32_t
eventlog_user_hash(struct eventlog_subscriber *subscriber, uint32_t channel_id,
    uint16_t stream_id)
{
	uint64_t key = ((uint64_t)channel_id << 16) | stream_id;

	/* Fibonacci hashing, then mask to the power-of-two table size. */
	return ((uint32_t)(key * 11400714819323198485ull >> 48) &
	    subscriber->u.device.user_hash_mask);
}

/*
 * Fully reclaim a live user stream: unlink it from its hash bucket, remove
 * it from the active-slot permutation (swap with the last live entry), free
 * its ring buffers, and mark it idle.  Only legal when the stream's source
 * holds no buffered events (timestamps[src] == NONE), so the merge never
 * references the freed buffers.  Caller holds user_lock.
 */
static void
eventlog_user_stream_reclaim(struct eventlog_subscriber *subscriber, int slot)
{
	struct eventlog_user_stream *us = &subscriber->u.device.user_streams[slot];
	struct eventlog_percpu_buffer *pcpu;
	uint32_t h;
	int16_t *pp;
	uint16_t pos, last, lastslot, src;

	mtx_assert(&subscriber->u.device.user_lock, MA_OWNED);

	/* Unlink from the hash bucket chain. */
	h = eventlog_user_hash(subscriber, us->channel_id, us->stream_id);
	for (pp = &subscriber->u.device.user_hash[h]; *pp != -1;
	    pp = &subscriber->u.device.user_streams[*pp].hnext) {
		if (*pp == slot) {
			*pp = us->hnext;
			break;
		}
	}
	us->hnext = -1;

	/* Remove from the active permutation: swap with the last live entry. */
	pos = us->active_idx;
	last = --subscriber->u.device.user_stream_active;
	lastslot = subscriber->u.device.user_active[last];
	subscriber->u.device.user_active[pos] = lastslot;
	subscriber->u.device.user_streams[lastslot].active_idx = pos;
	subscriber->u.device.user_active[last] = (uint16_t)slot;
	us->active_idx = last;

	/* Free the ring buffer; reactivation will re-allocate lazily. */
	src = subscriber->u.device.maxcpu + (uint16_t)slot;
	pcpu = &subscriber->u.device.percpu_buffers[src];
	if (pcpu->buffer != NULL) {
		free(pcpu->buffer, M_EVENTLOG);
		pcpu->buffer = NULL;
	}
	pcpu->buffer_size = 0;
	pcpu->buffer_mask = 0;
	/*
	 * Readers pair an acquire-load of head with a plain read of tail
	 * (eventlog_validate_ring, eventlog_copy_events_from_cpu,
	 * eventlog_ring_skip_pad), relying on head's acquire to also make
	 * tail's latest store visible. Reset tail first with a release
	 * store, then head, so a reader that observes the new head=0 is
	 * guaranteed to also observe tail=0 rather than a stale pre-reset
	 * tail -- the reverse order (or plain stores) can let a reader see
	 * head=0 with the old, larger tail still visible, underflowing
	 * head - tail.
	 */
	atomic_store_rel_32(&pcpu->tail, 0);
	atomic_store_rel_32(&pcpu->head, 0);
	subscriber->u.device.cpu_timestamps[src] = EVENTLOG_TIMESTAMP_NONE;
	us->active = false;
}

/*
 * Find (or lazily assign) the per-subscriber stream slot for a
 * (channel_id, stream_id) pair via the O(1) hash.  On a miss, claim a free
 * slot and allocate its ring buffers with M_NOWAIT (legal under user_lock,
 * an MTX_DEF mutex).  Returns NULL if the cap is reached or the buffer
 * allocation fails, in which case the caller drops and counts the record.
 *
 * Caller holds subscriber->u.device.user_lock.
 */
static struct eventlog_user_stream *
eventlog_user_stream_get(struct eventlog_subscriber *subscriber,
    uint32_t channel_id, uint16_t stream_id, uint64_t now)
{
	struct eventlog_user_stream *us;
	struct eventlog_percpu_buffer *pcpu;
	uint32_t h, sz;
	int16_t slot;
	uint16_t pos, src;

	mtx_assert(&subscriber->u.device.user_lock, MA_OWNED);

	h = eventlog_user_hash(subscriber, channel_id, stream_id);
	for (slot = subscriber->u.device.user_hash[h]; slot != -1;
	    slot = subscriber->u.device.user_streams[slot].hnext) {
		us = &subscriber->u.device.user_streams[slot];
		if (us->channel_id == channel_id && us->stream_id == stream_id)
			return (us);
	}

	/* Miss: claim the next free slot from the permutation, if any. */
	if (subscriber->u.device.user_stream_active >=
	    subscriber->u.device.user_stream_cap)
		return (NULL);
	pos = subscriber->u.device.user_stream_active;
	slot = subscriber->u.device.user_active[pos];
	us = &subscriber->u.device.user_streams[slot];

	/* Lazily allocate the ring buffer if this slot was never used or was
	 * reclaimed. */
	src = subscriber->u.device.maxcpu + (uint16_t)slot;
	pcpu = &subscriber->u.device.percpu_buffers[src];
	if (pcpu->buffer == NULL) {
		sz = eventlog_ring_pow2(subscriber->u.device.user_buffer_size);
		pcpu->buffer = malloc(sz, M_EVENTLOG, M_NOWAIT | M_ZERO);
		if (pcpu->buffer == NULL)
			return (NULL);
		pcpu->buffer_size = sz;
		pcpu->buffer_mask = sz - 1;
		pcpu->head = 0;
		pcpu->tail = 0;
	}

	/*
	 * Commit the activation.  The release store pairs with the lockless
	 * acquire loads in the reader's source scans, so a reader that
	 * observes the bumped count also observes the ring buffer and
	 * head/tail initialization above.
	 */
	atomic_store_rel_16(&subscriber->u.device.user_stream_active, pos + 1);
	us->active = true;
	us->channel_id = channel_id;
	us->stream_id = stream_id;
	us->join_wc = subscriber->u.device.consumer_wc;
	us->ws = 0;
	us->last_ts = 0;
	us->last_push_us = now;
	/*
	 * If the consumer has not been delivered anything yet there is no
	 * prefix to be out of order with, so the stream joins armed.
	 */
	us->armed = (us->join_wc == 0);

	/* Link into the hash bucket. */
	us->hnext = subscriber->u.device.user_hash[h];
	subscriber->u.device.user_hash[h] = slot;
	return (us);
}

/*
 * Map a provider_id to a provider registered on this channel, or NULL.
 * Linear over the channel's small provider set.
 */
static struct eventlog_provider *
eventlog_channel_lookup(struct eventlog_user_channel *chan,
    uint16_t provider_id)
{
	u_int i;

	for (i = 0; i < chan->nproviders; i++)
		if (chan->providers[i]->provider_id == provider_id)
			return (chan->providers[i]);
	return (NULL);
}

/*
 * If this subscriber is subscribed to provider, return true and its
 * level/keyword filter; otherwise false.
 */
static bool
eventlog_subscriber_wants(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider, enum eventlog_level *level_out,
    uint32_t *keywords_out)
{
	struct eventlog_subscription *sub;

	CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
		if (sub->provider == provider) {
			*level_out = sub->level;
			*keywords_out = sub->keywords;
			return (true);
		}
	}
	return (false);
}

/*
 * Route one validated push batch into a single subscriber. Records may mix
 * providers registered on the same channel, so each record resolves its
 * own provider and the subscriber's filter for it. Applies the level/
 * keyword filter, the late-join drop (events older than join_wc on an
 * unarmed stream), and the per-source ordering drop, then writes survivors
 * through the normal device write path so the merge orders them.
 *
 * Callers hold evl.subscribers_mtx (stable subscriber + subscription
 * lists). Device buffer writes are a lock-free single-producer ring
 * publish, so no SMR section is required here.
 */
static void
eventlog_user_push_to_subscriber(struct eventlog_subscriber *subscriber,
    struct eventlog_user_channel *chan, uint16_t stream_id,
    uint64_t ws_promise, const uint8_t *data, uint32_t bytes, uint32_t count,
    uint64_t now)
{
	struct eventlog_provider *provider;
	struct eventlog_user_stream *us;
	enum eventlog_level sub_level;
	uint32_t sub_keywords, off;
	uint16_t vid;
	uint32_t i;
	bool wrote = false;

	(void)bytes;

	/*
	 * Callback subscribers are synchronous and unordered; deliver the
	 * matching events immediately and return.
	 */
	if (subscriber->type == EVENTLOG_SUBSCRIBER_TYPE_CALLBACK) {
		off = 0;
		for (i = 0; i < count; i++) {
			const struct eventlog_push_record *r =
			    (const struct eventlog_push_record *)(data + off);
			struct eventlog_event_header hdr;
			struct iovec iov;

			off += sizeof(*r) + r->payload_len;
			provider = eventlog_channel_lookup(chan, r->provider_id);
			if (provider == NULL)
				continue;
			if (!eventlog_subscriber_wants(subscriber, provider,
			    &sub_level, &sub_keywords))
				continue;
			if ((enum eventlog_level)r->level > sub_level ||
			    (r->keywords & sub_keywords) == 0)
				continue;
			hdr.event_length = (uint16_t)(sizeof(hdr) +
			    r->payload_len);
			hdr.cpu = r->cpu;
			hdr.provider_id = provider->provider_id;
			/* Callback path doesn't use RESERVED as a
			 * merge-source index; zero per the wire's rule. */
			hdr.RESERVED = 0;
			hdr.timestamp = r->timestamp_us;
			hdr.session_id = r->session_id;
			hdr.event_id = r->event_id;
			hdr.thread_id = r->thread_id;
			iov.iov_base = (void *)(uintptr_t)(r + 1);
			iov.iov_len = r->payload_len;
			eventlog_subscriber_write_event_callback(subscriber,
			    provider, r->session_id, &hdr, &iov, 1,
			    r->payload_len);
		}
		return;
	}

	/* Device subscriber without a user-stream pool can't buffer these. */
	if (subscriber->u.device.user_stream_cap == 0) {
		atomic_add_long(&subscriber->user_dropped_late, count);
		return;
	}

	mtx_lock(&subscriber->u.device.user_lock);
	off = 0;
	for (i = 0; i < count; i++) {
		const struct eventlog_push_record *r =
		    (const struct eventlog_push_record *)(data + off);
		struct eventlog_event_header hdr;
		struct iovec iov;

		off += sizeof(*r) + r->payload_len;

		provider = eventlog_channel_lookup(chan, r->provider_id);
		if (provider == NULL)
			continue;
		if (!eventlog_subscriber_wants(subscriber, provider,
		    &sub_level, &sub_keywords))
			continue;
		if ((enum eventlog_level)r->level > sub_level ||
		    (r->keywords & sub_keywords) == 0)
			continue;

		us = eventlog_user_stream_get(subscriber, chan->channel_id,
		    stream_id, now);
		if (us == NULL) {
			atomic_add_long(&subscriber->user_dropped_late, 1);
			continue;
		}
		if (ws_promise > us->ws)
			us->ws = ws_promise;
		us->last_push_us = now;

		if (!us->armed && r->timestamp_us < us->join_wc) {
			atomic_add_long(&subscriber->user_dropped_prejoin, 1);
			continue;
		}
		if (r->timestamp_us < us->last_ts) {
			/* Would violate this source's sorted invariant. */
			atomic_add_long(&subscriber->user_dropped_late, 1);
			continue;
		}

		vid = subscriber->u.device.maxcpu + (uint16_t)(us -
		    subscriber->u.device.user_streams);
		hdr.event_length = (uint16_t)(sizeof(hdr) + r->payload_len);
		hdr.cpu = r->cpu;
		hdr.provider_id = provider->provider_id;
		hdr.RESERVED = 0;
		hdr.timestamp = r->timestamp_us;
		hdr.session_id = r->session_id;
		hdr.event_id = r->event_id;
		hdr.thread_id = r->thread_id;
		iov.iov_base = (void *)(uintptr_t)(r + 1);
		iov.iov_len = r->payload_len;
		eventlog_subscriber_write_event_device(subscriber, provider,
		    r->session_id, vid, &hdr, &iov, 1, r->payload_len);
		us->last_ts = r->timestamp_us;
		wrote = true;
	}
	mtx_unlock(&subscriber->u.device.user_lock);

	/* Nudge a blocked reader so it re-evaluates the boundary. */
	if (wrote &&
	    atomic_cmpset_32(&subscriber->u.device.reader_waiting, 1, 0))
		wakeup(subscriber);
}

/*
 * Validate and route a batch of packed user-space provider records (from the
 * submission ring or a PUSH_DUMP ioctl) already copied into kernel memory.
 * The record count is derived by walking the byte stream.  Returns 0 on
 * success or an errno; events may still be selectively dropped per
 * subscriber.
 */
static int
eventlog_user_push(struct eventlog_user_channel *chan, uint16_t stream_id,
    uint64_t watermark_us, uint32_t bytes, const uint8_t *data,
    uint64_t target_subscriber_id)
{
	struct eventlog_subscriber *subscriber;
	struct bintime bt;
	uint64_t now, ws_promise, prev_ts = 0, batch_max = 0;
	uint32_t off, count;

	if (bytes == 0)
		return (0);

	/*
	 * Validate the batch: every record fits, names a provider registered
	 * on this channel, timestamps are non-decreasing, levels and ids are
	 * sane, and the records exactly fill `bytes`. Reject reserved
	 * framework event ids so user space can't forge session lifecycle
	 * markers.
	 */
	off = 0;
	count = 0;
	while (off < bytes) {
		const struct eventlog_push_record *r;

		if (off + sizeof(*r) > bytes)
			return (EINVAL);
		r = (const struct eventlog_push_record *)(data + off);
		if (r->level > EVENTLOG_LEVEL_TRACE)
			return (EINVAL);
		if (eventlog_channel_lookup(chan, r->provider_id) == NULL)
			return (EINVAL);
		if (r->event_id == EVENTLOG_SESSION_CREATE_ID ||
		    r->event_id == EVENTLOG_SESSION_END_ID ||
		    r->event_id == EVENTLOG_DUMP_COMPLETE_ID ||
		    r->event_id == EVENTLOG_PROVIDER_INFO_ID ||
		    r->event_id == EVENTLOG_PROVIDER_BLOB_ID)
			return (EINVAL);
		if ((size_t)sizeof(struct eventlog_event_header) +
		    r->payload_len > UINT16_MAX)
			return (EINVAL);
		if (off + sizeof(*r) + r->payload_len > bytes)
			return (EINVAL);
		if (r->timestamp_us < prev_ts)
			return (EINVAL); /* not non-decreasing */
		prev_ts = r->timestamp_us;
		if (r->timestamp_us > batch_max)
			batch_max = r->timestamp_us;
		off += sizeof(*r) + r->payload_len;
		count++;
	}
	if (off != bytes)
		return (EINVAL);

	binuptime(&bt);
	now = bintime2us(&bt);

	/*
	 * Clamp the declared watermark so a producer can neither claim to
	 * be ahead of the clock nor behind the data it just delivered.
	 */
	ws_promise = watermark_us;
	if (ws_promise > now)
		ws_promise = now;
	if (ws_promise < batch_max)
		ws_promise = batch_max;

	mtx_lock(&chan->push_lock);
	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_FOREACH(subscriber, &evl.subscribers, link) {
		/*
		 * target_subscriber_id != 0 (a PUSH_DUMP state replay) routes
		 * only to the consumer that requested the dump, so others do
		 * not receive duplicate state.
		 */
		if (target_subscriber_id != 0 &&
		    subscriber->subscriber_id != target_subscriber_id)
			continue;
		eventlog_user_push_to_subscriber(subscriber, chan,
		    stream_id, ws_promise, data, bytes, count, now);
	}
	mtx_unlock(&evl.subscribers_mtx);
	mtx_unlock(&chan->push_lock);
	return (0);
}

/*
 * Set or clear a EVENTLOG_RING_F_* hint bit in every ring header on this
 * channel.  The word is kernel-owned but mmap-visible to the producer, which
 * reads it with a plain load to decide whether an EVENTLOG_IOCTL_KICK is
 * worthwhile.  No-op if no ring has been set up yet.
 */
static void
eventlog_channel_ring_flag(struct eventlog_user_channel *chan, uint32_t bit,
    bool on)
{
	u_int i;

	mtx_lock(&chan->drain_lock);
	for (i = 0; i < chan->nrings; i++) {
		struct eventlog_ring_hdr *hdr = chan->rings[i].kva;

		if (hdr == NULL)
			continue;
		if (on)
			atomic_set_32(&hdr->flags, bit);
		else
			atomic_clear_32(&hdr->flags, bit);
	}
	mtx_unlock(&chan->drain_lock);
}

/*
 * Publish whether any subscriber consumes a provider on this channel.  The
 * producer gates its high-water drain kick on this so a producer with no
 * listener stays zero-syscall instead of kicking drains that only discard.
 */
static void
eventlog_channel_publish_consumer(struct eventlog_user_channel *chan)
{
	bool present = false;
	u_int i;

	for (i = 0; i < chan->nproviders; i++) {
		if (chan->providers[i] != NULL &&
		    chan->providers[i]->has_subscribers) {
			present = true;
			break;
		}
	}
	eventlog_channel_ring_flag(chan, EVENTLOG_RING_F_CONSUMER_PRESENT,
	    present);
}

/*
 * A device reader is about to block waiting for data.  On the 0->1 edge, mark
 * every live producer ring NEED_WAKEUP so the next published record triggers a
 * kick instead of waiting for the periodic drain poll.  Coarse on purpose: a
 * kick that finds nothing to drain is a cheap no-op.
 */
static void
eventlog_reader_block_enter(void)
{
	struct eventlog_user_channel *chan;

	mtx_lock(&evl.user_channels_lock);
	if (evl.blocked_readers++ == 0) {
		LIST_FOREACH(chan, &evl.user_channels, link)
			eventlog_channel_ring_flag(chan,
			    EVENTLOG_RING_F_NEED_WAKEUP, true);
	}
	mtx_unlock(&evl.user_channels_lock);
}

/* The matching wake-up: clear NEED_WAKEUP once the last reader stops waiting. */
static void
eventlog_reader_block_exit(void)
{
	struct eventlog_user_channel *chan;

	mtx_lock(&evl.user_channels_lock);
	if (--evl.blocked_readers == 0) {
		LIST_FOREACH(chan, &evl.user_channels, link)
			eventlog_channel_ring_flag(chan,
			    EVENTLOG_RING_F_NEED_WAKEUP, false);
	}
	mtx_unlock(&evl.user_channels_lock);
}

/*
 * Drain one submission ring: snapshot [tail, head) into the channel's
 * private bounce buffer (defeating TOCTOU against a hostile producer), then
 * validate + fan out via eventlog_user_push and publish the new tail.  A
 * garbage/overrun head can never make the kernel read past the ring; such a
 * batch is discarded wholesale and tail resynced to head so a buggy producer
 * cannot wedge its own ring forever.  Caller holds drain_lock.
 */
static void
eventlog_drain_one_ring(struct eventlog_user_channel *chan,
    struct eventlog_user_ring *ring)
{
	struct eventlog_ring_hdr *hdr;
	const uint8_t *ringdata;
	uint64_t head, tail, watermark;
	uint32_t size, mask, navail, t, n1;
	uint16_t stream_id;

	hdr = (struct eventlog_ring_hdr *)ring->kva;
	if (hdr == NULL)
		return;
	size = ring->size;
	mask = size - 1;
	/*
	 * Use kernel-cached data_off / stream_id, never hdr fields: the
	 * producer maps the header read/write and could scribble them to
	 * steer ringdata OOB or demux into another stream.
	 */
	ringdata = (const uint8_t *)ring->kva + ring->data_off;

	tail = hdr->tail;			/* kernel-owned */
	head = atomic_load_acq_64(&hdr->head);	/* published by the producer */
	if (head == tail)
		return;

	navail = (uint32_t)(head - tail);
	if ((head - tail) > (uint64_t)size) {
		/*
		 * Producer overran the ring or head is garbage: we cannot
		 * trust the bytes.  Discard everything and resync.
		 */
		atomic_store_rel_64(&hdr->tail, head);
		return;
	}

	/* Snapshot the linear stream, splitting at the physical wrap. */
	t = (uint32_t)(tail & mask);
	n1 = size - t;
	if (n1 > navail)
		n1 = navail;
	memcpy(chan->drain_buf, ringdata + t, n1);
	if (navail > n1)
		memcpy(chan->drain_buf + n1, ringdata, navail - n1);

	stream_id = ring->stream_id;
	watermark = atomic_load_acq_64(&hdr->watermark_us);

	/*
	 * Fan the snapshot out to all current subscribers.  Whether it
	 * validates or not, we have consumed these bytes from the ring, so
	 * advance tail to the snapshotted head (a later drain handles records
	 * the producer published after our load).
	 */
	(void)eventlog_user_push(chan, stream_id, watermark, navail,
	    chan->drain_buf, 0);
	atomic_store_rel_64(&hdr->tail, head);
}

/*
 * Drain every submission ring on this channel.  KICK and the subscriber
 * read path both come through here, so one ioctl/read consumes the whole fd.
 */
static void
eventlog_drain_channel(struct eventlog_user_channel *chan)
{
	u_int i;

	if (chan->nrings == 0 || chan->closing)
		return;

	mtx_lock(&chan->drain_lock);
	for (i = 0; i < chan->nrings; i++)
		eventlog_drain_one_ring(chan, &chan->rings[i]);
	mtx_unlock(&chan->drain_lock);
}

/*
 * Drain every user-space submission ring, fanning each producer's records
 * out to all subscribers.  Called from the subscriber read path; a global
 * throttle collapses the stampede when many subscribers read at once (a
 * single recent drain has already delivered to every subscriber).  The walk
 * holds a refcount on the current and next channel so a concurrent fd close
 * cannot free a channel out from under us.
 */
static void
eventlog_drain_user_channels(void)
{
	static volatile uint64_t last_drain_us;
	struct eventlog_user_channel *chan, *next;
	struct bintime bt;
	uint64_t now, last;

	if (LIST_EMPTY(&evl.user_channels))
		return;

	binuptime(&bt);
	now = bintime2us(&bt);
	last = atomic_load_acq_64(&last_drain_us);
	if (now - last < EVENTLOG_DRAIN_THROTTLE_US)
		return;
	atomic_store_rel_64(&last_drain_us, now);

	mtx_lock(&evl.user_channels_lock);
	chan = LIST_FIRST(&evl.user_channels);
	if (chan != NULL)
		chan->refs++;
	while (chan != NULL) {
		mtx_unlock(&evl.user_channels_lock);

		eventlog_drain_channel(chan);

		mtx_lock(&evl.user_channels_lock);
		next = LIST_NEXT(chan, link);
		if (next != NULL)
			next->refs++;
		if (--chan->refs == 0 && chan->closing)
			wakeup(chan);
		chan = next;
	}
	mtx_unlock(&evl.user_channels_lock);
}

/*
 * Stop drains against a channel and unlink it from the global list: mark it
 * closing so no new drain starts, wait for any in-flight drain to drop its
 * ref, then remove it.  Called from the fd teardown path before the ring and
 * locks are freed.
 */
static void
eventlog_user_channel_unlist_wait(struct eventlog_user_channel *chan)
{
	if (!chan->listed)
		return;
	mtx_lock(&evl.user_channels_lock);
	chan->closing = true;
	while (chan->refs > 0)
		msleep(chan, &evl.user_channels_lock, PWAIT, "evchdrn", 0);
	LIST_REMOVE(chan, link);
	chan->listed = false;
	mtx_unlock(&evl.user_channels_lock);
}

/*
 * Append a control event to a channel's queue and wake its background
 * thread (if any).  Best-effort: returns an errno (and enqueues nothing) if
 * the channel is tearing down or memory is short, in which case the caller
 * unwinds any state it staged for the event.
 */
static int
eventlog_channel_enqueue_control(struct eventlog_user_channel *chan,
    uint16_t type, uint16_t provider_id, int32_t value,
    uint64_t subscriber_id)
{
	struct eventlog_control_entry *ce;

	ce = malloc(sizeof(*ce), M_EVENTLOG, M_NOWAIT | M_ZERO);
	if (ce == NULL)
		return (ENOMEM);
	ce->ev.type = type;
	ce->ev.provider_id = provider_id;
	ce->ev.value = value;
	ce->ev.subscriber_id = subscriber_id;

	mtx_lock(&chan->ctrl_lock);
	if (chan->ctrl_closing) {
		mtx_unlock(&chan->ctrl_lock);
		free(ce, M_EVENTLOG);
		return (ESHUTDOWN);
	}
	TAILQ_INSERT_TAIL(&chan->ctrl_q, ce, link);
	if (chan->ctrl_waiters > 0)
		wakeup(&chan->ctrl_q);
	mtx_unlock(&chan->ctrl_lock);
	return (0);
}

/*
 * Register an outstanding state-dump request against `subscriber` and post a
 * DUMP_REQUEST to the user-space provider's channel.  The dump_pending
 * reference is released by the producer's DUMP_DONE, by channel teardown, or
 * by subscriber teardown.  Best-effort: if the request can't be delivered,
 * the reference is unwound here so a draining subscriber never stalls.
 */
static void
eventlog_user_dump_request(struct eventlog_subscriber *subscriber,
    struct eventlog_provider *provider)
{
	struct eventlog_user_channel *chan = provider->chan;
	struct eventlog_user_dump *ud;

	if (chan == NULL)
		return;

	ud = malloc(sizeof(*ud), M_EVENTLOG, M_NOWAIT | M_ZERO);
	if (ud == NULL)
		return;
	ud->chan = chan;
	ud->provider_id = provider->provider_id;

	mtx_lock(&subscriber->dump_pending_mtx);
	subscriber->dump_pending++;
	TAILQ_INSERT_TAIL(&subscriber->user_dumps, ud, link);
	mtx_unlock(&subscriber->dump_pending_mtx);

	if (eventlog_channel_enqueue_control(chan, EVENTLOG_CONTROL_DUMP_REQUEST,
	    provider->provider_id, 0, subscriber->subscriber_id) != 0) {
		mtx_lock(&subscriber->dump_pending_mtx);
		TAILQ_REMOVE(&subscriber->user_dumps, ud, link);
		if (subscriber->dump_pending > 0 &&
		    --subscriber->dump_pending == 0)
			cv_broadcast(&subscriber->dump_pending_cv);
		mtx_unlock(&subscriber->dump_pending_mtx);
		free(ud, M_EVENTLOG);
	}
}

/*
 * A producer signalled it finished replaying state for (subscriber_id,
 * provider_id).  Synthesise DUMP_COMPLETE for that subscriber and release
 * the outstanding dump.  No-op if the subscriber is gone or the request was
 * already cancelled (e.g. by teardown), so a late/duplicate DUMP_DONE is
 * harmless.
 */
static void
eventlog_user_dump_done(struct eventlog_user_channel *chan,
    uint64_t subscriber_id, uint16_t provider_id)
{
	struct eventlog_subscriber *s, *target = NULL;
	struct eventlog_provider *provider = NULL;
	struct eventlog_user_dump *ud, *match = NULL;
	u_int i;

	for (i = 0; i < chan->nproviders; i++) {
		if (chan->providers[i]->provider_id == provider_id) {
			provider = chan->providers[i];
			break;
		}
	}
	if (provider == NULL)
		return;

	mtx_lock(&evl.subscribers_mtx);
	CK_LIST_FOREACH(s, &evl.subscribers, link) {
		if (s->subscriber_id == subscriber_id) {
			target = s;
			break;
		}
	}
	if (target != NULL) {
		mtx_lock(&target->dump_pending_mtx);
		TAILQ_FOREACH(ud, &target->user_dumps, link) {
			if (ud->chan == chan && ud->provider_id == provider_id) {
				match = ud;
				break;
			}
		}
		if (match != NULL) {
			TAILQ_REMOVE(&target->user_dumps, match, link);
			if (target->dump_pending > 0 &&
			    --target->dump_pending == 0)
				cv_broadcast(&target->dump_pending_cv);
		}
		mtx_unlock(&target->dump_pending_mtx);
		if (match != NULL)
			eventlog_emit_dump_complete(provider, target);
	}
	mtx_unlock(&evl.subscribers_mtx);

	free(match, M_EVENTLOG);
}

/*
 * Device operations
 */

/*
 * Allocate the per-provider enablement page: an OBJT_PHYS VM object the
 * provider process maps read/write at offset 0, plus a permanent kernel
 * mapping (enable_kva) the framework writes through.  Best effort: on
 * failure the provider works without the cheap mmap gate (the library
 * falls back to always-enabled and the kernel still filters on push).
 */
static int
eventlog_user_enable_alloc(struct eventlog_user_channel *chan)
{
	vm_page_t m;
	void *kva;
	vm_object_t obj;

	kva = kva_alloc(PAGE_SIZE);
	if (kva == NULL)
		return (ENOMEM);
	obj = vm_pager_allocate(OBJT_PHYS, 0, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, 0, curthread->td_ucred);
	if (obj == NULL) {
		kva_free(kva, PAGE_SIZE);
		return (ENOMEM);
	}
	VM_OBJECT_WLOCK(obj);
	m = vm_page_grab(obj, 0, VM_ALLOC_ZERO | VM_ALLOC_WIRED);
	vm_page_valid(m);
	vm_page_xunbusy(m);
	pmap_qenter(kva, &m, 1);
	VM_OBJECT_WUNLOCK(obj);

	chan->enable_obj = obj;
	chan->enable_kva = kva;
	return (0);
}

/*
 * Tear down the enablement page.  The caller must guarantee no further
 * kernel writes through provider->user_enable occur (i.e. the provider has
 * already been destroyed and unbound from all subscribers).
 */
static void
eventlog_user_enable_free(struct eventlog_user_channel *chan)
{
	struct pctrie_iter pages;
	vm_page_t m;

	if (chan->enable_kva != NULL) {
		pmap_qremove(chan->enable_kva, 1);
		kva_free(chan->enable_kva, PAGE_SIZE);
		chan->enable_kva = NULL;
	}
	if (chan->enable_obj != NULL) {
		vm_page_iter_limit_init(&pages, chan->enable_obj, 1);
		VM_OBJECT_WLOCK(chan->enable_obj);
		VM_RADIX_FORALL(m, &pages)
			vm_page_unwire_noq(m);
		VM_OBJECT_WUNLOCK(chan->enable_obj);
		vm_object_deallocate(chan->enable_obj);
		chan->enable_obj = NULL;
	}
}

/*
 * Total wired bytes a ring with the given data region occupies (header +
 * data, rounded to whole pages).  Shared by the allocator and the per-uid
 * quota pre-check so both agree on the charge.
 */
static uint32_t
eventlog_ring_total_bytes(uint32_t data_size)
{
	uint32_t data_off;

	data_off = roundup2((uint32_t)sizeof(struct eventlog_ring_hdr),
	    EVENTLOG_RING_CACHELINE);
	return (roundup2(data_off + data_size, (uint32_t)PAGE_SIZE));
}

/*
 * Charge `bytes` of wired ring memory to `uid`, failing with ENOMEM if it
 * would exceed the per-uid ceiling.  Root (uid 0) is trusted and exempt.
 */
static int
eventlog_ring_quota_charge(uid_t uid, uint64_t bytes)
{
	struct eventlog_ring_quota *q, *nq = NULL;
	u_long cap;
	int error = 0;

	if (uid == 0)
		return (0);
again:
	mtx_lock(&evl.ring_quota_lock);
	LIST_FOREACH(q, &evl.ring_quotas, link)
		if (q->uid == uid)
			break;
	if (q == NULL) {
		if (nq == NULL) {
			mtx_unlock(&evl.ring_quota_lock);
			nq = malloc(sizeof(*nq), M_EVENTLOG, M_WAITOK | M_ZERO);
			nq->uid = uid;
			goto again;
		}
		q = nq;
		nq = NULL;
		LIST_INSERT_HEAD(&evl.ring_quotas, q, link);
	}
	cap = eventlog_user_ring_max_per_uid;
	if (q->bytes + bytes > (uint64_t)cap)
		error = ENOMEM;
	else
		q->bytes += bytes;
	mtx_unlock(&evl.ring_quota_lock);
	if (nq != NULL)
		free(nq, M_EVENTLOG);
	return (error);
}

/* Return `bytes` of wired ring memory to `uid`'s accounting (uid 0 exempt). */
static void
eventlog_ring_quota_refund(uid_t uid, uint64_t bytes)
{
	struct eventlog_ring_quota *q;

	if (uid == 0 || bytes == 0)
		return;
	mtx_lock(&evl.ring_quota_lock);
	LIST_FOREACH(q, &evl.ring_quotas, link)
		if (q->uid == uid) {
			q->bytes = q->bytes >= bytes ? q->bytes - bytes : 0;
			break;
		}
	mtx_unlock(&evl.ring_quota_lock);
}

/*
 * Grow the channel's drain bounce buffer so it can snapshot a ring of
 * data_size bytes.  malloc is outside drain_lock; the swap is under it so a
 * concurrent drain cannot free the buffer it is copying into.
 */
static void
eventlog_channel_ensure_drain_buf(struct eventlog_user_channel *chan,
    uint32_t data_size)
{
	uint8_t *nb, *old;

	if (data_size <= chan->drain_buf_size)
		return;
	nb = malloc(data_size, M_EVENTLOG, M_WAITOK);
	mtx_lock(&chan->drain_lock);
	if (data_size > chan->drain_buf_size) {
		old = chan->drain_buf;
		chan->drain_buf = nb;
		chan->drain_buf_size = data_size;
		nb = NULL;
	} else
		old = NULL;
	mtx_unlock(&chan->drain_lock);
	free(nb, M_EVENTLOG);
	free(old, M_EVENTLOG);
}

/*
 * Allocate one submission ring: a multi-page OBJT_PHYS object the provider
 * maps read/write at a distinct mmap_offset, plus a permanent kernel mapping
 * of the same pages.  data_size must already be a clamped power of two.
 * stream_id / mmap_offset / uid are filled in by the caller on insert.
 */
static int
eventlog_user_ring_alloc(struct eventlog_user_ring *ring, uint32_t data_size)
{
	struct eventlog_ring_hdr *hdr;
	vm_object_t obj;
	vm_page_t m;
	void *kva;
	uint32_t data_off, total, npages, i;

	data_off = roundup2((uint32_t)sizeof(struct eventlog_ring_hdr),
	    EVENTLOG_RING_CACHELINE);
	total = eventlog_ring_total_bytes(data_size);
	npages = total / PAGE_SIZE;

	kva = kva_alloc(total);
	if (kva == NULL)
		return (ENOMEM);
	obj = vm_pager_allocate(OBJT_PHYS, 0, total, PROT_READ | PROT_WRITE, 0,
	    curthread->td_ucred);
	if (obj == NULL) {
		kva_free(kva, total);
		return (ENOMEM);
	}
	VM_OBJECT_WLOCK(obj);
	for (i = 0; i < npages; i++) {
		m = vm_page_grab(obj, i, VM_ALLOC_ZERO | VM_ALLOC_WIRED);
		vm_page_valid(m);
		vm_page_xunbusy(m);
		pmap_qenter((void *)((char *)kva + (size_t)i * PAGE_SIZE), &m, 1);
	}
	VM_OBJECT_WUNLOCK(obj);

	memset(ring, 0, sizeof(*ring));
	ring->obj = obj;
	ring->kva = kva;
	ring->size = data_size;
	ring->data_off = data_off;
	ring->total = total;

	hdr = (struct eventlog_ring_hdr *)kva;
	hdr->version = EVENTLOG_RING_VERSION;
	hdr->data_size = data_size;
	hdr->data_offset = data_off;
	return (0);
}

/*
 * Tear down one ring's kernel mapping and VM object, refunding its quota.
 */
static void
eventlog_user_ring_release(struct eventlog_user_ring *ring)
{
	struct pctrie_iter pages;
	vm_page_t m;

	if (ring->kva != NULL) {
		pmap_qremove(ring->kva, ring->total / PAGE_SIZE);
		kva_free(ring->kva, ring->total);
		ring->kva = NULL;
	}
	if (ring->obj != NULL) {
		vm_page_iter_limit_init(&pages, ring->obj,
		    ring->total / PAGE_SIZE);
		VM_OBJECT_WLOCK(ring->obj);
		VM_RADIX_FORALL(m, &pages)
			vm_page_unwire_noq(m);
		VM_OBJECT_WUNLOCK(ring->obj);
		vm_object_deallocate(ring->obj);
		ring->obj = NULL;
		eventlog_ring_quota_refund(ring->uid, ring->total);
		ring->total = 0;
	}
}

/*
 * Tear down every submission ring.  The caller must guarantee no drain is in
 * progress (the channel is unlisted and refs has drained to zero).
 */
static void
eventlog_user_ring_free(struct eventlog_user_channel *chan)
{
	u_int i;

	for (i = 0; i < chan->nrings; i++)
		eventlog_user_ring_release(&chan->rings[i]);
	free(chan->rings, M_EVENTLOG);
	chan->rings = NULL;
	chan->nrings = 0;
	free(chan->drain_buf, M_EVENTLOG);
	chan->drain_buf = NULL;
	chan->drain_buf_size = 0;
}

/*
 * mmap() handler.  Only a registered user-space provider fd may map: the
 * single enablement page at offset 0, or a submission ring at
 * EVENTLOG_RING_MMAP_OFFSET + n * EVENTLOG_RING_MMAP_STRIDE.  Returns the
 * matching shared VM object so the process and kernel share the same memory.
 */
static int
eventlog_dev_mmap_single(struct cdev *dev __unused, vm_ooffset_t *offset,
    vm_size_t size, struct vm_object **object, int nprot)
{
	struct eventlog_cdev_priv *priv;
	struct eventlog_user_channel *chan;
	int error;

	if ((nprot & PROT_EXEC) != 0)
		return (EACCES);
	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->kind != EVENTLOG_CDEV_PROVIDER)
		return (ENXIO);
	chan = priv->u.chan;

	if (*offset == 0) {
		if (chan->enable_obj == NULL)
			return (ENXIO);
		if (size > PAGE_SIZE)
			return (EINVAL);
		vm_object_reference(chan->enable_obj);
		*offset = 0;
		*object = chan->enable_obj;
		return (0);
	}
	if (*offset >= EVENTLOG_RING_MMAP_OFFSET) {
		vm_ooffset_t rel = *offset - EVENTLOG_RING_MMAP_OFFSET;
		u_int idx;

		if (rel % EVENTLOG_RING_MMAP_STRIDE == 0) {
			struct eventlog_user_ring *ring;

			idx = (u_int)(rel / EVENTLOG_RING_MMAP_STRIDE);
			/*
			 * Pair with the SETUP_RING publish (rings[] then
			 * nrings++) so a concurrent mmap never reads a ring
			 * slot ahead of its contents.
			 */
			mtx_lock(&chan->drain_lock);
			if (idx >= chan->nrings) {
				mtx_unlock(&chan->drain_lock);
				return (ENXIO);
			}
			ring = &chan->rings[idx];
			if (ring->obj == NULL) {
				mtx_unlock(&chan->drain_lock);
				return (ENXIO);
			}
			if (size > ring->total) {
				mtx_unlock(&chan->drain_lock);
				return (EINVAL);
			}
			vm_object_reference(ring->obj);
			*offset = 0;
			*object = ring->obj;
			mtx_unlock(&chan->drain_lock);
			return (0);
		}
	}
	return (EINVAL);
}

/*
 * Device open handler. The fd becomes a subscriber or a user-space
 * provider on its first CREATE / REGISTER_PROVIDER ioctl.
 * Only prison0 (the host) may open: the eventlog framework is host-global
 * and not safe to expose to jailed processes.
 */
/*
 * Subscribing reads the system-wide event stream (every provider's events,
 * including kernel providers), so it stays privileged even though producing
 * is open to unprivileged processes.  Allow root or members of the operator
 * group, matching the device's historical root:operator ownership.
 */
static int
eventlog_priv_subscribe(struct thread *td)
{
	if (groupmember(GID_OPERATOR, td->td_ucred))
		return (0);
	return (priv_check(td, PRIV_DRIVER));
}

static int
eventlog_dev_open(struct cdev *dev, int flags, int devtype __unused,
    struct thread *td)
{
	struct eventlog_cdev_priv *priv;
	int error;

	if (jailed(td->td_ucred))
		return (EPERM);

	/*
	 * Subscribers only read; user-space providers additionally need a
	 * writable fd so they can mmap the shared enablement page read-write
	 * (the library overlays its private session state on the rest of the
	 * page).  Permit read and write, but never exec/append/truncate.
	 */
	if (flags & (FEXEC | FAPPEND | O_TRUNC))
		return (ENODEV);

	priv = malloc(sizeof(*priv), M_EVENTLOG, M_WAITOK | M_ZERO);
	priv->kind = EVENTLOG_CDEV_NONE;
	error = devfs_set_cdevpriv(priv, eventlog_dev_clear_cdevpriv);
	if (error != 0) {
		free(priv, M_EVENTLOG);
		return (error);
	}
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
	struct eventlog_cdev_priv *priv = data;

	if (priv == NULL)
		return;

	switch (priv->kind) {
	case EVENTLOG_CDEV_SUBSCRIBER:
		eventlog_subscriber_destroy(priv->u.subscriber);
		break;
	case EVENTLOG_CDEV_PROVIDER: {
		struct eventlog_user_channel *chan = priv->u.chan;
		struct eventlog_subscriber *s;
		struct eventlog_control_entry *ce;
		u_int i;

		/*
		 * Remove the channel from the drain list and wait for any
		 * in-flight drain to finish, so nothing touches the ring or
		 * providers while we tear them down below.
		 */
		eventlog_user_channel_unlist_wait(chan);

		/*
		 * Stop accepting control events and wake any blocked waiter so
		 * a lingering WAIT_CONTROL returns instead of sleeping forever.
		 */
		mtx_lock(&chan->ctrl_lock);
		chan->ctrl_closing = true;
		if (chan->ctrl_waiters > 0)
			wakeup(&chan->ctrl_q);
		mtx_unlock(&chan->ctrl_lock);

		/*
		 * Cancel state-dump requests still owed by this channel so a
		 * draining subscriber is not left waiting on a producer that
		 * has gone away.
		 */
		mtx_lock(&evl.subscribers_mtx);
		CK_LIST_FOREACH(s, &evl.subscribers, link) {
			struct eventlog_user_dump *ud, *udn;

			mtx_lock(&s->dump_pending_mtx);
			TAILQ_FOREACH_SAFE(ud, &s->user_dumps, link, udn) {
				if (ud->chan != chan)
					continue;
				TAILQ_REMOVE(&s->user_dumps, ud, link);
				if (s->dump_pending > 0 &&
				    --s->dump_pending == 0)
					cv_broadcast(&s->dump_pending_cv);
				free(ud, M_EVENTLOG);
			}
			mtx_unlock(&s->dump_pending_mtx);
		}
		mtx_unlock(&evl.subscribers_mtx);

		/*
		 * Destroy every provider first: each unbinds from all
		 * subscribers so no further enablement updates touch its
		 * ->user_enable slot. Only then is it safe to free the shared
		 * page.
		 */
		for (i = 0; i < chan->nproviders; i++)
			eventlog_provider_destroy(chan->providers[i]);
		eventlog_user_enable_free(chan);
		eventlog_user_ring_free(chan);

		/* Free any control events that were never delivered. */
		while ((ce = TAILQ_FIRST(&chan->ctrl_q)) != NULL) {
			TAILQ_REMOVE(&chan->ctrl_q, ce, link);
			free(ce, M_EVENTLOG);
		}
		mtx_destroy(&chan->drain_lock);
		mtx_destroy(&chan->ctrl_lock);
		mtx_destroy(&chan->push_lock);
		free(chan, M_EVENTLOG);
		break;
	}
	case EVENTLOG_CDEV_NONE:
		break;
	}
	free(priv, M_EVENTLOG);
}

/*
 * Device ioctl handler.
 */
static int
eventlog_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	struct eventlog_cdev_priv *priv;
	struct eventlog_subscriber *subscriber;
	struct eventlog_subscription_req *sub_req;
	uint32_t i;
	int error;

	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);

	switch (IOCBASECMD(cmd)) {
	case IOCBASECMD(FIONBIO):
		/* Non-blocking is decided per-call from the fp flags
		 * eventlog_dev_read() already sees; nothing to store. */
		return (0);

	case IOCBASECMD(EVENTLOG_IOCTL_CREATE_BASE): {
		size_t base_size = __builtin_offsetof(struct eventlog_create_req, subscriptions);
		u_int ioctl_len = IOCPARM_LEN(cmd);
		struct eventlog_create_req *req = (struct eventlog_create_req *)data;

		if (priv->kind != EVENTLOG_CDEV_NONE)
			return (EEXIST); /* fd already claimed */

		/* Reading the event stream is privileged; producing is not. */
		error = eventlog_priv_subscribe(td);
		if (error != 0)
			return (error);

		/* Validate request size */
		if (ioctl_len < base_size ||
		    ioctl_len < (base_size + req->count * sizeof(struct eventlog_subscription_req)))
			return (EINVAL);

		if (req->buffer_size_per_cpu < EVENTLOG_BUFFER_SIZE_MIN ||
		    req->buffer_size_per_cpu > EVENTLOG_BUFFER_SIZE_MAX)
			return (EINVAL);

		subscriber = eventlog_subscriber_create_device(
		    req->buffer_size_per_cpu);
		if (subscriber == NULL)
			return (EINVAL);

		/* Process each subscription before claiming the fd. */
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

		priv->u.subscriber = subscriber;
		priv->kind = EVENTLOG_CDEV_SUBSCRIBER;
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_REGISTER_PROVIDER): {
		struct eventlog_provider_reg_req *req =
		    (struct eventlog_provider_reg_req *)data;
		struct eventlog_provider_config cfg;
		struct eventlog_user_channel *chan;
		struct eventlog_provider *p;
		void *blobcopy = NULL;
		uint32_t blobsize;
		size_t namelen;
		u_int slot;
		uid_t uid;
		int err;

		/* A fd is a subscriber XOR a provider channel. */
		if (priv->kind != EVENTLOG_CDEV_NONE &&
		    priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EEXIST);
		if (req->flags != 0)
			return (EINVAL);
		namelen = strnlen(req->name, EVENTLOG_PROVIDER_NAME_MAX);
		if (namelen == 0 || namelen >= EVENTLOG_PROVIDER_NAME_MAX)
			return (EINVAL);

		/*
		 * One provider channel per process for non-root callers:
		 * libeventlog already assumes this, so enforce it here to
		 * stop raw syscalls from opening many fds to multiply
		 * registrations.  Root is exempt, like the ring quota below,
		 * so test harnesses can still model many producers as many
		 * fds in one process.
		 */
		if (priv->kind == EVENTLOG_CDEV_NONE &&
		    td->td_ucred->cr_uid != 0) {
			struct eventlog_user_channel *c;
			pid_t pid = td->td_proc->p_pid;
			bool busy = false;

			mtx_lock(&evl.user_channels_lock);
			LIST_FOREACH(c, &evl.user_channels, link) {
				if (!c->closing && c->owner_pid == pid) {
					busy = true;
					break;
				}
			}
			mtx_unlock(&evl.user_channels_lock);
			if (busy)
				return (EBUSY);
		}

		/*
		 * Optionally copy in the schema decode blob.  The kernel owns
		 * this copy for the provider's lifetime (freed in
		 * eventlog_provider_destroy) so subscribers can fetch it via
		 * GET_DECODE_BLOB after the producer has handed it over.
		 */
		blobsize = req->decode_blob_size;
		if (req->decode_blob == 0)
			blobsize = 0;
		uid = td->td_ucred->cr_uid;
		if (blobsize != 0) {
			if (blobsize > EVENTLOG_USER_DECODE_BLOB_MAX)
				return (EFBIG);
			blobcopy = malloc(blobsize, M_EVENTLOG, M_WAITOK);
			if (copyin((const void *)(uintptr_t)req->decode_blob,
			    blobcopy, blobsize) != 0) {
				free(blobcopy, M_EVENTLOG);
				return (EFAULT);
			}
			/* Charge against the same per-uid quota as ring
			 * memory, else this is unbounded kernel memory an
			 * unprivileged producer could pin. */
			err = eventlog_ring_quota_charge(uid, blobsize);
			if (err != 0) {
				free(blobcopy, M_EVENTLOG);
				return (err);
			}
		}

		/* First registration on this fd creates the channel. */
		if (priv->kind == EVENTLOG_CDEV_NONE) {
			chan = malloc(sizeof(*chan), M_EVENTLOG,
			    M_WAITOK | M_ZERO);
			mtx_init(&chan->push_lock, "eventlog push", NULL,
			    MTX_DEF);
			mtx_init(&chan->ctrl_lock, "eventlog ctrl", NULL,
			    MTX_DEF);
			mtx_init(&chan->drain_lock, "eventlog drain", NULL,
			    MTX_DEF);
			TAILQ_INIT(&chan->ctrl_q);
			/* Best effort: providers still work without the gate. */
			(void)eventlog_user_enable_alloc(chan);
			priv->u.chan = chan;
			priv->kind = EVENTLOG_CDEV_PROVIDER;
			/*
			 * Publish on the global list so the subscriber read
			 * path can drain this channel's ring once set up.
			 */
			chan->owner_pid = td->td_proc->p_pid;
			mtx_lock(&evl.user_channels_lock);
			chan->channel_id = ++evl.next_channel_id;
			LIST_INSERT_HEAD(&evl.user_channels, chan, link);
			chan->listed = true;
			mtx_unlock(&evl.user_channels_lock);
		} else {
			chan = priv->u.chan;
		}

		if (chan->nproviders >= EVENTLOG_USER_PROVIDERS_PER_FD) {
			eventlog_ring_quota_refund(uid, blobsize);
			free(blobcopy, M_EVENTLOG);
			return (ENOSPC);
		}

		bzero(&cfg, sizeof(cfg));
		cfg.default_enabled = (req->default_enabled != 0) ? 1 : 0;
		cfg.decode_blob = blobcopy;
		cfg.decode_blob_size = blobsize;
		p = eventlog_provider_create(req->name, &cfg);
		if (p == NULL) {
			eventlog_ring_quota_refund(uid, blobsize);
			free(blobcopy, M_EVENTLOG);
			/*
			 * If this was the first provider the channel is empty
			 * and useless; tear it back down so the fd is reusable.
			 */
			if (chan->nproviders == 0) {
				eventlog_user_channel_unlist_wait(chan);
				eventlog_user_ring_free(chan);
				eventlog_user_enable_free(chan);
				mtx_destroy(&chan->drain_lock);
				mtx_destroy(&chan->ctrl_lock);
				mtx_destroy(&chan->push_lock);
				free(chan, M_EVENTLOG);
				priv->u.chan = NULL;
				priv->kind = EVENTLOG_CDEV_NONE;
			}
			/* Only failure mode is provider_id exhaustion;
			 * ENOSPC is more specific than ENOMEM here. */
			return (ENOSPC);
		}
		/*
		 * provider_create copied the blob pointer into the provider and
		 * derived its schema_id; the provider now owns the copy (freed
		 * in eventlog_provider_destroy).  It may have dropped an oversize
		 * blob, but we already bounded blobsize, so ownership is exact.
		 */
		p->decode_blob_owned = (blobcopy != NULL);
		p->blob_charge_uid = uid;
		p->is_userspace = true;
		p->chan = chan;
		chan->expected_cadence_us = req->expected_cadence_us;

		/*
		 * Assign the provider a 16-byte enable slot in the shared page
		 * and publish its current aggregated enablement (deferred
		 * subscribers may already have bound during
		 * eventlog_provider_create()) under sessions_lock, so we order
		 * against concurrent eventlog_update_provider_enablement.
		 */
		slot = chan->nproviders;
		if (chan->enable_kva != NULL) {
			struct eventlog_enable_page *ep =
			    &((struct eventlog_enable_page *)
			    chan->enable_kva)[slot];

			mtx_lock(&p->sessions_lock);
			ep->effective_keywords = p->keywords;
			ep->effective_level = (uint32_t)p->level;
			ep->generation = 1;
			p->user_enable = ep;
			mtx_unlock(&p->sessions_lock);
		}
		chan->providers[slot] = p;
		chan->nproviders++;

		/*
		 * A deferred subscriber may have bound during create, before
		 * p->chan was set, so the 0->N transition could not post a
		 * control event then.  Surface the current state now; the
		 * producer's first WAIT_CONTROL drains it.
		 */
		if (p->has_subscribers)
			(void)eventlog_channel_enqueue_control(chan,
			    EVENTLOG_CONTROL_SUBSCRIBERS_CHANGED,
			    p->provider_id, 1, 0);

		req->provider_id = p->provider_id;
		req->enable_offset = (uint16_t)(slot *
		    sizeof(struct eventlog_enable_page));
		req->RESERVED = 0;
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_SETUP_RING): {
		struct eventlog_ring_setup_req *req =
		    (struct eventlog_ring_setup_req *)data;
		struct eventlog_user_channel *chan;
		struct eventlog_user_ring tmp;
		struct eventlog_ring_hdr *hdr;
		uint32_t sz;
		u_int idx;
		uid_t uid;

		if (priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EINVAL);
		if (req->flags != 0)
			return (EINVAL);
		chan = priv->u.chan;
		if (chan->nrings >= EVENTLOG_USER_RINGS_MAX)
			return (ENOSPC);

		sz = req->size != 0 ? req->size : EVENTLOG_RING_SIZE_DEFAULT;
		if (sz < EVENTLOG_RING_SIZE_MIN)
			sz = EVENTLOG_RING_SIZE_MIN;
		if (!powerof2(sz))
			sz = 1U << fls(sz);	/* round up to a power of two */
		if (sz > EVENTLOG_RING_SIZE_MAX)
			sz = EVENTLOG_RING_SIZE_MAX;

		/*
		 * Charge the wired ring memory to the caller's uid before
		 * allocating so an unprivileged producer cannot pin more than
		 * its per-uid share of kernel memory.
		 */
		uid = td->td_ucred->cr_uid;
		error = eventlog_ring_quota_charge(uid,
		    eventlog_ring_total_bytes(sz));
		if (error != 0)
			return (error);
		error = eventlog_user_ring_alloc(&tmp, sz);
		if (error != 0) {
			eventlog_ring_quota_refund(uid,
			    eventlog_ring_total_bytes(sz));
			return (error);
		}
		tmp.uid = uid;
		eventlog_channel_ensure_drain_buf(chan, sz);

		mtx_lock(&chan->drain_lock);
		if (chan->rings == NULL) {
			chan->rings = mallocarray(EVENTLOG_USER_RINGS_MAX,
			    sizeof(*chan->rings), M_EVENTLOG,
			    M_NOWAIT | M_ZERO);
			if (chan->rings == NULL) {
				mtx_unlock(&chan->drain_lock);
				eventlog_user_ring_release(&tmp);
				return (ENOMEM);
			}
		}
		if (chan->nrings >= EVENTLOG_USER_RINGS_MAX) {
			mtx_unlock(&chan->drain_lock);
			eventlog_user_ring_release(&tmp);
			return (ENOSPC);
		}
		idx = chan->nrings;
		tmp.stream_id = (uint16_t)idx;
		if (idx >= EVENTLOG_DUMP_STREAM_ID)
			tmp.stream_id++;
		tmp.mmap_offset = EVENTLOG_RING_MMAP_OFFSET +
		    (uint64_t)idx * EVENTLOG_RING_MMAP_STRIDE;
		hdr = (struct eventlog_ring_hdr *)tmp.kva;
		hdr->stream_id = tmp.stream_id;
		chan->rings[idx] = tmp;
		chan->nrings++;
		mtx_unlock(&chan->drain_lock);
		/*
		 * Seed the kernel-owned wakeup hints now that the ring exists:
		 * subscribers may already be bound (deferred at register time)
		 * and a reader may already be blocked.
		 */
		eventlog_channel_publish_consumer(chan);
		mtx_lock(&evl.user_channels_lock);
		if (evl.blocked_readers > 0)
			eventlog_channel_ring_flag(chan,
			    EVENTLOG_RING_F_NEED_WAKEUP, true);
		mtx_unlock(&evl.user_channels_lock);
		req->size = tmp.size;
		req->flags = 0;
		req->mmap_offset = tmp.mmap_offset;
		req->mmap_size = tmp.total;
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_KICK): {
		if (priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EINVAL);
		/*
		 * Producer-requested drain: snapshot this fd's rings now and
		 * wake any blocked subscriber, shortcutting the periodic poll
		 * for a latency-sensitive or near-full producer.  libeventlog
		 * issues this only when a ring's flags warrant it, so the
		 * steady state stays syscall-free.
		 */
		eventlog_drain_channel(priv->u.chan);
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_REPORT_STATS_BASE): {
		size_t base_size = __builtin_offsetof(
		    struct eventlog_report_stats_req, stats);
		u_int ioctl_len = IOCPARM_LEN(cmd);
		struct eventlog_report_stats_req *req =
		    (struct eventlog_report_stats_req *)data;
		struct eventlog_provider *p;
		uint32_t k;

		if (priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EINVAL);
		if (ioctl_len < base_size ||
		    (size_t)ioctl_len < base_size + (size_t)req->count *
		    sizeof(struct eventlog_provider_stat))
			return (EINVAL);

		/*
		 * Fold each provider's delta-since-last-report into the shared
		 * stats counters.  created is monotonic (ignore any decrease);
		 * active/enabled are gauges and may move either way.
		 */
		for (k = 0; k < req->count; k++) {
			struct eventlog_provider_stat *ps = &req->stats[k];
			int64_t d;

			p = eventlog_channel_lookup(priv->u.chan,
			    ps->provider_id);
			if (p == NULL || p->stats == NULL)
				continue;
			d = (int64_t)(ps->sessions_created -
			    p->reported_created);
			if (d > 0)
				counter_u64_add(p->stats->sessions_created, d);
			d = (int64_t)(ps->sessions_active - p->reported_active);
			if (d != 0)
				counter_u64_add(p->stats->sessions_active, d);
			d = (int64_t)(ps->sessions_enabled -
			    p->reported_enabled);
			if (d != 0)
				counter_u64_add(p->stats->sessions_enabled, d);
			p->reported_created = ps->sessions_created;
			p->reported_active = ps->sessions_active;
			p->reported_enabled = ps->sessions_enabled;
		}
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_PUSH_DUMP_BASE): {
		size_t base_size =
		    __builtin_offsetof(struct eventlog_push_dump_req, data);
		u_int ioctl_len = IOCPARM_LEN(cmd);
		struct eventlog_push_dump_req *req =
		    (struct eventlog_push_dump_req *)data;

		if (priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EINVAL);
		if (req->subscriber_id == 0)
			return (EINVAL);
		if (ioctl_len < base_size ||
		    (size_t)ioctl_len < base_size + req->bytes)
			return (EINVAL);
		return (eventlog_user_push(priv->u.chan, req->stream_id,
		    req->watermark_us, req->bytes, req->data,
		    req->subscriber_id));
	}

	case IOCBASECMD(EVENTLOG_IOCTL_DUMP_DONE): {
		struct eventlog_dump_done_req *req =
		    (struct eventlog_dump_done_req *)data;

		if (priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EINVAL);
		if (IOCPARM_LEN(cmd) < sizeof(*req) || req->subscriber_id == 0)
			return (EINVAL);
		eventlog_user_dump_done(priv->u.chan, req->subscriber_id,
		    req->provider_id);
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_WAIT_CONTROL_BASE): {
		size_t base = __builtin_offsetof(
		    struct eventlog_wait_control_req, events);
		u_int ioctl_len = IOCPARM_LEN(cmd);
		struct eventlog_wait_control_req *req =
		    (struct eventlog_wait_control_req *)data;
		struct eventlog_user_channel *chan;
		struct eventlog_control_entry *ce;
		uint64_t timeout_us;
		uint32_t capacity, n = 0;
		int werr = 0;

		if (priv->kind != EVENTLOG_CDEV_PROVIDER)
			return (EINVAL);
		if (ioctl_len < base)
			return (EINVAL);
		capacity = req->count;
		if (capacity == 0 || (size_t)ioctl_len < base +
		    (size_t)capacity * sizeof(struct eventlog_control_event))
			return (EINVAL);
		timeout_us = req->timeout_us;
		/* Bound the sleep so ustosbt() can't overflow. */
		if (timeout_us > 3600ULL * 1000000ULL)
			timeout_us = 3600ULL * 1000000ULL;
		chan = priv->u.chan;

		mtx_lock(&chan->ctrl_lock);
		if (TAILQ_EMPTY(&chan->ctrl_q) && !chan->ctrl_closing &&
		    timeout_us > 0) {
			chan->ctrl_waiters++;
			werr = msleep_sbt(&chan->ctrl_q, &chan->ctrl_lock,
			    PCATCH, "evlctl", ustosbt(timeout_us), 0, 0);
			chan->ctrl_waiters--;
		}
		while (n < capacity &&
		    (ce = TAILQ_FIRST(&chan->ctrl_q)) != NULL) {
			TAILQ_REMOVE(&chan->ctrl_q, ce, link);
			req->events[n++] = ce->ev;
			free(ce, M_EVENTLOG);
		}
		mtx_unlock(&chan->ctrl_lock);

		req->count = n;
		/* Timeout is success; surface a real interrupt only if we
		 * collected nothing, so the producer can re-arm or exit. */
		if (werr == EWOULDBLOCK)
			werr = 0;
		return (n > 0 ? 0 : werr);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_DESTROY): {
		if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
			return (EINVAL);
		eventlog_subscriber_destroy(priv->u.subscriber);
		priv->u.subscriber = NULL;
		priv->kind = EVENTLOG_CDEV_NONE;
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_GET_STATS): {
		u_int ioctl_len = IOCPARM_LEN(cmd);
		if (ioctl_len < sizeof(struct eventlog_stats))
			return (EINVAL);
		if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
			return (EINVAL);

		eventlog_subscriber_get_stats(priv->u.subscriber,
		    (struct eventlog_stats *)data);
		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_GET_PROVIDERS_BASE): {
		struct eventlog_get_providers_resp *resp;
		struct eventlog_subscription *sub;
		size_t base = __builtin_offsetof(
		    struct eventlog_get_providers_resp, providers);
		u_int ioctl_len = IOCPARM_LEN(cmd);
		uint32_t capacity, total = 0;

		if (ioctl_len < base)
			return (EINVAL);
		if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
			return (EINVAL);
		subscriber = priv->u.subscriber;

		resp = (struct eventlog_get_providers_resp *)data;
		/* Capacity is bounded by both the caller's count and the
		 * buffer the ioctl actually carries.  Past ~163 entries the
		 * 13-bit IOCPARM_LEN field wraps; prefer GET_PROVIDERS2. */
		capacity = resp->count;
		if (capacity > (ioctl_len - base) /
		    sizeof(struct eventlog_provider_info))
			capacity = (ioctl_len - base) /
			    sizeof(struct eventlog_provider_info);
		resp->RESERVED = 0;

		smr_enter(evl.smr);
		CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
			if (total < capacity) {
				resp->providers[total].provider_id =
				    sub->provider->provider_id;
				strlcpy(resp->providers[total].name,
				    sub->provider->name,
				    EVENTLOG_PROVIDER_NAME_MAX);
				memcpy(resp->providers[total].schema_id,
				    sub->provider->schema_id,
				    EVENTLOG_DECODE_SCHEMA_ID_LEN);
			}
			total++;
		}
		smr_exit(evl.smr);
		/* Report the true total so a truncated caller can retry. */
		resp->count = total;

		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_GET_PROVIDERS2): {
		struct eventlog_get_providers2_req *req =
		    (struct eventlog_get_providers2_req *)data;
		struct eventlog_subscription *sub;
		struct eventlog_provider_info *tmp = NULL;
		uint32_t total = 0, capacity = 0;
		bool probe;

		if (IOCPARM_LEN(cmd) < sizeof(*req))
			return (EINVAL);
		if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
			return (EINVAL);
		subscriber = priv->u.subscriber;

		/*
		 * Size probe (no output buffer) just reports count.  A fetch
		 * copies into a kernel bounce buffer under SMR, then copyout
		 * after the section — same pattern as GET_DECODE_BLOB.
		 */
		probe = (req->buf == 0 || req->buf_size == 0);
		if (!probe) {
			capacity = req->buf_size /
			    sizeof(struct eventlog_provider_info);
			if (capacity == 0)
				return (EINVAL);
			if (capacity > 65536)
				capacity = 65536;
			tmp = malloc(capacity * sizeof(*tmp), M_EVENTLOG,
			    M_WAITOK | M_ZERO);
		}

		smr_enter(evl.smr);
		CK_SLIST_FOREACH(sub, &subscriber->subscriptions, link) {
			if (!probe && total < capacity) {
				tmp[total].provider_id =
				    sub->provider->provider_id;
				strlcpy(tmp[total].name, sub->provider->name,
				    EVENTLOG_PROVIDER_NAME_MAX);
				memcpy(tmp[total].schema_id,
				    sub->provider->schema_id,
				    EVENTLOG_DECODE_SCHEMA_ID_LEN);
			}
			total++;
		}
		smr_exit(evl.smr);

		req->count = total;
		if (probe)
			return (0);
		if (total > capacity) {
			free(tmp, M_EVENTLOG);
			return (ENOSPC);
		}
		error = copyout(tmp, (void *)(uintptr_t)req->buf,
		    (size_t)total * sizeof(*tmp));
		free(tmp, M_EVENTLOG);
		return (error);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_GET_DECODE_BLOB): {
		struct eventlog_get_decode_blob_req *req =
		    (struct eventlog_get_decode_blob_req *)data;
		struct eventlog_provider *provider;
		void *tmp = NULL;
		size_t tmpcap = 0, blob_size = 0;
		bool probe, found = false;

		if (IOCPARM_LEN(cmd) < sizeof(*req))
			return (EINVAL);
		if (req->lookup_kind != EVENTLOG_DECODE_LOOKUP_NAME &&
		    req->lookup_kind != EVENTLOG_DECODE_LOOKUP_SCHEMA_ID)
			return (EINVAL);

		req->provider_name[EVENTLOG_PROVIDER_NAME_MAX - 1] = '\0';

		/*
		 * A size probe (no output buffer) just reports blob_size; a
		 * fetch copies the blob out.  Pre-allocate the bounce buffer
		 * before taking providers_lock (malloc may sleep) so the copy
		 * below can happen under the lock.
		 */
		probe = (req->buf == 0 || req->buf_size == 0);
		if (!probe) {
			tmpcap = req->buf_size;
			if (tmpcap > EVENTLOG_DECODE_BLOB_MAX)
				tmpcap = EVENTLOG_DECODE_BLOB_MAX;
			tmp = malloc(tmpcap, M_EVENTLOG, M_WAITOK);
		}

		/*
		 * Look the provider up on the global list (no subscription
		 * required).  By schema_id this resolves the exact schema that
		 * produced a captured event (durable across reboot or a newer
		 * same-named provider); by name it serves pre-subscription
		 * keyword/event resolution.  Several providers may share a name
		 * (e.g. the default and RACK "tcp" providers); they register
		 * identical blobs, so the first match wins.  A user-space
		 * provider can free its blob on exit, so copy the bytes into the
		 * bounce buffer here under providers_lock rather than retaining
		 * the pointer across the unlock/copyout.
		 */
		mtx_lock(&evl.providers_lock);
		LIST_FOREACH(provider, &evl.providers, link) {
			bool match;

			if (provider->decode_blob == NULL)
				continue;
			if (req->lookup_kind == EVENTLOG_DECODE_LOOKUP_SCHEMA_ID)
				match = memcmp(provider->schema_id,
				    req->schema_id,
				    EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0;
			else
				match = strcmp(provider->name,
				    req->provider_name) == 0;
			if (match) {
				found = true;
				blob_size = provider->decode_blob_size;
				if (!probe && blob_size <= tmpcap)
					memcpy(tmp, provider->decode_blob,
					    blob_size);
				break;
			}
		}
		mtx_unlock(&evl.providers_lock);

		if (!found) {
			free(tmp, M_EVENTLOG);
			return (ENOENT);
		}
		if (blob_size > EVENTLOG_DECODE_BLOB_MAX) {
			free(tmp, M_EVENTLOG);
			return (EFBIG);
		}

		req->blob_size = (uint32_t)blob_size;

		/* Size probe: caller just wanted blob_size. */
		if (probe)
			return (0);

		if (req->buf_size < blob_size) {
			free(tmp, M_EVENTLOG);
			return (ENOSPC);
		}

		/* blob_size <= req->buf_size <= tmpcap, so it was copied. */
		MPASS(tmp != NULL && blob_size <= tmpcap);
		error = copyout(tmp, (void *)(uintptr_t)req->buf, blob_size);
		free(tmp, M_EVENTLOG);
		return (error);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_TRIGGER_DUMP_STATE): {
		if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
			return (EINVAL);

		eventlog_subscriber_trigger_dump_state(priv->u.subscriber);

		return (0);
	}

	case IOCBASECMD(EVENTLOG_IOCTL_SET_SUBSCRIPTION_KEYWORDS): {
		struct eventlog_set_subscription_keywords_req *req =
		    (struct eventlog_set_subscription_keywords_req *)data;

		if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
			return (EINVAL);

		req->provider_name[sizeof(req->provider_name) - 1] = '\0';

		return (eventlog_subscriber_set_subscription_keywords(
		    priv->u.subscriber, req->provider_name, req->keywords));
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
	struct eventlog_cdev_priv *priv;
	int error;

	error = devfs_get_cdevpriv((void **)&priv);
	if (error != 0)
		return (error);
	if (priv->kind != EVENTLOG_CDEV_SUBSCRIBER)
		return (EINVAL);

	return (eventlog_subscriber_read(priv->u.subscriber, uio, flags));
}

static struct cdevsw eventlog_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	eventlog_dev_open,
	.d_close =	eventlog_dev_close,
	.d_read =	eventlog_dev_read,
	.d_ioctl =	eventlog_dev_ioctl,
	.d_mmap_single = eventlog_dev_mmap_single,
	.d_name =	"eventlog",
};

/* Initialize single system-wide eventlog device */
static void
eventlog_device_init(void *unused)
{
	struct make_dev_args mda;
	int error;

	/*
	 * World rw: any process may open the device to register a provider
	 * and produce events into its own submission ring.  Reading the
	 * system-wide event stream is separately gated in-kernel (CREATE
	 * requires root or the operator group; see eventlog_priv_subscribe),
	 * and per-uid ring-memory accounting bounds what an unprivileged
	 * producer can pin.
	 */
	make_dev_args_init(&mda);
	mda.mda_devsw = &eventlog_cdevsw;
	/* uid/gid are vestigial now that mda_mode = 0666 grants world rw;
	 * kept as root:operator (the historical owner:group) for tooling
	 * that still stat(2)s device ownership. */
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_OPERATOR;
	mda.mda_mode = 0666;
	mda.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	error = make_dev_s(&mda, &evl.device, "eventlog");
	if (error != 0) {
		printf("eventlog: failed to create device: %d\n", error);
		return;
	}
}
SYSINIT(eventlog_device, SI_SUB_DRIVERS, SI_ORDER_MIDDLE,
    eventlog_device_init, NULL);
