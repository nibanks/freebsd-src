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
 * User-space eventlog producer runtime (libeventlog).
 *
 * One process opens a single /dev/eventlog channel (one fd, one mmap'd
 * enable page sliced into per-provider slots) and submits events from all
 * its sessions through a shared submission ring mmap'd from the same fd.
 * The default is one multi-writer ring for the process.  With
 * EVENTLOG_PROVIDER_PER_THREAD_RINGS the first provider opts the channel
 * into one SPSC ring per writing thread instead.  See <sys/eventlog.h>
 * (the !_KERNEL half) for the public scaling model.
 *
 * Shared-ring submission is zero-syscall in steady state and lock-free
 * across threads: a writer CAS-claims a byte range [s, s + recsize) on the
 * process-local reserve cursor, copies its payload into that slot in
 * parallel with other writers, then commits in reservation order -- it
 * spins until the producer head reaches its own s, stamps the timestamp
 * there (so the single ordered stream stays non-decreasing without a
 * global lock), writes its record header, and publishes the new head with
 * a release store.  A per-thread ring is SPSC: the writing thread is the
 * only producer, so it stores head directly.  The kernel drains
 * [tail, head) lazily from the subscriber read path, re-copies and
 * re-validates every record (it stays the trust boundary), and fans the
 * records out to all subscribers.  Records self-describe their
 * provider_id, so the kernel demultiplexes a mixed-provider stream.  If
 * the record would not fit the space the kernel has yet to drain it is
 * dropped and counted before the cursor moves (so a drop never leaves a
 * hole); no syscall and no blocking.
 *
 * By default a single per-process background thread services the kernel
 * control channel (EVENTLOG_IOCTL_WAIT_CONTROL) to drive the optional
 * dump/subscribers/default callbacks.  EVENTLOG_PROVIDER_EXTERNAL_CONTROL
 * skips that thread; the caller runs the same dispatch via
 * eventlog_provider_poll.  The hot paths (the _ENABLED() gate and
 * event writes) never touch this path.  State-dump replays still go
 * out-of-band through EVENTLOG_IOCTL_PUSH_DUMP.
 */

#define	EVENTLOG_INTERNAL	/* we provide the full struct eventlog_session */

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/thr.h>
#include <sys/uio.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/eventlog.h>
#include <sys/eventlog_dev.h>

#include "eventlog_user_test.h"

#define	EVENTLOG_DEV_PATH		"/dev/eventlog"
#define	EVENTLOG_USER_MAX_PROVIDERS	64
#define	EVENTLOG_POLL_US_DEFAULT		100000	/* control poll cadence */
#define	EVENTLOG_CTRL_BATCH		8	/* control events per WAIT */
#define	EVENTLOG_CTRL_WAIT_BYTES \
	(__builtin_offsetof(struct eventlog_wait_control_req, events) + \
	 EVENTLOG_CTRL_BATCH * sizeof(struct eventlog_control_event))
#define	EVENTLOG_STATS_REPORT_US	1000000	/* session-count report cadence */
#define	EVENTLOG_KICK_MIN_INTERVAL_US	1000	/* min spacing between drain kicks */
#define	EVENTLOG_COMMIT_YIELD_MASK	0xff	/* sched_yield() every N commit spins */
#define	EVENTLOG_COMMIT_TIMEOUT_US	200	/* count a wait past this; keep waiting */

/*
 * Per-session enablement disposition.  A session reads its effective
 * level/keywords through ->eff (never copied), so changing disposition is a
 * single pointer repoint with no fan-out:
 *   INHERIT  -> the provider's kernel-published mmap word
 *   OVERRIDE -> the session's inline override word
 *   DISABLED -> a process-global always-off word
 */
enum eventlog_session_state {
	EVENTLOG_SESSION_INHERIT = 0,
	EVENTLOG_SESSION_OVERRIDE,
	EVENTLOG_SESSION_DISABLED,
};

/*
 * User-space producer session handle (what the LOG macros take).  Cheap: no
 * fd, no mmap page, no staging buffer of its own.  ->eff (declared first to
 * match the public head in <sys/eventlog.h>) points at the enablement word
 * the _ENABLED() macro reads.
 */
struct eventlog_session {
	const struct eventlog_enable_page *eff;	/* what _ENABLED() reads */
	struct eventlog_provider	*provider;	/* owning registration */
	uint64_t			session_id;	/* stamped into records */
	uint8_t				state;		/* enum eventlog_session_state */
	_Atomic(uint8_t)		enabled;	/* counted in sess_enabled */
	uint8_t				gated;		/* set_enabled(0) data path */
	struct eventlog_enable_page	override;	/* inline OVERRIDE word */
};

/*
 * State-dump staging, used only by the control dispatcher while replaying a
 * provider's state for a subscriber.  Single-threaded, so it needs no lock
 * or atomics.  Pushed via EVENTLOG_IOCTL_PUSH_DUMP scoped to dump_target.
 */
struct eventlog_dump_stage {
	struct eventlog_push_dump_req *req;	/* lazily allocated */
	uint32_t		cap;
	uint32_t		rbytes;
	uint32_t		rcount;
	uint64_t		max_ts;
	uint64_t		last_ts;
};

/*
 * mmap region recorded so teardown can munmap every per-thread ring.
 */
struct eventlog_ring_map {
	struct eventlog_ring_map *next;
	void *base;
	size_t len;
};

/*
 * Process-wide push channel.  Created on the first eventlog_provider_create(),
 * shared by every provider and session, torn down when the last provider
 * closes.
 */
struct eventlog_channel {
	int			fd;		/* /dev/eventlog */
	void			*page;		/* mmap'd enable-slot page, or NULL */
	size_t			pgsz;
	unsigned		nproviders;	/* live provider registrations */

	pthread_mutex_t		lock;		/* provider registry */

	/*
	 * Shared submission ring (mmap'd at EVENTLOG_RING_MMAP_OFFSET).  The
	 * producer writes records into ring_data as a free-running byte
	 * stream at ring_hdr->head and publishes head; the kernel drains and
	 * advances ring_hdr->tail.  ring_hdr is NULL if ring setup failed (a
	 * fatal open error; see eventlog_provider_register).
	 */
	struct eventlog_ring_hdr *ring_hdr;	/* mmap base (header at offset 0) */
	uint8_t			*ring_data;	/* ring_hdr + data_offset */
	uint32_t		ring_size;	/* power-of-two data capacity */
	uint32_t		ring_mask;	/* ring_size - 1 */
	size_t			ring_map_len;	/* bytes mmap'd (for munmap) */
	int			per_thread_rings; /* EVENTLOG_PROVIDER_PER_THREAD_RINGS */
	int			per_thread_unsupported; /* kernel rejected; use shared ring */
	struct eventlog_ring_map *maps;	/* per-thread ring mmaps, for teardown */

	/*
	 * Multi-writer submission cursor.  reserve is the process-local
	 * allocation frontier: each writer CAS-claims [s, s + recsize) here,
	 * copies its payload in parallel, then commits in reservation order by
	 * advancing ring_hdr->head (the kernel-visible commit frontier) once
	 * head reaches its own s.  reserve lives in process memory -- all writer
	 * threads share this address space -- so only head crosses into the
	 * mapped ring and the wire ABI is unchanged.  Its own cache line keeps
	 * the CAS-hot cursor off the less-hot commit-time fields below.
	 */
	_Atomic(uint64_t)	reserve __aligned(EVENTLOG_RING_CACHELINE);

	/*
	 * Commit-time fields, aligned onto their own line so the committer's
	 * per-event last_ts store does not ping-pong the CAS-hot reserve line.
	 */
	_Atomic(uint64_t)	last_ts	__aligned(EVENTLOG_RING_CACHELINE);
	_Atomic(uint64_t)	last_kick_us;	/* last EVENTLOG_IOCTL_KICK time */
	_Atomic(unsigned long)	dropped;	/* events dropped: ring full */
	_Atomic(unsigned long)	stuck_commit_waits; /* commit waits past TIMEOUT */
	int			disabled;	/* set in a forked child */

	/* Provider registry for control-event dispatch (under lock). */
	struct eventlog_provider *provs[EVENTLOG_USER_MAX_PROVIDERS];
	unsigned		nprovs;

	/* Control thread, or caller poll (ctrl_external). */
	pthread_t		ctrl_thread;
	int			ctrl_started;
	int			ctrl_external;
	_Atomic int		ctrl_stop;
	pthread_mutex_t		poll_lock;	/* one poller at a time */
	uint64_t		stats_last_us;	/* last REPORT_STATS */

	/* Dump replay state (control dispatcher only). */
	struct eventlog_dump_stage dump;
	uint64_t		dump_target;	/* subscriber being replayed, or 0 */

	/* WAIT_CONTROL buffer (last: FAM-sized). */
	union {
		struct eventlog_wait_control_req req;
		uint8_t bytes[EVENTLOG_CTRL_WAIT_BYTES];
	} ctrl_wc;
};

/* Process-wide provider registration: a kernel provider_id + enable slot. */
struct eventlog_provider {
	struct eventlog_channel	*chan;
	struct eventlog_enable_page *enable;	/* slot in chan->page, or &fallback */
	struct eventlog_enable_page fallback;	/* used when the page is unavailable */
	uint16_t		provider_id;
	uint16_t		enable_offset;
	unsigned		refcount;	/* provider handle + live sessions */

	/*
	 * Per-connection session counts, reported to the kernel periodically
	 * by the control thread (EVENTLOG_IOCTL_REPORT_STATS) so they surface
	 * in kern.eventlog.<name>.*.
	 */
	_Atomic uint64_t	sess_created;	/* cumulative opened */
	_Atomic uint64_t	sess_active;	/* currently live */
	_Atomic uint64_t	sess_enabled;	/* live and enabled */

	/*
	 * Provider's default_enabled (kern.eventlog.<name>.default): seeded
	 * from eventlog_provider_config at create and tracked live via the
	 * kernel's DEFAULT_CHANGED control event.  When set, sessions count as
	 * enabled even with no subscriber attached, mirroring an
	 * enabled-by-default kernel provider (e.g. hpts).
	 */
	_Atomic int		default_enabled;

	/* Optional notification callbacks (see <sys/eventlog.h>). */
	eventlog_provider_dump_state_t	dump_callback;
	void			       *dump_callback_arg;
	eventlog_default_changed_t	default_changed;
	void			       *default_changed_arg;
	eventlog_subscribers_changed_t	subscribers_changed;
	void			       *subscribers_changed_arg;
};

/* A session whose ->eff points here is permanently silent. */
static const struct eventlog_enable_page eventlog_disabled_word = { 0, 0, 0, 0 };

/* The one channel per process. */
static pthread_mutex_t eventlog_chan_lock = PTHREAD_MUTEX_INITIALIZER;
static struct eventlog_channel *eventlog_chan;
static pthread_once_t eventlog_atfork_once = PTHREAD_ONCE_INIT;

/*
 * Test-only: the next append waits up to this many microseconds between
 * reserve and commit, ending early once another writer counts a stuck commit
 * wait, then clears the delay.  Zero in production.  delay_taken is
 * published when that wait begins.
 */
static _Atomic uint32_t eventlog_test_commit_delay_us;
static _Atomic uint32_t eventlog_test_delay_taken;

/*
 * Per-thread SPSC ring (EVENTLOG_PROVIDER_PER_THREAD_RINGS).  Bound on this
 * thread's first append; lives until process/channel teardown.  chan matches
 * the owning channel so a later provider_create() on a fresh channel does not
 * reuse a ring the old channel already unmapped.
 */
static __thread struct {
	struct eventlog_channel *chan;
	struct eventlog_ring_hdr *hdr;
	uint8_t *data;
	uint32_t size;
	uint32_t mask;
	uint64_t last_ts;
	bool setup_failed;	/* mmap failed after SETUP_RING; don't retry */
} eventlog_thr;

/*
 * Set to the channel for the duration of a dump callback, on the background
 * thread only.  While set, writes from this thread are routed to the dump
 * staging buffer (scoped to chan->dump_target) instead of the shared ring.
 */
static __thread struct eventlog_channel *eventlog_dump_active;

static int eventlog_dump_flush(struct eventlog_channel *chan);

/*
 * Microseconds on CLOCK_UPTIME, matching the kernel's binuptime-derived
 * timestamps so user and kernel events merge on a common timeline.
 */
static uint64_t
eventlog_user_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_UPTIME, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL);
}

/*
 * Cached thread id (lwpid).  thr_self() is a cheap syscall but we only
 * need it once per thread.
 */
static int32_t
eventlog_user_tid(void)
{
	static __thread long tid;

	if (tid == 0)
		(void)thr_self(&tid);
	return ((int32_t)tid);
}

/*
 * Current CPU at emit time, stamped into each record so subscribers can show
 * which core a user-space event ran on.  On x86 the kernel programs TSC_AUX
 * with the cpuid (see cpu_auxmsr()), so rdtscp reads it with no syscall; that
 * keeps the steady-state ring producer syscall-free.  Elsewhere fall back to
 * the sched_getcpu(2) syscall.
 */
static uint16_t
eventlog_user_cpu(void)
{
#if defined(__amd64__) || defined(__i386__)
	uint32_t low, high, aux;

	__asm__ volatile("rdtscp" : "=a"(low), "=d"(high), "=c"(aux));
	(void)low;
	(void)high;
	return ((uint16_t)aux);
#else
	int cpu = sched_getcpu();

	return (cpu < 0 ? 0 : (uint16_t)cpu);
#endif
}

/*
 * fork() handlers.  fork() in a multithreaded process leaves every mutex in
 * whatever state it had in the forking thread; a lock another thread held is
 * inherited locked-with-no-owner and would wedge the child.  The prepare/
 * parent/child trio brackets fork() so both processes resume with the
 * channel locks held and consistently released.
 */
static void
eventlog_atfork_prepare(void) __no_lock_analysis
{
	pthread_mutex_lock(&eventlog_chan_lock);
	if (eventlog_chan != NULL)
		pthread_mutex_lock(&eventlog_chan->lock);
}

static void
eventlog_atfork_parent(void) __no_lock_analysis
{
	if (eventlog_chan != NULL)
		pthread_mutex_unlock(&eventlog_chan->lock);
	pthread_mutex_unlock(&eventlog_chan_lock);
}

/*
 * The child inherits the parent's fd, mmap enable page, and submission ring,
 * but writing through them would corrupt the parent's single ordered stream,
 * and the background control thread did not survive the fork.  Mark the
 * inherited
 * channel disabled so session handles carried into the child drop their
 * writes, then detach it so a fresh eventlog_provider_create() in the child
 * builds its own channel (and starts its own thread).  The inherited channel object
 * is intentionally leaked: it cannot be safely reclaimed across fork().
 *
 * The fd is different: close(2) takes no userland lock fork could leave
 * inconsistent, so it's safe here, and it matters -- the kernel only
 * refunds this ring's per-uid quota once every duplicate fd is closed, so
 * a child that kept its copy open pinned that quota indefinitely.
 *
 * The forking thread's TLS ring pointer is dropped so a later
 * eventlog_provider_create() in the child binds a fresh ring.
 */
static void
eventlog_atfork_child(void) __no_lock_analysis
{
	struct eventlog_channel *chan = eventlog_chan;

	if (chan != NULL) {
		chan->disabled = 1;
		pthread_mutex_unlock(&chan->lock);
		eventlog_chan = NULL;
		if (chan->fd >= 0)
			(void)close(chan->fd);
	}
	memset(&eventlog_thr, 0, sizeof(eventlog_thr));
	pthread_mutex_unlock(&eventlog_chan_lock);
}

static void
eventlog_atfork_install(void)
{
	(void)pthread_atfork(eventlog_atfork_prepare, eventlog_atfork_parent,
	    eventlog_atfork_child);
}

/*
 * A dump batch must fit in a single ioctl.  The command encodes its argument
 * size in an IOCPARM_SHIFT-bit field, so the total (header + records) must
 * not exceed IOCPARM_MASK.  Reserve room for the request header; the
 * remainder is record+payload staging.
 */
static uint32_t
eventlog_dump_cap(void)
{
	return ((uint32_t)((size_t)IOCPARM_MASK -
	    sizeof(struct eventlog_push_dump_req)));
}

/*
 * Spin hint for the in-order commit wait.  Mirrors libthr's per-arch
 * CPU_SPINWAIT: a "pause" on x86 (relaxes the pipeline and yields the SMT
 * sibling), a no-op elsewhere.  The wait is backed by sched_yield() below,
 * so an empty hint only costs a little extra spinning.
 */
static inline void
eventlog_cpu_pause(void)
{
#if defined(__amd64__) || defined(__i386__)
	__asm__ volatile("pause" : : : "memory");
#endif
}

/*
 * Ring cursor accessor.  head/watermark are producer-owned; tail is
 * kernel-owned and read with acquire so the data it has consumed is visible
 * before we reuse that space.  head is read directly (acquire) in the commit
 * spin, so only tail needs an accessor here.
 */
static inline uint64_t
eventlog_ring_tail(const struct eventlog_channel *chan)
{
	return (atomic_load_explicit(
	    (_Atomic(uint64_t) *)(uintptr_t)&chan->ring_hdr->tail,
	    memory_order_acquire));
}

static inline void
eventlog_ring_put_buf(uint8_t *data, uint32_t size, uint64_t pos,
    const void *src, size_t len)
{
	uint32_t off = (uint32_t)(pos & (size - 1));
	size_t n1 = size - off;

	if (n1 >= len) {
		memcpy(data + off, src, len);
	} else {
		memcpy(data + off, src, n1);
		memcpy(data, (const uint8_t *)src + n1, len - n1);
	}
}

/*
 * Copy len bytes into the ring at logical offset pos, splitting at the
 * physical wrap.  The caller has already ensured the space is free.
 */
static inline void
eventlog_ring_put(struct eventlog_channel *chan, uint64_t pos,
    const void *src, size_t len)
{
	eventlog_ring_put_buf(chan->ring_data, chan->ring_size, pos, src, len);
}

/* Lazily allocate the dump staging buffer.  Returns 0 on success. */
static int
eventlog_dump_stage_alloc(struct eventlog_channel *chan)
{
	struct eventlog_dump_stage *d = &chan->dump;
	uint32_t cap;

	if (d->req != NULL)
		return (0);
	cap = eventlog_dump_cap();
	d->req = malloc(sizeof(struct eventlog_push_dump_req) + cap);
	if (d->req == NULL)
		return (-1);
	d->cap = cap;
	d->rbytes = 0;
	d->rcount = 0;
	d->max_ts = 0;
	d->last_ts = 0;
	return (0);
}

/*
 * Push the staged dump batch to chan->dump_target in a single PUSH_DUMP
 * ioctl, then reset the buffer.  Single-threaded (background thread only).
 */
static int
eventlog_dump_flush(struct eventlog_channel *chan)
{
	struct eventlog_dump_stage *d = &chan->dump;
	int rc;

	if (d->req == NULL || d->rcount == 0)
		return (0);
	d->req->subscriber_id = chan->dump_target;
	d->req->stream_id = EVENTLOG_DUMP_STREAM_ID;
	d->req->flags = 0;
	d->req->count = d->rcount;
	d->req->watermark_us = d->max_ts;
	d->req->bytes = d->rbytes;
	d->req->RESERVED = 0;
	rc = ioctl(chan->fd, EVENTLOG_IOCTL_PUSH_DUMP_SIZE(d->rbytes), d->req);
	d->rbytes = 0;
	d->rcount = 0;
	d->max_ts = 0;
	return (rc != 0 ? -1 : 0);
}

/*
 * Stage one record into the dump buffer (background thread, inside a dump
 * callback).  Flushes mid-dump if the batch fills.  Drops silently on error,
 * matching the void write API.
 */
static void
eventlog_dump_stage(struct eventlog_session *s, uint32_t id,
    enum eventlog_level level, uint32_t keywords, const struct iovec *iov,
    int iovcnt, size_t length, uint64_t ts_arg)
{
	struct eventlog_channel *chan = s->provider->chan;
	struct eventlog_dump_stage *d = &chan->dump;
	struct eventlog_push_record rec;
	uint8_t *p;
	uint64_t now;
	size_t recsize;
	int i;

	if (length > UINT16_MAX)
		return;
	if (eventlog_dump_stage_alloc(chan) != 0)
		return;
	recsize = sizeof(rec) + length;
	if (recsize > d->cap)
		return;
	if ((size_t)d->rbytes + recsize > d->cap) {
		(void)eventlog_dump_flush(chan);
		if ((size_t)d->rbytes + recsize > d->cap)
			return;
	}

	now = ts_arg != 0 ? ts_arg : eventlog_user_now_us();
	if (now <= d->last_ts)
		now = d->last_ts + 1;
	d->last_ts = now;

	p = d->req->data + d->rbytes;
	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = now;
	rec.session_id = s->session_id;
	rec.event_id = id;
	rec.keywords = keywords;
	rec.thread_id = eventlog_user_tid();
	rec.payload_len = (uint16_t)length;
	rec.provider_id = s->provider->provider_id;
	rec.level = (uint8_t)level;
	rec.cpu = eventlog_user_cpu();
	memcpy(p, &rec, sizeof(rec));
	p += sizeof(rec);
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len == 0)
			continue;
		memcpy(p, iov[i].iov_base, iov[i].iov_len);
		p += iov[i].iov_len;
	}
	d->rbytes += (uint32_t)recsize;
	d->rcount++;
	if (now > d->max_ts)
		d->max_ts = now;
}

static inline void
eventlog_test_maybe_delay_commit(struct eventlog_channel *chan)
{
	uint32_t delay = atomic_load_explicit(
	    &eventlog_test_commit_delay_us, memory_order_relaxed);
	unsigned long stuck;
	uint64_t start;

	if (__predict_false(delay != 0)) {
		delay = atomic_exchange_explicit(
		    &eventlog_test_commit_delay_us, 0, memory_order_relaxed);
		if (delay != 0) {
			stuck = atomic_load_explicit(&chan->stuck_commit_waits,
			    memory_order_relaxed);
			start = eventlog_user_now_us();
			atomic_store_explicit(&eventlog_test_delay_taken, 1,
			    memory_order_release);
			while (atomic_load_explicit(&chan->stuck_commit_waits,
			    memory_order_relaxed) == stuck &&
			    eventlog_user_now_us() - start < delay)
				usleep(1000);
		}
	}
}

/*
 * Set up the process-wide shared submission ring on chan.  On success
 * chan->ring_hdr et al. are populated; on failure ring_hdr stays NULL and
 * the caller's writes drop (and count).  Caller holds chan->lock.
 */
static void
eventlog_shared_ring_setup(struct eventlog_channel *chan)
{
	struct eventlog_ring_setup_req rr;

	memset(&rr, 0, sizeof(rr));
	if (ioctl(chan->fd, EVENTLOG_IOCTL_SETUP_RING, &rr) == 0) {
		void *rp = mmap(NULL, (size_t)rr.mmap_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED, chan->fd,
		    (off_t)rr.mmap_offset);
		if (rp != MAP_FAILED) {
			chan->ring_hdr = (struct eventlog_ring_hdr *)rp;
			chan->ring_data = (uint8_t *)rp +
			    chan->ring_hdr->data_offset;
			chan->ring_size = chan->ring_hdr->data_size;
			chan->ring_mask = chan->ring_size - 1;
			chan->ring_map_len = (size_t)rr.mmap_size;
		} else {
			syslog(LOG_WARNING,
			    "eventlog: mmap of the submission ring "
			    "failed (%s); this process's eventlog "
			    "writes will be silently dropped",
			    strerror(errno));
		}
	} else {
		syslog(LOG_WARNING,
		    "eventlog: EVENTLOG_IOCTL_SETUP_RING failed (%s); "
		    "this process's eventlog writes will be silently "
		    "dropped (common cause: kern.eventlog."
		    "user_ring_max_bytes_per_uid exceeded for this uid)",
		    strerror(errno));
	}
}

/*
 * Probe the kernel for multi-ring (per-thread) support by reading
 * kern.eventlog.user_rings_max: present and >1 means the kernel supports a
 * repeatable EVENTLOG_IOCTL_SETUP_RING.  The sysctl is absent (ENOENT) on
 * kernels predating multi-ring support, so this needs no /dev/eventlog fd
 * and has no side effects.  This is the documented way for a
 * statically-linked producer to decide whether
 * EVENTLOG_PROVIDER_PER_THREAD_RINGS is usable before committing to it.
 */
int
eventlog_user_per_thread_rings_supported(void)
{
	u_int max = 0;
	size_t len = sizeof(max);

	if (sysctlbyname("kern.eventlog.user_rings_max", &max, &len,
	    NULL, 0) != 0)
		return (0);
	return (max > 1);
}

/*
 * Bind this thread's SPSC ring on first use: SETUP_RING + mmap, recorded on
 * chan->maps so teardown can munmap.  A failed setup counts a drop on the
 * caller.  Concurrent first-writes serialize on chan->lock.
 */
static bool
eventlog_thread_ring_ensure(struct eventlog_channel *chan)
{
	struct eventlog_ring_setup_req rr;
	struct eventlog_ring_map *map;
	void *rp;

	if (eventlog_thr.chan == chan &&
	    (eventlog_thr.hdr != NULL || eventlog_thr.setup_failed))
		return (eventlog_thr.hdr != NULL);

	pthread_mutex_lock(&chan->lock);
	if (eventlog_thr.hdr != NULL && eventlog_thr.chan == chan) {
		pthread_mutex_unlock(&chan->lock);
		return (true);
	}

	map = malloc(sizeof(*map));
	if (map == NULL) {
		pthread_mutex_unlock(&chan->lock);
		syslog(LOG_WARNING,
		    "eventlog: malloc of a per-thread ring map failed; "
		    "this thread's eventlog writes will be silently dropped");
		return (false);
	}

	memset(&rr, 0, sizeof(rr));
	rr.size = EVENTLOG_RING_SIZE_MIN;
	if (ioctl(chan->fd, EVENTLOG_IOCTL_SETUP_RING, &rr) != 0) {
		int err = errno;

		free(map);
		/*
		 * EEXIST means the kernel predates multi-ring support (one
		 * ring per fd) -- or, on a multi-ring kernel, that the shared
		 * ring already exists alongside per-thread ones, which the
		 * provider flags should have prevented.  Either way the safe
		 * response is the same: stop trying per-thread rings and fall
		 * the whole channel back to the shared ring so no thread's
		 * writes are silently dropped.  Latch it so later threads skip
		 * straight to the shared path.
		 */
		if (err == EEXIST) {
			chan->per_thread_unsupported = 1;
			if (chan->ring_hdr == NULL)
				eventlog_shared_ring_setup(chan);
			pthread_mutex_unlock(&chan->lock);
			syslog(LOG_WARNING,
			    "eventlog: kernel rejected a per-thread ring "
			    "(EEXIST); falling back to the shared "
			    "multi-writer ring");
			return (false);
		}
		pthread_mutex_unlock(&chan->lock);
		syslog(LOG_WARNING,
		    "eventlog: EVENTLOG_IOCTL_SETUP_RING failed (%s); "
		    "this thread's eventlog writes will be silently dropped "
		    "(common cause: kern.eventlog."
		    "user_ring_max_bytes_per_uid exceeded, or "
		    "EVENTLOG_USER_RINGS_MAX reached)",
		    strerror(err));
		return (false);
	}
	rp = mmap(NULL, (size_t)rr.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, chan->fd, (off_t)rr.mmap_offset);
	if (rp == MAP_FAILED) {
		free(map);
		/*
		 * The kernel already committed a ring slot for this SETUP_RING
		 * and has no teardown ioctl to undo it; latch setup_failed so
		 * this thread doesn't keep allocating (and leaking) slots on
		 * every subsequent write.  Scope it to this channel so a later
		 * provider_create() on a fresh channel gets a clean attempt.
		 * Clear hdr so a ring bound to an earlier channel is not
		 * mistaken for this channel's.
		 */
		eventlog_thr.chan = chan;
		eventlog_thr.hdr = NULL;
		eventlog_thr.setup_failed = true;
		pthread_mutex_unlock(&chan->lock);
		syslog(LOG_WARNING,
		    "eventlog: mmap of a per-thread submission ring "
		    "failed (%s); this thread's eventlog writes will be "
		    "silently dropped",
		    strerror(errno));
		return (false);
	}

	map->base = rp;
	map->len = (size_t)rr.mmap_size;
	map->next = chan->maps;
	chan->maps = map;

	eventlog_thr.chan = chan;
	eventlog_thr.hdr = (struct eventlog_ring_hdr *)rp;
	eventlog_thr.data = (uint8_t *)rp + eventlog_thr.hdr->data_offset;
	eventlog_thr.size = eventlog_thr.hdr->data_size;
	eventlog_thr.mask = eventlog_thr.size - 1;
	eventlog_thr.last_ts = 0;

	pthread_mutex_unlock(&chan->lock);
	return (true);
}

/*
 * Single-producer append on this thread's ring.  Caller has already bound
 * the ring via eventlog_thread_ring_ensure().  head is the allocation
 * cursor; this thread is the only writer, so a plain store publishes it.
 */
static void
eventlog_user_append_spsc(struct eventlog_session *s, uint32_t id,
    enum eventlog_level level, uint32_t keywords, const struct iovec *iov,
    int iovcnt, size_t length, uint64_t ts_arg)
{
	struct eventlog_channel *chan = s->provider->chan;
	struct eventlog_ring_hdr *hdr;
	struct eventlog_push_record rec;
	uint64_t now, last, head, end, tail, wp;
	size_t recsize;
	bool do_kick = false;
	int i;

	hdr = eventlog_thr.hdr;
	recsize = sizeof(struct eventlog_push_record) + length;
	if (recsize > eventlog_thr.size) {
		atomic_fetch_add_explicit(&chan->dropped, 1,
		    memory_order_relaxed);
		return;
	}

	head = hdr->head;
	end = head + recsize;
	tail = atomic_load_explicit(
	    (_Atomic(uint64_t) *)(uintptr_t)&hdr->tail,
	    memory_order_acquire);
	if ((uint64_t)(end - tail) > (uint64_t)eventlog_thr.size) {
		atomic_fetch_add_explicit(&chan->dropped, 1,
		    memory_order_relaxed);
		atomic_fetch_add_explicit(
		    (_Atomic(uint64_t) *)(uintptr_t)&hdr->dropped, 1,
		    memory_order_relaxed);
		return;
	}

	wp = head + sizeof(rec);
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len == 0)
			continue;
		eventlog_ring_put_buf(eventlog_thr.data, eventlog_thr.size,
		    wp, iov[i].iov_base, iov[i].iov_len);
		wp += iov[i].iov_len;
	}

	now = ts_arg != 0 ? ts_arg : eventlog_user_now_us();
	last = eventlog_thr.last_ts;
	if (now <= last)
		now = last + 1;
	eventlog_thr.last_ts = now;

	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = now;
	rec.session_id = s->session_id;
	rec.event_id = id;
	rec.keywords = keywords;
	rec.thread_id = eventlog_user_tid();
	rec.payload_len = (uint16_t)length;
	rec.provider_id = s->provider->provider_id;
	rec.level = (uint8_t)level;
	rec.cpu = eventlog_user_cpu();
	eventlog_ring_put_buf(eventlog_thr.data, eventlog_thr.size,
	    head, &rec, sizeof(rec));

	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->watermark_us,
	    now, memory_order_release);
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->head,
	    end, memory_order_release);

	{
		uint32_t flags = atomic_load_explicit(
		    (_Atomic(uint32_t) *)(uintptr_t)&hdr->flags,
		    memory_order_acquire);
		uint32_t fill = (uint32_t)(end - tail);
		uint32_t hiwater = eventlog_thr.size >>
		    EVENTLOG_RING_KICK_HIWATER_SHIFT;
		bool want = (flags & EVENTLOG_RING_F_NEED_WAKEUP) != 0 ||
		    ((flags & EVENTLOG_RING_F_CONSUMER_PRESENT) != 0 &&
		    fill >= hiwater);

		if (want) {
			uint64_t lastk = atomic_load_explicit(
			    &chan->last_kick_us, memory_order_relaxed);

			if (now - lastk >= EVENTLOG_KICK_MIN_INTERVAL_US &&
			    atomic_compare_exchange_strong_explicit(
			    &chan->last_kick_us, &lastk, now,
			    memory_order_relaxed, memory_order_relaxed))
				do_kick = true;
		}
	}

	if (do_kick)
		(void)ioctl(chan->fd, EVENTLOG_IOCTL_KICK);
}

/*
 * Submit one record (optionally with a gathered payload) into the shared
 * ring.  Errors are silently dropped because the producer write API returns
 * void, matching the kernel's fire-and-forget semantics; drops are counted
 * for observability (both in chan->dropped and the ring header so the kernel
 * can surface them too).
 */
static void
eventlog_user_append(struct eventlog_session *s, uint32_t id,
    enum eventlog_level level, uint32_t keywords, const struct iovec *iov,
    int iovcnt, size_t length, uint64_t ts_arg)
{
	struct eventlog_channel *chan;
	struct eventlog_ring_hdr *hdr;
	struct eventlog_push_record rec;
	uint64_t now, last, slot, end, tail, wp, wait_start;
	size_t recsize;
	unsigned spins;
	bool do_kick = false;
	bool counted_stuck = false;
	int i;

	if (s == NULL || length > UINT16_MAX)
		return;
	chan = s->provider->chan;

	/*
	 * Inside a dump callback (background thread): route to the dump
	 * staging buffer so the replay reaches only the requesting subscriber
	 * via PUSH_DUMP, instead of the broadcast shared ring.
	 */
	if (eventlog_dump_active == chan) {
		eventlog_dump_stage(s, id, level, keywords, iov, iovcnt, length,
		    ts_arg);
		return;
	}

	if (chan->disabled) {
		atomic_fetch_add_explicit(&chan->dropped, 1,
		    memory_order_relaxed);
		return;
	}

	if (chan->per_thread_rings && !chan->per_thread_unsupported) {
		if (eventlog_thread_ring_ensure(chan)) {
			eventlog_user_append_spsc(s, id, level, keywords, iov,
			    iovcnt, length, ts_arg);
			return;
		}
		if (!chan->per_thread_unsupported) {
			atomic_fetch_add_explicit(&chan->dropped, 1,
			    memory_order_relaxed);
			return;
		}
		/* EEXIST fallback: drop through to the shared ring. */
	}

	recsize = sizeof(struct eventlog_push_record) + length;

	hdr = chan->ring_hdr;
	if (hdr == NULL) {
		atomic_fetch_add_explicit(&chan->dropped, 1,
		    memory_order_relaxed);
		return;
	}
	if (recsize > chan->ring_size) {
		/* A single record can never fit the ring; drop it. */
		atomic_fetch_add_explicit(&chan->dropped, 1,
		    memory_order_relaxed);
		return;
	}

	/*
	 * (1) Reserve [slot, end) by CAS-advancing the process-local allocation
	 * cursor.  tail is published by the kernel as it drains; it only ever
	 * advances, so a stale snapshot is conservative.  Because we test the
	 * fit before committing the CAS, a dropped record never moves the cursor
	 * and so never leaves a hole in the byte stream the kernel parses.  A
	 * "does not fit" result can also mean our slot is stale (other writers
	 * advanced reserve and the kernel drained past it), so we reload and
	 * only drop when the cursor is genuinely unchanged.
	 */
	slot = atomic_load_explicit(&chan->reserve, memory_order_relaxed);
	for (;;) {
		uint64_t cur;

		end = slot + recsize;
		tail = eventlog_ring_tail(chan);
		if ((uint64_t)(end - tail) > (uint64_t)chan->ring_size) {
			cur = atomic_load_explicit(&chan->reserve,
			    memory_order_relaxed);
			if (cur != slot) {
				slot = cur;
				continue;
			}
			atomic_fetch_add_explicit(&chan->dropped, 1,
			    memory_order_relaxed);
			atomic_fetch_add_explicit(
			    (_Atomic(uint64_t) *)(uintptr_t)&hdr->dropped, 1,
			    memory_order_relaxed);
			return;
		}
		if (atomic_compare_exchange_weak_explicit(&chan->reserve, &slot,
		    end, memory_order_relaxed, memory_order_relaxed))
			break;
		/* CAS reloaded slot with the current cursor; retry. */
	}

	/*
	 * (2) Copy the payload into our reserved slot in parallel with other
	 * writers -- each reservation owns a disjoint byte range, so no
	 * coordination is needed.  The record header (including the timestamp)
	 * is written at commit time below.
	 */
	wp = slot + sizeof(rec);
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len == 0)
			continue;
		eventlog_ring_put(chan, wp, iov[i].iov_base, iov[i].iov_len);
		wp += iov[i].iov_len;
	}

	eventlog_test_maybe_delay_commit(chan);

	/*
	 * (3) Commit in reservation order.  Spin until head reaches our slot:
	 * head is monotonic and each reservation is unique, so it matches
	 * exactly once, and when it does every earlier record is fully written
	 * (head only advances over completed records).  Pause-spin with a
	 * periodic sched_yield() so a writer preempted between reserve and
	 * commit cannot pin a CPU while stalling us.
	 *
	 * Waiters keep their reservation until the predecessor commits.  After
	 * EVENTLOG_COMMIT_TIMEOUT_US the wait is counted in
	 * chan->stuck_commit_waits and continues, so a slow predecessor
	 * unblocks everyone when it publishes head.  See eventlog_user(3).
	 */
	wait_start = 0;
	for (spins = 0; atomic_load_explicit(
	    (_Atomic(uint64_t) *)(uintptr_t)&hdr->head,
	    memory_order_acquire) != slot; spins++) {
		if ((spins & EVENTLOG_COMMIT_YIELD_MASK) ==
		    EVENTLOG_COMMIT_YIELD_MASK) {
			now = eventlog_user_now_us();
			if (wait_start == 0)
				wait_start = now;
			else if (!counted_stuck &&
			    now - wait_start >= EVENTLOG_COMMIT_TIMEOUT_US) {
				atomic_fetch_add_explicit(
				    &chan->stuck_commit_waits, 1,
				    memory_order_relaxed);
				counted_stuck = true;
			}
			sched_yield();
		} else
			eventlog_cpu_pause();
	}

	/*
	 * We now hold the exclusive right to advance head from slot, so stamp
	 * the timestamp here: commits serialize in byte order, so reading the
	 * clock at commit yields non-decreasing timestamps across the stream
	 * (what the kernel requires) with no global lock.  last_ts is touched
	 * only in this serialized window; the head handoff (release/acquire)
	 * publishes the previous committer's store to us.
	 */
	now = ts_arg != 0 ? ts_arg : eventlog_user_now_us();
	last = atomic_load_explicit(&chan->last_ts, memory_order_relaxed);
	if (now <= last)
		now = last + 1;
	atomic_store_explicit(&chan->last_ts, now, memory_order_relaxed);

	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = now;
	rec.session_id = s->session_id;
	rec.event_id = id;
	rec.keywords = keywords;
	rec.thread_id = eventlog_user_tid();
	rec.payload_len = (uint16_t)length;
	rec.provider_id = s->provider->provider_id;
	rec.level = (uint8_t)level;
	rec.cpu = eventlog_user_cpu();
	eventlog_ring_put(chan, slot, &rec, sizeof(rec));

	/*
	 * Publish: the watermark promise (no further event at or below this
	 * timestamp) is released before head so a kernel that observes the new
	 * head (acquire) also sees a consistent watermark; the release store of
	 * head makes the header and payload bytes visible to the draining
	 * kernel.  Both stores are release to pair cleanly with the kernel's
	 * acquire loads.
	 */
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->watermark_us,
	    now, memory_order_release);
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->head,
	    end, memory_order_release);

	/*
	 * Decide whether to poke the kernel.  The steady state is syscall-free:
	 * we only kick when the kernel has published a hint that it is worth it
	 * -- a reader is blocked (wake it now rather than after its drain poll),
	 * or the ring has crossed its high-water mark while a consumer is
	 * present (force a drain before we start dropping).  A minimum interval
	 * bounds the syscall rate; the CAS on last_kick_us lets exactly one
	 * writer claim each interval so concurrent writers don't all kick.
	 */
	{
		uint32_t flags = atomic_load_explicit(
		    (_Atomic(uint32_t) *)(uintptr_t)&hdr->flags,
		    memory_order_acquire);
		uint32_t fill = (uint32_t)(end - tail);
		uint32_t hiwater = chan->ring_size >>
		    EVENTLOG_RING_KICK_HIWATER_SHIFT;
		bool want = (flags & EVENTLOG_RING_F_NEED_WAKEUP) != 0 ||
		    ((flags & EVENTLOG_RING_F_CONSUMER_PRESENT) != 0 &&
		    fill >= hiwater);

		if (want) {
			uint64_t lastk = atomic_load_explicit(
			    &chan->last_kick_us, memory_order_relaxed);

			if (now - lastk >= EVENTLOG_KICK_MIN_INTERVAL_US &&
			    atomic_compare_exchange_strong_explicit(
			    &chan->last_kick_us, &lastk, now,
			    memory_order_relaxed, memory_order_relaxed))
				do_kick = true;
		}
	}

	/* Kick without any lock: the ioctl must not serialize other writers. */
	if (do_kick)
		(void)ioctl(chan->fd, EVENTLOG_IOCTL_KICK);
}

/* Test hook: next append waits up to `us` microseconds between reserve and commit. */
void
eventlog_test_set_commit_delay_us(uint32_t us)
{
	atomic_store_explicit(&eventlog_test_delay_taken, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&eventlog_test_commit_delay_us, us,
	    memory_order_relaxed);
}

/* Test hook: the armed delay has been claimed and the sleeper is in usleep. */
int
eventlog_test_commit_delay_taken(void)
{
	return (atomic_load_explicit(&eventlog_test_delay_taken,
	    memory_order_acquire) != 0);
}

/* Test hook: read the process channel's dropped-write counter. */
unsigned long
eventlog_test_get_dropped(struct eventlog_provider *provider)
{
	struct eventlog_channel *chan = provider->chan;

	if (chan == NULL)
		return (0);
	return (atomic_load_explicit(&chan->dropped, memory_order_relaxed));
}

/* Test hook: commit waits that exceeded EVENTLOG_COMMIT_TIMEOUT_US. */
unsigned long
eventlog_test_get_stuck_commit_waits(struct eventlog_provider *provider)
{
	struct eventlog_channel *chan = provider->chan;

	if (chan == NULL)
		return (0);
	return (atomic_load_explicit(&chan->stuck_commit_waits,
	    memory_order_relaxed));
}

/* Test hook: read the provider's live-enabled session count. */
uint64_t
eventlog_test_get_sess_enabled(struct eventlog_provider *provider)
{
	return (atomic_load_explicit(&provider->sess_enabled,
	    memory_order_relaxed));
}

void
eventlog_event_write_at(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length,
    uint64_t timestamp_us)
{
	struct iovec iov;

	if (length != 0) {
		iov.iov_base = buffer;
		iov.iov_len = length;
		eventlog_user_append(session, id, level, keywords, &iov, 1,
		    length, timestamp_us);
	} else {
		eventlog_user_append(session, id, level, keywords, NULL, 0, 0,
		    timestamp_us);
	}
}

void
eventlog_event_write(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, void *buffer, size_t length)
{
	eventlog_event_write_at(session, id, level, keywords, buffer, length, 0);
}

void
eventlog_event_write_gather_at(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, const struct iovec *iov,
    int iovcnt, uint64_t timestamp_us)
{
	size_t length;
	int i;

	length = 0;
	for (i = 0; i < iovcnt; i++)
		length += iov[i].iov_len;
	eventlog_user_append(session, id, level, keywords, iov, iovcnt, length,
	    timestamp_us);
}

void
eventlog_event_write_gather(struct eventlog_session *session, uint32_t id,
    enum eventlog_level level, uint32_t keywords, const struct iovec *iov,
    int iovcnt)
{
	eventlog_event_write_gather_at(session, id, level, keywords, iov,
	    iovcnt, 0);
}

/* Tell the kernel a state-dump replay for (subscriber, provider) is done. */
static void
eventlog_dump_done(struct eventlog_channel *chan, uint64_t subscriber_id,
    uint16_t provider_id)
{
	struct eventlog_dump_done_req req;

	memset(&req, 0, sizeof(req));
	req.subscriber_id = subscriber_id;
	req.provider_id = provider_id;
	(void)ioctl(chan->fd, EVENTLOG_IOCTL_DUMP_DONE, &req);
}

/*
 * Dispatch one control event to the owning provider's callback.  Callback
 * pointers are snapshotted under chan->lock so a concurrent provider close
 * cannot free them mid-call; the callback then runs unlocked (it may write
 * events, which re-take chan->lock).
 */
static void
eventlog_ctrl_dispatch(struct eventlog_channel *chan,
    const struct eventlog_control_event *ev)
{
	struct eventlog_provider *prov = NULL;
	eventlog_provider_dump_state_t dump_callback = NULL;
	void *dump_callback_arg = NULL;
	eventlog_default_changed_t default_changed = NULL;
	void *default_changed_arg = NULL;
	eventlog_subscribers_changed_t subscribers_changed = NULL;
	void *subscribers_changed_arg = NULL;
	unsigned i;

	pthread_mutex_lock(&chan->lock);
	for (i = 0; i < chan->nprovs; i++) {
		if (chan->provs[i]->provider_id == ev->provider_id) {
			prov = chan->provs[i];
			dump_callback = prov->dump_callback;
			dump_callback_arg = prov->dump_callback_arg;
			default_changed = prov->default_changed;
			default_changed_arg = prov->default_changed_arg;
			subscribers_changed = prov->subscribers_changed;
			subscribers_changed_arg = prov->subscribers_changed_arg;
			break;
		}
	}
	pthread_mutex_unlock(&chan->lock);

	switch (ev->type) {
	case EVENTLOG_CONTROL_DUMP_REQUEST:
		/*
		 * Always acknowledge a dump request (even with no callback or
		 * an unknown provider): the kernel bumped the subscriber's
		 * dump_pending and a draining consumer waits for our DUMP_DONE.
		 */
		chan->dump_target = ev->subscriber_id;
		if (dump_callback != NULL) {
			eventlog_dump_active = chan;
			dump_callback(prov, dump_callback_arg);
			eventlog_dump_active = NULL;
			(void)eventlog_dump_flush(chan);
		}
		chan->dump_target = 0;
		eventlog_dump_done(chan, ev->subscriber_id, ev->provider_id);
		break;
	case EVENTLOG_CONTROL_SUBSCRIBERS_CHANGED:
		if (subscribers_changed != NULL)
			subscribers_changed(prov, ev->value != 0,
			    subscribers_changed_arg);
		break;
	case EVENTLOG_CONTROL_DEFAULT_CHANGED:
		/*
		 * Track default_enabled so the reported sessions_enabled count
		 * follows a live kern.eventlog.<name>.default change.  Sysctl
		 * values: 0/-1 disable, 1/2 enable.
		 */
		if (prov != NULL)
			atomic_store_explicit(&prov->default_enabled,
			    (ev->value == 1 || ev->value == 2) ? 1 : 0,
			    memory_order_relaxed);
		if (default_changed != NULL)
			default_changed(prov, ev->value, default_changed_arg);
		break;
	default:
		break;
	}
}

/*
 * Report each provider's current per-connection session counts to the kernel
 * so they surface under kern.eventlog.<name>.*.  User-space sessions never
 * enter the kernel, so this periodic snapshot is the only way the counters
 * stay current (even with no subscriber attached).  Best effort: a failure
 * (e.g. an older kernel without the ioctl) is ignored.
 */
static void
eventlog_report_stats(struct eventlog_channel *chan)
{
	_Alignas(uint64_t) uint8_t buf[
	    __builtin_offsetof(struct eventlog_report_stats_req, stats) +
	    EVENTLOG_USER_MAX_PROVIDERS *
	    sizeof(struct eventlog_provider_stat)];
	struct eventlog_report_stats_req *req = (void *)buf;
	uint32_t n = 0;
	unsigned i;

	pthread_mutex_lock(&chan->lock);
	for (i = 0; i < chan->nprovs && n < EVENTLOG_USER_MAX_PROVIDERS; i++) {
		struct eventlog_provider *prov = chan->provs[i];
		struct eventlog_provider_stat *ps = &req->stats[n++];
		uint64_t active;

		active = atomic_load_explicit(&prov->sess_active,
		    memory_order_relaxed);
		ps->provider_id = prov->provider_id;
		ps->RESERVED = 0;
		ps->RESERVED2 = 0;
		ps->sessions_created = atomic_load_explicit(&prov->sess_created,
		    memory_order_relaxed);
		ps->sessions_active = active;
		ps->sessions_enabled = atomic_load_explicit(&prov->sess_enabled,
		    memory_order_relaxed);
	}
	pthread_mutex_unlock(&chan->lock);

	if (n == 0)
		return;
	req->count = n;
	req->RESERVED = 0;
	(void)ioctl(chan->fd, EVENTLOG_IOCTL_REPORT_STATS_SIZE(n), req);
}

/*
 * Drain WAIT_CONTROL (blocking up to timeout_us, or not at all when 0),
 * dispatch, then report session counts about once a second.  Serialized so
 * dump staging and the wait buffer have a single owner.
 */
static int
eventlog_channel_poll(struct eventlog_channel *chan, uint64_t timeout_us)
{
	struct eventlog_wait_control_req *wc = &chan->ctrl_wc.req;
	uint32_t i;
	uint64_t now;
	int n, saved;

	pthread_mutex_lock(&chan->poll_lock);

	wc->timeout_us = timeout_us;
	wc->count = EVENTLOG_CTRL_BATCH;
	wc->RESERVED = 0;
	if (ioctl(chan->fd, EVENTLOG_IOCTL_WAIT_CONTROL_SIZE(EVENTLOG_CTRL_BATCH),
	    wc) != 0)
		n = -1;
	else {
		for (i = 0; i < wc->count; i++)
			eventlog_ctrl_dispatch(chan, &wc->events[i]);
		n = (int)wc->count;
	}

	saved = errno;
	now = eventlog_user_now_us();
	if (now - chan->stats_last_us >= EVENTLOG_STATS_REPORT_US) {
		eventlog_report_stats(chan);
		chan->stats_last_us = now;
	}
	if (n < 0)
		errno = saved;
	pthread_mutex_unlock(&chan->poll_lock);
	return (n);
}

int
eventlog_provider_poll(struct eventlog_provider *provider)
{
	struct eventlog_channel *chan;

	if (provider == NULL || provider->chan == NULL) {
		errno = EINVAL;
		return (-1);
	}
	chan = provider->chan;
	if (chan->ctrl_started) {
		errno = EBUSY;
		return (-1);
	}
	return (eventlog_channel_poll(chan, 0));
}

/*
 * The one background thread per process.  Services the kernel control
 * channel (dump/subscribers/default callbacks) and periodically reports
 * per-provider session counts; the kernel polls the submission ring itself,
 * so this thread no longer flushes.
 */
static void *
eventlog_ctrl_thread(void *arg)
{
	struct eventlog_channel *chan = arg;

	while (atomic_load_explicit(&chan->ctrl_stop, memory_order_acquire) ==
	    0) {
		if (eventlog_channel_poll(chan, EVENTLOG_POLL_US_DEFAULT) < 0 &&
		    errno != EINTR)
			usleep(EVENTLOG_POLL_US_DEFAULT);
	}
	return (NULL);
}

/*
 * Create (or reuse) the process channel and register provider_name on it.
 * Caller holds eventlog_chan_lock.  Returns a provider on success, or NULL
 * with errno set.
 */
static struct eventlog_provider *
eventlog_provider_register(const char *provider_name,
    const struct eventlog_provider_config *config)
{
	struct eventlog_channel *chan;
	struct eventlog_provider *prov;
	struct eventlog_provider_reg_req req;
	int first, saved;

	first = (eventlog_chan == NULL);
	if (first) {
		/*
		 * Cache-line align the channel so the CAS-hot reserve cursor
		 * gets its own line (see struct eventlog_channel); aligned_alloc
		 * needs a size that is a multiple of the alignment.
		 */
		chan = aligned_alloc(EVENTLOG_RING_CACHELINE,
		    (sizeof(*chan) + EVENTLOG_RING_CACHELINE - 1) &
		    ~((size_t)EVENTLOG_RING_CACHELINE - 1));
		if (chan == NULL)
			return (NULL);
		memset(chan, 0, sizeof(*chan));
		chan->fd = open(EVENTLOG_DEV_PATH, O_RDWR | O_CLOEXEC);
		if (chan->fd < 0) {
			saved = errno;
			free(chan);
			errno = saved;
			return (NULL);
		}
		if (pthread_mutex_init(&chan->lock, NULL) != 0) {
			saved = errno;
			(void)close(chan->fd);
			free(chan);
			errno = saved;
			return (NULL);
		}
		if (pthread_mutex_init(&chan->poll_lock, NULL) != 0) {
			saved = errno;
			pthread_mutex_destroy(&chan->lock);
			(void)close(chan->fd);
			free(chan);
			errno = saved;
			return (NULL);
		}
		chan->page = NULL;
		chan->pgsz = (size_t)sysconf(_SC_PAGESIZE);
		if ((long)chan->pgsz <= 0)
			chan->pgsz = 4096;
		chan->ctrl_external =
		    !!(config->flags & EVENTLOG_PROVIDER_EXTERNAL_CONTROL);
		chan->per_thread_rings =
		    (config->flags & EVENTLOG_PROVIDER_PER_THREAD_RINGS) != 0;
		eventlog_chan = chan;
	} else {
		chan = eventlog_chan;
		/*
		 * Control dispatch is one per-process channel: every provider
		 * must use the same model (thread or caller poll).
		 */
		if (!!(config->flags & EVENTLOG_PROVIDER_EXTERNAL_CONTROL) !=
		    chan->ctrl_external) {
			errno = EINVAL;
			return (NULL);
		}
	}

	if (chan->nprovs >= EVENTLOG_USER_MAX_PROVIDERS) {
		if (first) {
			pthread_mutex_destroy(&chan->poll_lock);
			pthread_mutex_destroy(&chan->lock);
			(void)close(chan->fd);
			free(chan);
			eventlog_chan = NULL;
		}
		errno = ENOSPC;
		return (NULL);
	}

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, provider_name, sizeof(req.name));
	req.default_enabled = config->default_enabled;
	req.flags = 0;
	req.expected_cadence_us = 0;	/* kernel uses its default ring sizing */
	/*
	 * Hand the schema decode blob to the kernel (it copies and owns it) so
	 * subscribers can fetch it via EVENTLOG_IOCTL_GET_DECODE_BLOB and decode
	 * this provider's events at runtime, exactly as for a kernel provider.
	 */
	req.decode_blob = (uint64_t)(uintptr_t)config->decode_blob;
	req.decode_blob_size = (config->decode_blob != NULL) ?
	    (uint32_t)config->decode_blob_size : 0;
	if (ioctl(chan->fd, EVENTLOG_IOCTL_REGISTER_PROVIDER, &req) != 0) {
		saved = errno;
		if (first) {
			pthread_mutex_destroy(&chan->poll_lock);
			pthread_mutex_destroy(&chan->lock);
			(void)close(chan->fd);
			free(chan);
			eventlog_chan = NULL;
		}
		errno = saved;
		return (NULL);
	}

	/*
	 * Map the shared enable page once per process.  Best effort: without
	 * it providers fall back to an always-enabled word (the kernel still
	 * filters per subscriber on push).
	 */
	if (chan->page == NULL) {
		void *pg = mmap(NULL, chan->pgsz, PROT_READ | PROT_WRITE,
		    MAP_SHARED, chan->fd, 0);
		if (pg != MAP_FAILED)
			chan->page = pg;
	}

	/*
	 * Set up the shared submission ring once per channel.  Best effort:
	 * if setup or mmap fails, ring_hdr stays NULL and event writes drop
	 * (and count) instead of corrupting anything.  eventlog_provider_create()
	 * still returns success in that case, so syslog(3) it -- otherwise a
	 * producer that hits e.g. the per-uid quota goes dark silently.
	 * Per-thread rings are allocated lazily on each thread's first write.
	 */
	if (!chan->per_thread_rings && chan->ring_hdr == NULL)
		eventlog_shared_ring_setup(chan);

	prov = calloc(1, sizeof(*prov));
	if (prov == NULL) {
		saved = errno;
		/* Leave the registration in the kernel; it is freed on close. */
		if (first) {
			if (chan->ring_hdr != NULL)
				(void)munmap(chan->ring_hdr,
				    chan->ring_map_len);
			if (chan->page != NULL)
				(void)munmap(chan->page, chan->pgsz);
			pthread_mutex_destroy(&chan->poll_lock);
			pthread_mutex_destroy(&chan->lock);
			(void)close(chan->fd);
			free(chan);
			eventlog_chan = NULL;
		}
		errno = saved;
		return (NULL);
	}
	prov->chan = chan;
	prov->provider_id = req.provider_id;
	prov->enable_offset = req.enable_offset;
	if (chan->page != NULL) {
		prov->enable = (struct eventlog_enable_page *)(void *)
		    ((char *)chan->page + req.enable_offset);
	} else {
		prov->fallback.effective_level = EVENTLOG_LEVEL_TRACE;
		prov->fallback.effective_keywords = 0xFFFFFFFFu;
		prov->enable = &prov->fallback;
	}
	prov->refcount = 1;
	atomic_store_explicit(&prov->default_enabled, config->default_enabled,
	    memory_order_relaxed);
	prov->dump_callback = config->dump_callback;
	prov->dump_callback_arg = config->dump_callback_arg;
	prov->default_changed = config->default_changed;
	prov->default_changed_arg = config->default_changed_arg;
	prov->subscribers_changed = config->subscribers_changed;
	prov->subscribers_changed_arg = config->subscribers_changed_arg;

	pthread_mutex_lock(&chan->lock);
	chan->provs[chan->nprovs++] = prov;
	pthread_mutex_unlock(&chan->lock);
	chan->nproviders++;

	/*
	 * Start the background control thread once per channel unless the
	 * channel's providers poll from their own thread.  Best effort: if
	 * creation fails the producer still submits events (the kernel
	 * polls the ring), but dump/notify callbacks are not delivered.
	 */
	if (!chan->ctrl_started && !chan->ctrl_external) {
		if (pthread_create(&chan->ctrl_thread, NULL,
		    eventlog_ctrl_thread, chan) == 0)
			chan->ctrl_started = 1;
	}

	return (prov);
}

struct eventlog_provider *
eventlog_provider_create(const char *name,
    const struct eventlog_provider_config *config)
{
	struct eventlog_provider_config defcfg;
	struct eventlog_provider *prov;

	if (config == NULL) {
		memset(&defcfg, 0, sizeof(defcfg));
		config = &defcfg;
	}
	if (name == NULL || name[0] == '\0' ||
	    strlen(name) >= EVENTLOG_PROVIDER_NAME_MAX) {
		errno = EINVAL;
		return (NULL);
	}

	(void)pthread_once(&eventlog_atfork_once, eventlog_atfork_install);

	pthread_mutex_lock(&eventlog_chan_lock);
	prov = eventlog_provider_register(name, config);
	pthread_mutex_unlock(&eventlog_chan_lock);
	return (prov);
}

struct eventlog_session *
eventlog_session_create(struct eventlog_provider *provider, uint64_t session_id,
    bool waitok, void *create_payload, size_t create_payload_size)
{
	struct eventlog_session *s;

	(void)waitok;			/* user runtime always heap-allocates */
	(void)create_payload;		/* user sessions emit no SESSION_CREATE */
	(void)create_payload_size;

	if (provider == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return (NULL);

	pthread_mutex_lock(&eventlog_chan_lock);
	provider->refcount++;
	pthread_mutex_unlock(&eventlog_chan_lock);

	atomic_fetch_add_explicit(&provider->sess_created, 1,
	    memory_order_relaxed);
	atomic_fetch_add_explicit(&provider->sess_active, 1,
	    memory_order_relaxed);

	s->provider = provider;
	s->session_id = session_id;
	s->state = EVENTLOG_SESSION_INHERIT;
	s->eff = provider->enable;
	if (atomic_load_explicit(&provider->default_enabled,
	    memory_order_relaxed) != 0) {
		s->enabled = 1;
		atomic_fetch_add_explicit(&provider->sess_enabled, 1,
		    memory_order_relaxed);
	}
	return (s);
}

void
eventlog_session_set_enabled(struct eventlog_session *session, int enabled)
{
	struct eventlog_provider *provider;

	if (session == NULL)
		return;
	provider = session->provider;
	if (enabled) {
		uint8_t expected = 0;

		if (atomic_compare_exchange_strong_explicit(&session->enabled,
		    &expected, 1, memory_order_relaxed, memory_order_relaxed))
			atomic_fetch_add_explicit(&provider->sess_enabled, 1,
			    memory_order_relaxed);
		session->gated = 0;
		if (session->state == EVENTLOG_SESSION_OVERRIDE)
			session->eff = &session->override;
		else {
			session->state = EVENTLOG_SESSION_INHERIT;
			session->eff = provider->enable;
		}
	} else {
		uint8_t expected = 1;

		if (atomic_compare_exchange_strong_explicit(&session->enabled,
		    &expected, 0, memory_order_relaxed, memory_order_relaxed))
			atomic_fetch_sub_explicit(&provider->sess_enabled, 1,
			    memory_order_relaxed);
		session->gated = 1;
		session->eff = &eventlog_disabled_word;
	}
}

void
eventlog_session_set_filter(struct eventlog_session *session,
    enum eventlog_level level, uint32_t keywords)
{
	if (session == NULL)
		return;
	session->override.effective_level = (uint32_t)level;
	session->override.effective_keywords = keywords;
	session->override.generation = 0;
	session->override.RESERVED = 0;
	session->state = EVENTLOG_SESSION_OVERRIDE;
	session->eff = session->gated ? &eventlog_disabled_word :
	    &session->override;
}

/* Remove a provider from its channel's dispatch registry (under chan->lock). */
static void
eventlog_chan_unregister_provider(struct eventlog_channel *chan,
    struct eventlog_provider *prov)
{
	unsigned i;

	pthread_mutex_lock(&chan->lock);
	for (i = 0; i < chan->nprovs; i++) {
		if (chan->provs[i] == prov) {
			chan->provs[i] = chan->provs[chan->nprovs - 1];
			chan->nprovs--;
			break;
		}
	}
	pthread_mutex_unlock(&chan->lock);
}

/*
 * Drop one reference to a provider (a live session, or the provider handle
 * from eventlog_provider_create).  When the last reference goes the provider
 * is removed from control dispatch and freed; the channel is torn down once
 * its final provider is gone.  Reference order does not matter.
 */
static void
eventlog_provider_unref(struct eventlog_provider *prov)
{
	struct eventlog_channel *chan = prov->chan;
	int free_prov = 0, teardown = 0;

	pthread_mutex_lock(&eventlog_chan_lock);
	if (prov->refcount > 0)
		prov->refcount--;
	if (prov->refcount == 0) {
		free_prov = 1;
		if (chan->nproviders > 0)
			chan->nproviders--;
		if (chan->nproviders == 0) {
			teardown = 1;
			eventlog_chan = NULL;
		}
	}
	pthread_mutex_unlock(&eventlog_chan_lock);

	/*
	 * Drop the provider from dispatch first so the control thread cannot
	 * pick it up once we free it (when other providers keep the channel,
	 * and hence the thread, alive).
	 */
	if (free_prov)
		eventlog_chan_unregister_provider(chan, prov);

	if (teardown) {
		/* Stop the background thread before tearing the channel down. */
		if (chan->ctrl_started) {
			atomic_store_explicit(&chan->ctrl_stop, 1,
			    memory_order_release);
			(void)pthread_join(chan->ctrl_thread, NULL);
		}
		/*
		 * Final drain: with the fd still open and the channel not yet
		 * closing, ask the kernel to consume any records published but
		 * not yet drained so they reach subscribers before the rings are
		 * unmapped and the fd closed.
		 */
		if (chan->ring_hdr != NULL || chan->maps != NULL)
			(void)ioctl(chan->fd, EVENTLOG_IOCTL_KICK);
		if (chan->ring_hdr != NULL)
			(void)munmap(chan->ring_hdr, chan->ring_map_len);
		while (chan->maps != NULL) {
			struct eventlog_ring_map *m = chan->maps;

			chan->maps = m->next;
			(void)munmap(m->base, m->len);
			free(m);
		}
		if (chan->page != NULL)
			(void)munmap(chan->page, chan->pgsz);
		free(chan->dump.req);
		pthread_mutex_destroy(&chan->poll_lock);
		pthread_mutex_destroy(&chan->lock);
		(void)close(chan->fd);
		free(chan);
	}

	if (free_prov)
		free(prov);
}

void
eventlog_session_destroy(struct eventlog_session *session)
{
	struct eventlog_provider *prov;

	if (session == NULL)
		return;
	prov = session->provider;
	if (session->enabled)
		atomic_fetch_sub_explicit(&prov->sess_enabled, 1,
		    memory_order_relaxed);
	atomic_fetch_sub_explicit(&prov->sess_active, 1, memory_order_relaxed);
	eventlog_provider_unref(prov);
	free(session);
}

void
eventlog_provider_destroy(struct eventlog_provider *provider)
{
	struct eventlog_channel *chan;

	if (provider == NULL)
		return;
	chan = provider->chan;
	/*
	 * Records are published into the ring as they are written, so there
	 * is nothing to flush; a fence just ensures prior writes are globally
	 * visible before any teardown.
	 */
	if (chan->ring_hdr != NULL || chan->per_thread_rings)
		atomic_thread_fence(memory_order_release);
	eventlog_provider_unref(provider);
}
