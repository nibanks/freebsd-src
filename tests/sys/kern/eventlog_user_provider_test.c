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
 * End-to-end tests for user-space eventlog PROVIDERS.
 *
 * These drive the full userland path against a live kernel through
 * /dev/eventlog: a process registers a provider with
 * EVENTLOG_IOCTL_REGISTER_PROVIDER, sets up a shared submission ring with
 * EVENTLOG_IOCTL_SETUP_RING and mmap(2), writes event records directly into
 * the ring (zero submit syscalls), and a separate subscriber fd reads the
 * merged, timestamp-ordered stream back with read(2) -- which is also what
 * lazily drives the kernel to drain the ring.  They exercise ordering,
 * multi-source merge, deferred (late-binding) subscriptions, the self-tuning
 * emit boundary, drop accounting, ring wrap/overflow, and input validation.
 *
 * One fd may hold several submission rings (repeated SETUP_RING); a test
 * that needs independent merge sources can also open several provider fds.
 * The kernel keys a user stream on (provider_id, stream_id).
 *
 * Determinism note: the emit boundary B never exceeds "now" (uptime).
 * Tests that expect immediate delivery therefore stamp events a little
 * in the past so B has already advanced past them; the one boundary test
 * that wants to observe hold-back stamps an event in the future and polls
 * until wall-clock time crosses it.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/eventlog.h>
#include <sys/eventlog_subscriber.h>

#define	DEV_EVENTLOG	"/dev/eventlog"
#define	BUF_PER_CPU	(64u * 1024u)
#define	READ_BUF_SZ	(1u << 20)
#define	UNPRIV_UID	65534		/* nobody: produce yes, subscribe no */
#define	UNPRIV_GID	65534		/* nobody / nogroup */

/* A single event the test wants to produce. */
struct test_event {
	uint64_t	ts;
	uint64_t	session_id;
	uint32_t	event_id;
	uint32_t	keywords;
	int32_t		thread_id;
	uint8_t		level;
	const void     *payload;
	uint16_t	payload_len;
};

/* A single event parsed back out of the subscriber's read stream. */
struct got_event {
	uint16_t	cpu;
	uint16_t	provider_id;
	uint64_t	timestamp;
	uint64_t	session_id;
	uint32_t	event_id;
	int32_t		thread_id;
	uint16_t	payload_len;
	uint8_t		payload[256];
};

/*
 * Common preconditions: must be root and /dev/eventlog must exist.
 * Returns an open fd (caller closes) or skips the test.
 *
 * The fd is opened non-blocking at open() time rather than via a later
 * fcntl(F_SETFL): devfs forwards FIONBIO to the driver's d_ioctl, which
 * the eventlog cdev does not implement, so fcntl(F_SETFL, O_NONBLOCK)
 * fails with ENOTTY.  O_NONBLOCK in the open flags sets FNONBLOCK on the
 * file directly, which the read path honours by returning EAGAIN when no
 * event is yet past the emit boundary.
 */
static int
open_eventlog_or_skip(void)
{
	int fd;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	fd = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present (eventlog not in kernel)",
			    DEV_EVENTLOG);
		atf_tc_fail("open(%s): %s", DEV_EVENTLOG, strerror(errno));
	}
	return (fd);
}

static uint64_t
uptime_us(void)
{
	struct timespec ts;

	ATF_REQUIRE(clock_gettime(CLOCK_UPTIME, &ts) == 0);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

/*
 * The kernel assigns each registered provider a (1-based) provider_id and
 * expects every pushed record to carry it.  Remember the id keyed by the
 * provider fd so do_push() can stamp records without each call site
 * threading the id through.  One provider per fd in these tests.
 */
#define	FD_PROVIDER_MAX	1024
static uint16_t fd_provider_id[FD_PROVIDER_MAX];

/* Register the calling fd as a user-space provider. */
static int
do_register(int fd, const char *name, int default_enabled)
{
	struct eventlog_provider_reg_req req;
	int rc;

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, name, EVENTLOG_PROVIDER_NAME_MAX);
	req.default_enabled = default_enabled;
	req.flags = 0;
	req.expected_cadence_us = 0;
	rc = ioctl(fd, EVENTLOG_IOCTL_REGISTER_PROVIDER, &req);
	if (rc == 0 && fd >= 0 && fd < FD_PROVIDER_MAX)
		fd_provider_id[fd] = req.provider_id;
	return (rc);
}

/*
 * Open /dev/eventlog read-write (a provider mmaps the enable page and the
 * submission ring MAP_SHARED, which needs a writable fd) and register it as
 * a provider, skipping/failing loudly.
 */
static int
open_register_provider(const char *name)
{
	int fd;

	fd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_MSG(do_register(fd, name, 1) == 0, "register %s: %s", name,
	    strerror(errno));
	return (fd);
}

/* Turn the calling fd into a subscriber with a single subscription. */
static int
do_create(int fd, uint16_t user_streams, const char *provider,
    enum eventlog_level level, uint32_t keywords, uint32_t sub_flags)
{
	struct eventlog_create_req *req;
	size_t reqsz;
	int rc, saved;

	reqsz = __builtin_offsetof(struct eventlog_create_req, subscriptions) +
	    sizeof(struct eventlog_subscription_req);
	(void)user_streams;	/* Kernel auto-manages user streams now. */
	req = calloc(1, reqsz);
	ATF_REQUIRE(req != NULL);
	req->buffer_size_per_cpu = BUF_PER_CPU;
	req->count = 1;
	strlcpy(req->subscriptions[0].provider_name, provider,
	    EVENTLOG_PROVIDER_NAME_MAX);
	req->subscriptions[0].level = level;
	req->subscriptions[0].keywords = keywords;
	req->subscriptions[0].flags = sub_flags;

	rc = ioctl(fd, EVENTLOG_IOCTL_CREATE_SIZE(1), req);
	saved = errno;
	free(req);
	errno = saved;
	return (rc);
}

/*
 * GET_PROVIDERS into a caller array of up to cap entries.  Returns the total
 * provider count the kernel reports (which may exceed cap if truncated), or
 * -1 on ioctl error.  Copies min(total, cap) entries into out (if non-NULL).
 */
static int
do_get_providers(int fd, struct eventlog_provider_info *out, uint32_t cap)
{
	struct eventlog_get_providers_resp *resp;
	size_t base = __builtin_offsetof(struct eventlog_get_providers_resp,
	    providers);
	uint32_t total, ncopy;
	int rc, saved;

	resp = calloc(1, base + (size_t)cap * sizeof(*out));
	ATF_REQUIRE(resp != NULL);
	resp->count = cap;
	rc = ioctl(fd, EVENTLOG_IOCTL_GET_PROVIDERS_SIZE(cap), resp);
	if (rc != 0) {
		saved = errno;
		free(resp);
		errno = saved;
		return (-1);
	}
	total = resp->count;
	ncopy = total < cap ? total : cap;
	if (out != NULL && ncopy > 0)
		memcpy(out, resp->providers, ncopy * sizeof(*out));
	free(resp);
	return ((int)total);
}

/*
 * Per-fd submission ring, set up lazily on first do_push().  Tests that
 * need extra rings on the same fd issue SETUP_RING themselves.
 */
struct fd_ring {
	struct eventlog_ring_hdr *hdr;
	uint8_t		*data;
	uint32_t	size;
	uint32_t	mask;
	size_t		maplen;
};
static struct fd_ring fd_ring[FD_PROVIDER_MAX];

/* Set up and map the submission ring for a provider fd (idempotent). */
static int
ring_setup(int fd)
{
	struct eventlog_ring_setup_req rr;
	void *p;

	if (fd < 0 || fd >= FD_PROVIDER_MAX) {
		errno = EINVAL;
		return (-1);
	}
	if (fd_ring[fd].hdr != NULL)
		return (0);
	memset(&rr, 0, sizeof(rr));
	if (ioctl(fd, EVENTLOG_IOCTL_SETUP_RING, &rr) != 0)
		return (-1);
	p = mmap(NULL, (size_t)rr.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, (off_t)rr.mmap_offset);
	if (p == MAP_FAILED)
		return (-1);
	fd_ring[fd].hdr = (struct eventlog_ring_hdr *)p;
	fd_ring[fd].data = (uint8_t *)p + fd_ring[fd].hdr->data_offset;
	fd_ring[fd].size = fd_ring[fd].hdr->data_size;
	fd_ring[fd].mask = fd_ring[fd].size - 1;
	fd_ring[fd].maplen = (size_t)rr.mmap_size;
	return (0);
}

/* Copy len bytes into the ring at logical offset pos, splitting at the wrap. */
static void
ring_put(struct fd_ring *r, uint64_t pos, const void *src, size_t len)
{
	uint32_t off = (uint32_t)(pos & r->mask);
	size_t n1 = r->size - off;

	if (n1 >= len) {
		memcpy(r->data + off, src, len);
	} else {
		memcpy(r->data + off, src, n1);
		memcpy(r->data, (const uint8_t *)src + n1, len - n1);
	}
}

/* Map another SETUP_RING on fd into *out (caller munmaps out->hdr). */
static int
ring_setup_extra(int fd, struct fd_ring *out)
{
	struct eventlog_ring_setup_req rr;
	void *p;

	memset(&rr, 0, sizeof(rr));
	if (ioctl(fd, EVENTLOG_IOCTL_SETUP_RING, &rr) != 0)
		return (-1);
	p = mmap(NULL, (size_t)rr.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, (off_t)rr.mmap_offset);
	if (p == MAP_FAILED)
		return (-1);
	out->hdr = (struct eventlog_ring_hdr *)p;
	out->data = (uint8_t *)p + out->hdr->data_offset;
	out->size = out->hdr->data_size;
	out->mask = out->size - 1;
	out->maplen = (size_t)rr.mmap_size;
	return (0);
}

/*
 * Publish a batch onto an already-mapped ring.  stream_id is kernel-assigned
 * at SETUP_RING; drain uses that cached id, not the mmap header.
 */
static int
do_push_on(struct fd_ring *r, uint16_t pid, uint64_t watermark_us,
    const struct test_event *evs, uint32_t count)
{
	struct eventlog_ring_hdr *hdr = r->hdr;
	uint32_t i, bytes = 0;
	uint64_t head, tail, wp;

	for (i = 0; i < count; i++)
		bytes += sizeof(struct eventlog_push_record) + evs[i].payload_len;
	if (bytes > r->size) {
		errno = E2BIG;
		return (-1);
	}

	head = hdr->head;
	tail = atomic_load_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->tail,
	    memory_order_acquire);
	if (bytes > r->size - (uint32_t)(head - tail)) {
		hdr->dropped++;
		errno = ENXIO;	/* ring full */
		return (-1);
	}

	wp = head;
	for (i = 0; i < count; i++) {
		struct eventlog_push_record rec;

		memset(&rec, 0, sizeof(rec));
		rec.timestamp_us = evs[i].ts;
		rec.session_id = evs[i].session_id;
		rec.event_id = evs[i].event_id;
		rec.keywords = evs[i].keywords;
		rec.thread_id = evs[i].thread_id;
		rec.payload_len = evs[i].payload_len;
		rec.provider_id = pid;
		rec.level = evs[i].level;
		ring_put(r, wp, &rec, sizeof(rec));
		wp += sizeof(rec);
		if (evs[i].payload_len != 0) {
			ring_put(r, wp, evs[i].payload, evs[i].payload_len);
			wp += evs[i].payload_len;
		}
	}

	hdr->watermark_us = watermark_us;
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->head,
	    head + bytes, memory_order_release);
	return (0);
}

/*
 * Write one batch of records into the fd's submission ring and publish the
 * new head, exactly as libeventlog does.  Unlike the retired ioctl push,
 * this is asynchronous: the kernel validates and delivers on the next
 * subscriber drain, so a malformed batch is dropped silently rather than
 * reported here.  Returns -1 (ENXIO) if the ring has no room, or propagates
 * a SETUP_RING failure (e.g. EINVAL on an unregistered fd).
 */
static int
do_push(int fd, uint16_t stream_id, uint64_t watermark_us,
    const struct test_event *evs, uint32_t count)
{
	uint16_t pid;

	(void)stream_id;
	if (ring_setup(fd) != 0)
		return (-1);
	pid = (fd >= 0 && fd < FD_PROVIDER_MAX) ? fd_provider_id[fd] : 0;
	return (do_push_on(&fd_ring[fd], pid, watermark_us, evs, count));
}

/*
 * Drain up to maxout events from a subscriber fd, polling for up to
 * timeout_ms for events to become emittable.  The fd is opened
 * non-blocking, so a stalled boundary returns EAGAIN rather than
 * sleeping.  Returns the number of events parsed.
 */
static int
drain_events(int fd, struct got_event *out, int maxout, int timeout_ms)
{
	uint8_t *buf;
	int got = 0, waited = 0;

	buf = malloc(READ_BUF_SZ);
	ATF_REQUIRE(buf != NULL);

	for (;;) {
		ssize_t n = read(fd, buf, READ_BUF_SZ);
		size_t off = 0;

		if (n < 0) {
			if (errno != EAGAIN)
				atf_tc_fail("read(%s): %s", DEV_EVENTLOG,
				    strerror(errno));
			/*
			 * Nothing more is emittable right now. If we have
			 * already drained events this round we are done (a
			 * single batch becomes emittable atomically); only
			 * keep polling while still waiting for the boundary
			 * to first release something.
			 */
			if (got > 0 || waited >= timeout_ms)
				break;
			usleep(10000);
			waited += 10;
			continue;
		}
		if (n == 0)
			break;

		while (off + sizeof(struct eventlog_event_header) <= (size_t)n) {
			struct eventlog_event_header hdr;
			uint16_t plen;

			memcpy(&hdr, buf + off, sizeof(hdr));
			ATF_REQUIRE(hdr.event_length >= sizeof(hdr));
			ATF_REQUIRE(off + hdr.event_length <= (size_t)n);
			plen = hdr.event_length - sizeof(hdr);

			/*
			 * Bind-time PROVIDER_INFO/BLOB records share the merged
			 * stream. drain_events returns the caller's records.
			 */
			if (hdr.event_id == EVENTLOG_PROVIDER_INFO_ID ||
			    hdr.event_id == EVENTLOG_PROVIDER_BLOB_ID) {
				off += hdr.event_length;
				continue;
			}

			if (got < maxout) {
				struct got_event *g = &out[got];

				g->cpu = hdr.cpu;
				g->provider_id = hdr.provider_id;
				g->timestamp = hdr.timestamp;
				g->session_id = hdr.session_id;
				g->event_id = hdr.event_id;
				g->thread_id = hdr.thread_id;
				g->payload_len = plen;
				if (plen > sizeof(g->payload))
					plen = sizeof(g->payload);
				memcpy(g->payload, buf + off + sizeof(hdr), plen);
			}
			got++;
			off += hdr.event_length;
		}
	}

	free(buf);
	return (got);
}

static void
get_stats(int fd, struct eventlog_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	ATF_REQUIRE_MSG(ioctl(fd, EVENTLOG_IOCTL_GET_STATS, stats) == 0,
	    "GET_STATS: %s", strerror(errno));
}

static u_int
get_uint_sysctl(const char *name)
{
	u_int v;
	size_t len = sizeof(v);

	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "sysctl %s: %s", name, strerror(errno));
	return (v);
}

static void
set_uint_sysctl(const char *name, u_int v)
{
	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &v, sizeof(v)) == 0,
	    "sysctl %s=%u: %s", name, v, strerror(errno));
}

static u_long
get_ulong_sysctl(const char *name)
{
	u_long v;
	size_t len = sizeof(v);

	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "sysctl %s: %s", name, strerror(errno));
	return (v);
}

static uint64_t
get_u64_sysctl(const char *name)
{
	uint64_t v;
	size_t len = sizeof(v);

	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "sysctl %s: %s", name, strerror(errno));
	return (v);
}

static void
set_ulong_sysctl(const char *name, u_long v)
{
	ATF_REQUIRE_MSG(sysctlbyname(name, NULL, NULL, &v, sizeof(v)) == 0,
	    "sysctl %s=%lu: %s", name, v, strerror(errno));
}

/*
 * Build and submit one PUSH_DUMP batch, scoped to subscriber_id (the dump
 * target named in a DUMP_REQUEST control event).  Same record packing as
 * do_push().
 */
static int
do_push_dump(int fd, uint64_t subscriber_id, uint16_t stream_id,
    uint64_t watermark_us, const struct test_event *evs, uint32_t count)
{
	struct eventlog_push_dump_req *req;
	uint16_t pid;
	uint32_t i, off, bytes = 0;
	size_t reqsz;
	int rc, saved;

	pid = (fd >= 0 && fd < FD_PROVIDER_MAX) ? fd_provider_id[fd] : 0;

	for (i = 0; i < count; i++)
		bytes += sizeof(struct eventlog_push_record) + evs[i].payload_len;

	reqsz = __builtin_offsetof(struct eventlog_push_dump_req, data) + bytes;
	req = calloc(1, reqsz);
	ATF_REQUIRE(req != NULL);
	req->subscriber_id = subscriber_id;
	req->stream_id = stream_id;
	req->flags = 0;
	req->count = count;
	req->watermark_us = watermark_us;
	req->bytes = bytes;

	off = 0;
	for (i = 0; i < count; i++) {
		struct eventlog_push_record *r =
		    (struct eventlog_push_record *)(req->data + off);

		r->timestamp_us = evs[i].ts;
		r->session_id = evs[i].session_id;
		r->event_id = evs[i].event_id;
		r->keywords = evs[i].keywords;
		r->thread_id = evs[i].thread_id;
		r->payload_len = evs[i].payload_len;
		r->provider_id = pid;
		r->level = evs[i].level;
		off += sizeof(*r);
		if (evs[i].payload_len != 0) {
			memcpy(req->data + off, evs[i].payload,
			    evs[i].payload_len);
			off += evs[i].payload_len;
		}
	}

	rc = ioctl(fd, EVENTLOG_IOCTL_PUSH_DUMP_SIZE(bytes), req);
	saved = errno;
	free(req);
	errno = saved;
	return (rc);
}

/* Tell the kernel a (subscriber, provider) state-dump replay is finished. */
static int
do_dump_done(int fd, uint64_t subscriber_id, uint16_t provider_id)
{
	struct eventlog_dump_done_req req;

	memset(&req, 0, sizeof(req));
	req.subscriber_id = subscriber_id;
	req.provider_id = provider_id;
	return (ioctl(fd, EVENTLOG_IOCTL_DUMP_DONE, &req));
}

/*
 * Collect control events from a provider fd, polling up to timeout_ms.  Each
 * WAIT_CONTROL blocks in the kernel until an event is queued or its own
 * 50 ms timeout fires; this keeps re-issuing it until at least one event is
 * collected or the deadline passes.  Returns the number copied into out.
 */
static int
wait_control(int fd, struct eventlog_control_event *out, uint32_t cap,
    int timeout_ms)
{
	struct eventlog_wait_control_req *req;
	size_t reqsz;
	int waited = 0, got = 0;

	reqsz = __builtin_offsetof(struct eventlog_wait_control_req, events) +
	    (size_t)cap * sizeof(struct eventlog_control_event);
	req = malloc(reqsz);
	ATF_REQUIRE(req != NULL);

	for (;;) {
		uint32_t i;

		req->timeout_us = 50000;
		req->count = cap;
		req->RESERVED = 0;
		if (ioctl(fd, EVENTLOG_IOCTL_WAIT_CONTROL_SIZE(cap), req) != 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (i = 0; i < req->count && (uint32_t)got < cap; i++)
			out[got++] = req->events[i];
		if (got > 0 || waited >= timeout_ms)
			break;
		waited += 50;
	}

	free(req);
	return (got);
}

/* Index of the first control event of `type` in evs[0..n), or -1. */
static int
find_control(const struct eventlog_control_event *evs, int n, uint16_t type)
{
	int i;

	for (i = 0; i < n; i++)
		if (evs[i].type == type)
			return (i);
	return (-1);
}

/*
 * Drain events from a subscriber across several attempts, accumulating into
 * out.  Unlike a single drain_events() call, this tolerates a state dump
 * arriving in two pieces: the replayed records (via the user-stream merge)
 * and the synthesised DUMP_COMPLETE (written straight to the device buffer)
 * can land in separate reads.  Returns the total collected.
 */
static int
drain_events_accum(int fd, struct got_event *out, int maxout, int want,
    int timeout_ms)
{
	int total = 0, slept = 0;

	while (total < maxout) {
		int r = drain_events(fd, out + total, maxout - total, 200);

		total += r;
		if (total >= want)
			break;
		if (r == 0) {
			if (slept >= timeout_ms)
				break;
			usleep(50000);
			slept += 50;
		}
	}
	return (total);
}

/* --------------------------------------------------------------------- */

ATF_TC(register_provider);
ATF_TC_HEAD(register_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "REGISTER_PROVIDER claims the fd; bad name fails, a second "
	    "provider on the same fd is additive");
}
ATF_TC_BODY(register_provider, tc)
{
	uint16_t first_id;
	int fd;

	fd = open_eventlog_or_skip();

	/* Empty name is rejected. */
	ATF_REQUIRE_ERRNO(EINVAL, do_register(fd, "", 0) == -1);

	/* Valid registration claims the fd. */
	ATF_REQUIRE_MSG(do_register(fd, "uprov_reg", 0) == 0,
	    "register: %s", strerror(errno));
	first_id = fd_provider_id[fd];
	ATF_CHECK(first_id != 0);

	/*
	 * A second registration on the same fd is now additive: many
	 * providers share one fd, each getting its own provider_id.
	 */
	ATF_REQUIRE_MSG(do_register(fd, "uprov_reg2", 0) == 0,
	    "second register: %s", strerror(errno));
	ATF_CHECK_MSG(fd_provider_id[fd] != first_id,
	    "second provider reused the first id %u", first_id);

	/* CREATE on a provider fd is refused (already a provider). */
	ATF_REQUIRE_ERRNO(EEXIST,
	    do_create(fd, 4, "uprov_reg", EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == -1);

	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC(push_without_register);
ATF_TC_HEAD(push_without_register, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Setting up a submission ring on an unclaimed fd is rejected");
}
ATF_TC_BODY(push_without_register, tc)
{
	struct test_event ev = { .ts = 1, .event_id = 1, .keywords = 1,
	    .level = EVENTLOG_LEVEL_INFO };
	int fd;

	fd = open_eventlog_or_skip();
	/* do_push lazily issues SETUP_RING, which rejects a non-provider fd. */
	ATF_REQUIRE_ERRNO(EINVAL, do_push(fd, 0, 1, &ev, 1) == -1);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC(end_to_end_basic);
ATF_TC_HEAD(end_to_end_basic, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Events pushed by a user provider are read back in order");
}
ATF_TC_BODY(end_to_end_basic, tc)
{
	const char *pname = "uprov_basic";
	struct test_event evs[8];
	struct got_event got[16];
	char payloads[8][16];
	uint64_t base;
	int pfd, sfd, n, i;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	/* Subscriber first, deferred so it binds when the provider appears. */
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0,
	    "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0,
	    "register: %s", strerror(errno));

	/* Stamp in the past so the boundary has already moved past them. */
	base = uptime_us() - 100000;
	for (i = 0; i < 8; i++) {
		snprintf(payloads[i], sizeof(payloads[i]), "evt-%d", i);
		evs[i].ts = base + (uint64_t)i;
		evs[i].session_id = 0x1000 + i;
		evs[i].event_id = 100 + i;
		evs[i].keywords = 0x1;
		evs[i].thread_id = 4242;
		evs[i].level = EVENTLOG_LEVEL_INFO;
		evs[i].payload = payloads[i];
		evs[i].payload_len = (uint16_t)(strlen(payloads[i]) + 1);
	}
	ATF_REQUIRE_MSG(do_push(pfd, 0, base + 8, evs, 8) == 0,
	    "push: %s", strerror(errno));

	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(8, n, "expected 8 events, got %d", n);

	for (i = 0; i < 8; i++) {
		ATF_CHECK_EQ_MSG(base + (uint64_t)i, got[i].timestamp,
		    "event %d timestamp", i);
		ATF_CHECK_EQ_MSG((uint32_t)(100 + i), got[i].event_id,
		    "event %d id", i);
		ATF_CHECK_EQ_MSG((uint64_t)(0x1000 + i), got[i].session_id,
		    "event %d session", i);
		ATF_CHECK_EQ(4242, got[i].thread_id);
		ATF_CHECK_STREQ(payloads[i], (const char *)got[i].payload);
		/* All events share the same (single) provider id. */
		ATF_CHECK_EQ(got[0].provider_id, got[i].provider_id);
	}
	ATF_CHECK(got[0].provider_id != 0);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(merge_two_streams);
ATF_TC_HEAD(merge_two_streams, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Two provider streams are merged into one timestamp-ordered read");
}
ATF_TC_BODY(merge_two_streams, tc)
{
	const char *pname = "uprov_merge";
	struct test_event a[3], b[3];
	struct got_event got[16];
	uint64_t base;
	int pfd_a, pfd_b, sfd, n, i;

	sfd = open_eventlog_or_skip();

	/*
	 * One ring carries one ordered stream, so the two interleaved sources
	 * are two provider fds sharing the name: the single subscription binds
	 * to both, and the kernel merges them into one ordered read.
	 */
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	pfd_a = open_register_provider(pname);
	pfd_b = open_register_provider(pname);

	base = uptime_us() - 100000;
	/* Stream 0: even timestamps; stream 1: odd timestamps. */
	for (i = 0; i < 3; i++) {
		a[i].ts = base + (uint64_t)(i * 2);
		a[i].session_id = 1;
		a[i].event_id = 200 + i;
		a[i].keywords = 0x1;
		a[i].thread_id = 1;
		a[i].level = EVENTLOG_LEVEL_INFO;
		a[i].payload = NULL;
		a[i].payload_len = 0;

		b[i].ts = base + (uint64_t)(i * 2 + 1);
		b[i].session_id = 2;
		b[i].event_id = 300 + i;
		b[i].keywords = 0x1;
		b[i].thread_id = 2;
		b[i].level = EVENTLOG_LEVEL_INFO;
		b[i].payload = NULL;
		b[i].payload_len = 0;
	}
	ATF_REQUIRE(do_push(pfd_a, 0, base + 5, a, 3) == 0);
	ATF_REQUIRE(do_push(pfd_b, 0, base + 5, b, 3) == 0);

	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(6, n, "expected 6 merged events, got %d", n);

	/* Globally ordered by timestamp. */
	for (i = 0; i < 6; i++)
		ATF_CHECK_EQ_MSG(base + (uint64_t)i, got[i].timestamp,
		    "merged position %d", i);

	/* The two sources are distinct providers; cpu now carries the
	 * physical CPU, so the distinction shows in provider_id. */
	ATF_CHECK(got[0].provider_id != got[1].provider_id);

	ATF_REQUIRE(close(pfd_a) == 0);
	ATF_REQUIRE(close(pfd_b) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(absent_provider_defers);
ATF_TC_HEAD(absent_provider_defers, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Subscribing to an absent provider always succeeds and defers");
}
ATF_TC_BODY(absent_provider_defers, tc)
{
	int fd;

	fd = open_eventlog_or_skip();
	/* No such provider: the create succeeds and waits for late binding. */
	ATF_REQUIRE_MSG(do_create(fd, 4, "uprov_nope", EVENTLOG_LEVEL_TRACE,
	    ~0u, 0) == 0, "deferred create: %s", strerror(errno));
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC(level_keyword_filter);
ATF_TC_HEAD(level_keyword_filter, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Subscriber level/keyword filter drops non-matching pushed events");
}
ATF_TC_BODY(level_keyword_filter, tc)
{
	const char *pname = "uprov_filter";
	struct test_event evs[4];
	struct got_event got[8];
	uint64_t base;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	/* Subscribe at WARN level, keyword bit 0x2 only. */
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_WARN, 0x2,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	base = uptime_us() - 100000;
	/* [0] kept: ERROR<=WARN, kw 0x2 matches. */
	evs[0] = (struct test_event){ .ts = base + 0, .event_id = 1,
	    .keywords = 0x2, .level = EVENTLOG_LEVEL_ERROR };
	/* [1] dropped: level INFO > WARN. */
	evs[1] = (struct test_event){ .ts = base + 1, .event_id = 2,
	    .keywords = 0x2, .level = EVENTLOG_LEVEL_INFO };
	/* [2] dropped: keyword 0x1 doesn't intersect 0x2. */
	evs[2] = (struct test_event){ .ts = base + 2, .event_id = 3,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_WARN };
	/* [3] kept: WARN<=WARN, kw 0x2 matches. */
	evs[3] = (struct test_event){ .ts = base + 3, .event_id = 4,
	    .keywords = 0x2, .level = EVENTLOG_LEVEL_WARN };

	ATF_REQUIRE(do_push(pfd, 0, base + 4, evs, 4) == 0);

	n = drain_events(sfd, got, 8, 2000);
	ATF_REQUIRE_EQ_MSG(2, n, "expected 2 filtered events, got %d", n);
	ATF_CHECK_EQ(1u, got[0].event_id);
	ATF_CHECK_EQ(4u, got[1].event_id);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(out_of_order_drop_stats);
ATF_TC_HEAD(out_of_order_drop_stats, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A batch older than already-buffered data is dropped and counted");
}
ATF_TC_BODY(out_of_order_drop_stats, tc)
{
	const char *pname = "uprov_ooo";
	struct test_event hi[3], lo[2];
	struct eventlog_stats stats;
	struct got_event got[8];
	uint64_t base;
	int pfd, sfd, i;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	base = uptime_us() - 100000;
	for (i = 0; i < 3; i++)
		hi[i] = (struct test_event){ .ts = base + 100 + i,
		    .event_id = (uint32_t)(10 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	/* Older than the high batch's last_ts on the same stream. */
	for (i = 0; i < 2; i++)
		lo[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .event_id = (uint32_t)(20 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };

	ATF_REQUIRE(do_push(pfd, 0, base + 103, hi, 3) == 0);
	/*
	 * Drain the high batch as its own snapshot so the stream's write
	 * position advances past it; otherwise both batches drain together
	 * and the in-snapshot timestamp regression would discard the whole
	 * thing rather than counting the older records as late.
	 */
	ATF_REQUIRE_EQ_MSG(3, drain_events(sfd, got, 8, 2000),
	    "high batch should deliver before the late batch arrives");

	/* Older than the stream's last_ts now, so each record drops as late. */
	ATF_REQUIRE(do_push(pfd, 0, base + 103, lo, 2) == 0);
	(void)drain_events(sfd, got, 8, 500);

	get_stats(sfd, &stats);
	ATF_CHECK_EQ_MSG(2, (int)stats.user_dropped_late,
	    "expected 2 late drops, got %ju",
	    (uintmax_t)stats.user_dropped_late);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(invalid_batches_rejected);
ATF_TC_HEAD(invalid_batches_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed ring batches are discarded by the kernel drain and "
	    "never reach a subscriber");
}
ATF_TC_BODY(invalid_batches_rejected, tc)
{
	const char *pname = "uprov_inval";
	struct test_event evs[2];
	struct got_event got[4];
	uint64_t base;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	base = uptime_us() - 100000;

	/*
	 * Validation moved into the kernel drain: the producer's ring write
	 * always "succeeds" locally, but a malformed batch is discarded
	 * wholesale on drain (tail resynced to head) and nothing is delivered.
	 * Each batch is pushed alone and read on its own so the discard of one
	 * cannot mask a later good batch.
	 */

	/* Decreasing timestamps within a batch. */
	evs[0] = (struct test_event){ .ts = base + 10, .event_id = 1,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_INFO };
	evs[1] = (struct test_event){ .ts = base + 5, .event_id = 2,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base + 10, evs, 2) == 0);
	n = drain_events(sfd, got, 4, 300);
	ATF_CHECK_EQ_MSG(0, n, "decreasing-ts batch delivered %d events", n);

	/* Reserved framework event id. */
	evs[0] = (struct test_event){ .ts = base, .event_id = EVENTLOG_SESSION_END_ID,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base, evs, 1) == 0);
	n = drain_events(sfd, got, 4, 300);
	ATF_CHECK_EQ_MSG(0, n, "reserved-id batch delivered %d events", n);

	/* Level out of range. */
	evs[0] = (struct test_event){ .ts = base, .event_id = 7,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_TRACE + 1 };
	ATF_REQUIRE(do_push(pfd, 0, base, evs, 1) == 0);
	n = drain_events(sfd, got, 4, 300);
	ATF_CHECK_EQ_MSG(0, n, "bad-level batch delivered %d events", n);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(boundary_holds_future_event);
ATF_TC_HEAD(boundary_holds_future_event, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An event stamped in the future is held back, then released "
	    "once wall-clock time crosses it");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(boundary_holds_future_event, tc)
{
	const char *pname = "uprov_future";
	struct test_event ev;
	struct got_event got[4];
	uint64_t future;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	/* 500ms in the future: the emit boundary B never exceeds now. */
	future = uptime_us() + 500000;
	ev = (struct test_event){ .ts = future, .event_id = 99,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, future, &ev, 1) == 0);

	/*
	 * Immediately: a bind-time announcement may already be readable.
	 * The future user event stays held until wall time crosses it.
	 */
	{
		uint8_t buf[512];

		for (;;) {
			struct eventlog_event_header hdr;
			ssize_t r = read(sfd, buf, sizeof(buf));

			if (r < 0 && errno == EAGAIN)
				break;
			ATF_REQUIRE_MSG(r >= (ssize_t)sizeof(hdr),
			    "future event should be held back (r=%zd errno=%d)",
			    r, errno);
			memcpy(&hdr, buf, sizeof(hdr));
			ATF_REQUIRE_MSG(
			    hdr.event_id == EVENTLOG_PROVIDER_INFO_ID ||
			    hdr.event_id == EVENTLOG_PROVIDER_BLOB_ID,
			    "future event should be held back (event %#x)",
			    hdr.event_id);
		}
	}

	/* Within a few seconds, time crosses the timestamp and it releases. */
	n = drain_events(sfd, got, 4, 5000);
	ATF_REQUIRE_EQ_MSG(1, n, "expected the future event to release, got %d",
	    n);
	ATF_CHECK_EQ(99u, got[0].event_id);
	ATF_CHECK_EQ(future, got[0].timestamp);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(get_providers_lists_user_provider);
ATF_TC_HEAD(get_providers_lists_user_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "GET_PROVIDERS reports a bound user provider; id matches events");
}
ATF_TC_BODY(get_providers_lists_user_provider, tc)
{
	const char *pname = "uprov_list";
	struct eventlog_provider_info info[4];
	struct got_event got[2];
	struct test_event ev;
	uint64_t base;
	int pfd, sfd, n, total;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	total = do_get_providers(sfd, info, nitems(info));
	ATF_REQUIRE_MSG(total >= 0, "GET_PROVIDERS: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(1, total, "expected 1 provider, got %d", total);
	ATF_CHECK_STREQ(pname, info[0].name);
	ATF_CHECK(info[0].provider_id != 0);

	base = uptime_us() - 100000;
	ev = (struct test_event){ .ts = base, .event_id = 1, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base, &ev, 1) == 0);
	n = drain_events(sfd, got, 2, 2000);
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ_MSG(info[0].provider_id, got[0].provider_id,
	    "GET_PROVIDERS id should match event header id");

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(multi_subscriber_fanout);
ATF_TC_HEAD(multi_subscriber_fanout, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "One provider push is delivered to every subscribing subscriber");
}
ATF_TC_BODY(multi_subscriber_fanout, tc)
{
	const char *pname = "uprov_fanout";
	struct test_event evs[3];
	struct got_event g1[8], g2[8];
	uint64_t base;
	int pfd, s1, s2, n1, n2, i;

	s1 = open_eventlog_or_skip();
	s2 = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(s2 >= 0);
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(s1, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_create(s2, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	base = uptime_us() - 100000;
	for (i = 0; i < 3; i++)
		evs[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .event_id = (uint32_t)(500 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base + 2, evs, 3) == 0);

	n1 = drain_events(s1, g1, 8, 2000);
	n2 = drain_events(s2, g2, 8, 2000);
	ATF_CHECK_EQ_MSG(3, n1, "subscriber 1 got %d", n1);
	ATF_CHECK_EQ_MSG(3, n2, "subscriber 2 got %d", n2);
	for (i = 0; i < 3 && i < n1 && i < n2; i++) {
		ATF_CHECK_EQ((uint32_t)(500 + i), g1[i].event_id);
		ATF_CHECK_EQ((uint32_t)(500 + i), g2[i].event_id);
	}

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(s1) == 0);
	ATF_REQUIRE(close(s2) == 0);
}

#define	PROCESS_PROVIDER	"process"
#define	PROCESS_THREAD_CREATE_ID	0

static void
spawn_fork_thread(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0)
		_exit(0);
	ATF_REQUIRE_MSG(pid > 0, "fork: %s", strerror(errno));
	ATF_REQUIRE_MSG(waitpid(pid, NULL, 0) == pid, "waitpid: %s",
	    strerror(errno));
}

static int
count_event_id(const struct got_event *evs, int n, uint32_t event_id)
{
	int c, i;

	c = 0;
	for (i = 0; i < n; i++)
		if (evs[i].event_id == event_id)
			c++;
	return (c);
}

/*
 * Kernel events fan out to every device subscriber through one shared
 * header.  A bug that zeroed hdr->RESERVED after the list-head write
 * mis-routed every later subscriber's kernel events into source 0 and
 * stalled the incumbent's merge while a second elog was live.
 */
ATF_TC(multi_device_subscriber_kernel_fanout);
ATF_TC_HEAD(multi_device_subscriber_kernel_fanout, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Kernel provider events reach every concurrent device subscriber");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(multi_device_subscriber_kernel_fanout, tc)
{
	struct got_event g1[64], g2[64];
	int s1, s2, n1, n2, tc1, tc2;

	s1 = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_create(s1, 4, PROCESS_PROVIDER, EVENTLOG_LEVEL_TRACE,
	    ~0u, 0) == 0, "create s1: %s", strerror(errno));

	/* Sanity: a lone subscriber receives kernel process events. */
	spawn_fork_thread();
	n1 = drain_events(s1, g1, 64, 2000);
	ATF_REQUIRE_MSG(n1 > 0,
	    "s1 alone should see fork events from the process provider, got %d",
	    n1);

	/*
	 * Second subscriber is inserted at the list head, so s1 is now the
	 * incumbent that used to lose every kernel event.
	 */
	s2 = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(s2 >= 0);
	ATF_REQUIRE_MSG(do_create(s2, 4, PROCESS_PROVIDER, EVENTLOG_LEVEL_TRACE,
	    ~0u, 0) == 0, "create s2: %s", strerror(errno));

	spawn_fork_thread();
	n1 = drain_events(s1, g1, 64, 2000);
	n2 = drain_events(s2, g2, 64, 2000);
	ATF_REQUIRE_MSG(n1 > 0,
	    "incumbent s1 stalled while s2 was live: got %d events", n1);
	ATF_REQUIRE_MSG(n2 > 0, "s2 got %d events", n2);

	tc1 = count_event_id(g1, n1, PROCESS_THREAD_CREATE_ID);
	tc2 = count_event_id(g2, n2, PROCESS_THREAD_CREATE_ID);
	ATF_CHECK_MSG(tc1 > 0, "s1 saw %d THREAD_CREATE events", tc1);
	ATF_CHECK_MSG(tc2 > 0, "s2 saw %d THREAD_CREATE events", tc2);

	ATF_REQUIRE(close(s1) == 0);
	ATF_REQUIRE(close(s2) == 0);
}

ATF_TC(provider_close_unbind_and_rebind);
ATF_TC_HEAD(provider_close_unbind_and_rebind, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Closing the provider fd unbinds it; re-registering rebinds and "
	    "events flow again");
}
ATF_TC_BODY(provider_close_unbind_and_rebind, tc)
{
	const char *pname = "uprov_life";
	struct got_event got[2];
	struct test_event ev;
	uint64_t base;
	int pfd, sfd, n, total;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	total = do_get_providers(sfd, NULL, 8);
	ATF_REQUIRE_EQ_MSG(1, total, "after register: %d", total);

	/* Closing the provider fd destroys and unbinds the provider. */
	ATF_REQUIRE(close(pfd) == 0);
	total = do_get_providers(sfd, NULL, 8);
	ATF_CHECK_EQ_MSG(0, total, "after provider close: %d", total);

	/* The subscriber kept its spec, so re-registering rebinds. */
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	total = do_get_providers(sfd, NULL, 8);
	ATF_CHECK_EQ_MSG(1, total, "after re-register: %d", total);

	base = uptime_us() - 100000;
	ev = (struct test_event){ .ts = base, .event_id = 7, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base, &ev, 1) == 0);
	n = drain_events(sfd, got, 2, 2000);
	ATF_CHECK_EQ_MSG(1, n, "events should flow after rebind, got %d", n);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(streams_auto_allocated);
ATF_TC_HEAD(streams_auto_allocated, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "The subscriber sizes nothing; the kernel allocates a user-stream "
	    "ring buffer on demand for each (provider, stream) that pushes");
}
ATF_TC_BODY(streams_auto_allocated, tc)
{
	const char *pname = "uprov_auto";
	struct eventlog_stats stats;
	struct test_event evs[2];
	struct got_event got[64];
	const int nstreams = 16;
	uint64_t base;
	int pfd[16], sfd, n, s;

	sfd = open_eventlog_or_skip();

	/* No stream sizing is supplied; the default cap is plenty. */
	ATF_REQUIRE(do_create(sfd, 0, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);

	/*
	 * Many same-named provider fds: each is its own ring/stream and the
	 * kernel lazily allocates a user-stream buffer per (provider, stream).
	 * Every push declares the same watermark above all event timestamps so
	 * the merge boundary (the min watermark across live streams) covers
	 * them all and everything is immediately emittable.
	 */
	base = uptime_us() - 100000;
	for (s = 0; s < nstreams; s++) {
		pfd[s] = open_register_provider(pname);
		evs[0] = (struct test_event){ .ts = base + (uint64_t)(2 * s),
		    .event_id = (uint32_t)(s * 10), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
		evs[1] = (struct test_event){ .ts = base + (uint64_t)(2 * s) + 1,
		    .event_id = (uint32_t)(s * 10 + 1), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
		ATF_REQUIRE(do_push(pfd[s], 0, base + 1000, evs, 2) == 0);
	}

	n = drain_events(sfd, got, 64, 3000);
	ATF_CHECK_EQ_MSG(2 * nstreams, n,
	    "expected %d events from %d auto streams, got %d", 2 * nstreams,
	    nstreams, n);
	get_stats(sfd, &stats);
	ATF_CHECK_EQ_MSG(0, (int)stats.user_dropped_late,
	    "no drops expected under the default cap, got %ju",
	    (uintmax_t)stats.user_dropped_late);

	for (s = 0; s < nstreams; s++)
		ATF_REQUIRE(close(pfd[s]) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(stream_cap_exhaustion);
ATF_TC_HEAD(stream_cap_exhaustion, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Streams beyond kern.eventlog.max_user_streams are dropped and "
	    "counted; the cap is sized at subscribe time");
}
ATF_TC_BODY(stream_cap_exhaustion, tc)
{
	const char *pname = "uprov_cap";
	const char *capname = "kern.eventlog.max_user_streams";
	struct eventlog_stats stats;
	struct test_event evs[2];
	struct got_event got[16];
	u_int saved_cap;
	uint64_t base;
	int pfd[4], sfd, n, s;

	sfd = open_eventlog_or_skip();

	/* Lower the cap to 2 *before* subscribing: metadata sizes to it. */
	saved_cap = get_uint_sysctl(capname);
	set_uint_sysctl(capname, 2);

	ATF_REQUIRE(do_create(sfd, 0, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);

	/* Restore immediately; this subscriber already captured cap == 2. */
	set_uint_sysctl(capname, saved_cap);

	/* Four same-named provider fds => four (provider, stream) streams. */
	base = uptime_us() - 100000;
	for (s = 0; s < 4; s++) {
		pfd[s] = open_register_provider(pname);
		evs[0] = (struct test_event){ .ts = base,
		    .event_id = (uint32_t)(s * 10), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
		evs[1] = (struct test_event){ .ts = base + 1,
		    .event_id = (uint32_t)(s * 10 + 1), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
		ATF_REQUIRE(do_push(pfd[s], 0, base + 1, evs, 2) == 0);
	}

	/* Two streams fit (4 events); the other two hit the cap. */
	n = drain_events(sfd, got, 16, 2000);
	ATF_CHECK_EQ_MSG(4, n, "expected 4 events from 2 streams, got %d", n);
	get_stats(sfd, &stats);
	ATF_CHECK_EQ_MSG(4, (int)stats.user_dropped_late,
	    "expected 4 drops (2 over-cap streams), got %ju",
	    (uintmax_t)stats.user_dropped_late);

	for (s = 0; s < 4; s++)
		ATF_REQUIRE(close(pfd[s]) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * A user stream idle past kern.eventlog.user_idle_reclaim_us has its ring
 * buffers reclaimed; a later push on the same (provider, stream) re-allocates
 * lazily and delivers, exercising the alloc -> reclaim -> re-alloc path and
 * the O(1) slot reuse without loss or panic.
 */
ATF_TC(stream_idle_reclaim_and_reuse);
ATF_TC_HEAD(stream_idle_reclaim_and_reuse, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "an idle user stream is reclaimed, then re-allocated on reuse");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(stream_idle_reclaim_and_reuse, tc)
{
	const char *pname = "uprov_reclaim";
	const char *idlename = "kern.eventlog.user_idle_reclaim_us";
	struct test_event ev;
	struct got_event got[8];
	u_long saved_idle;
	uint64_t base;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	/* Short idle window so the stream is reclaimed within the test. */
	saved_idle = get_ulong_sysctl(idlename);
	set_ulong_sysctl(idlename, 200000);	/* 200 ms */

	ATF_REQUIRE(do_create(sfd, 0, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	/* First round: stream 0 allocates a buffer and delivers. */
	base = uptime_us() - 100000;
	ev = (struct test_event){ .ts = base, .event_id = 1, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base, &ev, 1) == 0);
	n = drain_events(sfd, got, 8, 2000);
	ATF_REQUIRE_EQ_MSG(1, n, "first round got %d", n);
	ATF_CHECK_EQ(1u, got[0].event_id);

	/*
	 * Let the stream go idle past the reclaim window.  The reclaim sweep
	 * runs on read/push activity, so keep reading to drive it.
	 */
	usleep(400000);
	n = drain_events(sfd, got, 8, 300);
	ATF_CHECK_EQ_MSG(0, n, "no events expected while idle, got %d", n);

	/*
	 * Second round on the same stream id: must re-allocate and deliver.
	 * Stamp at now. The idle drain may have consumed the bind-time
	 * announcement and advanced the join watermark past a backdated ts.
	 */
	base = uptime_us();
	ev = (struct test_event){ .ts = base, .event_id = 2, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base, &ev, 1) == 0);
	n = drain_events(sfd, got, 8, 2000);
	ATF_REQUIRE_EQ_MSG(1, n, "reuse round got %d", n);
	ATF_CHECK_EQ(2u, got[0].event_id);

	set_ulong_sysctl(idlename, saved_idle);
	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * More than 32 providers can register under the same name (one per fd), and
 * a subscriber that joins afterward binds to all of them -- the old
 * matched[32] cap in add_subscription is gone.  GET_PROVIDERS reports the
 * full set, and an event pushed from every provider is delivered.
 */
ATF_TC(bind_more_than_32_providers);
ATF_TC_HEAD(bind_more_than_32_providers, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a subscriber binds to >32 same-name providers; GET_PROVIDERS "
	    "reports them all and events from each are delivered");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(bind_more_than_32_providers, tc)
{
	const char *pname = "uprov_many";
	const int nprov = 40;
	struct eventlog_provider_info *info;
	struct test_event ev;
	struct got_event *got;
	uint64_t base;
	int pfd[40];
	int sfd, n, i, total;

	sfd = open_eventlog_or_skip();

	for (i = 0; i < nprov; i++) {
		pfd[i] = open(DEV_EVENTLOG, O_RDWR);
		ATF_REQUIRE(pfd[i] >= 0);
		ATF_REQUIRE_MSG(do_register(pfd[i], pname, 1) == 0,
		    "register %d: %s", i, strerror(errno));
	}

	/* Subscribe AFTER all providers exist: add_subscription must bind all. */
	ATF_REQUIRE(do_create(sfd, 0, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);

	info = calloc(nprov + 8, sizeof(*info));
	ATF_REQUIRE(info != NULL);
	total = do_get_providers(sfd, info, nprov + 8);
	ATF_REQUIRE_EQ_MSG(nprov, total,
	    "GET_PROVIDERS should report all %d providers, got %d", nprov,
	    total);

	/*
	 * One event from each provider; all must be delivered (all bound).
	 * A common watermark above every event timestamp keeps the merge
	 * boundary from holding any stream back.
	 */
	base = uptime_us() - 100000;
	for (i = 0; i < nprov; i++) {
		ev = (struct test_event){ .ts = base + (uint64_t)i,
		    .event_id = (uint32_t)(100 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
		/* Distinct stream id per provider so none collide. */
		ATF_REQUIRE(do_push(pfd[i], (uint16_t)i, base + 1000,
		    &ev, 1) == 0);
	}

	got = calloc(nprov, sizeof(*got));
	ATF_REQUIRE(got != NULL);
	n = drain_events(sfd, got, nprov, 5000);
	ATF_CHECK_EQ_MSG(nprov, n,
	    "expected an event from each of %d bound providers, got %d",
	    nprov, n);

	free(got);
	free(info);
	for (i = 0; i < nprov; i++)
		ATF_REQUIRE(close(pfd[i]) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * GET_PROVIDERS uses a capacity-in / total-out protocol: a request with a
 * capacity below the live provider count still reports the true total (so
 * the caller can resize and retry) and fills only up to capacity.
 */
ATF_TC(get_providers_beyond_32);
ATF_TC_HEAD(get_providers_beyond_32, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "GET_PROVIDERS reports >32 providers and honors a short capacity");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(get_providers_beyond_32, tc)
{
	const char *pname = "uprov_count";
	const int nprov = 40;
	struct eventlog_provider_info small[8];
	int pfd[40];
	int sfd, i, total;

	sfd = open_eventlog_or_skip();
	ATF_REQUIRE(do_create(sfd, 0, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);

	for (i = 0; i < nprov; i++) {
		pfd[i] = open(DEV_EVENTLOG, O_RDWR);
		ATF_REQUIRE(pfd[i] >= 0);
		ATF_REQUIRE(do_register(pfd[i], pname, 1) == 0);
	}

	/* A short capacity still returns the full total (capacity-in/total-out). */
	total = do_get_providers(sfd, small, 8);
	ATF_CHECK_EQ_MSG(nprov, total,
	    "short-capacity query should still report total %d, got %d",
	    nprov, total);

	for (i = 0; i < nprov; i++)
		ATF_REQUIRE(close(pfd[i]) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(user_buffer_overflow_drops);
ATF_TC_HEAD(user_buffer_overflow_drops, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Overflowing an undrained user-stream buffer is counted in "
	    "user_dropped_full, not the generic counter");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(user_buffer_overflow_drops, tc)
{
	const char *pname = "uprov_full";
	struct eventlog_stats stats;
	struct test_event evs[6];
	uint8_t *rb;
	char payload[1024];
	uint64_t base, ts;
	int pfd, sfd, p, i;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	/* One stream; user_buffer_size defaults to 512 KiB. */
	ATF_REQUIRE(do_create(sfd, 1, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);

	memset(payload, 0xab, sizeof(payload));
	/*
	 * ~620 KiB of records (100 * 6 * (32 + 1024)) fit in the 1 MiB
	 * submission ring, but a single kernel drain bulk-copies them into the
	 * subscriber's 512 KiB user-stream ring, overflowing it.  Stamp far
	 * in the past so the records are emittable, then the triggering read
	 * below both drains and over-fills the pool.
	 */
	base = uptime_us() - 1000000;
	ts = base;
	for (p = 0; p < 100; p++) {
		for (i = 0; i < 6; i++)
			evs[i] = (struct test_event){ .ts = ts++,
			    .event_id = 1, .keywords = 0x1,
			    .level = EVENTLOG_LEVEL_INFO, .payload = payload,
			    .payload_len = (uint16_t)sizeof(payload) };
		ATF_REQUIRE_MSG(do_push(pfd, 0, ts, evs, 6) == 0,
		    "push %d: %s", p, strerror(errno));
	}

	/*
	 * Nothing has been read yet, so the kernel has not drained the ring.
	 * Reads trigger the drain (globally throttled, so poll a few times)
	 * which floods the undrained user-stream buffer and counts the
	 * overflow.
	 */
	rb = malloc(READ_BUF_SZ);
	ATF_REQUIRE(rb != NULL);
	for (p = 0; p < 10; p++) {
		(void)read(sfd, rb, READ_BUF_SZ);
		usleep(10000);
	}
	free(rb);

	get_stats(sfd, &stats);
	ATF_CHECK_MSG(stats.user_dropped_full > 0,
	    "expected user_dropped_full > 0, got %ju",
	    (uintmax_t)stats.user_dropped_full);
	/* Pure user-stream traffic, so no real-CPU drops should be counted. */
	ATF_CHECK_EQ_MSG(0, (int)stats.dropped_events,
	    "expected 0 generic drops, got %ju",
	    (uintmax_t)stats.dropped_events);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(late_join_arming);
ATF_TC_HEAD(late_join_arming, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A stream that joins after the consumer advanced drops its "
	    "pre-join events, stays held until armed, then delivers");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(late_join_arming, tc)
{
	const char *pname = "uprov_join";
	struct eventlog_stats stats;
	struct test_event b1[4], prejoin[3], good[4];
	struct got_event got[16];
	struct fd_ring extra;
	uint16_t pid;
	uint64_t base, join_wc;
	int pfd, sfd, n, i;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	pid = (pfd >= 0 && pfd < FD_PROVIDER_MAX) ? fd_provider_id[pfd] : 0;

	/*
	 * Stream 0 establishes the consumer watermark.  After this read the
	 * consumer has been delivered everything up to base+3, so a stream
	 * that joins now will use base+3 as its join point.
	 */
	base = uptime_us() - 100000;
	for (i = 0; i < 4; i++)
		b1[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .event_id = (uint32_t)i, .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base + 3, b1, 4) == 0);
	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(4, n, "stream 0 drain got %d", n);
	join_wc = base + 3;

	/*
	 * A second live ring on this fd (stream_id 2) joins unarmed.  These
	 * records predate the join point and must be dropped as pre-join;
	 * with the stream's watermark left below the join point it also
	 * stays unarmed, so nothing is emitted.
	 */
	memset(&extra, 0, sizeof(extra));
	ATF_REQUIRE(ring_setup_extra(pfd, &extra) == 0);
	ATF_CHECK_EQ((uint16_t)(EVENTLOG_DUMP_STREAM_ID + 1),
	    extra.hdr->stream_id);
	for (i = 0; i < 3; i++)
		prejoin[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .event_id = (uint32_t)(90 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push_on(&extra, pid, base + 2, prejoin, 3) == 0);
	n = drain_events(sfd, got, 16, 500);
	ATF_CHECK_EQ_MSG(0, n, "unarmed stream should deliver nothing, got %d",
	    n);
	get_stats(sfd, &stats);
	ATF_CHECK_EQ_MSG(3, (int)stats.user_dropped_prejoin,
	    "expected 3 pre-join drops, got %ju",
	    (uintmax_t)stats.user_dropped_prejoin);

	/*
	 * Now the stream catches up to the join point: records at exactly
	 * the join watermark arm the stream and become emittable (stream 0's
	 * watermark, also base+3, is the merged boundary).
	 */
	for (i = 0; i < 4; i++)
		good[i] = (struct test_event){ .ts = join_wc,
		    .event_id = (uint32_t)(93 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push_on(&extra, pid, join_wc, good, 4) == 0);
	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(4, n, "armed stream should deliver 4, got %d", n);
	for (i = 0; i < 4 && i < n; i++)
		ATF_CHECK_EQ_MSG((uint32_t)(93 + i), got[i].event_id,
		    "post-arm event %d", i);
	/* No additional pre-join drops from the good batch. */
	get_stats(sfd, &stats);
	ATF_CHECK_EQ_MSG(3, (int)stats.user_dropped_prejoin,
	    "pre-join count should be unchanged, got %ju",
	    (uintmax_t)stats.user_dropped_prejoin);

	ATF_REQUIRE(munmap(extra.hdr, extra.maplen) == 0);
	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * REPORT_STATS round-trip: the kernel folds a producer's reported
 * created/active/enabled gauges into kern.eventlog.<name>.* as deltas from
 * the fd's last report, and backs the contribution out when the provider
 * closes.  Two registrations share the stats node so it survives the first
 * close (a lone provider's sysctl is freed with it).
 */
ATF_TC(report_stats_roundtrip);
ATF_TC_HEAD(report_stats_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "REPORT_STATS folds created/active/enabled into the sysctls as "
	    "deltas and backs gauges out on provider close");
}
ATF_TC_BODY(report_stats_roundtrip, tc)
{
	const char *pname = "uprov_stats";
	char mib_created[128], mib_active[128], mib_enabled[128];
	_Alignas(uint64_t) uint8_t buf[
	    __builtin_offsetof(struct eventlog_report_stats_req, stats) +
	    sizeof(struct eventlog_provider_stat)];
	struct eventlog_report_stats_req *req = (void *)buf;
	struct eventlog_provider_stat *ps = &req->stats[0];
	uint64_t created0, active0, enabled0;
	int pfd, hold;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 0) == 0, "register: %s",
	    strerror(errno));
	/* Keep a second handle so the shared sysctl node outlives pfd. */
	hold = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(hold, pname, 0) == 0, "register hold: %s",
	    strerror(errno));

	snprintf(mib_created, sizeof(mib_created),
	    "kern.eventlog.%s.sessions_created", pname);
	snprintf(mib_active, sizeof(mib_active),
	    "kern.eventlog.%s.sessions_active", pname);
	snprintf(mib_enabled, sizeof(mib_enabled),
	    "kern.eventlog.%s.sessions_enabled", pname);
	created0 = get_u64_sysctl(mib_created);
	active0 = get_u64_sysctl(mib_active);
	enabled0 = get_u64_sysctl(mib_enabled);

	memset(req, 0, sizeof(buf));
	req->count = 1;
	ps->provider_id = fd_provider_id[pfd];
	ps->sessions_created = 7;
	ps->sessions_active = 5;
	ps->sessions_enabled = 3;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_REPORT_STATS_SIZE(1),
	    req) == 0, "REPORT_STATS: %s", strerror(errno));

	ATF_CHECK_EQ_MSG(created0 + 7, get_u64_sysctl(mib_created),
	    "sessions_created did not move by +7");
	ATF_CHECK_EQ_MSG(active0 + 5, get_u64_sysctl(mib_active),
	    "sessions_active did not move by +5");
	ATF_CHECK_EQ_MSG(enabled0 + 3, get_u64_sysctl(mib_enabled),
	    "sessions_enabled did not move by +3");

	/* A second report folds only the delta since the first. */
	ps->sessions_created = 9;
	ps->sessions_active = 4;
	ps->sessions_enabled = 2;
	ATF_REQUIRE(ioctl(pfd, EVENTLOG_IOCTL_REPORT_STATS_SIZE(1),
	    req) == 0);

	ATF_CHECK_EQ(created0 + 9, get_u64_sysctl(mib_created));
	ATF_CHECK_EQ(active0 + 4, get_u64_sysctl(mib_active));
	ATF_CHECK_EQ(enabled0 + 2, get_u64_sysctl(mib_enabled));

	/* Close backs out this fd's active/enabled gauges; created stays. */
	ATF_REQUIRE(close(pfd) == 0);
	ATF_CHECK_EQ(created0 + 9, get_u64_sysctl(mib_created));
	ATF_CHECK_EQ(active0, get_u64_sysctl(mib_active));
	ATF_CHECK_EQ(enabled0, get_u64_sysctl(mib_enabled));

	ATF_REQUIRE(close(hold) == 0);
}

/*
 * A user stream that joins after the subscriber has already been reading
 * must be discovered even though the read-side sweeps now scan only the
 * live user_active[] permutation, not the full user_stream_cap tail.  The
 * join activates a slot (user_stream_active 0 -> 1) mid-stream; if the
 * resweep/discovery still walked only dead slots the new stream's events
 * would never be folded into the merge.  This is the live-scan counterpart
 * to late_join_arming's watermark protocol.
 */
ATF_TC(late_join_discovered_live_scan);
ATF_TC_HEAD(late_join_discovered_live_scan, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A user stream joining mid-read is discovered by the live-only "
	    "source scan and merged in order");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(late_join_discovered_live_scan, tc)
{
	const char *pname = "uprov_livescan";
	struct test_event a[4], b[4];
	struct got_event got[16];
	uint64_t base;
	int pfd_a, pfd_b, sfd, n, i, j;

	sfd = open_eventlog_or_skip();
	pfd_a = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd_a >= 0);
	pfd_b = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd_b >= 0);

	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd_a, pname, 1) == 0);
	ATF_REQUIRE(do_register(pfd_b, pname, 1) == 0);

	/* Stream A establishes the consumer watermark and is drained, so the
	 * merge heap has seen a read with only stream A live. */
	base = uptime_us() - 100000;
	for (i = 0; i < 4; i++)
		a[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .event_id = (uint32_t)i, .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd_a, 0, base + 3, a, 4) == 0);
	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(4, n, "stream A drain got %d", n);

	/* Stream B joins now (activates a fresh user slot) with events at or
	 * after the join point so they arm and become emittable. */
	for (j = 0; j < 4; j++)
		b[j] = (struct test_event){ .ts = base + 3,
		    .event_id = (uint32_t)(100 + j), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd_b, 0, base + 3, b, 4) == 0);
	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(4, n,
	    "late-joining stream B should deliver 4, got %d", n);
	for (j = 0; j < 4 && j < n; j++)
		ATF_CHECK_EQ_MSG((uint32_t)(100 + j), got[j].event_id,
		    "stream B event %d", j);

	ATF_REQUIRE(close(pfd_a) == 0);
	ATF_REQUIRE(close(pfd_b) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * The control channel reports a 0<->N subscriber transition to a user
 * provider: the first subscriber yields SUBSCRIBERS_CHANGED value=1, and the
 * last one leaving yields value=0.  A push-only mmap gate cannot express
 * this edge, so the producer's WAIT_CONTROL is the only way it learns.
 */
ATF_TC(control_subscribers_changed);
ATF_TC_HEAD(control_subscribers_changed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "WAIT_CONTROL reports the 0<->N subscriber transition");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(control_subscribers_changed, tc)
{
	const char *pname = "uprov_subs";
	struct eventlog_control_event evs[8];
	int pfd, sfd, n, idx;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 0) == 0, "register: %s",
	    strerror(errno));

	/* No subscribers yet: WAIT_CONTROL just times out empty. */
	n = wait_control(pfd, evs, 8, 300);
	ATF_CHECK_EQ_MSG(0, n, "unexpected control event before subscribe");

	/* First subscriber: 0 -> 1 transition. */
	sfd = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u, 0)
	    == 0, "create: %s", strerror(errno));

	n = wait_control(pfd, evs, 8, 2000);
	idx = find_control(evs, n, EVENTLOG_CONTROL_SUBSCRIBERS_CHANGED);
	ATF_REQUIRE_MSG(idx >= 0, "no SUBSCRIBERS_CHANGED after subscribe");
	ATF_CHECK_EQ_MSG(1, evs[idx].value, "expected has_subscribers=1");
	ATF_CHECK_EQ(fd_provider_id[pfd], evs[idx].provider_id);

	/* Last subscriber leaving: 1 -> 0 transition. */
	ATF_REQUIRE(close(sfd) == 0);
	n = wait_control(pfd, evs, 8, 2000);
	idx = find_control(evs, n, EVENTLOG_CONTROL_SUBSCRIBERS_CHANGED);
	ATF_REQUIRE_MSG(idx >= 0, "no SUBSCRIBERS_CHANGED after unsubscribe");
	ATF_CHECK_EQ_MSG(0, evs[idx].value, "expected has_subscribers=0");

	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * Writing kern.eventlog.<name>.default posts a DEFAULT_CHANGED control event
 * carrying the raw sysctl value to a user provider, mirroring the in-kernel
 * default_changed callback.
 */
ATF_TC(control_default_changed);
ATF_TC_HEAD(control_default_changed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a default-tunable change is reported via WAIT_CONTROL");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(control_default_changed, tc)
{
	const char *pname = "uprov_defchg";
	char oid[64];
	struct eventlog_control_event evs[8];
	int pfd, n, idx;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 0) == 0, "register: %s",
	    strerror(errno));

	snprintf(oid, sizeof(oid), "kern.eventlog.%s.default", pname);
	/* 2 means "enable all sessions, then settle at 1": a distinct value. */
	set_uint_sysctl(oid, 2);

	n = wait_control(pfd, evs, 8, 2000);
	idx = find_control(evs, n, EVENTLOG_CONTROL_DEFAULT_CHANGED);
	ATF_REQUIRE_MSG(idx >= 0, "no DEFAULT_CHANGED after sysctl write");
	ATF_CHECK_EQ_MSG(2, evs[idx].value, "raw sysctl value should pass through");
	ATF_CHECK_EQ(fd_provider_id[pfd], evs[idx].provider_id);

	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * The full out-of-process state-dump path: a subscriber that joins with
 * DUMP_STATE causes a DUMP_REQUEST naming it; the producer replays state via
 * PUSH_DUMP scoped to that subscriber, then DUMP_DONE synthesises a
 * DUMP_COMPLETE.  A second, plain subscriber must see none of the replay.
 */
ATF_TC(dump_request_routed_to_subscriber);
ATF_TC_HEAD(dump_request_routed_to_subscriber, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "DUMP_STATE drives DUMP_REQUEST/PUSH_DUMP/DUMP_DONE, scoped to the "
	    "requesting subscriber");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(dump_request_routed_to_subscriber, tc)
{
	const char *pname = "uprov_dump";
	struct eventlog_control_event cev[8];
	struct test_event dvs[3];
	struct got_event g1[16], g2[8];
	uint64_t base, sub_id;
	int pfd, s1, s2, n, idx, i, complete;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0, "register: %s",
	    strerror(errno));

	/* s1 wants a state replay; s2 is an ordinary live subscriber. */
	s1 = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(s1 >= 0);
	ATF_REQUIRE_MSG(do_create(s1, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE) == 0, "create s1: %s",
	    strerror(errno));
	s2 = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(s2 >= 0);
	ATF_REQUIRE_MSG(do_create(s2, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u, 0)
	    == 0, "create s2: %s", strerror(errno));

	/* The producer learns of the dump request and its target subscriber. */
	n = wait_control(pfd, cev, 8, 2000);
	idx = find_control(cev, n, EVENTLOG_CONTROL_DUMP_REQUEST);
	ATF_REQUIRE_MSG(idx >= 0, "no DUMP_REQUEST after DUMP_STATE subscribe");
	sub_id = cev[idx].subscriber_id;
	ATF_CHECK(sub_id != 0);
	ATF_CHECK_EQ(fd_provider_id[pfd], cev[idx].provider_id);

	/* Replay three state records to that subscriber only. */
	base = uptime_us() - 100000;
	for (i = 0; i < 3; i++)
		dvs[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .session_id = (uint64_t)(0x500 + i),
		    .event_id = (uint32_t)(700 + i), .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE_MSG(do_push_dump(pfd, sub_id, 0, base + 3, dvs, 3) == 0,
	    "push_dump: %s", strerror(errno));
	ATF_REQUIRE_MSG(do_dump_done(pfd, sub_id, fd_provider_id[pfd]) == 0,
	    "dump_done: %s", strerror(errno));

	/* s1 sees the three replayed records plus a DUMP_COMPLETE. */
	n = drain_events_accum(s1, g1, 16, 4, 3000);
	ATF_REQUIRE_EQ_MSG(4, n, "expected 3 dump records + DUMP_COMPLETE, got %d",
	    n);
	complete = 0;
	for (i = 0; i < n; i++)
		if (g1[i].event_id == EVENTLOG_DUMP_COMPLETE_ID) {
			complete++;
			ATF_CHECK_EQ(EVENTLOG_SESSION_ID_NONE, g1[i].session_id);
		}
	ATF_CHECK_EQ_MSG(1, complete, "expected exactly one DUMP_COMPLETE");

	/* s2 saw nothing: the replay was scoped to s1. */
	n = drain_events(s2, g2, 8, 500);
	ATF_CHECK_EQ_MSG(0, n, "plain subscriber should not see the dump, got %d",
	    n);

	ATF_REQUIRE(close(s1) == 0);
	ATF_REQUIRE(close(s2) == 0);
	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * A DUMP_STATE subscriber leaves an outstanding dump owed by the provider.
 * Closing the provider fd must cancel that obligation so the subscriber's
 * own teardown (which drains outstanding dumps) does not block forever.
 */
ATF_TC(dump_cancelled_on_provider_close);
ATF_TC_HEAD(dump_cancelled_on_provider_close, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "closing a provider with an unanswered dump request cancels it so "
	    "the subscriber does not hang on close");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(dump_cancelled_on_provider_close, tc)
{
	const char *pname = "uprov_dcancel";
	struct eventlog_control_event cev[8];
	int pfd, sfd, n, idx;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0, "register: %s",
	    strerror(errno));

	sfd = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE) == 0, "create: %s",
	    strerror(errno));

	/* Confirm the request reached the producer, then ignore it. */
	n = wait_control(pfd, cev, 8, 2000);
	idx = find_control(cev, n, EVENTLOG_CONTROL_DUMP_REQUEST);
	ATF_REQUIRE_MSG(idx >= 0, "no DUMP_REQUEST queued");

	/* Provider goes away without DUMP_DONE; teardown must cancel it. */
	ATF_REQUIRE(close(pfd) == 0);
	/* Would block here if the dump were not cancelled (test times out). */
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * The mirror case: the subscriber leaves first, while a dump it requested is
 * still outstanding.  Its own teardown must cancel the request rather than
 * wait on a producer that will never answer.
 */
ATF_TC(dump_cancelled_on_subscriber_close);
ATF_TC_HEAD(dump_cancelled_on_subscriber_close, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a subscriber closing with its own dump still outstanding does not "
	    "hang");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(dump_cancelled_on_subscriber_close, tc)
{
	const char *pname = "uprov_scancel";
	int pfd, sfd;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0, "register: %s",
	    strerror(errno));

	sfd = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE) == 0, "create: %s",
	    strerror(errno));

	/* Close the subscriber before the producer answers: must not hang. */
	ATF_REQUIRE(close(sfd) == 0);
	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * Input validation for the new provider ioctls: a dump-target of zero is
 * rejected, and the control/dump ioctls are provider-only.
 */
ATF_TC(dump_ioctl_validation);
ATF_TC_HEAD(dump_ioctl_validation, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "PUSH_DUMP/DUMP_DONE reject a zero target; control ioctls are "
	    "provider-only");
}
ATF_TC_BODY(dump_ioctl_validation, tc)
{
	const char *pname = "uprov_dumpval";
	struct test_event ev = { .ts = 1, .event_id = 1, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	struct eventlog_wait_control_req wreq;
	int pfd, sfd;

	pfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0, "register: %s",
	    strerror(errno));

	/* Zero dump target is rejected. */
	ATF_REQUIRE_ERRNO(EINVAL, do_push_dump(pfd, 0, 0, 1, &ev, 1) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    do_dump_done(pfd, 0, fd_provider_id[pfd]) == -1);

	/* Provider-only ioctls are refused on a subscriber fd. */
	sfd = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u, 0)
	    == 0, "create: %s", strerror(errno));
	memset(&wreq, 0, sizeof(wreq));
	wreq.timeout_us = 0;
	wreq.count = 1;
	ATF_REQUIRE_ERRNO(EINVAL,
	    ioctl(sfd, EVENTLOG_IOCTL_WAIT_CONTROL_SIZE(1), &wreq) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, do_dump_done(sfd, 1, 1) == -1);

	ATF_REQUIRE(close(sfd) == 0);
	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * Records that do not divide the ring size straddle the physical wrap once
 * enough bytes have been written; the kernel linearises each straddling
 * record on drain, so every event must arrive intact and in order even as
 * head/tail wrap several times.
 */
ATF_TC(ring_wrap_straddle);
ATF_TC_HEAD(ring_wrap_straddle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Records straddling the ring's physical wrap are delivered intact");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(ring_wrap_straddle, tc)
{
	const char *pname = "uprov_wrap";
	struct got_event *got;
	const int nrec = 3000, batch = 32;
	uint64_t base;
	int pfd, sfd, total, i;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));

	/*
	 * 48-byte records (40-byte header + 4-byte payload, rounded) do not
	 * divide the 64 KB ring, so pushing well over one ring's worth -- with
	 * reads draining tail between batches -- forces records to straddle the
	 * physical wrap repeatedly.
	 */
	got = calloc(nrec, sizeof(*got));
	ATF_REQUIRE(got != NULL);

	base = uptime_us() - 5000000;
	total = 0;
	for (i = 0; i < nrec; ) {
		struct test_event evs[32];
		uint32_t plbuf[32];
		int k = (nrec - i < batch) ? nrec - i : batch;
		int j;

		for (j = 0; j < k; j++) {
			plbuf[j] = (uint32_t)(i + j);
			evs[j] = (struct test_event){
			    .ts = base + (uint64_t)(i + j),
			    .session_id = 0x5000 + (uint64_t)(i + j),
			    .event_id = (uint32_t)(i + j),
			    .keywords = 0x1, .thread_id = 7,
			    .level = EVENTLOG_LEVEL_INFO,
			    .payload = &plbuf[j],
			    .payload_len = sizeof(plbuf[j]),
			};
		}
		ATF_REQUIRE_MSG(do_push(pfd, 0, base + (uint64_t)(i + k), evs,
		    (uint32_t)k) == 0, "push at %d: %s", i, strerror(errno));
		i += k;
		total += drain_events(sfd, got + total, nrec - total, 1000);
	}
	/* Final sweep for whatever the last watermark released. */
	total += drain_events(sfd, got + total, nrec - total, 2000);

	ATF_REQUIRE_EQ_MSG(nrec, total, "expected %d events, got %d", nrec,
	    total);
	for (i = 0; i < nrec; i++) {
		uint32_t idx = 0;

		ATF_CHECK_EQ_MSG(base + (uint64_t)i, got[i].timestamp,
		    "event %d timestamp", i);
		ATF_CHECK_EQ_MSG((uint32_t)i, got[i].event_id, "event %d id", i);
		memcpy(&idx, got[i].payload, sizeof(idx));
		ATF_CHECK_EQ_MSG((uint32_t)i, idx, "event %d payload", i);
	}
	free(got);
	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * With no subscriber draining it, a producer's ring fills and further writes
 * are dropped and counted in the shared header rather than corrupting the
 * stream.
 */
ATF_TC(ring_full_drops);
ATF_TC_HEAD(ring_full_drops, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A ring that fills (no drain) drops and counts further writes");
}
ATF_TC_BODY(ring_full_drops, tc)
{
	const char *pname = "uprov_ringfull";
	struct eventlog_ring_hdr *hdr;
	struct test_event ev;
	uint32_t recsz;
	int pfd, i, full_at = -1;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	pfd = open(DEV_EVENTLOG, O_RDWR);
	if (pfd < 0) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		atf_tc_fail("open(%s): %s", DEV_EVENTLOG, strerror(errno));
	}
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));
	hdr = fd_ring[pfd].hdr;
	recsz = sizeof(struct eventlog_push_record);

	/* No subscriber exists, so the kernel never advances tail. */
	ev = (struct test_event){ .event_id = 1, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	for (i = 0; i < 1000000; i++) {
		ev.ts = (uint64_t)i + 1;
		if (do_push(pfd, 0, ev.ts, &ev, 1) != 0) {
			ATF_CHECK_EQ_MSG(ENXIO, errno,
			    "unexpected errno %d on full ring", errno);
			full_at = i;
			break;
		}
	}
	ATF_REQUIRE_MSG(full_at > 0, "ring never reported full");
	ATF_CHECK_MSG(hdr->dropped > 0, "expected drop accounting, got %ju",
	    (uintmax_t)hdr->dropped);
	/* The ring held about one capacity's worth of fixed-size records. */
	ATF_CHECK_MSG((uint64_t)(full_at + 2) * recsz >= fd_ring[pfd].size,
	    "filled at %d records (%u bytes) for a %u-byte ring", full_at,
	    (uint32_t)((uint64_t)full_at * recsz), fd_ring[pfd].size);
	ATF_CHECK_MSG((uint64_t)full_at * recsz <= fd_ring[pfd].size,
	    "ring accepted more than its capacity (%d records)", full_at);

	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * A hostile/buggy producer that publishes a head far past the ring must not
 * make the kernel read out of bounds: the drain discards the bogus range,
 * resyncs tail to head, and the channel keeps working for honest writes.
 */
ATF_TC(garbage_head_clamped);
ATF_TC_HEAD(garbage_head_clamped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A garbage producer head is clamped/discarded without corruption");
}
ATF_TC_BODY(garbage_head_clamped, tc)
{
	const char *pname = "uprov_garbage";
	struct eventlog_ring_hdr *hdr;
	struct test_event ev;
	struct got_event got[8];
	uint64_t base;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));
	hdr = fd_ring[pfd].hdr;

	/* Publish head - tail > size: nothing in the ring can back it. */
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->head,
	    (uint64_t)fd_ring[pfd].size * 4, memory_order_release);

	n = drain_events(sfd, got, 8, 500);
	ATF_CHECK_EQ_MSG(0, n, "garbage head delivered %d events", n);
	ATF_CHECK_EQ_MSG(hdr->head, hdr->tail,
	    "kernel should resync tail to head (head=%ju tail=%ju)",
	    (uintmax_t)hdr->head, (uintmax_t)hdr->tail);

	/*
	 * The channel recovers: an honest push after the resync is delivered.
	 * Stamp at now so the record stays at or ahead of the join watermark
	 * the announcement drain just published.
	 */
	base = uptime_us();
	ev = (struct test_event){ .ts = base, .event_id = 42, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base, &ev, 1) == 0);
	n = drain_events(sfd, got, 8, 2000);
	ATF_REQUIRE_EQ_MSG(1, n, "post-resync push delivered %d events", n);
	ATF_CHECK_EQ(42u, got[0].event_id);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * A producer that scribbles the shared ring header's data_offset/data_size
 * (both live in the header it maps read/write) must not steer the kernel
 * drain outside the ring.  A pre-fix kernel added hdr->data_offset to
 * ring_kva and could read ~1 GB out of bounds; the kernel now drains from its
 * own cached geometry, so honest records still decode and nothing panics.
 */
ATF_TC(tampered_ring_geometry_contained);
ATF_TC_HEAD(tampered_ring_geometry_contained, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A tampered ring-header data_offset/data_size cannot force an "
	    "out-of-bounds kernel read; honest records still deliver");
}
ATF_TC_BODY(tampered_ring_geometry_contained, tc)
{
	const char *pname = "uprov_tampergeo";
	struct eventlog_ring_hdr *hdr;
	struct test_event evs[8];
	struct got_event got[16];
	uint64_t base;
	int pfd, sfd, n, i;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));
	hdr = fd_ring[pfd].hdr;

	/* Publish honest records at the real data offset. */
	base = uptime_us() - 100000;
	for (i = 0; i < 8; i++) {
		evs[i] = (struct test_event){ .ts = base + (uint64_t)i,
		    .session_id = 1, .event_id = 600 + i, .keywords = 0x1,
		    .thread_id = 1, .level = EVENTLOG_LEVEL_INFO };
	}
	ATF_REQUIRE(do_push(pfd, 0, base + 8, evs, 8) == 0);

	/* Scribble the geometry fields the producer can reach in the header. */
	hdr->data_offset = 0x40000000u;
	hdr->data_size = 0xdeadbeefu;

	/* Kick: the kernel drains synchronously from its cached geometry. */
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_KICK) == 0,
	    "KICK: %s", strerror(errno));
	ATF_CHECK_MSG(hdr->tail == hdr->head,
	    "kick did not drain ring (head=%ju tail=%ju)",
	    (uintmax_t)hdr->head, (uintmax_t)hdr->tail);

	/* Every honest record decoded correctly despite the tampering. */
	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(8, n, "expected 8 events after tamper+kick, got %d",
	    n);
	for (i = 0; i < n; i++)
		ATF_CHECK_MSG(got[i].event_id >= 600 && got[i].event_id <= 607,
		    "unexpected event id %u (tampered geometry leaked wrong "
		    "bytes)", got[i].event_id);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * The producer issues no submit syscall, yet a blocked subscriber read() is
 * woken and delivered the event by the kernel's lazy drain poll.
 */
ATF_TC(drain_wakes_blocked_reader);
ATF_TC_HEAD(drain_wakes_blocked_reader, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A blocked reader is woken by the poll drain with zero producer "
	    "submit syscalls");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(drain_wakes_blocked_reader, tc)
{
	const char *pname = "uprov_pollwake";
	struct eventlog_event_header ehdr;
	struct test_event ev;
	uint64_t base;
	uint8_t buf[256];
	ssize_t r;
	int pfd, sfd;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	/* A blocking subscriber fd: read() sleeps until the drain delivers. */
	sfd = open(DEV_EVENTLOG, O_RDONLY);
	if (sfd < 0) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		atf_tc_fail("open(%s): %s", DEV_EVENTLOG, strerror(errno));
	}
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));

	/* Stamp in the past so the emit boundary has already crossed it. */
	base = uptime_us() - 100000;
	ev = (struct test_event){ .ts = base, .event_id = 77, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ATF_REQUIRE(do_push(pfd, 0, base + 1, &ev, 1) == 0);

	/* No ioctl/flush from the producer: only the kernel poll delivers. */
	r = read(sfd, buf, sizeof(buf));
	ATF_REQUIRE_MSG(r >= (ssize_t)sizeof(ehdr),
	    "blocked read returned %zd (%s)", r, strerror(errno));
	memcpy(&ehdr, buf, sizeof(ehdr));
	ATF_CHECK_EQ_MSG(77u, ehdr.event_id, "delivered event id %u",
	    ehdr.event_id);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * The kernel publishes EVENTLOG_RING_F_CONSUMER_PRESENT into a provider's ring
 * header so the producer can gate its high-water drain kick: clear with no
 * subscriber, set once one binds, clear again when it leaves.
 */
ATF_TC(kick_consumer_flag_published);
ATF_TC_HEAD(kick_consumer_flag_published, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "CONSUMER_PRESENT ring flag tracks whether a subscriber is bound");
}
ATF_TC_BODY(kick_consumer_flag_published, tc)
{
	const char *pname = "uprov_consflag";
	struct eventlog_ring_hdr *hdr;
	int pfd, sfd, i;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));
	hdr = fd_ring[pfd].hdr;

	/* No subscriber yet: the flag must be clear. */
	ATF_CHECK_MSG((hdr->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0,
	    "consumer flag set with no subscriber (flags=0x%x)", hdr->flags);

	/* Bind a subscriber: the 0->1 transition sets the flag. */
	sfd = open_eventlog_or_skip();
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_CHECK_MSG((hdr->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) != 0,
	    "consumer flag not set after subscribe (flags=0x%x)", hdr->flags);

	/* Drop the subscriber: the 1->0 transition clears it (allow the
	 * close-side teardown a moment to publish). */
	ATF_REQUIRE(close(sfd) == 0);
	for (i = 0; i < 50; i++) {
		if ((hdr->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0)
			break;
		usleep(20000);
	}
	ATF_CHECK_MSG((hdr->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0,
	    "consumer flag still set after subscriber closed (flags=0x%x)",
	    hdr->flags);

	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * EVENTLOG_IOCTL_KICK drains the producer's ring immediately: tail catches up
 * to head (freeing space, the drop-avoidance path) and the records reach the
 * subscriber -- without relying on the periodic poll.
 */
ATF_TC(kick_drains_ring);
ATF_TC_HEAD(kick_drains_ring, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "EVENTLOG_IOCTL_KICK drains the ring and frees space on demand");
}
ATF_TC_BODY(kick_drains_ring, tc)
{
	const char *pname = "uprov_kickdrain";
	struct eventlog_ring_hdr *hdr;
	struct test_event evs[8];
	struct got_event got[16];
	uint64_t base;
	int pfd, sfd, n, i;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));
	hdr = fd_ring[pfd].hdr;

	base = uptime_us() - 100000;
	for (i = 0; i < 8; i++) {
		evs[i].ts = base + (uint64_t)i;
		evs[i].session_id = 1;
		evs[i].event_id = 500 + i;
		evs[i].keywords = 0x1;
		evs[i].thread_id = 1;
		evs[i].level = EVENTLOG_LEVEL_INFO;
		evs[i].payload = NULL;
		evs[i].payload_len = 0;
	}
	ATF_REQUIRE(do_push(pfd, 0, base + 8, evs, 8) == 0);

	/* Data is published but not yet consumed: head is ahead of tail. */
	ATF_REQUIRE_MSG(hdr->head > hdr->tail,
	    "ring should hold pending data (head=%ju tail=%ju)",
	    (uintmax_t)hdr->head, (uintmax_t)hdr->tail);

	/* Kick: the kernel drains synchronously, advancing tail to head. */
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_KICK) == 0,
	    "KICK: %s", strerror(errno));
	ATF_CHECK_MSG(hdr->tail == hdr->head,
	    "kick did not drain ring (head=%ju tail=%ju)",
	    (uintmax_t)hdr->head, (uintmax_t)hdr->tail);

	/* The drained records reached the subscriber. */
	n = drain_events(sfd, got, 16, 2000);
	ATF_REQUIRE_EQ_MSG(8, n, "expected 8 events after kick, got %d", n);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/* Interrupt a blocked read() so a failed wake fails the test fast. */
static void
kick_sigalrm(int sig __unused)
{
}

/*
 * A kick wakes a reader that is already blocked: with the periodic poll set
 * far longer than the test, only EVENTLOG_IOCTL_KICK can deliver in time.  A
 * producer child writes one record and kicks after the parent has entered its
 * blocking read(); an alarm bounds the wait so a broken kick fails rather than
 * waiting out the poll.
 */
ATF_TC(kick_wakes_blocked_reader);
ATF_TC_HEAD(kick_wakes_blocked_reader, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "EVENTLOG_IOCTL_KICK wakes a blocked reader before the poll fires");
	atf_tc_set_md_var(tc, "timeout", "40");
}
ATF_TC_BODY(kick_wakes_blocked_reader, tc)
{
	const char *pname = "uprov_kickwake";
	struct sigaction sa;
	struct eventlog_event_header ehdr;
	u_long saved_poll;
	uint8_t buf[256];
	int pfd, sfd, sync_pipe[2], status, saved_errno;
	ssize_t r;
	pid_t pid;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");

	/*
	 * Make the periodic drain poll effectively never fire during the
	 * test so a successful read can only be the kick's doing.
	 */
	saved_poll = get_ulong_sysctl("kern.eventlog.user_drain_poll_us");
	set_ulong_sysctl("kern.eventlog.user_drain_poll_us", 20000000);

	sfd = open(DEV_EVENTLOG, O_RDONLY);	/* blocking */
	ATF_REQUIRE(sfd >= 0);
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0);
	ATF_REQUIRE(do_register(pfd, pname, 1) == 0);
	ATF_REQUIRE_MSG(ring_setup(pfd) == 0, "ring setup: %s",
	    strerror(errno));

	/*
	 * Drop the bind-time announcement before the blocking read, so that
	 * read waits for the kicked user event. The announcement is stamped
	 * at now and stays behind the emit boundary for a few microseconds.
	 */
	{
		int fl = fcntl(sfd, F_GETFL);
		int spins = 0;

		ATF_REQUIRE(fl >= 0);
		ATF_REQUIRE(fcntl(sfd, F_SETFL, fl | O_NONBLOCK) == 0);
		for (;;) {
			r = read(sfd, buf, sizeof(buf));
			if (r < 0 && errno == EAGAIN) {
				if (spins++ > 50)
					break;
				usleep(1000);
				continue;
			}
			ATF_REQUIRE_MSG(r >= (ssize_t)sizeof(ehdr),
			    "draining announcement: r=%zd", r);
			memcpy(&ehdr, buf, sizeof(ehdr));
			ATF_REQUIRE_MSG(
			    ehdr.event_id == EVENTLOG_PROVIDER_INFO_ID ||
			    ehdr.event_id == EVENTLOG_PROVIDER_BLOB_ID,
			    "unexpected event %#x before kick", ehdr.event_id);
			spins = 0;
		}
		ATF_REQUIRE(fcntl(sfd, F_SETFL, fl) == 0);
	}
	ATF_REQUIRE(pipe(sync_pipe) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct test_event ev;
		char b;

		(void)close(sync_pipe[1]);
		/* Wait for the parent to be about to block, then give it a
		 * beat to actually reach the sleep before publishing. */
		(void)read(sync_pipe[0], &b, 1);
		usleep(300000);
		ev = (struct test_event){ .ts = uptime_us(),
		    .event_id = 91, .keywords = 0x1,
		    .level = EVENTLOG_LEVEL_INFO };
		(void)do_push(pfd, 0, ev.ts, &ev, 1);
		(void)ioctl(pfd, EVENTLOG_IOCTL_KICK);
		_exit(0);
	}
	(void)close(sync_pipe[0]);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = kick_sigalrm;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGALRM, &sa, NULL);
	(void)write(sync_pipe[1], "x", 1);
	alarm(10);
	r = read(sfd, buf, sizeof(buf));
	saved_errno = errno;
	alarm(0);
	(void)waitpid(pid, &status, 0);

	/* Restore the sysctl before asserting so a failure cannot leak it. */
	set_ulong_sysctl("kern.eventlog.user_drain_poll_us", saved_poll);

	ATF_REQUIRE_MSG(r >= (ssize_t)sizeof(ehdr),
	    "kick did not wake blocked reader: r=%zd (%s)", r,
	    strerror(saved_errno));
	memcpy(&ehdr, buf, sizeof(ehdr));
	ATF_CHECK_EQ_MSG(91u, ehdr.event_id, "delivered event id %u",
	    ehdr.event_id);

	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * Producing must not require root: an unprivileged child registers the
 * provider, sets up + maps its ring, and writes one record; the (privileged)
 * subscriber reads it back.  Two pipes order the cross-process handshake so
 * the child keeps its ring fd open until the parent has drained it.
 */
ATF_TC(unpriv_producer_no_root);
ATF_TC_HEAD(unpriv_producer_no_root, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unprivileged process can register a provider and produce events");
}
ATF_TC_BODY(unpriv_producer_no_root, tc)
{
	const char *pname = "uprov_unpriv";
	struct got_event got[8];
	int sfd, n, status;
	int rdy[2], go[2];
	pid_t pid;
	char b;

	ATF_REQUIRE(pipe(rdy) == 0);	/* child -> parent: provider pushed */
	ATF_REQUIRE(pipe(go) == 0);	/* parent -> child: drained, may exit */

	sfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0,
	    "create: %s", strerror(errno));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct eventlog_provider_reg_req rreq;
		struct eventlog_ring_setup_req rr;
		struct eventlog_ring_hdr *hdr;
		struct eventlog_push_record rec;
		struct timespec tsv;
		uint8_t *data;
		uint64_t ts;
		void *p;
		int fd;
		char one = 1;

		close(rdy[0]);
		close(go[1]);
		if (setgid(UNPRIV_GID) != 0 || setuid(UNPRIV_UID) != 0)
			_exit(10);
		if (geteuid() == 0)
			_exit(15);	/* must really be unprivileged */
		fd = open(DEV_EVENTLOG, O_RDWR);
		if (fd < 0)
			_exit(11);
		memset(&rreq, 0, sizeof(rreq));
		strlcpy(rreq.name, pname, EVENTLOG_PROVIDER_NAME_MAX);
		if (ioctl(fd, EVENTLOG_IOCTL_REGISTER_PROVIDER, &rreq) != 0)
			_exit(12);
		memset(&rr, 0, sizeof(rr));
		if (ioctl(fd, EVENTLOG_IOCTL_SETUP_RING, &rr) != 0)
			_exit(13);
		p = mmap(NULL, (size_t)rr.mmap_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, (off_t)rr.mmap_offset);
		if (p == MAP_FAILED)
			_exit(14);
		hdr = (struct eventlog_ring_hdr *)p;
		data = (uint8_t *)p + hdr->data_offset;

		/* One record, stamped in the past so the boundary releases it. */
		clock_gettime(CLOCK_UPTIME, &tsv);
		ts = (uint64_t)tsv.tv_sec * 1000000 +
		    (uint64_t)tsv.tv_nsec / 1000 - 100000;
		memset(&rec, 0, sizeof(rec));
		rec.timestamp_us = ts;
		rec.session_id = 0x55;
		rec.event_id = 4242;
		rec.keywords = 0x1;
		rec.provider_id = rreq.provider_id;
		rec.level = EVENTLOG_LEVEL_INFO;
		memcpy(data, &rec, sizeof(rec));
		hdr->stream_id = 0;
		hdr->watermark_us = ts + 1;
		atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&hdr->head,
		    sizeof(rec), memory_order_release);

		(void)write(rdy[1], &one, 1);	/* pushed */
		(void)read(go[0], &b, 1);	/* wait until parent drained */
		_exit(0);
	}

	close(rdy[1]);
	close(go[0]);
	ATF_REQUIRE_MSG(read(rdy[0], &b, 1) == 1,
	    "unprivileged producer child failed before push");

	n = drain_events(sfd, got, 8, 2000);
	(void)write(go[1], &b, 1);	/* release the child */
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %d (10=setuid,11=open,12=register,13=setup_ring,"
	    "14=mmap,15=still-root)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	ATF_REQUIRE_EQ_MSG(1, n, "expected 1 event from unpriv producer, got %d",
	    n);
	ATF_CHECK_EQ_MSG(4242u, got[0].event_id, "event id %u", got[0].event_id);
	ATF_CHECK_EQ((uint64_t)0x55, got[0].session_id);

	ATF_REQUIRE(close(sfd) == 0);
}

/*
 * Subscribing reads every provider's events, so it stays privileged: an
 * unprivileged process may open the device (to produce) but its CREATE
 * (subscribe) is rejected with EPERM.
 */
ATF_TC(unpriv_subscribe_denied);
ATF_TC_HEAD(unpriv_subscribe_denied, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unprivileged process cannot subscribe to the event stream");
}
ATF_TC_BODY(unpriv_subscribe_denied, tc)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct eventlog_create_req *req;
		size_t reqsz;
		int fd, rc;

		if (setgid(UNPRIV_GID) != 0 || setuid(UNPRIV_UID) != 0)
			_exit(10);
		if (geteuid() == 0)
			_exit(15);
		/* Opening must still succeed for unprivileged users (0666). */
		fd = open(DEV_EVENTLOG, O_RDONLY);
		if (fd < 0)
			_exit(11);
		reqsz = __builtin_offsetof(struct eventlog_create_req,
		    subscriptions) + sizeof(struct eventlog_subscription_req);
		req = calloc(1, reqsz);
		if (req == NULL)
			_exit(12);
		req->buffer_size_per_cpu = BUF_PER_CPU;
		req->count = 1;
		strlcpy(req->subscriptions[0].provider_name, "uprov_denied",
		    EVENTLOG_PROVIDER_NAME_MAX);
		req->subscriptions[0].level = EVENTLOG_LEVEL_INFO;
		req->subscriptions[0].keywords = ~0u;
		rc = ioctl(fd, EVENTLOG_IOCTL_CREATE_SIZE(1), req);
		if (rc == 0)
			_exit(1);	/* subscribe wrongly allowed */
		if (errno != EPERM)
			_exit(2);	/* denied, but wrong errno */
		free(req);
		(void)close(fd);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %d (1=subscribe-allowed,2=wrong-errno,10=setuid,"
	    "11=open,12=calloc,15=still-root)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/*
 * An unprivileged process is limited to one provider channel: a second
 * fd's REGISTER_PROVIDER is rejected (EBUSY) until the first closes.
 * Root is exempt (see e.g. bind_more_than_32_providers), so this runs
 * as UNPRIV_UID.
 */
ATF_TC(unpriv_one_channel_per_process);
ATF_TC_HEAD(unpriv_one_channel_per_process, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "An unprivileged process is limited to one provider channel; "
	    "a second is rejected (EBUSY) until the first closes");
}
ATF_TC_BODY(unpriv_one_channel_per_process, tc)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct eventlog_provider_reg_req rreq1, rreq2;
		int fd1, fd2, rc;

		if (setgid(UNPRIV_GID) != 0 || setuid(UNPRIV_UID) != 0)
			_exit(10);
		if (geteuid() == 0)
			_exit(15);

		fd1 = open(DEV_EVENTLOG, O_RDWR);
		if (fd1 < 0)
			_exit(11);
		memset(&rreq1, 0, sizeof(rreq1));
		strlcpy(rreq1.name, "uprov_onechan1", EVENTLOG_PROVIDER_NAME_MAX);
		if (ioctl(fd1, EVENTLOG_IOCTL_REGISTER_PROVIDER, &rreq1) != 0)
			_exit(12);	/* the first channel must succeed */

		/* (a) A second fd from this same process is rejected. */
		fd2 = open(DEV_EVENTLOG, O_RDWR);
		if (fd2 < 0)
			_exit(13);
		memset(&rreq2, 0, sizeof(rreq2));
		strlcpy(rreq2.name, "uprov_onechan2", EVENTLOG_PROVIDER_NAME_MAX);
		rc = ioctl(fd2, EVENTLOG_IOCTL_REGISTER_PROVIDER, &rreq2);
		if (rc == 0)
			_exit(1);	/* second channel wrongly allowed */
		if (errno != EBUSY)
			_exit(2);	/* rejected, but wrong errno */

		/* (b) Closing the first frees the process up to register again. */
		if (close(fd1) != 0)
			_exit(14);
		if (ioctl(fd2, EVENTLOG_IOCTL_REGISTER_PROVIDER, &rreq2) != 0)
			_exit(3);	/* should succeed once fd1 is gone */

		(void)close(fd2);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %d (1=second-chan-allowed,2=wrong-errno,"
	    "3=retry-after-close-failed,10=setuid,11=open1,12=register1,"
	    "13=open2,14=close1,15=still-root)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/*
 * SETUP_RING may be called more than once on a provider fd.  Each call
 * returns a distinct mmap_offset and stream_id (0, then 2, skipping the
 * dump stream); a kick drains both, and a subscriber sees both records.
 */
ATF_TC(two_rings_one_fd);
ATF_TC_HEAD(two_rings_one_fd, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a second SETUP_RING on the same fd maps a distinct stream");
}
ATF_TC_BODY(two_rings_one_fd, tc)
{
	const char *pname = "uprov_tworing";
	struct eventlog_ring_setup_req rr0, rr1;
	struct eventlog_ring_hdr *h0, *h1;
	struct eventlog_push_record rec;
	struct test_event ev0, ev1;
	struct got_event got[8];
	uint64_t base;
	uint16_t pid;
	void *p0, *p1;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0,
	    "register: %s", strerror(errno));
	pid = (pfd >= 0 && pfd < FD_PROVIDER_MAX) ? fd_provider_id[pfd] : 0;

	memset(&rr0, 0, sizeof(rr0));
	rr0.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr0) == 0,
	    "first SETUP_RING: %s", strerror(errno));
	ATF_CHECK_EQ(EVENTLOG_RING_MMAP_OFFSET, rr0.mmap_offset);

	memset(&rr1, 0, sizeof(rr1));
	rr1.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr1) == 0,
	    "second SETUP_RING: %s", strerror(errno));
	ATF_CHECK_EQ(EVENTLOG_RING_MMAP_OFFSET + EVENTLOG_RING_MMAP_STRIDE,
	    rr1.mmap_offset);

	p0 = mmap(NULL, (size_t)rr0.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, pfd, (off_t)rr0.mmap_offset);
	ATF_REQUIRE(p0 != MAP_FAILED);
	p1 = mmap(NULL, (size_t)rr1.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, pfd, (off_t)rr1.mmap_offset);
	ATF_REQUIRE(p1 != MAP_FAILED);
	h0 = p0;
	h1 = p1;
	ATF_CHECK_EQ(EVENTLOG_LIVE_STREAM_ID, h0->stream_id);
	ATF_CHECK_EQ((uint16_t)(EVENTLOG_DUMP_STREAM_ID + 1), h1->stream_id);

	base = uptime_us() - 100000;
	ev0 = (struct test_event){ .ts = base, .event_id = 10, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ev1 = (struct test_event){ .ts = base + 1, .event_id = 11,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_INFO };

	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = ev0.ts;
	rec.event_id = ev0.event_id;
	rec.keywords = ev0.keywords;
	rec.provider_id = pid;
	rec.level = ev0.level;
	memcpy((uint8_t *)p0 + h0->data_offset, &rec, sizeof(rec));
	h0->watermark_us = ev0.ts;
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&h0->head,
	    sizeof(rec), memory_order_release);

	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = ev1.ts;
	rec.event_id = ev1.event_id;
	rec.keywords = ev1.keywords;
	rec.provider_id = pid;
	rec.level = ev1.level;
	memcpy((uint8_t *)p1 + h1->data_offset, &rec, sizeof(rec));
	h1->watermark_us = ev1.ts;
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&h1->head,
	    sizeof(rec), memory_order_release);

	ATF_REQUIRE(ioctl(pfd, EVENTLOG_IOCTL_KICK) == 0);

	/*
	 * The two rings commit with different watermarks (base vs. base+1),
	 * so the merge boundary releases them in separate batches: ring0's
	 * event is emittable immediately, but ring1's is held back behind
	 * ring0's stalled watermark until the liveness timeout promotes it
	 * (eventlog_max_holdback_us, ~500ms) -- a plain drain_events() stops
	 * polling after the first non-empty read and misses it.
	 */
	n = drain_events_accum(sfd, got, 8, 2, 2000);
	ATF_REQUIRE_EQ_MSG(2, n, "expected 2 events, got %d", n);
	ATF_CHECK_EQ(10u, got[0].event_id);
	ATF_CHECK_EQ(11u, got[1].event_id);
	ATF_CHECK_EQ(base, got[0].timestamp);
	ATF_CHECK_EQ(base + 1, got[1].timestamp);

	ATF_REQUIRE(munmap(p0, (size_t)rr0.mmap_size) == 0);
	ATF_REQUIRE(munmap(p1, (size_t)rr1.mmap_size) == 0);
	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TC(setup_ring_cap_enospc);
ATF_TC_HEAD(setup_ring_cap_enospc, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "SETUP_RING fails with ENOSPC once EVENTLOG_USER_RINGS_MAX is reached");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(setup_ring_cap_enospc, tc)
{
	const char *pname = "uprov_ringcap";
	struct eventlog_ring_setup_req rr;
	uint64_t last_off = 0;
	u_int i;
	int pfd;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0,
	    "register: %s", strerror(errno));

	for (i = 0; i < EVENTLOG_USER_RINGS_MAX; i++) {
		memset(&rr, 0, sizeof(rr));
		rr.size = EVENTLOG_RING_SIZE_MIN;
		ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr) == 0,
		    "SETUP_RING %u: %s", i, strerror(errno));
		ATF_CHECK_EQ(EVENTLOG_RING_MMAP_OFFSET +
		    (uint64_t)i * EVENTLOG_RING_MMAP_STRIDE, rr.mmap_offset);
		last_off = rr.mmap_offset;
	}
	ATF_CHECK_EQ(EVENTLOG_RING_MMAP_OFFSET +
	    (uint64_t)(EVENTLOG_USER_RINGS_MAX - 1) * EVENTLOG_RING_MMAP_STRIDE,
	    last_off);

	memset(&rr, 0, sizeof(rr));
	rr.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_ERRNO(ENOSPC,
	    ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr) == -1);

	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * A ring allocated after a subscriber is already bound inherits
 * CONSUMER_PRESENT: SETUP publishes the flag across every ring on the fd.
 */
ATF_TC(consumer_flag_on_late_ring);
ATF_TC_HEAD(consumer_flag_on_late_ring, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "CONSUMER_PRESENT is set on a ring created after subscribe");
}
ATF_TC_BODY(consumer_flag_on_late_ring, tc)
{
	const char *pname = "uprov_lateflag";
	struct eventlog_ring_setup_req rr0, rr1;
	struct eventlog_ring_hdr *h0, *h1;
	void *p0, *p1;
	int pfd, sfd, i;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0,
	    "register: %s", strerror(errno));

	sfd = open_eventlog_or_skip();
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0, "create: %s", strerror(errno));

	memset(&rr0, 0, sizeof(rr0));
	rr0.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr0) == 0,
	    "first SETUP_RING: %s", strerror(errno));
	memset(&rr1, 0, sizeof(rr1));
	rr1.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr1) == 0,
	    "second SETUP_RING: %s", strerror(errno));

	p0 = mmap(NULL, (size_t)rr0.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, pfd, (off_t)rr0.mmap_offset);
	ATF_REQUIRE(p0 != MAP_FAILED);
	p1 = mmap(NULL, (size_t)rr1.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, pfd, (off_t)rr1.mmap_offset);
	ATF_REQUIRE(p1 != MAP_FAILED);
	h0 = p0;
	h1 = p1;

	ATF_CHECK_MSG((h0->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) != 0,
	    "ring 0 missing CONSUMER_PRESENT (flags=0x%x)", h0->flags);
	ATF_CHECK_MSG((h1->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) != 0,
	    "late ring missing CONSUMER_PRESENT (flags=0x%x)", h1->flags);

	ATF_REQUIRE(close(sfd) == 0);
	for (i = 0; i < 50; i++) {
		if ((h0->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0 &&
		    (h1->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0)
			break;
		usleep(20000);
	}
	ATF_CHECK_MSG((h0->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0,
	    "ring 0 still CONSUMER_PRESENT after close (flags=0x%x)", h0->flags);
	ATF_CHECK_MSG((h1->flags & EVENTLOG_RING_F_CONSUMER_PRESENT) == 0,
	    "late ring still CONSUMER_PRESENT after close (flags=0x%x)",
	    h1->flags);

	ATF_REQUIRE(munmap(p0, (size_t)rr0.mmap_size) == 0);
	ATF_REQUIRE(munmap(p1, (size_t)rr1.mmap_size) == 0);
	ATF_REQUIRE(close(pfd) == 0);
}

/*
 * Unprivileged uid is charged per ring.  With the per-uid cap set to one
 * MIN ring, a second SETUP_RING fails with ENOMEM.
 */
ATF_TC(unpriv_multi_ring_quota);
ATF_TC_HEAD(unpriv_multi_ring_quota, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "unprivileged SETUP_RING is charged; a second ring past the cap is ENOMEM");
}
ATF_TC_BODY(unpriv_multi_ring_quota, tc)
{
	const char *capname = "kern.eventlog.user_ring_max_bytes_per_uid";
	const char *pname = "uprov_rquota";
	struct eventlog_ring_setup_req rr;
	u_long saved_cap, ring_bytes;
	pid_t pid;
	int pfd, status;

	if (geteuid() != 0)
		atf_tc_skip("eventlog provider tests must run as root");

	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE_MSG(do_register(pfd, "uprov_qmeas", 1) == 0,
	    "register: %s", strerror(errno));
	memset(&rr, 0, sizeof(rr));
	rr.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr) == 0,
	    "measure SETUP_RING: %s", strerror(errno));
	ring_bytes = (u_long)rr.mmap_size;
	ATF_REQUIRE(close(pfd) == 0);

	saved_cap = get_ulong_sysctl(capname);
	set_ulong_sysctl(capname, ring_bytes);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct eventlog_provider_reg_req rreq;
		int fd;

		if (setgid(UNPRIV_GID) != 0 || setuid(UNPRIV_UID) != 0)
			_exit(10);
		if (geteuid() == 0)
			_exit(15);
		fd = open(DEV_EVENTLOG, O_RDWR);
		if (fd < 0)
			_exit(11);
		memset(&rreq, 0, sizeof(rreq));
		strlcpy(rreq.name, pname, EVENTLOG_PROVIDER_NAME_MAX);
		if (ioctl(fd, EVENTLOG_IOCTL_REGISTER_PROVIDER, &rreq) != 0)
			_exit(12);
		memset(&rr, 0, sizeof(rr));
		rr.size = EVENTLOG_RING_SIZE_MIN;
		if (ioctl(fd, EVENTLOG_IOCTL_SETUP_RING, &rr) != 0)
			_exit(13);
		memset(&rr, 0, sizeof(rr));
		rr.size = EVENTLOG_RING_SIZE_MIN;
		if (ioctl(fd, EVENTLOG_IOCTL_SETUP_RING, &rr) == 0)
			_exit(14);
		if (errno != ENOMEM)
			_exit(16);
		_exit(0);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	set_ulong_sysctl(capname, saved_cap);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %d (10=setuid,11=open,12=register,13=first-setup,"
	    "14=second-setup-ok,15=still-root,16=wrong-errno)",
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

/*
 * Subscriber read drains every ring on the fd; KICK is not required.
 */
ATF_TC(two_rings_lazy_drain);
ATF_TC_HEAD(two_rings_lazy_drain, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a subscriber read drains both rings without EVENTLOG_IOCTL_KICK");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(two_rings_lazy_drain, tc)
{
	const char *pname = "uprov_lazydrain";
	struct eventlog_ring_setup_req rr0, rr1;
	struct eventlog_ring_hdr *h0, *h1;
	struct eventlog_push_record rec;
	struct test_event ev0, ev1;
	struct got_event got[8];
	uint64_t base;
	uint16_t pid;
	void *p0, *p1;
	int pfd, sfd, n;

	sfd = open_eventlog_or_skip();
	pfd = open(DEV_EVENTLOG, O_RDWR);
	ATF_REQUIRE(pfd >= 0);
	ATF_REQUIRE_MSG(do_create(sfd, 4, pname, EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(do_register(pfd, pname, 1) == 0,
	    "register: %s", strerror(errno));
	pid = (pfd >= 0 && pfd < FD_PROVIDER_MAX) ? fd_provider_id[pfd] : 0;

	memset(&rr0, 0, sizeof(rr0));
	rr0.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr0) == 0,
	    "first SETUP_RING: %s", strerror(errno));
	memset(&rr1, 0, sizeof(rr1));
	rr1.size = EVENTLOG_RING_SIZE_MIN;
	ATF_REQUIRE_MSG(ioctl(pfd, EVENTLOG_IOCTL_SETUP_RING, &rr1) == 0,
	    "second SETUP_RING: %s", strerror(errno));

	p0 = mmap(NULL, (size_t)rr0.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, pfd, (off_t)rr0.mmap_offset);
	ATF_REQUIRE(p0 != MAP_FAILED);
	p1 = mmap(NULL, (size_t)rr1.mmap_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, pfd, (off_t)rr1.mmap_offset);
	ATF_REQUIRE(p1 != MAP_FAILED);
	h0 = p0;
	h1 = p1;

	base = uptime_us() - 100000;
	ev0 = (struct test_event){ .ts = base, .event_id = 20, .keywords = 0x1,
	    .level = EVENTLOG_LEVEL_INFO };
	ev1 = (struct test_event){ .ts = base + 1, .event_id = 21,
	    .keywords = 0x1, .level = EVENTLOG_LEVEL_INFO };

	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = ev0.ts;
	rec.event_id = ev0.event_id;
	rec.keywords = ev0.keywords;
	rec.provider_id = pid;
	rec.level = ev0.level;
	memcpy((uint8_t *)p0 + h0->data_offset, &rec, sizeof(rec));
	h0->watermark_us = ev0.ts;
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&h0->head,
	    sizeof(rec), memory_order_release);

	memset(&rec, 0, sizeof(rec));
	rec.timestamp_us = ev1.ts;
	rec.event_id = ev1.event_id;
	rec.keywords = ev1.keywords;
	rec.provider_id = pid;
	rec.level = ev1.level;
	memcpy((uint8_t *)p1 + h1->data_offset, &rec, sizeof(rec));
	h1->watermark_us = ev1.ts;
	atomic_store_explicit((_Atomic(uint64_t) *)(uintptr_t)&h1->head,
	    sizeof(rec), memory_order_release);

	n = drain_events_accum(sfd, got, 8, 2, 3000);
	ATF_REQUIRE_EQ_MSG(2, n, "expected 2 events without KICK, got %d", n);
	ATF_CHECK_EQ(20u, got[0].event_id);
	ATF_CHECK_EQ(21u, got[1].event_id);

	ATF_REQUIRE(munmap(p0, (size_t)rr0.mmap_size) == 0);
	ATF_REQUIRE(munmap(p1, (size_t)rr1.mmap_size) == 0);
	ATF_REQUIRE(close(pfd) == 0);
	ATF_REQUIRE(close(sfd) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, register_provider);
	ATF_TP_ADD_TC(tp, push_without_register);
	ATF_TP_ADD_TC(tp, end_to_end_basic);
	ATF_TP_ADD_TC(tp, merge_two_streams);
	ATF_TP_ADD_TC(tp, absent_provider_defers);
	ATF_TP_ADD_TC(tp, level_keyword_filter);
	ATF_TP_ADD_TC(tp, out_of_order_drop_stats);
	ATF_TP_ADD_TC(tp, invalid_batches_rejected);
	ATF_TP_ADD_TC(tp, boundary_holds_future_event);
	ATF_TP_ADD_TC(tp, get_providers_lists_user_provider);
	ATF_TP_ADD_TC(tp, multi_subscriber_fanout);
	ATF_TP_ADD_TC(tp, multi_device_subscriber_kernel_fanout);
	ATF_TP_ADD_TC(tp, provider_close_unbind_and_rebind);
	ATF_TP_ADD_TC(tp, streams_auto_allocated);
	ATF_TP_ADD_TC(tp, stream_cap_exhaustion);
	ATF_TP_ADD_TC(tp, stream_idle_reclaim_and_reuse);
	ATF_TP_ADD_TC(tp, bind_more_than_32_providers);
	ATF_TP_ADD_TC(tp, get_providers_beyond_32);
	ATF_TP_ADD_TC(tp, user_buffer_overflow_drops);
	ATF_TP_ADD_TC(tp, late_join_arming);
	ATF_TP_ADD_TC(tp, late_join_discovered_live_scan);
	ATF_TP_ADD_TC(tp, control_subscribers_changed);
	ATF_TP_ADD_TC(tp, control_default_changed);
	ATF_TP_ADD_TC(tp, report_stats_roundtrip);
	ATF_TP_ADD_TC(tp, dump_request_routed_to_subscriber);
	ATF_TP_ADD_TC(tp, dump_cancelled_on_provider_close);
	ATF_TP_ADD_TC(tp, dump_cancelled_on_subscriber_close);
	ATF_TP_ADD_TC(tp, dump_ioctl_validation);
	ATF_TP_ADD_TC(tp, ring_wrap_straddle);
	ATF_TP_ADD_TC(tp, ring_full_drops);
	ATF_TP_ADD_TC(tp, garbage_head_clamped);
	ATF_TP_ADD_TC(tp, tampered_ring_geometry_contained);
	ATF_TP_ADD_TC(tp, drain_wakes_blocked_reader);
	ATF_TP_ADD_TC(tp, kick_consumer_flag_published);
	ATF_TP_ADD_TC(tp, kick_drains_ring);
	ATF_TP_ADD_TC(tp, kick_wakes_blocked_reader);
	ATF_TP_ADD_TC(tp, unpriv_producer_no_root);
	ATF_TP_ADD_TC(tp, unpriv_subscribe_denied);
	ATF_TP_ADD_TC(tp, unpriv_one_channel_per_process);
	ATF_TP_ADD_TC(tp, two_rings_one_fd);
	ATF_TP_ADD_TC(tp, setup_ring_cap_enospc);
	ATF_TP_ADD_TC(tp, consumer_flag_on_late_ring);
	ATF_TP_ADD_TC(tp, unpriv_multi_ring_quota);
	ATF_TP_ADD_TC(tp, two_rings_lazy_drain);

	return (atf_no_error());
}
