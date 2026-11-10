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
 * End-to-end tests for the user-space producer workflow.
 *
 * These prove that a client gets the exact kernel pattern: a schema
 * (test_eventlog_schema.src, wired in via EVENTLOG_SCHEMA in the Makefile),
 * the generated producer header (<eventlog/test_eventlog.h>), and the
 * generated LOG macros -- now emitting from user space through libeventlog.
 *
 * The macros take an eventlog_session obtained from eventlog_session_create()
 * on a provider from eventlog_provider_create(), which registers a provider on
 * /dev/eventlog and mmap()s the kernel's enablement word.  A separate
 * subscriber fd reads the merged stream back.
 *
 * Coverage:
 *   - enablement_gate_via_mmap: the mmap'd word tracks subscriber interest,
 *     so the _ENABLED() macro flips with no system call.
 *   - end_to_end_macro: scalar events emitted via the macros arrive in
 *     order with intact payloads, provider_id, and session_id.
 *   - varlen_macro: the variable-length gather path round-trips.
 *   - per_thread_rings: EVENTLOG_PROVIDER_PER_THREAD_RINGS delivers every
 *     concurrent write with no drops.
 *   - per_thread_rings_fork_child: a forked child's new per-thread
 *     provider does not write into the parent's ring.
 *   - per_thread_rings_wrap: 64 KB SPSC records that straddle the wrap arrive.
 *   - per_thread_rings_vs_drain: concurrent drain accounts every SPSC write.
 *   - per_thread_rings_first_flag_wins: the first provider's flags latch
 *     the process channel onto the shared-ring commit path.
 *   - per_thread_rings_oversize_drops: a record larger than the 64 KB ring
 *     is dropped and later writes still land.
 *   - per_thread_rings_dump: DUMP_STATE replay still scopes to one subscriber.
 *   - per_thread_rings_varlen: the gather path round-trips on an SPSC ring.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/eventlog_dev.h>
/*
 * Compile the generated decode blob (test_eventlog_decode_blob[]) into this
 * test so lib_decode_blob_registered can register it and read it back over
 * EVENTLOG_IOCTL_GET_DECODE_BLOB, exercising the user-space producer blob path.
 */
#define	TEST_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/test_eventlog.h>

#include "eventlog_user_test.h"

#define	DEV_EVENTLOG	"/dev/eventlog"
#define	BUF_PER_CPU	(64u * 1024u)
#define	READ_BUF_SZ	(1u << 20)
#define	PROVIDER_NAME	"umtest"	/* runtime name; macros are name-agnostic */

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
 * Open /dev/eventlog non-blocking, skipping if not root or the device is
 * absent.  Non-blocking via open flags (devfs does not forward FIONBIO to
 * the cdev), so reads return EAGAIN rather than sleeping.
 */
static int
open_dev_or_skip(void)
{
	int fd;

	if (geteuid() != 0)
		atf_tc_skip("eventlog producer tests must run as root");
	fd = open(DEV_EVENTLOG, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present (eventlog not in kernel)",
			    DEV_EVENTLOG);
		atf_tc_fail("open(%s): %s", DEV_EVENTLOG, strerror(errno));
	}
	return (fd);
}

/* Turn an fd into a subscriber with a single subscription. */
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

/* Subscribe one fd to several providers at once (TRACE, all keywords). */
static int
do_create_n(int fd, const char *const *providers, int n)
{
	struct eventlog_create_req *req;
	size_t reqsz;
	int rc, saved, i;

	reqsz = __builtin_offsetof(struct eventlog_create_req, subscriptions) +
	    (size_t)n * sizeof(struct eventlog_subscription_req);
	req = calloc(1, reqsz);
	ATF_REQUIRE(req != NULL);
	req->buffer_size_per_cpu = BUF_PER_CPU;
	req->count = n;
	for (i = 0; i < n; i++) {
		strlcpy(req->subscriptions[i].provider_name, providers[i],
		    EVENTLOG_PROVIDER_NAME_MAX);
		req->subscriptions[i].level = EVENTLOG_LEVEL_TRACE;
		req->subscriptions[i].keywords = ~0u;
		req->subscriptions[i].flags = 0;
	}
	rc = ioctl(fd, EVENTLOG_IOCTL_CREATE_SIZE(n), req);
	saved = errno;
	free(req);
	errno = saved;
	return (rc);
}

/*
 * Drain up to maxout events from a subscriber fd, polling up to timeout_ms
 * for the emit boundary to release them.
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
			if (got > 0 || waited >= timeout_ms)
				break;
			usleep(10000);
			waited += 10;
			continue;
		}
		if (n == 0)
			break;

		while (off + sizeof(struct eventlog_event_header) <=
		    (size_t)n) {
			struct eventlog_event_header hdr;
			uint16_t plen;

			memcpy(&hdr, buf + off, sizeof(hdr));
			ATF_REQUIRE(hdr.event_length >= sizeof(hdr));
			ATF_REQUIRE(off + hdr.event_length <= (size_t)n);
			plen = hdr.event_length - sizeof(hdr);

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
				memcpy(g->payload, buf + off + sizeof(hdr),
				    plen);
			}
			got++;
			off += hdr.event_length;
		}
	}

	free(buf);
	return (got);
}

/*
 * Drain across several attempts, accumulating into out: drain_events()
 * returns as soon as one non-empty read lands, but the merge boundary can
 * release a producer's records in more than one batch (e.g. a state dump
 * arriving in two pieces -- the replayed records via the user-stream merge
 * and the DUMP_COMPLETE written straight to the device buffer -- or
 * multiple producer streams whose watermarks stagger delivery), so callers
 * expecting more than one batch need to keep polling past the first hit.
 */
static int
drain_accum(int fd, struct got_event *out, int maxout, int want,
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

/* Poll until the mmap'd effective_level reaches want (or time out). */
static int
wait_level(struct eventlog_session *s, uint32_t want, int timeout_ms)
{
	int waited = 0;

	while (s->eff->effective_level != want) {
		if (waited >= timeout_ms)
			return (-1);
		usleep(5000);
		waited += 5;
	}
	return (0);
}

/* --------------------------------------------------------------------- */

ATF_TC(enablement_gate_via_mmap);
ATF_TC_HEAD(enablement_gate_via_mmap, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "the mmap'd enablement word tracks subscriber interest");
}
ATF_TC_BODY(enablement_gate_via_mmap, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	int sub_fd;

	/* Provider with no subscribers: the gate starts closed. */
	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));
	ATF_CHECK_EQ(EVENTLOG_LEVEL_NONE, s->eff->effective_level);
	ATF_CHECK(!TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(s));

	/* A subscriber expressing interest opens the gate, with no syscall
	 * on the producer side -- the kernel updates the shared page. */
	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_INFO, ~0u, 0) == 0, "create: %s", strerror(errno));

	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_INFO, 1000) == 0,
	    "gate did not open (effective_level=%u)", s->eff->effective_level);
	ATF_CHECK(TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(s));

	/* When the subscriber leaves, the gate closes again. */
	ATF_REQUIRE(close(sub_fd) == 0);
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_NONE, 1000) == 0,
	    "gate did not close (effective_level=%u)", s->eff->effective_level);
	ATF_CHECK(!TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(s));

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
}

struct slow_pred_arg {
	struct eventlog_session *s;
};

static void *
slow_pred_writer(void *varg)
{
	struct slow_pred_arg *arg = varg;

	TEST_EVENTLOG_SIMPLE_EVENT_LOG_ALWAYS(arg->s, 0x1111);
	return (NULL);
}

static int
wait_commit_delay_taken(int timeout_ms)
{
	int waited = 0;

	while (!eventlog_test_commit_delay_taken()) {
		if (waited >= timeout_ms)
			return (-1);
		usleep(1000);
		waited += 1;
	}
	return (0);
}

/*
 * sessions_enabled tracks per-session enablement: a session created on a
 * default_enabled provider counts until set_enabled(0) or destroy; a
 * set_filter override does not enable a disabled session; two providers on
 * one channel count independently.
 */
ATF_TC(sessions_enabled_counting);
ATF_TC_HEAD(sessions_enabled_counting, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "per-session set_enabled moves the provider's sessions_enabled "
	    "count; set_filter does not enable a disabled session");
}
ATF_TC_BODY(sessions_enabled_counting, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p, *q;
	struct eventlog_session *s, *t;

	memset(&config, 0, sizeof(config));
	config.default_enabled = 1;
	p = eventlog_provider_create("umen", &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	q = eventlog_provider_create("umen2", NULL);
	ATF_REQUIRE_MSG(q != NULL, "eventlog_provider_create(q): %s",
	    strerror(errno));

	/* default_enabled provider counts its sessions. */
	s = eventlog_session_create(p, 1, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));
	ATF_CHECK_EQ(1, eventlog_test_get_sess_enabled(p));

	/* default-disabled provider does not. */
	t = eventlog_session_create(q, 2, false, NULL, 0);
	ATF_REQUIRE_MSG(t != NULL, "session_create(q): %s", strerror(errno));
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(q));

	/* Per-session disable/enable moves only its provider's count. */
	eventlog_session_set_enabled(s, 0);
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(p));
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(q));
	eventlog_session_set_enabled(s, 1);
	ATF_CHECK_EQ(1, eventlog_test_get_sess_enabled(p));

	/* Idempotent: re-setting the same state does not double-count. */
	eventlog_session_set_enabled(s, 1);
	ATF_CHECK_EQ(1, eventlog_test_get_sess_enabled(p));
	eventlog_session_set_enabled(s, 0);
	eventlog_session_set_enabled(s, 0);
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(p));

	/* A filter override does not enable a disabled session. */
	eventlog_session_set_filter(s, EVENTLOG_LEVEL_TRACE, 0x5);
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(p));
	ATF_CHECK_EQ(EVENTLOG_LEVEL_NONE, s->eff->effective_level);
	ATF_CHECK(!TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(s));

	/* Re-enabling applies the remembered override, like the kernel. */
	eventlog_session_set_enabled(s, 1);
	ATF_CHECK_EQ(1, eventlog_test_get_sess_enabled(p));
	ATF_CHECK_EQ(EVENTLOG_LEVEL_TRACE, s->eff->effective_level);
	ATF_CHECK_EQ(0x5u, s->eff->effective_keywords);

	/* Destroy of an enabled session decrements; of a disabled one does not. */
	eventlog_session_destroy(s);
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(p));
	eventlog_session_destroy(t);
	ATF_CHECK_EQ(0, eventlog_test_get_sess_enabled(q));

	eventlog_provider_destroy(p);
	eventlog_provider_destroy(q);
}

/*
 * A slow predecessor between reserve and commit: the waiter holds its
 * reservation until head advances, then both writes land.  The 200 µs
 * threshold only counts the wait.
 */
ATF_TC(commit_waits_for_slow_predecessor);
ATF_TC_HEAD(commit_waits_for_slow_predecessor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a write behind a slow reservation waits and then succeeds; "
	    "the channel stays writable");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(commit_waits_for_slow_predecessor, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct slow_pred_arg arg;
	struct got_event ev[8];
	pthread_t th;
	uint32_t v0, v1;
	unsigned long dropped;
	int sub_fd, n;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not become enabled");

	eventlog_test_set_commit_delay_us(5000000);
	arg.s = s;
	ATF_REQUIRE(pthread_create(&th, NULL, slow_pred_writer, &arg) == 0);
	ATF_REQUIRE_MSG(wait_commit_delay_taken(2000) == 0,
	    "predecessor never took the commit delay");

	TEST_EVENTLOG_SIMPLE_EVENT_LOG_ALWAYS(s, 0x2222);
	ATF_REQUIRE(pthread_join(th, NULL) == 0);

	dropped = eventlog_test_get_dropped(p);
	ATF_CHECK_EQ_MSG(0UL, dropped,
	    "a write behind a slow reservation was dropped (%lu)", dropped);
	ATF_CHECK_MSG(eventlog_test_get_stuck_commit_waits(p) >= 1,
	    "waiter did not count a stuck commit wait");

	n = drain_accum(sub_fd, ev, 8, 2, 3000);
	ATF_REQUIRE_EQ_MSG(2, n, "expected both events, got %d", n);
	ATF_CHECK_EQ(TEST_EVENTLOG_SIMPLE_EVENT_ID, ev[0].event_id);
	ATF_CHECK_EQ(TEST_EVENTLOG_SIMPLE_EVENT_ID, ev[1].event_id);
	memcpy(&v0, ev[0].payload, sizeof(v0));
	memcpy(&v1, ev[1].payload, sizeof(v1));
	ATF_CHECK_EQ((uint32_t)0x1111, v0);
	ATF_CHECK_EQ((uint32_t)0x2222, v1);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

ATF_TC(end_to_end_macro);
ATF_TC_HEAD(end_to_end_macro, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "scalar events emitted via the generated macros arrive in order");
}
ATF_TC_BODY(end_to_end_macro, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[8];
	struct test_eventlog_status_event status;
	struct test_eventlog_complex_event cplx;
	uint32_t simple;
	int sub_fd, n, i;
	uint16_t pid;

	/* Provider first; batch several events into one push. */
	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0x5151515151515151ULL, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	/* A subscriber opens the gate (immediate bind: provider exists). */
	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));

	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not become enabled (effective_level=%u)",
	    s->eff->effective_level);

	TEST_EVENTLOG_SIMPLE_EVENT_LOG(s, 0xDEADBEEF);
	TEST_EVENTLOG_STATUS_EVENT_LOG(s, 0xAABBCCDD, TEST_EVENTLOG_TEST_STATUS_RUNNING);
	TEST_EVENTLOG_COMPLEX_EVENT_LOG(s, 0x1122334455667788ULL, 0x99, TEST_EVENTLOG_TEST_STATUS_SUCCESS, TEST_EVENTLOG_FLAG_FLAG_B, -7);
	n = drain_accum(sub_fd, ev, 8, 3, 3000);
	ATF_REQUIRE_EQ_MSG(3, n, "expected 3 events, got %d", n);

	/* In timestamp order: SIMPLE(0), STATUS(1), COMPLEX(3). */
	ATF_CHECK_EQ(TEST_EVENTLOG_SIMPLE_EVENT_ID, ev[0].event_id);
	ATF_CHECK_EQ(TEST_EVENTLOG_STATUS_EVENT_ID, ev[1].event_id);
	ATF_CHECK_EQ(TEST_EVENTLOG_COMPLEX_EVENT_ID, ev[2].event_id);

	/* Strictly increasing per-stream timestamps and stable session_id. */
	for (i = 0; i < n; i++) {
		ATF_CHECK_EQ(0x5151515151515151ULL, ev[i].session_id);
		if (i > 0)
			ATF_CHECK_MSG(ev[i].timestamp > ev[i - 1].timestamp,
			    "timestamps not increasing at %d", i);
	}

	/* All events carry the same provider_id, matching GET_PROVIDERS. */
	pid = ev[0].provider_id;
	for (i = 1; i < n; i++)
		ATF_CHECK_EQ(pid, ev[i].provider_id);
	{
		struct eventlog_get_providers_resp *provs;
		size_t base = __builtin_offsetof(
		    struct eventlog_get_providers_resp, providers);
		uint32_t cap = 16, k;
		bool found = false;

		provs = calloc(1, base + cap * sizeof(provs->providers[0]));
		ATF_REQUIRE(provs != NULL);
		provs->count = cap;
		ATF_REQUIRE(ioctl(sub_fd,
		    EVENTLOG_IOCTL_GET_PROVIDERS_SIZE(cap), provs) == 0);
		for (k = 0; k < provs->count && k < cap; k++) {
			if (strcmp(provs->providers[k].name, PROVIDER_NAME) == 0 &&
			    provs->providers[k].provider_id == pid)
				found = true;
		}
		ATF_CHECK_MSG(found, "provider_id %u not in GET_PROVIDERS", pid);
		free(provs);
	}

	/* Payloads round-trip intact (memcpy out to avoid aliasing the
	 * byte buffer with a higher-aligned struct pointer). */
	memcpy(&simple, ev[0].payload, sizeof(simple));
	ATF_CHECK_EQ((uint32_t)0xDEADBEEF, simple);

	memcpy(&status, ev[1].payload, sizeof(status));
	ATF_CHECK_EQ((uint64_t)0xAABBCCDD, status.id);
	ATF_CHECK_EQ(TEST_EVENTLOG_TEST_STATUS_RUNNING, status.status);

	memcpy(&cplx, ev[2].payload, sizeof(cplx));
	ATF_CHECK_EQ(0x1122334455667788ULL, cplx.id);
	ATF_CHECK_EQ((uint32_t)0x99, cplx.value);
	ATF_CHECK_EQ(TEST_EVENTLOG_TEST_STATUS_SUCCESS, cplx.status);
	ATF_CHECK_EQ(-7, cplx.counter);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

ATF_TC(varlen_macro);
ATF_TC_HEAD(varlen_macro, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "the variable-length gather macro round-trips its array");
}
ATF_TC_BODY(varlen_macro, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[2];
	struct test_eventlog_varlen_event head;
	uint64_t src[4] = { 0x11, 0x22, 0x33, 0x44 };
	int sub_fd, n, i;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not become enabled");

	/* The write lands in the ring; the subscriber read drives the drain. */
	TEST_EVENTLOG_VARLEN_EVENT_LOG(s, 0xCAFEF00D, 4, src);

	n = drain_events(sub_fd, ev, 2, 3000);
	ATF_REQUIRE_EQ_MSG(1, n, "expected 1 event, got %d", n);
	ATF_CHECK_EQ(TEST_EVENTLOG_VARLEN_EVENT_ID, ev[0].event_id);

	/* Wire layout: fixed head, then count*uint64_t values. */
	memcpy(&head, ev[0].payload, sizeof(head));
	ATF_CHECK_EQ(0xCAFEF00DULL, head.id);
	ATF_CHECK_EQ(4, head.count);
	ATF_REQUIRE_MSG(ev[0].payload_len >= sizeof(head) + 4 * sizeof(uint64_t),
	    "varlen payload too short: %u", ev[0].payload_len);
	for (i = 0; i < 4; i++) {
		uint64_t v;

		memcpy(&v, ev[0].payload + sizeof(head) + i * sizeof(uint64_t),
		    sizeof(v));
		ATF_CHECK_EQ(src[i], v);
	}

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

ATF_TC(large_burst_delivered);
ATF_TC_HEAD(large_burst_delivered, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a burst far larger than the retired single-ioctl push limit flows "
	    "through the submission ring and every event arrives intact");
}
ATF_TC_BODY(large_burst_delivered, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event *ev;
	uint8_t *payload;
	/*
	 * The old path pushed each batch through one ioctl capped at
	 * IOCPARM_MAX (~8 KB).  The ring has no such per-submit cap, so emit a
	 * burst many times that size (512 * 128 B = 64 KB) and require every
	 * event back -- the case the retired length field could silently drop.
	 */
	const int nrec = 512;
	const size_t payload_len =
	    128 - sizeof(struct eventlog_push_record);
	int sub_fd, n, i;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not become enabled");

	ev = calloc(nrec, sizeof(*ev));
	ATF_REQUIRE(ev != NULL);
	payload = malloc(payload_len);
	ATF_REQUIRE(payload != NULL);
	for (i = 0; i < nrec; i++) {
		memset(payload, 0x40 + (i & 0x3f), payload_len);
		eventlog_event_write(s, 0x100 + i, EVENTLOG_LEVEL_INFO, 1,
		    payload, payload_len);
	}
	/* Writes self-publish; the kernel drains them from the subscriber read. */
	n = drain_accum(sub_fd, ev, nrec, nrec, 3000);
	ATF_REQUIRE_EQ_MSG(nrec, n, "expected %d events, got %d", nrec, n);
	for (i = 0; i < nrec; i++) {
		ATF_CHECK_EQ((uint32_t)(0x100 + i), ev[i].event_id);
		ATF_CHECK_EQ((uint16_t)payload_len, ev[i].payload_len);
		ATF_CHECK_EQ((uint8_t)(0x40 + (i & 0x3f)), ev[i].payload[0]);
	}

	free(payload);
	free(ev);
	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * Two providers registered by one process share a single fd and a single
 * submission ring; both records ride one ring and each event self-describes
 * its provider_id, so the kernel drain routes and filters per record (no
 * demux on the producer side).
 */
ATF_TC(multi_provider_one_push);
ATF_TC_HEAD(multi_provider_one_push, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "two providers on one ring: the drain delivers both, routed by "
	    "per-record provider_id");
}
ATF_TC_BODY(multi_provider_one_push, tc)
{
	static const char *const names[] = { "umtestA", "umtestB" };
	struct eventlog_provider *pa, *pb;
	struct eventlog_session *a, *b;
	struct got_event ev[8];
	uint16_t ida, idb;
	uint32_t va, vb;
	int sub_fd, n, i;

	pa = eventlog_provider_create(names[0], NULL);
	if (pa == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create(A): %s", strerror(errno));
	}
	pb = eventlog_provider_create(names[1], NULL);
	ATF_REQUIRE_MSG(pb != NULL, "eventlog_provider_create(B): %s",
	    strerror(errno));
	a = eventlog_session_create(pa, 0xA1A1A1A1A1A1A1A1ULL, false, NULL, 0);
	ATF_REQUIRE_MSG(a != NULL, "session_create(A): %s", strerror(errno));
	b = eventlog_session_create(pb, 0xB2B2B2B2B2B2B2B2ULL, false, NULL, 0);
	ATF_REQUIRE_MSG(b != NULL, "session_create(B): %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create_n(sub_fd, names, 2) == 0, "create: %s",
	    strerror(errno));
	ATF_REQUIRE_MSG(wait_level(a, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider A did not enable");
	ATF_REQUIRE_MSG(wait_level(b, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider B did not enable");

	/* Interleave writes on the two providers into the one buffer. */
	TEST_EVENTLOG_SIMPLE_EVENT_LOG(a, 0x0A0A0A0A);
	TEST_EVENTLOG_SIMPLE_EVENT_LOG(b, 0x0B0B0B0B);

	n = drain_accum(sub_fd, ev, 8, 2, 3000);
	ATF_REQUIRE_EQ_MSG(2, n, "expected 2 events, got %d", n);

	/* The two events carry distinct provider_ids and session_ids. */
	ida = ev[0].provider_id;
	idb = ev[1].provider_id;
	ATF_CHECK_MSG(ida != idb, "providers shared an id (%u)", ida);

	/* Map provider_id -> name via GET_PROVIDERS and check routing. */
	{
		struct eventlog_get_providers_resp *provs;
		size_t pbase = __builtin_offsetof(
		    struct eventlog_get_providers_resp, providers);
		uint32_t cap = 16, k;
		const char *na = NULL, *nb = NULL;

		provs = calloc(1, pbase + cap * sizeof(provs->providers[0]));
		ATF_REQUIRE(provs != NULL);
		provs->count = cap;
		ATF_REQUIRE(ioctl(sub_fd,
		    EVENTLOG_IOCTL_GET_PROVIDERS_SIZE(cap), provs) == 0);
		for (k = 0; k < provs->count && k < cap; k++) {
			if (provs->providers[k].provider_id == ida)
				na = strdup(provs->providers[k].name);
			if (provs->providers[k].provider_id == idb)
				nb = strdup(provs->providers[k].name);
		}
		ATF_REQUIRE_MSG(na != NULL && nb != NULL,
		    "event provider_ids not found in GET_PROVIDERS");
		ATF_CHECK_STREQ(names[0], na);
		ATF_CHECK_STREQ(names[1], nb);
		free(provs);
	}

	/* Session ids and payloads track the originating provider. */
	ATF_CHECK_EQ(0xA1A1A1A1A1A1A1A1ULL, ev[0].session_id);
	ATF_CHECK_EQ(0xB2B2B2B2B2B2B2B2ULL, ev[1].session_id);
	memcpy(&va, ev[0].payload, sizeof(va));
	memcpy(&vb, ev[1].payload, sizeof(vb));
	ATF_CHECK_EQ((uint32_t)0x0A0A0A0A, va);
	ATF_CHECK_EQ((uint32_t)0x0B0B0B0B, vb);
	(void)i;

	eventlog_session_destroy(a);
	eventlog_session_destroy(b);
	eventlog_provider_destroy(pa);
	eventlog_provider_destroy(pb);
	ATF_REQUIRE(close(sub_fd) == 0);
}

#define	STRESS_THREADS	4
#define	STRESS_PER	200
#define	STRESS_SID_BASE	0x9000ULL

struct stress_payload {
	uint32_t	thread_idx;
	uint32_t	seq;
};

struct stress_arg {
	struct eventlog_provider	*provider;
	uint64_t			ts_base;
	int				idx;
};

static void *
stress_writer(void *varg)
{
	struct stress_arg *arg = varg;
	struct eventlog_session *s;
	struct stress_payload pl;
	int i;

	/* A cheap per-"connection" session keyed by a distinct session_id. */
	s = eventlog_session_create(arg->provider,
	    STRESS_SID_BASE + (uint64_t)arg->idx, false, NULL, 0);
	if (s == NULL)
		return ((void *)(intptr_t)errno);
	pl.thread_idx = (uint32_t)arg->idx;
	for (i = 0; i < STRESS_PER; i++) {
		pl.seq = (uint32_t)i;
		/*
		 * Stamp in the past so events are immediately past the emit
		 * boundary; the channel forces them strictly increasing, so
		 * the whole process stream stays monotonic regardless of how
		 * the threads interleave.
		 */
		eventlog_event_write_at(s, (uint32_t)i, EVENTLOG_LEVEL_INFO, 1,
		    &pl, sizeof(pl), arg->ts_base + (uint64_t)i);
	}
	eventlog_session_destroy(s);
	return (NULL);
}

struct shared_arg {
	struct eventlog_session	*session;
	int			idx;
};

/*
 * Pour events at auto (clock-stamped) timestamps into ONE shared session from
 * many threads.  Unlike stress_writer, this leaves the timestamp for the
 * library to assign, exercising the commit-time stamp: each writer reads the
 * clock only while it holds the exclusive right to advance head, so the single
 * stream stays monotonic without a lock even as threads race on the reserve
 * cursor.
 */
static void *
stress_writer_shared(void *varg)
{
	struct shared_arg *arg = varg;
	struct stress_payload pl;
	int i;

	pl.thread_idx = (uint32_t)arg->idx;
	for (i = 0; i < STRESS_PER; i++) {
		pl.seq = (uint32_t)i;
		eventlog_event_write(arg->session, (uint32_t)i,
		    EVENTLOG_LEVEL_INFO, 1, &pl, sizeof(pl));
	}
	return (NULL);
}

/*
 * Many cheap sessions (distinct session_ids) and many threads pour into the
 * one shared buffer concurrently.  Every event must arrive intact, and each
 * session's events must stay in the order that session emitted them -- the
 * reserve/commit ring must neither lose nor corrupt records under
 * contention.
 */
ATF_TC(multi_session_threads);
ATF_TC_HEAD(multi_session_threads, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "concurrent threads writing many sessions into one buffer lose no "
	    "events and preserve per-session order");
}
ATF_TC_BODY(multi_session_threads, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *gate;
	pthread_t th[STRESS_THREADS];
	struct stress_arg args[STRESS_THREADS];
	struct got_event *got;
	int last_seq[STRESS_THREADS];
	int seen[STRESS_THREADS];
	const int total = STRESS_THREADS * STRESS_PER;
	uint64_t ts_base;
	int sub_fd, n, i, t;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	gate = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(gate != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(gate, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	/* Base 2s in the past leaves head room for total us-spaced events. */
	ts_base = 0;
	{
		struct timespec tsp;
		if (clock_gettime(CLOCK_UPTIME, &tsp) == 0)
			ts_base = (uint64_t)tsp.tv_sec * 1000000ULL +
			    (uint64_t)tsp.tv_nsec / 1000ULL;
	}
	ATF_REQUIRE(ts_base > 2000000ULL);
	ts_base -= 2000000ULL;

	for (t = 0; t < STRESS_THREADS; t++) {
		args[t].provider = p;
		args[t].ts_base = ts_base + (uint64_t)t * STRESS_PER;
		args[t].idx = t;
		ATF_REQUIRE(pthread_create(&th[t], NULL, stress_writer,
		    &args[t]) == 0);
	}
	for (t = 0; t < STRESS_THREADS; t++) {
		void *rv;
		ATF_REQUIRE(pthread_join(th[t], &rv) == 0);
		ATF_REQUIRE_MSG(rv == NULL, "writer %d failed: %s", t,
		    strerror((int)(intptr_t)rv));
	}
	got = calloc(total, sizeof(*got));
	ATF_REQUIRE(got != NULL);
	n = drain_accum(sub_fd, got, total, total, 5000);
	ATF_REQUIRE_EQ_MSG(total, n, "expected %d events, got %d", total, n);

	for (t = 0; t < STRESS_THREADS; t++) {
		last_seq[t] = -1;
		seen[t] = 0;
	}
	for (i = 0; i < n; i++) {
		struct stress_payload pl;
		int tidx;

		ATF_REQUIRE_EQ_MSG(sizeof(pl), got[i].payload_len,
		    "event %d bad payload_len %u", i, got[i].payload_len);
		memcpy(&pl, got[i].payload, sizeof(pl));
		ATF_REQUIRE_MSG(got[i].session_id >= STRESS_SID_BASE &&
		    got[i].session_id < STRESS_SID_BASE + STRESS_THREADS,
		    "event %d bad session_id %#jx", i,
		    (uintmax_t)got[i].session_id);
		tidx = (int)(got[i].session_id - STRESS_SID_BASE);
		ATF_CHECK_EQ_MSG((uint32_t)tidx, pl.thread_idx,
		    "session/payload thread mismatch at %d", i);
		ATF_CHECK_EQ_MSG((uint32_t)got[i].event_id, pl.seq,
		    "event_id/payload seq mismatch at %d", i);
		/* This session's events arrive in the order it wrote them. */
		ATF_CHECK_MSG((int)pl.seq > last_seq[tidx],
		    "session %d out of order: seq %u after %d", tidx, pl.seq,
		    last_seq[tidx]);
		last_seq[tidx] = (int)pl.seq;
		seen[tidx]++;
	}
	for (t = 0; t < STRESS_THREADS; t++)
		ATF_CHECK_EQ_MSG(STRESS_PER, seen[t],
		    "session %d got %d events", t, seen[t]);

	free(got);
	eventlog_session_destroy(gate);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * The same shared session written from many threads at auto timestamps: every
 * event arrives, the merged stream is strictly increasing (the commit-time
 * stamp under the head handoff keeps one stream monotonic without a global
 * lock), and each thread's events stay in the order it emitted them.
 */
ATF_TC(multi_thread_shared_session);
ATF_TC_HEAD(multi_thread_shared_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "concurrent auto-timestamped writes to one shared session lose no "
	    "events and stay globally monotonic and per-thread ordered");
}
ATF_TC_BODY(multi_thread_shared_session, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	pthread_t th[STRESS_THREADS];
	struct shared_arg args[STRESS_THREADS];
	struct got_event *got;
	int last_seq[STRESS_THREADS];
	int seen[STRESS_THREADS];
	const int total = STRESS_THREADS * STRESS_PER;
	int sub_fd, n, i, t;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, STRESS_SID_BASE, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	for (t = 0; t < STRESS_THREADS; t++) {
		args[t].session = s;
		args[t].idx = t;
		ATF_REQUIRE(pthread_create(&th[t], NULL, stress_writer_shared,
		    &args[t]) == 0);
	}
	for (t = 0; t < STRESS_THREADS; t++) {
		void *rv;
		ATF_REQUIRE(pthread_join(th[t], &rv) == 0);
		ATF_REQUIRE(rv == NULL);
	}

	got = calloc(total, sizeof(*got));
	ATF_REQUIRE(got != NULL);
	n = drain_accum(sub_fd, got, total, total, 5000);
	ATF_REQUIRE_EQ_MSG(total, n, "expected %d events, got %d", total, n);

	for (t = 0; t < STRESS_THREADS; t++) {
		last_seq[t] = -1;
		seen[t] = 0;
	}
	for (i = 0; i < n; i++) {
		struct stress_payload pl;
		int tidx;

		ATF_REQUIRE_EQ_MSG(sizeof(pl), got[i].payload_len,
		    "event %d bad payload_len %u", i, got[i].payload_len);
		/* One shared session: every record carries its session_id. */
		ATF_CHECK_EQ_MSG(STRESS_SID_BASE, got[i].session_id,
		    "event %d bad session_id %#jx", i,
		    (uintmax_t)got[i].session_id);
		/* Single stream => strictly increasing merged timestamps. */
		if (i > 0)
			ATF_CHECK_MSG(got[i].timestamp > got[i - 1].timestamp,
			    "timestamps not increasing at %d", i);
		memcpy(&pl, got[i].payload, sizeof(pl));
		ATF_REQUIRE_MSG(pl.thread_idx < STRESS_THREADS,
		    "event %d bad thread_idx %u", i, pl.thread_idx);
		tidx = (int)pl.thread_idx;
		ATF_CHECK_EQ_MSG((uint32_t)got[i].event_id, pl.seq,
		    "event_id/payload seq mismatch at %d", i);
		/* Each thread's events keep the order it emitted them. */
		ATF_CHECK_MSG((int)pl.seq > last_seq[tidx],
		    "thread %d out of order: seq %u after %d", tidx, pl.seq,
		    last_seq[tidx]);
		last_seq[tidx] = (int)pl.seq;
		seen[tidx]++;
	}
	for (t = 0; t < STRESS_THREADS; t++)
		ATF_CHECK_EQ_MSG(STRESS_PER, seen[t],
		    "thread %d got %d events", t, seen[t]);

	free(got);
	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * EVENTLOG_PROVIDER_PER_THREAD_RINGS: concurrent writers each get an SPSC
 * ring.  Every event arrives, each thread stays ordered, and the shared-ring
 * commit wait is not on the path (dropped stays 0).
 */
ATF_TC(per_thread_rings);
ATF_TC_HEAD(per_thread_rings, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "PER_THREAD_RINGS delivers every concurrent write with no drops");
}
ATF_TC_BODY(per_thread_rings, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p;
	struct eventlog_session *s;
	pthread_t th[STRESS_THREADS];
	struct shared_arg args[STRESS_THREADS];
	struct got_event *got;
	int last_seq[STRESS_THREADS];
	int seen[STRESS_THREADS];
	const int total = STRESS_THREADS * STRESS_PER;
	int sub_fd, n, i, t;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, STRESS_SID_BASE, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	for (t = 0; t < STRESS_THREADS; t++) {
		args[t].session = s;
		args[t].idx = t;
		ATF_REQUIRE(pthread_create(&th[t], NULL, stress_writer_shared,
		    &args[t]) == 0);
	}
	for (t = 0; t < STRESS_THREADS; t++) {
		void *rv;
		ATF_REQUIRE(pthread_join(th[t], &rv) == 0);
		ATF_REQUIRE(rv == NULL);
	}

	ATF_CHECK_EQ_MSG(0UL, eventlog_test_get_dropped(p),
	    "per-thread rings dropped %lu", eventlog_test_get_dropped(p));

	got = calloc(total, sizeof(*got));
	ATF_REQUIRE(got != NULL);
	/*
	 * Each thread's ring commits with its own watermark, so the merge
	 * boundary can release them in separate batches (whichever ring's
	 * watermark trails holds the others back until the liveness timeout
	 * promotes it); drain_events() alone stops polling after the first
	 * non-empty read and would miss the later batches.
	 */
	n = drain_accum(sub_fd, got, total, total, 5000);
	ATF_REQUIRE_EQ_MSG(total, n, "expected %d events, got %d", total, n);

	for (t = 0; t < STRESS_THREADS; t++) {
		last_seq[t] = -1;
		seen[t] = 0;
	}
	for (i = 0; i < n; i++) {
		struct stress_payload pl;
		int tidx;

		ATF_REQUIRE_EQ_MSG(sizeof(pl), got[i].payload_len,
		    "event %d bad payload_len %u", i, got[i].payload_len);
		ATF_CHECK_EQ_MSG(STRESS_SID_BASE, got[i].session_id,
		    "event %d bad session_id %#jx", i,
		    (uintmax_t)got[i].session_id);
		memcpy(&pl, got[i].payload, sizeof(pl));
		ATF_REQUIRE_MSG(pl.thread_idx < STRESS_THREADS,
		    "event %d bad thread_idx %u", i, pl.thread_idx);
		tidx = (int)pl.thread_idx;
		ATF_CHECK_EQ_MSG((uint32_t)got[i].event_id, pl.seq,
		    "event_id/payload seq mismatch at %d", i);
		ATF_CHECK_MSG((int)pl.seq > last_seq[tidx],
		    "thread %d out of order: seq %u after %d", tidx, pl.seq,
		    last_seq[tidx]);
		last_seq[tidx] = (int)pl.seq;
		seen[tidx]++;
	}
	for (t = 0; t < STRESS_THREADS; t++)
		ATF_CHECK_EQ_MSG(STRESS_PER, seen[t],
		    "thread %d got %d events", t, seen[t]);

	free(got);
	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

ATF_TC(per_thread_rings_supported);
ATF_TC_HEAD(per_thread_rings_supported, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "per_thread_rings_supported() probe matches the running kernel");
}
ATF_TC_BODY(per_thread_rings_supported, tc)
{
	/*
	 * This test runs against the kernel under test, which has multi-ring
	 * support, so the probe must report supported.  (On a downlevel
	 * single-ring kernel it would report 0; that path is exercised by the
	 * EEXIST fallback, not here.)
	 */
	if (access(DEV_EVENTLOG, F_OK) != 0)
		atf_tc_skip("%s not present", DEV_EVENTLOG);
	if (geteuid() != 0)
		atf_tc_skip("must run as root");
	ATF_CHECK_MSG(eventlog_user_per_thread_rings_supported() != 0,
	    "multi-ring kernel reported per-thread rings unsupported");
}

/* Same thread count as multi_thread_shared_session (proven reliable in
 * this environment); higher per-thread count to approach the 1 MB ring. */
#define	FIT_STRESS_THREADS	4
#define	FIT_STRESS_PER		2000
#define	FIT_STRESS_SID		0xA000ULL

/* Like stress_writer_shared(), but loops FIT_STRESS_PER times for more
 * volume against a concurrent drain. */
static void *
fit_stress_writer(void *varg)
{
	struct shared_arg *arg = varg;
	struct stress_payload pl;
	int i;

	pl.thread_idx = (uint32_t)arg->idx;
	for (i = 0; i < FIT_STRESS_PER; i++) {
		pl.seq = (uint32_t)i;
		eventlog_event_write(arg->session, (uint32_t)i,
		    EVENTLOG_LEVEL_INFO, 1, &pl, sizeof(pl));
	}
	return (NULL);
}

/* Repeatedly drain into *out until told to stop, then one final sweep. */
struct fit_drain_arg {
	int			fd;
	struct got_event	*out;
	int			cap;
	int			got;
	volatile int		stop;
};

static void *
fit_drain_thread(void *varg)
{
	struct fit_drain_arg *da = varg;

	while (!da->stop && da->got < da->cap) {
		da->got += drain_events(da->fd, da->out + da->got,
		    da->cap - da->got, 50);
	}
	if (da->got < da->cap)
		da->got += drain_accum(da->fd, da->out + da->got,
		    da->cap - da->got, da->cap - da->got, 3000);
	return (NULL);
}

/*
 * Unlike multi_thread_shared_session, this drains concurrently with the
 * writers for the whole burst, exercising the reservation fit-check
 * against an actively-moving tail rather than only push-then-read. Every
 * attempted write must be either delivered or counted by a drop counter
 * (library or kernel-side); nothing should vanish silently.
 */
ATF_TC(concurrent_writers_vs_drain_fit_check);
ATF_TC_HEAD(concurrent_writers_vs_drain_fit_check, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "the ring's reservation fit-check stays correct (no loss, no "
	    "corruption) when the kernel drains concurrently with writers, "
	    "not just push-then-read");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(concurrent_writers_vs_drain_fit_check, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct eventlog_stats stats;
	pthread_t th[FIT_STRESS_THREADS], drain_th;
	struct shared_arg args[FIT_STRESS_THREADS];
	struct fit_drain_arg da;
	int last_seq[FIT_STRESS_THREADS];
	int seen[FIT_STRESS_THREADS];
	const int total = FIT_STRESS_THREADS * FIT_STRESS_PER;
	unsigned long lib_dropped, kern_dropped, accounted;
	int sub_fd, i, t;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, FIT_STRESS_SID, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	da.fd = sub_fd;
	da.out = calloc(total, sizeof(*da.out));
	ATF_REQUIRE(da.out != NULL);
	da.cap = total;
	da.got = 0;
	da.stop = 0;
	ATF_REQUIRE(pthread_create(&drain_th, NULL, fit_drain_thread, &da) ==
	    0);

	for (t = 0; t < FIT_STRESS_THREADS; t++) {
		args[t].session = s;
		args[t].idx = t;
		ATF_REQUIRE(pthread_create(&th[t], NULL, fit_stress_writer,
		    &args[t]) == 0);
	}
	for (t = 0; t < FIT_STRESS_THREADS; t++) {
		void *rv;
		ATF_REQUIRE(pthread_join(th[t], &rv) == 0);
		ATF_REQUIRE(rv == NULL);
	}
	da.stop = 1;
	ATF_REQUIRE(pthread_join(drain_th, NULL) == 0);

	lib_dropped = eventlog_test_get_dropped(p);
	ATF_REQUIRE(ioctl(sub_fd, EVENTLOG_IOCTL_GET_STATS, &stats) == 0);
	kern_dropped = stats.user_dropped_full + stats.user_dropped_prejoin +
	    stats.user_dropped_late;
	accounted = (unsigned long)da.got + lib_dropped + kern_dropped;
	ATF_CHECK_MSG(accounted == (unsigned long)total,
	    "delivered (%d) + lib dropped (%lu) + kernel dropped (%lu) = %lu, "
	    "expected %d -- an event went missing unaccounted for",
	    da.got, lib_dropped, kern_dropped, accounted, total);

	for (t = 0; t < FIT_STRESS_THREADS; t++) {
		last_seq[t] = -1;
		seen[t] = 0;
	}
	for (i = 0; i < da.got; i++) {
		struct stress_payload pl;
		int tidx;

		ATF_REQUIRE_EQ_MSG(sizeof(pl), da.out[i].payload_len,
		    "event %d bad payload_len %u", i, da.out[i].payload_len);
		ATF_CHECK_EQ_MSG(FIT_STRESS_SID, da.out[i].session_id,
		    "event %d bad session_id %#jx", i,
		    (uintmax_t)da.out[i].session_id);
		/*
		 * Drops (either origin) happen before a timestamp is ever
		 * assigned, so every *delivered* record still comes from a
		 * commit that strictly advanced chan->last_ts.
		 */
		if (i > 0)
			ATF_CHECK_MSG(da.out[i].timestamp >
			    da.out[i - 1].timestamp,
			    "timestamps not strictly increasing at %d", i);
		memcpy(&pl, da.out[i].payload, sizeof(pl));
		ATF_REQUIRE_MSG(pl.thread_idx < FIT_STRESS_THREADS,
		    "event %d bad thread_idx %u", i, pl.thread_idx);
		tidx = (int)pl.thread_idx;
		/* A dropped event can leave a gap; order must still hold. */
		ATF_CHECK_MSG((int)pl.seq > last_seq[tidx],
		    "thread %d out of order: seq %u after %d", tidx, pl.seq,
		    last_seq[tidx]);
		last_seq[tidx] = (int)pl.seq;
		seen[tidx]++;
	}
	for (t = 0; t < FIT_STRESS_THREADS; t++)
		ATF_CHECK_MSG(seen[t] <= FIT_STRESS_PER,
		    "thread %d got %d events, more than it sent", t, seen[t]);

	free(da.out);
	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * Per-session enablement is pure pointer indirection: a cheap session
 * inherits its provider's live kernel-published state, an override pins its
 * own level/keywords regardless of the provider, and a disabled session
 * gates off regardless of subscriber interest -- mirroring the kernel's
 * eventlog_session_update_effective dispositions with no per-session syscall.
 */
ATF_TC(session_enablement_dispositions);
ATF_TC_HEAD(session_enablement_dispositions, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "inherit tracks the provider, override pins, disabled gates off");
}
ATF_TC_BODY(session_enablement_dispositions, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *root, *child;
	int sub_fd;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	root = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(root != NULL, "session_create: %s", strerror(errno));

	/* No subscriber yet: inherit => gate closed. */
	child = eventlog_session_create(p, 0x1234, false, NULL, 0);
	ATF_REQUIRE_MSG(child != NULL, "session_create: %s", strerror(errno));
	ATF_CHECK_EQ(EVENTLOG_LEVEL_NONE, child->eff->effective_level);
	ATF_CHECK(!TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(child));

	/* A subscriber attaches: the inheriting child follows with no action. */
	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_INFO, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(root, EVENTLOG_LEVEL_INFO, 1000) == 0,
	    "provider did not enable");
	ATF_CHECK_EQ(EVENTLOG_LEVEL_INFO, child->eff->effective_level);
	ATF_CHECK(TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(child));

	/* Disabled: gates off even though the subscriber is still interested. */
	eventlog_session_set_enabled(child, 0);
	ATF_CHECK_EQ(EVENTLOG_LEVEL_NONE, child->eff->effective_level);
	ATF_CHECK(!TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(child));
	/* The root session is unaffected. */
	ATF_CHECK_EQ(EVENTLOG_LEVEL_INFO, root->eff->effective_level);

	/* Re-enable: back to inheriting the provider. */
	eventlog_session_set_enabled(child, 1);
	ATF_CHECK_EQ(EVENTLOG_LEVEL_INFO, child->eff->effective_level);

	/* Override pins TRACE regardless of the provider's state. */
	eventlog_session_set_filter(child, EVENTLOG_LEVEL_TRACE, 0x5);
	ATF_CHECK_EQ(EVENTLOG_LEVEL_TRACE, child->eff->effective_level);
	ATF_CHECK_EQ(0x5u, child->eff->effective_keywords);

	/* Subscriber leaves: provider falls to NONE, but the override holds. */
	ATF_REQUIRE(close(sub_fd) == 0);
	ATF_REQUIRE_MSG(wait_level(root, EVENTLOG_LEVEL_NONE, 1000) == 0,
	    "provider did not disable");
	ATF_CHECK_EQ(EVENTLOG_LEVEL_TRACE, child->eff->effective_level);

	eventlog_session_destroy(child);
	eventlog_session_destroy(root);
	eventlog_provider_destroy(p);
}

/*
 * After fork(2) the child inherits the parent's fd, page, and buffer, but a
 * pthread_atfork child handler marks the inherited channel unusable so the
 * child's writes drop rather than racing the parent's ordered stream.  The
 * subscriber must see only the parent's events.
 */
ATF_TC(fork_child_drops);
ATF_TC_HEAD(fork_child_drops, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a forked child's writes drop; only the parent's events arrive");
}
ATF_TC_BODY(fork_child_drops, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[8];
	pid_t pid;
	int sub_fd, n, i, status;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Child: these writes must be dropped by the atfork handler. */
		eventlog_event_write(s, 0xC1, EVENTLOG_LEVEL_INFO, 1, NULL, 0);
		eventlog_event_write(s, 0xC2, EVENTLOG_LEVEL_INFO, 1, NULL, 0);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Parent: a single distinct event. */
	eventlog_event_write(s, 0x50, EVENTLOG_LEVEL_INFO, 1, NULL, 0);
	n = drain_events(sub_fd, ev, 8, 3000);
	ATF_REQUIRE_EQ_MSG(1, n, "expected only the parent's event, got %d", n);
	ATF_CHECK_EQ((uint32_t)0x50, ev[0].event_id);
	for (i = 0; i < n; i++)
		ATF_CHECK_MSG(ev[i].event_id != 0xC1 && ev[i].event_id != 0xC2,
		    "a child event leaked (id %#x)", ev[i].event_id);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

ATF_TC(per_thread_rings_fork_child);
ATF_TC_HEAD(per_thread_rings_fork_child, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a forked child's new PER_THREAD_RINGS provider binds a fresh ring");
}
ATF_TC_BODY(per_thread_rings_fork_child, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[8];
	pid_t pid;
	int sub_fd, n, i, ndata, status;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	eventlog_event_write(s, 0x50, EVENTLOG_LEVEL_INFO, 1, NULL, 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct eventlog_provider *p2;
		struct eventlog_session *s2;

		p2 = eventlog_provider_create(PROVIDER_NAME, &config);
		if (p2 == NULL)
			_exit(1);
		s2 = eventlog_session_create(p2, 0, false, NULL, 0);
		if (s2 == NULL)
			_exit(2);
		eventlog_event_write(s2, 0xC1, EVENTLOG_LEVEL_INFO, 1,
		    NULL, 0);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	eventlog_event_write(s, 0x51, EVENTLOG_LEVEL_INFO, 1, NULL, 0);
	n = drain_events(sub_fd, ev, 8, 3000);
	/*
	 * The child's new same-name provider late-binds to this subscriber
	 * and the kernel emits a PROVIDER_INFO announcement for it. Compact
	 * that (and PROVIDER_BLOB) out before asserting on the data events.
	 */
	for (i = 0, ndata = 0; i < n; i++) {
		if (ev[i].event_id == EVENTLOG_PROVIDER_INFO_ID ||
		    ev[i].event_id == EVENTLOG_PROVIDER_BLOB_ID)
			continue;
		ATF_CHECK_MSG(ev[i].event_id != 0xC1,
		    "a child event leaked (id %#x)", ev[i].event_id);
		ev[ndata++] = ev[i];
	}
	ATF_REQUIRE_EQ_MSG(2, ndata,
	    "expected only the parent's events, got %d", ndata);
	ATF_CHECK_EQ((uint32_t)0x50, ev[0].event_id);
	ATF_CHECK_EQ((uint32_t)0x51, ev[1].event_id);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * 48-byte records do not divide the 64 KB SPSC ring.  Write well over one
 * ring with the subscriber draining between batches so records straddle
 * the wrap; every seq arrives in order.
 */
#define	PTR_WRAP_NREC	3000
#define	PTR_WRAP_BATCH	32

ATF_TC(per_thread_rings_wrap);
ATF_TC_HEAD(per_thread_rings_wrap, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "PER_THREAD_RINGS records that straddle the 64 KB wrap arrive intact");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(per_thread_rings_wrap, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event *got;
	struct stress_payload pl;
	int sub_fd, n, i, last;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	got = calloc(PTR_WRAP_NREC, sizeof(*got));
	ATF_REQUIRE(got != NULL);
	n = 0;
	for (i = 0; i < PTR_WRAP_NREC; ) {
		int k = PTR_WRAP_NREC - i;
		int j, r;

		if (k > PTR_WRAP_BATCH)
			k = PTR_WRAP_BATCH;
		for (j = 0; j < k; j++) {
			pl.thread_idx = 0;
			pl.seq = (uint32_t)(i + j);
			eventlog_event_write(s, pl.seq, EVENTLOG_LEVEL_INFO, 1,
			    &pl, sizeof(pl));
		}
		r = drain_events(sub_fd, got + n, PTR_WRAP_NREC - n, 200);
		n += r;
		i += k;
	}
	if (n < PTR_WRAP_NREC)
		n += drain_accum(sub_fd, got + n, PTR_WRAP_NREC - n,
		    PTR_WRAP_NREC - n, 3000);

	ATF_CHECK_EQ_MSG(0UL, eventlog_test_get_dropped(p),
	    "wrap path dropped %lu", eventlog_test_get_dropped(p));
	ATF_REQUIRE_EQ_MSG(PTR_WRAP_NREC, n, "expected %d events, got %d",
	    PTR_WRAP_NREC, n);
	last = -1;
	for (i = 0; i < n; i++) {
		ATF_REQUIRE_EQ_MSG(sizeof(pl), got[i].payload_len,
		    "event %d bad payload_len %u", i, got[i].payload_len);
		memcpy(&pl, got[i].payload, sizeof(pl));
		ATF_CHECK_EQ_MSG((uint32_t)got[i].event_id, pl.seq,
		    "event_id/payload seq mismatch at %d", i);
		ATF_CHECK_MSG((int)pl.seq > last,
		    "out of order: seq %u after %d", pl.seq, last);
		last = (int)pl.seq;
	}

	free(got);
	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * Concurrent drain against SPSC rings: every write is delivered or counted
 * as a drop.  Per-thread last_ts is independent, so global timestamp order
 * is not required; per-thread seq order is.
 */
ATF_TC(per_thread_rings_vs_drain);
ATF_TC_HEAD(per_thread_rings_vs_drain, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "PER_THREAD_RINGS accounts every write when the kernel drains concurrently");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(per_thread_rings_vs_drain, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct eventlog_stats stats;
	pthread_t th[FIT_STRESS_THREADS], drain_th;
	struct shared_arg args[FIT_STRESS_THREADS];
	struct fit_drain_arg da;
	int last_seq[FIT_STRESS_THREADS];
	int seen[FIT_STRESS_THREADS];
	const int total = FIT_STRESS_THREADS * FIT_STRESS_PER;
	unsigned long lib_dropped, kern_dropped, accounted;
	int sub_fd, i, t;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, FIT_STRESS_SID, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	da.fd = sub_fd;
	da.out = calloc(total, sizeof(*da.out));
	ATF_REQUIRE(da.out != NULL);
	da.cap = total;
	da.got = 0;
	da.stop = 0;
	ATF_REQUIRE(pthread_create(&drain_th, NULL, fit_drain_thread, &da) ==
	    0);

	for (t = 0; t < FIT_STRESS_THREADS; t++) {
		args[t].session = s;
		args[t].idx = t;
		ATF_REQUIRE(pthread_create(&th[t], NULL, fit_stress_writer,
		    &args[t]) == 0);
	}
	for (t = 0; t < FIT_STRESS_THREADS; t++) {
		void *rv;
		ATF_REQUIRE(pthread_join(th[t], &rv) == 0);
		ATF_REQUIRE(rv == NULL);
	}
	da.stop = 1;
	ATF_REQUIRE(pthread_join(drain_th, NULL) == 0);
	if (da.got < total)
		da.got += drain_accum(sub_fd, da.out + da.got, da.cap - da.got,
		    total - da.got, 5000);

	lib_dropped = eventlog_test_get_dropped(p);
	ATF_REQUIRE(ioctl(sub_fd, EVENTLOG_IOCTL_GET_STATS, &stats) == 0);
	kern_dropped = stats.user_dropped_full + stats.user_dropped_prejoin +
	    stats.user_dropped_late;
	accounted = (unsigned long)da.got + lib_dropped + kern_dropped;
	ATF_CHECK_MSG(accounted == (unsigned long)total,
	    "delivered (%d) + lib dropped (%lu) + kernel dropped (%lu) = %lu, "
	    "expected %d -- an event went missing unaccounted for",
	    da.got, lib_dropped, kern_dropped, accounted, total);

	for (t = 0; t < FIT_STRESS_THREADS; t++) {
		last_seq[t] = -1;
		seen[t] = 0;
	}
	for (i = 0; i < da.got; i++) {
		struct stress_payload pl;
		int tidx;

		ATF_REQUIRE_EQ_MSG(sizeof(pl), da.out[i].payload_len,
		    "event %d bad payload_len %u", i, da.out[i].payload_len);
		memcpy(&pl, da.out[i].payload, sizeof(pl));
		ATF_REQUIRE_MSG(pl.thread_idx < FIT_STRESS_THREADS,
		    "event %d bad thread_idx %u", i, pl.thread_idx);
		tidx = (int)pl.thread_idx;
		ATF_CHECK_MSG((int)pl.seq > last_seq[tidx],
		    "thread %d out of order: seq %u after %d", tidx, pl.seq,
		    last_seq[tidx]);
		last_seq[tidx] = (int)pl.seq;
		seen[tidx]++;
	}
	for (t = 0; t < FIT_STRESS_THREADS; t++)
		ATF_CHECK_MSG(seen[t] <= FIT_STRESS_PER,
		    "thread %d got %d events, more than it sent", t, seen[t]);

	free(da.out);
	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * The first provider's flags latch the process channel.  A later create
 * with PER_THREAD_RINGS still shares the commit-wait path, so a slow
 * predecessor is counted in stuck_commit_waits.
 */
ATF_TC(per_thread_rings_first_flag_wins);
ATF_TC_HEAD(per_thread_rings_first_flag_wins, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "the first provider's flags latch the process channel");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(per_thread_rings_first_flag_wins, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p1, *p2;
	struct eventlog_session *s;
	struct slow_pred_arg arg;
	pthread_t th;

	p1 = eventlog_provider_create("umflagA", NULL);
	if (p1 == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p2 = eventlog_provider_create("umflagB", &config);
	ATF_REQUIRE_MSG(p2 != NULL, "second create: %s", strerror(errno));
	s = eventlog_session_create(p2, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	eventlog_test_set_commit_delay_us(5000000);
	arg.s = s;
	ATF_REQUIRE(pthread_create(&th, NULL, slow_pred_writer, &arg) == 0);
	ATF_REQUIRE_MSG(wait_commit_delay_taken(2000) == 0,
	    "predecessor never took the commit delay");
	TEST_EVENTLOG_SIMPLE_EVENT_LOG_ALWAYS(s, 0x2222);
	ATF_REQUIRE(pthread_join(th, NULL) == 0);

	ATF_CHECK_EQ_MSG(0UL, eventlog_test_get_dropped(p2),
	    "shared-path write dropped (%lu)", eventlog_test_get_dropped(p2));
	ATF_CHECK_MSG(eventlog_test_get_stuck_commit_waits(p2) >= 1,
	    "waiter did not count a stuck commit wait; PER_THREAD_RINGS "
	    "leaked onto a shared-ring channel");

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p2);
	eventlog_provider_destroy(p1);
}

/*
 * A payload that cannot fit the 64 KB SPSC ring is dropped; a later small
 * write on the same thread still lands.
 */
ATF_TC(per_thread_rings_oversize_drops);
ATF_TC_HEAD(per_thread_rings_oversize_drops, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a record larger than the per-thread ring is dropped; later writes land");
}
ATF_TC_BODY(per_thread_rings_oversize_drops, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[4];
	void *buf;
	int sub_fd, n;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	buf = malloc(UINT16_MAX);
	ATF_REQUIRE(buf != NULL);
	memset(buf, 0x5a, UINT16_MAX);
	eventlog_event_write(s, 0xEE, EVENTLOG_LEVEL_INFO, 1, buf, UINT16_MAX);
	free(buf);
	ATF_CHECK_EQ_MSG(1UL, eventlog_test_get_dropped(p),
	    "oversize write dropped %lu, expected 1",
	    eventlog_test_get_dropped(p));

	eventlog_event_write(s, 0xEF, EVENTLOG_LEVEL_INFO, 1, NULL, 0);
	n = drain_events(sub_fd, ev, 4, 3000);
	ATF_REQUIRE_EQ_MSG(1, n, "expected the small follow-up event, got %d", n);
	ATF_CHECK_EQ((uint32_t)0xEF, ev[0].event_id);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

ATF_TC(per_thread_rings_varlen);
ATF_TC_HEAD(per_thread_rings_varlen, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "the variable-length gather macro round-trips on a per-thread ring");
}
ATF_TC_BODY(per_thread_rings_varlen, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[2];
	struct test_eventlog_varlen_event head;
	uint64_t src[4] = { 0x11, 0x22, 0x33, 0x44 };
	int sub_fd, n, i;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not become enabled");

	TEST_EVENTLOG_VARLEN_EVENT_LOG(s, 0xCAFEF00D, 4, src);

	n = drain_events(sub_fd, ev, 2, 3000);
	ATF_REQUIRE_EQ_MSG(1, n, "expected 1 event, got %d", n);
	ATF_CHECK_EQ(TEST_EVENTLOG_VARLEN_EVENT_ID, ev[0].event_id);

	memcpy(&head, ev[0].payload, sizeof(head));
	ATF_CHECK_EQ(0xCAFEF00DULL, head.id);
	ATF_CHECK_EQ(4, head.count);
	ATF_REQUIRE_MSG(ev[0].payload_len >= sizeof(head) + 4 * sizeof(uint64_t),
	    "varlen payload too short: %u", ev[0].payload_len);
	for (i = 0; i < 4; i++) {
		uint64_t v;

		memcpy(&v, ev[0].payload + sizeof(head) + i * sizeof(uint64_t),
		    sizeof(v));
		ATF_CHECK_EQ(src[i], v);
	}

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

/*
 * Turn an fd into a subscriber with a single subscription carrying flags
 * (e.g. EVENTLOG_SUBSCRIPTION_DUMP_STATE).  Like do_create() but lets the
 * caller pass subscription flags.
 */
static int
do_create_flags(int fd, const char *provider, enum eventlog_level level,
    uint32_t keywords, uint32_t sub_flags)
{
	return (do_create(fd, 4, provider, level, keywords, sub_flags));
}

/* dump_cb context: the session to replay through, set after open. */
struct dump_cb_ctx {
	struct eventlog_session *s;
	volatile int		fired;
};

static void
test_dump_cb(struct eventlog_provider *provider __unused, void *arg)
{
	struct dump_cb_ctx *c = arg;
	int i;

	/* Writes here are routed to the requesting subscriber via PUSH_DUMP. */
	for (i = 0; i < 3; i++)
		eventlog_event_write(c->s, (uint32_t)(700 + i),
		    EVENTLOG_LEVEL_INFO, 0x1, NULL, 0);
	c->fired = 1;
}

/*
 * The library drives the whole out-of-process dump protocol on its
 * background thread: a DUMP_STATE subscriber triggers the registered
 * dump_cb, whose writes are replayed only to that subscriber and capped
 * with a DUMP_COMPLETE.  A second, plain subscriber sees none of it -- the
 * consumer never calls any dump plumbing itself.
 */
ATF_TC(lib_dump_callback_scoped);
ATF_TC_HEAD(lib_dump_callback_scoped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "a DUMP_STATE subscriber drives the dump_cb; the replay reaches "
	    "only it, ending in DUMP_COMPLETE");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(lib_dump_callback_scoped, tc)
{
	struct eventlog_provider_config config;
	struct dump_cb_ctx ctx = { 0 };
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event g1[16], g2[8];
	int s1, s2, n, i, complete;

	memset(&config, 0, sizeof(config));
	config.dump_callback = test_dump_cb;
	config.dump_callback_arg = &ctx;
	p = eventlog_provider_create("umdump", &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));
	ctx.s = s;	/* the callback replays through this session */

	/* s1 asks for a replay; s2 is an ordinary live subscriber. */
	s1 = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create_flags(s1, "umdump", EVENTLOG_LEVEL_TRACE, ~0u,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE) == 0, "create s1: %s",
	    strerror(errno));
	s2 = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create_flags(s2, "umdump", EVENTLOG_LEVEL_TRACE, ~0u,
	    0) == 0, "create s2: %s", strerror(errno));

	/* The background thread runs the dump_cb and replays to s1 only. */
	n = drain_accum(s1, g1, 16, 4, 5000);
	ATF_REQUIRE_EQ_MSG(4, n,
	    "expected 3 replayed records + DUMP_COMPLETE, got %d", n);
	complete = 0;
	for (i = 0; i < n; i++)
		if (g1[i].event_id == EVENTLOG_DUMP_COMPLETE_ID) {
			complete++;
			ATF_CHECK_EQ(EVENTLOG_SESSION_ID_NONE, g1[i].session_id);
		}
	ATF_CHECK_MSG(ctx.fired != 0, "dump_cb never ran");
	ATF_CHECK_EQ_MSG(1, complete, "expected exactly one DUMP_COMPLETE");

	/* s2 never sees the scoped replay. */
	n = drain_events(s2, g2, 8, 500);
	ATF_CHECK_EQ_MSG(0, n, "plain subscriber saw the dump (%d events)", n);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(s1) == 0);
	ATF_REQUIRE(close(s2) == 0);
}

ATF_TC(per_thread_rings_dump);
ATF_TC_HEAD(per_thread_rings_dump, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "DUMP_STATE replay on a PER_THREAD_RINGS provider reaches only that subscriber");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(per_thread_rings_dump, tc)
{
	struct eventlog_provider_config config;
	struct dump_cb_ctx ctx = { 0 };
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event g1[16], g2[8];
	int s1, s2, n, i, complete;

	memset(&config, 0, sizeof(config));
	config.flags = EVENTLOG_PROVIDER_PER_THREAD_RINGS;
	config.dump_callback = test_dump_cb;
	config.dump_callback_arg = &ctx;
	p = eventlog_provider_create("umdumppt", &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));
	ctx.s = s;

	s1 = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create_flags(s1, "umdumppt", EVENTLOG_LEVEL_TRACE,
	    ~0u, EVENTLOG_SUBSCRIPTION_DUMP_STATE) == 0, "create s1: %s",
	    strerror(errno));
	s2 = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create_flags(s2, "umdumppt", EVENTLOG_LEVEL_TRACE,
	    ~0u, 0) == 0, "create s2: %s", strerror(errno));

	n = drain_accum(s1, g1, 16, 4, 5000);
	ATF_REQUIRE_EQ_MSG(4, n,
	    "expected 3 replayed records + DUMP_COMPLETE, got %d", n);
	complete = 0;
	for (i = 0; i < n; i++)
		if (g1[i].event_id == EVENTLOG_DUMP_COMPLETE_ID) {
			complete++;
			ATF_CHECK_EQ(EVENTLOG_SESSION_ID_NONE, g1[i].session_id);
		}
	ATF_CHECK_MSG(ctx.fired != 0, "dump_cb never ran");
	ATF_CHECK_EQ_MSG(1, complete, "expected exactly one DUMP_COMPLETE");

	n = drain_events(s2, g2, 8, 500);
	ATF_CHECK_EQ_MSG(0, n, "plain subscriber saw the dump (%d events)", n);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(s1) == 0);
	ATF_REQUIRE(close(s2) == 0);
}

/*
 * A lone event written with no explicit flush still arrives: the macro
 * publishes it straight into the submission ring, and the kernel drains the
 * ring from the subscriber's read, so a consumer of this API never has to
 * manage delivery.
 */
/*
 * A lone event written with no explicit flush still arrives: the macro
 * publishes it straight into the submission ring, and the kernel drains the
 * ring from the subscriber's read, so a consumer of this API never has to
 * manage delivery.
 */
ATF_TC(lib_unflushed_event_delivers);
ATF_TC_HEAD(lib_unflushed_event_delivers, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "an un-flushed event reaches the subscriber via the kernel drain");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(lib_unflushed_event_delivers, tc)
{
	struct eventlog_provider *p;
	struct eventlog_session *s;
	struct got_event ev[4];
	int sub_fd, n;

	p = eventlog_provider_create(PROVIDER_NAME, NULL);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}
	s = eventlog_session_create(p, 0, false, NULL, 0);
	ATF_REQUIRE_MSG(s != NULL, "session_create: %s", strerror(errno));

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_level(s, EVENTLOG_LEVEL_TRACE, 1000) == 0,
	    "provider did not enable");

	/* No flush call: the ring write alone must suffice for delivery. */
	TEST_EVENTLOG_SIMPLE_EVENT_LOG(s, 0xF00DF00D);

	n = drain_events(sub_fd, ev, 4, 3000);
	ATF_REQUIRE_EQ_MSG(1, n, "un-flushed event was not delivered (%d)", n);
	ATF_CHECK_EQ(TEST_EVENTLOG_SIMPLE_EVENT_ID, ev[0].event_id);

	eventlog_session_destroy(s);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
}

struct subs_cb_ctx {
	volatile int	last;	/* last has_subscribers seen (-1 = none yet) */
	volatile int	calls;
};

static void
test_subs_cb(struct eventlog_provider *provider __unused, bool has_subscribers,
    void *arg)
{
	struct subs_cb_ctx *c = arg;

	c->last = has_subscribers;
	c->calls++;
}

/* Poll until *v == want or the deadline passes; return 0 on match. */
static int
wait_int(volatile int *v, int want, int timeout_ms)
{
	int waited = 0;

	while (*v != want) {
		if (waited >= timeout_ms)
			return (-1);
		usleep(5000);
		waited += 5;
	}
	return (0);
}

/*
 * The library delivers the 0<->N subscriber transition to the registered
 * subscribers_cb on its background thread, with no work on the producer's
 * hot path.
 */
ATF_TC(lib_subscribers_callback);
ATF_TC_HEAD(lib_subscribers_callback, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "subscribers_cb fires with 1 when a consumer attaches and 0 when "
	    "the last leaves");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(lib_subscribers_callback, tc)
{
	struct eventlog_provider_config config;
	struct subs_cb_ctx ctx = { .last = -1, .calls = 0 };
	struct eventlog_provider *p;
	int sub_fd;

	memset(&config, 0, sizeof(config));
	config.subscribers_changed = test_subs_cb;
	config.subscribers_changed_arg = &ctx;
	p = eventlog_provider_create("umsubs", &config);
	if (p == NULL) {
		if (errno == ENOENT)
			atf_tc_skip("%s not present", DEV_EVENTLOG);
		if (geteuid() != 0)
			atf_tc_skip("must run as root");
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));
	}

	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 4, "umsubs", EVENTLOG_LEVEL_TRACE,
	    ~0u, 0) == 0, "create: %s", strerror(errno));
	ATF_REQUIRE_MSG(wait_int(&ctx.last, 1, 2000) == 0,
	    "subscribers_cb(1) never fired (last=%d)", ctx.last);

	ATF_REQUIRE(close(sub_fd) == 0);
	ATF_REQUIRE_MSG(wait_int(&ctx.last, 0, 2000) == 0,
	    "subscribers_cb(0) never fired (last=%d)", ctx.last);

	eventlog_provider_destroy(p);
}

/*
 * A user-space provider that registers a decode blob makes that blob, and the
 * derived schema_id, available to subscribers exactly like a kernel provider:
 * EVENTLOG_IOCTL_GET_DECODE_BLOB returns the bytes by registered name and by
 * schema_id, and GET_PROVIDERS reports a non-zero schema_id.
 */
ATF_TC(lib_decode_blob_registered);
ATF_TC_HEAD(lib_decode_blob_registered, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lib_decode_blob_registered, tc)
{
	struct eventlog_provider_config config;
	struct eventlog_get_decode_blob_req req;
	struct eventlog_provider *p;
	uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	uint8_t *got;
	int fd, sub_fd;
	bool zero_id;

	fd = open_dev_or_skip();

	memset(&config, 0, sizeof(config));
	config.decode_blob = test_eventlog_decode_blob;
	config.decode_blob_size = test_eventlog_decode_blob_size;
	p = eventlog_provider_create(PROVIDER_NAME, &config);
	if (p == NULL)
		atf_tc_fail("eventlog_provider_create: %s", strerror(errno));

	/* Size probe by registered name. */
	memset(&req, 0, sizeof(req));
	strlcpy(req.provider_name, PROVIDER_NAME, sizeof(req.provider_name));
	req.lookup_kind = EVENTLOG_DECODE_LOOKUP_NAME;
	ATF_REQUIRE_MSG(ioctl(fd, EVENTLOG_IOCTL_GET_DECODE_BLOB, &req) == 0,
	    "GET_DECODE_BLOB probe: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(test_eventlog_decode_blob_size, req.blob_size,
	    "probe size %u != registered %u", req.blob_size,
	    test_eventlog_decode_blob_size);

	/* Fetch by name and compare bytes. */
	got = malloc(req.blob_size);
	ATF_REQUIRE(got != NULL);
	req.buf = (uint64_t)(uintptr_t)got;
	req.buf_size = test_eventlog_decode_blob_size;
	ATF_REQUIRE_MSG(ioctl(fd, EVENTLOG_IOCTL_GET_DECODE_BLOB, &req) == 0,
	    "GET_DECODE_BLOB fetch: %s", strerror(errno));
	ATF_CHECK_EQ(test_eventlog_decode_blob_size, req.blob_size);
	ATF_CHECK_MSG(memcmp(got, test_eventlog_decode_blob,
	    test_eventlog_decode_blob_size) == 0,
	    "fetched blob differs from registered blob");

	/*
	 * Subscribe to learn the kernel-derived schema_id (GET_PROVIDERS lists
	 * the subscriber's providers), assert it is non-zero, then resolve the
	 * blob by schema_id.
	 */
	sub_fd = open_dev_or_skip();
	ATF_REQUIRE_MSG(do_create(sub_fd, 0, PROVIDER_NAME,
	    EVENTLOG_LEVEL_TRACE, ~0u, 0) == 0, "do_create: %s",
	    strerror(errno));
	{
		struct eventlog_get_providers_resp *provs;
		size_t base = __builtin_offsetof(
		    struct eventlog_get_providers_resp, providers);
		uint32_t cap = 16, k;
		bool found = false;

		provs = calloc(1, base + cap * sizeof(provs->providers[0]));
		ATF_REQUIRE(provs != NULL);
		provs->count = cap;
		ATF_REQUIRE(ioctl(sub_fd,
		    EVENTLOG_IOCTL_GET_PROVIDERS_SIZE(cap), provs) == 0);
		for (k = 0; k < provs->count && k < cap; k++) {
			if (strcmp(provs->providers[k].name,
			    PROVIDER_NAME) == 0) {
				memcpy(schema_id, provs->providers[k].schema_id,
				    sizeof(schema_id));
				found = true;
				break;
			}
		}
		free(provs);
		ATF_REQUIRE_MSG(found, "provider not in GET_PROVIDERS");
	}

	zero_id = true;
	for (size_t i = 0; i < sizeof(schema_id); i++)
		if (schema_id[i] != 0)
			zero_id = false;
	ATF_CHECK_MSG(!zero_id, "schema_id is all zero for a blob provider");

	memset(&req, 0, sizeof(req));
	memcpy(req.schema_id, schema_id, sizeof(req.schema_id));
	req.lookup_kind = EVENTLOG_DECODE_LOOKUP_SCHEMA_ID;
	req.buf = (uint64_t)(uintptr_t)got;
	req.buf_size = test_eventlog_decode_blob_size;
	ATF_REQUIRE_MSG(ioctl(fd, EVENTLOG_IOCTL_GET_DECODE_BLOB, &req) == 0,
	    "GET_DECODE_BLOB by schema_id: %s", strerror(errno));
	ATF_CHECK_EQ(test_eventlog_decode_blob_size, req.blob_size);
	ATF_CHECK_MSG(memcmp(got, test_eventlog_decode_blob,
	    test_eventlog_decode_blob_size) == 0,
	    "schema_id-fetched blob differs");

	free(got);
	eventlog_provider_destroy(p);
	ATF_REQUIRE(close(sub_fd) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, enablement_gate_via_mmap);
	ATF_TP_ADD_TC(tp, commit_waits_for_slow_predecessor);
	ATF_TP_ADD_TC(tp, sessions_enabled_counting);
	ATF_TP_ADD_TC(tp, concurrent_writers_vs_drain_fit_check);
	ATF_TP_ADD_TC(tp, end_to_end_macro);
	ATF_TP_ADD_TC(tp, varlen_macro);
	ATF_TP_ADD_TC(tp, large_burst_delivered);
	ATF_TP_ADD_TC(tp, multi_provider_one_push);
	ATF_TP_ADD_TC(tp, multi_session_threads);
	ATF_TP_ADD_TC(tp, multi_thread_shared_session);
	ATF_TP_ADD_TC(tp, per_thread_rings);
	ATF_TP_ADD_TC(tp, per_thread_rings_supported);
	ATF_TP_ADD_TC(tp, per_thread_rings_wrap);
	ATF_TP_ADD_TC(tp, per_thread_rings_vs_drain);
	ATF_TP_ADD_TC(tp, per_thread_rings_first_flag_wins);
	ATF_TP_ADD_TC(tp, per_thread_rings_oversize_drops);
	ATF_TP_ADD_TC(tp, per_thread_rings_varlen);
	ATF_TP_ADD_TC(tp, session_enablement_dispositions);
	ATF_TP_ADD_TC(tp, fork_child_drops);
	ATF_TP_ADD_TC(tp, per_thread_rings_fork_child);
	ATF_TP_ADD_TC(tp, lib_dump_callback_scoped);
	ATF_TP_ADD_TC(tp, per_thread_rings_dump);
	ATF_TP_ADD_TC(tp, lib_unflushed_event_delivers);
	ATF_TP_ADD_TC(tp, lib_subscribers_callback);
	ATF_TP_ADD_TC(tp, lib_decode_blob_registered);
	return (atf_no_error());
}
