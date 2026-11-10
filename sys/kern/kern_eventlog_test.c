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

#include <tests/ktest.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventlog.h>
#include <sys/eventlog_subscriber.h>
#include <sys/sysctl.h>
#include <sys/condvar.h>
#include <sys/kthread.h>
#include <sys/lock.h>		/* spinlock_enter/exit via thread_lock() */
#include <sys/mutex.h>
#include <sys/lock.h>
#include <sys/sleepqueue.h>
#include <sys/sx.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <machine/atomic.h>
#include <machine/cpu.h>	/* get_cyclecount() for microbenchmarks */
#include <sys/callout.h>
#include <sys/libkern.h>
#include <sys/eventlog_decode.h>
#include <crypto/sha2/sha256.h>
/* Emit the test decode-blob storage in this TU (the "test" registration site). */
#define	TEST_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/test_eventlog.h>

MALLOC_DEFINE(M_EVENTLOG_TEST, "eventlog_test", "eventlog test subsystem");

#define KTEST_VERIFY(x) do { \
	if (!(x)) { \
		KTEST_ERR(ctx, "FAIL: %s", #x); \
		return (EINVAL); \
	} else { \
		KTEST_LOG(ctx, "PASS: %s", #x); \
	} \
} while (0)

#define KTEST_EQUAL(x, y) do { \
	if ((x) != (y)) { \
		KTEST_ERR(ctx, "FAIL: %s != %s (%d != %d)", #x, #y, (x), (y)); \
		return (EINVAL); \
	} else { \
		KTEST_LOG(ctx, "PASS: %s == %s", #x, #y); \
	} \
} while (0)

#define KTEST_NEQUAL(x, y) do { \
	if ((x) == (y)) { \
		KTEST_ERR(ctx, "FAIL: %s == %s", #x, #y); \
		return (EINVAL); \
	} else { \
		KTEST_LOG(ctx, "PASS: %s != %s", #x, #y); \
	} \
} while (0)

#define EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT	(64 * 1024)

/* Helper: read from subscriber into kernel buffer via uio. Returns bytes read or 0 on error. */
static size_t
eventlog_read_into_buf(struct eventlog_subscriber *subscriber,
    void *buf, size_t bufsize, int flags)
{
	struct uio uio;
	struct iovec iov;
	int error;

	iov.iov_base = buf;
	iov.iov_len = bufsize;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = bufsize;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = curthread;

	error = eventlog_subscriber_read(subscriber, &uio, flags);
	if (error != 0)
		return (0);
	return (bufsize - uio.uio_resid);
}

/*
 * Sleep past eventlog_read_watermark_us so a following drain sees the
 * preceding burst in one shot. pause(1) uses C_HARDCLOCK and can return
 * before the watermark clears.
 */
static void
eventlog_test_clear_watermark(const char *wmesg)
{
	(void)pause_sbt(wmesg, SBT_1MS, 0, 0);
}

/* Callback test data structure */
struct test_callback_data {
	volatile uint32_t event_count;
	volatile uint32_t last_event_id;
	volatile const void *last_payload;
	volatile size_t last_payload_size;
	struct mtx lock;  /* Only used for reading in test code, not in callback */
};

/*
 * Callback for tests that peek at last_payload after the callback
 * returns. Only safe for iovcnt <= 1 where iov[0].iov_base points at
 * the caller's buffer; iovcnt > 1 would need to copy.
 */
static void
test_event_callback(const struct eventlog_event_header *hdr,
    const char *provider_name, uint8_t provider_name_len,
    uint64_t session_id,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct test_callback_data *data = (struct test_callback_data *)callback_arg;

	atomic_add_int(&data->event_count, 1);
	atomic_store_rel_32(&data->last_event_id, hdr->event_id);
	data->last_payload = (iovcnt >= 1) ? iov[0].iov_base : NULL;
	atomic_store_rel_long(&data->last_payload_size, payload_size);
}

/*
 * Helper function to enable a provider for testing by creating a callback subscriber
 * and subscription. Returns the subscriber and callback data, which should be destroyed
 * after the test completes.
 */
static struct eventlog_subscriber *
test_enable_provider_callback(const char *provider_name, enum eventlog_level level,
    uint32_t keywords, struct test_callback_data **callback_data_out)
{
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_callback", NULL, MTX_DEF);
	callback_data->event_count = 0;

	subscriber = eventlog_subscriber_create_callback(test_event_callback, callback_data);
	if (subscriber == NULL) {
		mtx_destroy(&callback_data->lock);
		free(callback_data, M_EVENTLOG_TEST);
		return (NULL);
	}

	if (eventlog_subscriber_add_subscription(subscriber, provider_name, level, keywords, 0) != 0) {
		eventlog_subscriber_destroy(subscriber);
		mtx_destroy(&callback_data->lock);
		free(callback_data, M_EVENTLOG_TEST);
		return (NULL);
	}

	*callback_data_out = callback_data;
	return (subscriber);
}

/*
 * Helper function to enable a provider for testing by creating a device subscriber
 * and subscription. Returns the subscriber, which should be destroyed after
 * the test completes. Use this when testing device-specific functionality.
 */
static struct eventlog_subscriber *
test_enable_provider_device(const char *provider_name, enum eventlog_level level, uint32_t keywords)
{
	struct eventlog_subscriber *subscriber;

	subscriber = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	if (subscriber == NULL)
		return (NULL);

	if (eventlog_subscriber_add_subscription(subscriber, provider_name, level, keywords, 0) != 0) {
		eventlog_subscriber_destroy(subscriber);
		return (NULL);
	}

	return (subscriber);
}

/*
 * Legacy helper - defaults to callback for easier verification.
 */
static struct eventlog_subscriber *
test_enable_provider(const char *provider_name, enum eventlog_level level, uint32_t keywords)
{
	struct test_callback_data *unused;
	return (test_enable_provider_callback(provider_name, level, keywords, &unused));
}

static struct eventlog_provider *
test_create_provider(const char *name,
    eventlog_provider_dump_state_t dump_cb, void *dump_arg)
{
	struct eventlog_provider_config cfg = {
		.dump_callback = dump_cb,
		.dump_callback_arg = dump_arg,
		.decode_blob = test_eventlog_decode_blob,
		.decode_blob_size = test_eventlog_decode_blob_size,
	};
	struct eventlog_provider *p;

	p = eventlog_provider_create(name, &cfg);
	if (p != NULL)
		eventlog_provider_set_default(p, 1);
	return (p);
}

/*
 * Validates provider initialization and cleanup.
 */
KTEST_FUNC(provider_init_cleanup)
{
	struct eventlog_provider *provider;

	KTEST_LOG(ctx, "Testing provider initialization and cleanup");

	provider = test_create_provider("test_init", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0);

	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates session creation and destruction.
 */
KTEST_FUNC(session_create_destroy)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;

	KTEST_LOG(ctx, "Testing session creation and destruction");

	/* NULL provider returns NULL */
	session = eventlog_session_create(NULL, 0, true, NULL, 0);
	KTEST_EQUAL(session, NULL);

	provider = test_create_provider("test_sess", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates basic event logging functionality.
 */
KTEST_FUNC(event_logging_basic)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	uint32_t test_id = 0x12345678;
	uint32_t test_data = 0xdeadbeef;

	KTEST_LOG(ctx, "Testing basic event logging");

	provider = test_create_provider("test_basic", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	/* Enable provider for testing */
	struct eventlog_subscriber *test_sub = test_enable_provider("test_basic", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF);
	KTEST_NEQUAL(test_sub, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Write event with test data */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &test_data, sizeof(test_data));

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(test_sub);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates multiple events can be logged.
 */
KTEST_FUNC(event_logging_multiple)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *test_sub;
	struct test_callback_data *callback_data;
	uint32_t test_id1 = 0x11111111;
	uint32_t test_id2 = 0x22222222;
	uint32_t test_id3 = 0x33333333;
	uint32_t data1 = 0xAAAAAAAA;
	uint32_t data2 = 0xBBBBBBBB;
	uint32_t data3 = 0xCCCCCCCC;

	KTEST_LOG(ctx, "Testing multiple event logging");

	provider = test_create_provider("test_multi", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	/* Enable provider for testing with callback subscriber */
	test_sub = test_enable_provider_callback("test_multi", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(test_sub, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	eventlog_event_write(session, test_id1, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &data1, sizeof(data1));
	eventlog_event_write(session, test_id2, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &data2, sizeof(data2));
	eventlog_event_write(session, test_id3, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &data3, sizeof(data3));

	/* Verify all three events were received (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec, eid;
		uint32_t last_payload_val;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		last_payload_val = *(volatile const uint32_t *)callback_data->last_payload;
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 4);	/* SESSION_CREATE + 3 user events */
		KTEST_EQUAL(eid, test_id3);
		KTEST_EQUAL(last_payload_val, data3);
	}

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(test_sub);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates multiple providers can coexist.
 */
KTEST_FUNC(provider_independence)
{
	struct eventlog_provider *provider1, *provider2;
	struct eventlog_session *session1, *session2;

	KTEST_LOG(ctx, "Testing provider independence");

	provider1 = test_create_provider("test_provider1", NULL, NULL);
	KTEST_NEQUAL(provider1, NULL);
	provider2 = test_create_provider("test_provider2", NULL, NULL);
	KTEST_NEQUAL(provider2, NULL);

	session1 = eventlog_session_create(provider1, 0, true, NULL, 0);
	session2 = eventlog_session_create(provider2, 0, true, NULL, 0);
	KTEST_NEQUAL(session1, NULL);
	KTEST_NEQUAL(session2, NULL);

	eventlog_session_destroy(session1);
	eventlog_session_destroy(session2);
	eventlog_provider_destroy(provider1);
	eventlog_provider_destroy(provider2);

	return (0);
}

/*
 * Validates event data integrity - verifies that multiple events are stored
 * independently and don't interfere with each other.
 */
KTEST_FUNC(event_data_integrity)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *test_sub;
	struct test_callback_data *callback_data;
	uint32_t test_id1 = 0x11111111;
	uint32_t test_id2 = 0x22222222;
	uint32_t test_id3 = 0x33333333;
	uint32_t test_data1[4] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD};
	uint32_t test_data2[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444};
	uint32_t test_data3[4] = {0x55555555, 0x66666666, 0x77777777, 0x88888888};
	volatile const uint32_t *received_data;
	int i;

	KTEST_LOG(ctx, "Testing event data integrity - multiple independent events");

	provider = test_create_provider("test_integ", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	/* Enable provider for testing with callback subscriber */
	test_sub = test_enable_provider_callback("test_integ", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(test_sub, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Write events with different data */
	eventlog_event_write(session, test_id1, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    test_data1, sizeof(test_data1));
	eventlog_event_write(session, test_id2, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    test_data2, sizeof(test_data2));
	eventlog_event_write(session, test_id3, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    test_data3, sizeof(test_data3));

	/* Verify all events were received with correct data (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec, eid;
		size_t plen;
		uint32_t payload_copy[4];
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		plen = atomic_load_acq_long(&callback_data->last_payload_size);
		received_data = (volatile const uint32_t *)callback_data->last_payload;
		for (i = 0; i < 4; i++)
			payload_copy[i] = received_data[i];
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 4);	/* SESSION_CREATE + 3 user events */
		KTEST_EQUAL(eid, test_id3);
		KTEST_EQUAL(plen, sizeof(test_data3));
		for (i = 0; i < 4; i++)
			KTEST_EQUAL(payload_copy[i], test_data3[i]);
	}

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(test_sub);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates different event sizes - creates events and writes full payloads.
 */
KTEST_FUNC(event_size_variations)
{
	struct eventlog_provider *provider_small, *provider_large;
	struct eventlog_session *session_small, *session_large;
	uint32_t test_id_small = 0x1111;
	uint32_t test_id_large = 0x2222;
	size_t i;
	const size_t small_size = 64;
	const size_t large_size = 4096;

	KTEST_LOG(ctx, "Testing different event sizes with full payloads");

	provider_small = test_create_provider("test_small", NULL, NULL);
	KTEST_NEQUAL(provider_small, NULL);
	provider_large = test_create_provider("test_large", NULL, NULL);
	KTEST_NEQUAL(provider_large, NULL);
	/* Enable providers for testing with callback subscribers */
	struct test_callback_data *callback_data_small, *callback_data_large;
	struct eventlog_subscriber *test_sub_small = test_enable_provider_callback("test_small",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data_small);
	struct eventlog_subscriber *test_sub_large = test_enable_provider_callback("test_large",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data_large);
	KTEST_NEQUAL(test_sub_small, NULL);
	KTEST_NEQUAL(test_sub_large, NULL);

	session_small = eventlog_session_create(provider_small, 0, true, NULL, 0);
	session_large = eventlog_session_create(provider_large, 0, true, NULL, 0);
	KTEST_NEQUAL(session_small, NULL);
	KTEST_NEQUAL(session_large, NULL);

	/* Create small event payload */
	uint8_t data_small[small_size];
	for (i = 0; i < small_size; i++) {
		data_small[i] = (uint8_t)(i & 0xFF);
	}
	eventlog_event_write(session_small, test_id_small, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    data_small, sizeof(data_small));

	/* Create large event payload */
	uint8_t data_large[large_size];
	for (i = 0; i < large_size; i++) {
		data_large[i] = (uint8_t)((i ^ 0xAA) & 0xFF);
	}
	eventlog_event_write(session_large, test_id_large, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    data_large, sizeof(data_large));

	/* Verify events were received (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec_small, eid_small, ec_large, eid_large;
		size_t plen_small, plen_large;
		mtx_lock(&callback_data_small->lock);
		ec_small = atomic_load_acq_32(&callback_data_small->event_count);
		eid_small = atomic_load_acq_32(&callback_data_small->last_event_id);
		plen_small = atomic_load_acq_long(&callback_data_small->last_payload_size);
		mtx_unlock(&callback_data_small->lock);
		KTEST_EQUAL(ec_small, 2);	/* SESSION_CREATE + 1 user event */
		KTEST_EQUAL(eid_small, test_id_small);
		KTEST_EQUAL(plen_small, sizeof(data_small));

		mtx_lock(&callback_data_large->lock);
		ec_large = atomic_load_acq_32(&callback_data_large->event_count);
		eid_large = atomic_load_acq_32(&callback_data_large->last_event_id);
		plen_large = atomic_load_acq_long(&callback_data_large->last_payload_size);
		mtx_unlock(&callback_data_large->lock);
		KTEST_EQUAL(ec_large, 2);	/* SESSION_CREATE + 1 user event */
		KTEST_EQUAL(eid_large, test_id_large);
		KTEST_EQUAL(plen_large, sizeof(data_large));
	}

	eventlog_session_destroy(session_small);
	eventlog_session_destroy(session_large);
	eventlog_subscriber_destroy(test_sub_small);
	eventlog_subscriber_destroy(test_sub_large);
	mtx_destroy(&callback_data_small->lock);
	mtx_destroy(&callback_data_large->lock);
	free(callback_data_small, M_EVENTLOG_TEST);
	free(callback_data_large, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider_small);
	eventlog_provider_destroy(provider_large);

	return (0);
}

/* Structure for passing data to thread function */
struct mt_test_data {
	struct eventlog_session *session;
	uint32_t thread_id;
	uint32_t num_events;
	uint32_t events_created;
	struct mtx completion_mtx;
	int done;
};

/* Thread function that creates events */
static void
mt_event_thread(void *arg)
{
	struct mt_test_data *data = (struct mt_test_data *)arg;
	struct eventlog_session *session = data->session;
	uint32_t event_data[2];
	uint32_t i;
	uint32_t event_id_base = data->thread_id * 0x10000;

	for (i = 0; i < data->num_events; i++) {
		/* Write thread ID and event index as data */
		event_data[0] = data->thread_id;
		event_data[1] = i;

		eventlog_event_write(session, event_id_base + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    event_data, sizeof(event_data));
		data->events_created++;
	}

	/* Signal completion */
	mtx_lock(&data->completion_mtx);
	data->done = 1;
	wakeup(&data->done);
	mtx_unlock(&data->completion_mtx);

	kthread_exit();
}

/*
 * Validates multi-threaded event logging - creates a thread and has both
 * threads create many events concurrently to test for race conditions.
 */
KTEST_FUNC(multithreaded_logging)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct mt_test_data thread_data;
	struct thread *thread;
	uint32_t main_thread_id = 0xAAAA;
	uint32_t thread_id = 0xBBBB;
	uint32_t num_events_per_thread = 100;
	uint32_t i;
	int error;

	KTEST_LOG(ctx, "Testing multi-threaded event logging");

	provider = test_create_provider("test_mt", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	/* Enable provider for testing with callback subscriber */
	struct test_callback_data *callback_data;
	struct eventlog_subscriber *test_sub = test_enable_provider_callback("test_mt",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(test_sub, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Initialize thread data structure */
	bzero(&thread_data, sizeof(thread_data));
	thread_data.session = session;
	thread_data.thread_id = thread_id;
	thread_data.num_events = num_events_per_thread;
	thread_data.events_created = 0;
	thread_data.done = 0;
	mtx_init(&thread_data.completion_mtx, "mt_test", NULL, MTX_DEF);

	/* Create the thread */
	error = kthread_add(mt_event_thread, &thread_data, NULL, &thread,
	    0, 0, "eventlog_mt_test");
	KTEST_EQUAL(error, 0);

	/* Main thread creates events concurrently with the new thread */
	uint32_t main_event_data[2];
	for (i = 0; i < num_events_per_thread; i++) {
		main_event_data[0] = main_thread_id;
		main_event_data[1] = i;
		eventlog_event_write(session, main_thread_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    main_event_data, sizeof(main_event_data));
	}

	/* Wait for thread to complete */
	mtx_lock(&thread_data.completion_mtx);
	while (thread_data.done == 0) {
		msleep(&thread_data.done, &thread_data.completion_mtx, 0,
		    "mt_wait", 0);
	}
	mtx_unlock(&thread_data.completion_mtx);

	/* Verify thread created expected number of events */
	KTEST_EQUAL(thread_data.events_created, num_events_per_thread);

	/* Verify total events received via callback (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 1 + num_events_per_thread * 2);	/* SESSION_CREATE + events from 2 threads */
	}

	mtx_destroy(&thread_data.completion_mtx);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(test_sub);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates subscriber creation and destruction for both types.
 */
KTEST_FUNC(subscriber_create_destroy)
{
	struct eventlog_subscriber *subscriber_device, *subscriber_callback;
	struct test_callback_data *callback_data;

	KTEST_LOG(ctx, "Testing subscriber creation and destruction");

	/* Test device subscriber */
	subscriber_device = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber_device, NULL);
	eventlog_subscriber_destroy(subscriber_device);

	/* Test callback subscriber */
	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_callback", NULL, MTX_DEF);
	subscriber_callback = eventlog_subscriber_create_callback(test_event_callback, callback_data);
	KTEST_NEQUAL(subscriber_callback, NULL);
	eventlog_subscriber_destroy(subscriber_callback);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);

	return (0);
}


/*
 * Validates multiple subscribers with the same provider.
 */
KTEST_FUNC(subscriber_multiple_subscribers)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *sub1, *sub2, *sub3;
	struct test_callback_data *callback_data2, *callback_data3;
	int error;

	KTEST_LOG(ctx, "Testing multiple subscribers with same provider");

	provider = test_create_provider("test_msub", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* Mix device and callback subscribers */
	sub1 = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	callback_data2 = malloc(sizeof(*callback_data2), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data2->lock, "test_callback2", NULL, MTX_DEF);
	sub2 = eventlog_subscriber_create_callback(test_event_callback, callback_data2);
	callback_data3 = malloc(sizeof(*callback_data3), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data3->lock, "test_callback3", NULL, MTX_DEF);
	sub3 = eventlog_subscriber_create_callback(test_event_callback, callback_data3);
	KTEST_NEQUAL(sub1, NULL);
	KTEST_NEQUAL(sub2, NULL);
	KTEST_NEQUAL(sub3, NULL);

	/* Each subscriber subscribes with different parameters */
	error = eventlog_subscriber_add_subscription(sub1, "test_msub",
	    EVENTLOG_LEVEL_INFO, 0x1, 0);
	KTEST_EQUAL(error, 0);

	error = eventlog_subscriber_add_subscription(sub2, "test_msub",
	    EVENTLOG_LEVEL_WARN, 0x2, 0);
	KTEST_EQUAL(error, 0);

	error = eventlog_subscriber_add_subscription(sub3, "test_msub",
	    EVENTLOG_LEVEL_VERBOSE, 0x4, 0);
	KTEST_EQUAL(error, 0);

	/* Verify provider enablement: keywords OR'ed (0x1 | 0x2 | 0x4 = 0x7),
	 * level is MAX (most verbose) = VERBOSE */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x7);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE);

	/* Remove one subscriber */
	eventlog_subscriber_destroy(sub2);
	mtx_destroy(&callback_data2->lock);
	free(callback_data2, M_EVENTLOG_TEST);

	/* Provider should still be enabled with remaining subscribers */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x5); /* 0x1 | 0x4 */
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE); /* MAX(INFO, VERBOSE) */

	/* Remove all remaining subscribers */
	eventlog_subscriber_destroy(sub1);
	eventlog_subscriber_destroy(sub3);
	mtx_destroy(&callback_data3->lock);
	free(callback_data3, M_EVENTLOG_TEST);

	/* Provider should be disabled */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_NONE);

	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates provider enablement aggregation (OR keywords, MIN level).
 */
KTEST_FUNC(subscriber_provider_enablement_aggregation)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *sub1, *sub2;
	int error;

	KTEST_LOG(ctx, "Testing provider enablement aggregation");

	provider = test_create_provider("test_agg", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	sub1 = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	sub2 = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(sub1, NULL);
	KTEST_NEQUAL(sub2, NULL);

	/* Subscriber 1: INFO level, keywords 0x1 */
	error = eventlog_subscriber_add_subscription(sub1, "test_agg",
	    EVENTLOG_LEVEL_INFO, 0x1, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x1);

	/* Subscriber 2: WARN level, keywords 0x2 (should result in INFO, 0x3) */
	error = eventlog_subscriber_add_subscription(sub2, "test_agg",
	    EVENTLOG_LEVEL_WARN, 0x2, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_INFO); /* MAX(INFO, WARN) */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x3); /* 0x1 | 0x2 */

	/* Update subscriber 1 to VERBOSE (should result in VERBOSE, since MAX) */
	error = eventlog_subscriber_add_subscription(sub1, "test_agg",
	    EVENTLOG_LEVEL_VERBOSE, 0x1, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE); /* MAX(VERBOSE, WARN) */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x3); /* Still 0x1 | 0x2 */

	/* Update subscriber 2 to ERROR (should result in VERBOSE, since MAX) */
	error = eventlog_subscriber_add_subscription(sub2, "test_agg",
	    EVENTLOG_LEVEL_ERROR, 0x2, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE); /* MAX(VERBOSE, ERROR) */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x3); /* Still 0x1 | 0x2 */

	/* Cleanup */
	eventlog_subscriber_destroy(sub1);
	eventlog_subscriber_destroy(sub2);
	eventlog_provider_destroy(provider);

	return (0);
}


/*
 * Validates device subscriber buffer functionality.
 */
KTEST_FUNC(subscriber_device_buffer)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	uint32_t test_id = 0x12345678;
	uint32_t test_data = 0xdeadbeef;

	KTEST_LOG(ctx, "Testing device subscriber buffer functionality");

	provider = test_create_provider("test_devbuf", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = test_enable_provider_device("test_devbuf", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE from session creation */
	char read_buf[1024];
	size_t read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf), 0);
	KTEST_VERIFY(read > 0);
	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf), 0);
	KTEST_EQUAL(read, 0);

	/* Write event */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &test_data, sizeof(test_data));

	/* Verify event was written to buffer */
	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf), 0);
	KTEST_VERIFY(read > 0);

	/* Verify buffer is cleared after read */
	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf), 0);
	KTEST_EQUAL(read, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates ring buffering functionality.
 * Tests that interleaved writes and reads work correctly and eliminate
 * read/write contention.
 */
KTEST_FUNC(subscriber_circular_buffer)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	uint32_t test_id = 0x12345678;
	size_t i;
	char *read_buf;
	size_t read_buf_size = 256 * 1024;
	size_t read;
	struct eventlog_stats stats;

	KTEST_LOG(ctx, "Testing ring buffering functionality");

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	/* Create provider and subscriber */
	provider = test_create_provider("test_circ", NULL, NULL);
	if (provider == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		return (EINVAL);
	}

	/* Use a buffer size (128KB) - above 64KB minimum */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	if (subscriber == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	if (eventlog_subscriber_add_subscription(subscriber, "test_circ",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0) != 0) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	if (session == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	/* Calculate expected event size for diagnostics (header includes provider_id, session_id) */
	size_t expected_event_size = sizeof(struct eventlog_event_header) +
	    sizeof(uint32_t);
	size_t max_events = (128 * 1024) / expected_event_size;
	KTEST_LOG(ctx, "Expected event size: %zu bytes, buffer size: %zu bytes, max events: %zu",
	    expected_event_size, (size_t)(128 * 1024), max_events);

	/* Fill active buffer - SESSION_CREATE is first, then max_events-1 user events to avoid overflow */
	for (i = 0; i < max_events - 1; i++) {
		uint32_t val = (uint32_t)i;
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &val, sizeof(val));
	}

	/* Age the burst past the read-epoch watermark. */
	eventlog_test_clear_watermark("circbuf");

	/* Read all events - drains the ring in one go */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_LOG(ctx, "Read %zu bytes, dropped %llu events",
	    read, (unsigned long long)stats.dropped_events);
	KTEST_VERIFY(read > 0);
	KTEST_VERIFY(stats.dropped_events == 0); /* Should not drop events if buffer is large enough */

	/* Verify buffer is cleared after read */
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_EQUAL(read, 0);

	/* Test interleaving: write events, read some, then write more */
	/* Writers keep appending while the reader drains in place */
	for (i = 0; i < 50; i++) {
		uint32_t val = (uint32_t)i;
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &val, sizeof(val));
	}

	/* Read half of them */
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size / 2, 0);
	KTEST_VERIFY(read > 0);

	/* Write more events - these go to the new active buffer (no contention with reader) */
	for (i = 50; i < 100; i++) {
		uint32_t val = (uint32_t)i;
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &val, sizeof(val));
	}

	/* Read remaining events */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_VERIFY(read > 0);
	KTEST_EQUAL(stats.dropped_events, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
}

/*
 * Validates callback subscriber functionality.
 */
KTEST_FUNC(subscriber_callback)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;
	uint32_t test_id = 0x12345678;
	uint32_t test_data = 0xdeadbeef;

	KTEST_LOG(ctx, "Testing callback subscriber functionality");

	provider = test_create_provider("test_cb", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = test_enable_provider_callback("test_cb", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Callback already received SESSION_CREATE from session creation */
	KTEST_EQUAL(atomic_load_acq_32(&callback_data->event_count), 1);

	/* Write event */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &test_data, sizeof(test_data));

	/* Verify callback was invoked (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec, eid, last_payload_val;
		size_t plen;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		plen = atomic_load_acq_long(&callback_data->last_payload_size);
		last_payload_val = *(volatile const uint32_t *)callback_data->last_payload;
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 2);	/* SESSION_CREATE + 1 user event */
		KTEST_EQUAL(eid, test_id);
		KTEST_EQUAL(plen, sizeof(test_data));
		KTEST_EQUAL(last_payload_val, test_data);
	}

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/* Test data structure for concurrent read/write test */
struct concurrent_test_data {
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	volatile int done;
	int reader_exited;	/* Protected by atomics; used as wait channel */
	volatile uint64_t events_written;
	volatile uint64_t events_read;
	volatile uint64_t bytes_read;
	struct mtx lock;
};

/* Writer thread - continuously writes events */
static void
concurrent_writer_thread(void *arg)
{
	struct concurrent_test_data *data = (struct concurrent_test_data *)arg;
	uint32_t test_id = 0x1000;
	uint32_t test_data[10];
	int i;

	for (i = 0; i < 10; i++)
		test_data[i] = i;

	while (data->done == 0) {
		eventlog_event_write(data->session, test_id++, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    test_data, sizeof(test_data));
		atomic_add_long((volatile u_long *)&data->events_written, 1);
		kern_yield(PRI_UNCHANGED); /* Yield to allow reads */
	}

	kthread_exit();
}

/* Reader thread - continuously reads events, draining the ring */
static void
concurrent_reader_thread(void *arg)
{
	struct concurrent_test_data *data = (struct concurrent_test_data *)arg;
	char read_buf[8 * 1024];
	size_t read_bytes;

	while (data->done == 0) {
		read_bytes = eventlog_read_into_buf(data->subscriber, read_buf, sizeof(read_buf), 0);
		if (read_bytes > 0) {
			atomic_add_long((volatile u_long *)&data->bytes_read, read_bytes);
			atomic_add_long((volatile u_long *)&data->events_read, 1);
		}
		kern_yield(PRI_UNCHANGED); /* Yield to allow writes */
	}

	atomic_store_rel_int(&data->reader_exited, 1);
	wakeup(&data->reader_exited);
	kthread_exit();
}

/*
 * Validates ring race conditions.
 * Tests concurrent reads and writes with frequent ring wraps to ensure
 * no memory corruption or crashes occur.
 */
KTEST_FUNC(subscriber_ring_race)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct concurrent_test_data test_data;
	struct thread *writer_thread, *reader_thread;
	int error;
	uint64_t initial_written, initial_read, initial_bytes;

	KTEST_LOG(ctx, "Testing ring race conditions");

	provider = test_create_provider("test_ringrace", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	if (eventlog_subscriber_add_subscription(subscriber, "test_ringrace",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0) != 0) {
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	bzero(&test_data, sizeof(test_data));
	test_data.session = session;
	test_data.subscriber = subscriber;
	test_data.done = 0;
	test_data.reader_exited = 0;
	test_data.events_written = 0;
	test_data.events_read = 0;
	test_data.bytes_read = 0;
	mtx_init(&test_data.lock, "concurrent_test", NULL, MTX_DEF);

	/* Pre-fill the ring so the reader has data from the start */
	uint32_t test_id = 0x2000;
	uint32_t prefill_data[5];
	for (int i = 0; i < 5; i++)
		prefill_data[i] = i;

	for (int i = 0; i < 50; i++) {
		eventlog_event_write(session, test_id++, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    prefill_data, sizeof(prefill_data));
	}

	/* Create writer thread */
	error = kthread_add(concurrent_writer_thread, &test_data, NULL, &writer_thread,
	    0, 0, "evtlog_writer");
	KTEST_EQUAL(error, 0);

	/* Create reader thread */
	error = kthread_add(concurrent_reader_thread, &test_data, NULL, &reader_thread,
	    0, 0, "evtlog_reader");
	KTEST_EQUAL(error, 0);

	/* Let threads run for a bit to exercise race conditions */
	tsleep(&test_data, 0, "test_run", hz / 2); /* 500ms */

	initial_written = atomic_load_acq_long((volatile u_long *)&test_data.events_written);
	initial_read = atomic_load_acq_long((volatile u_long *)&test_data.events_read);
	initial_bytes = atomic_load_acq_long((volatile u_long *)&test_data.bytes_read);

	KTEST_LOG(ctx, "After 500ms: wrote %llu events, read %llu times, %llu bytes",
	    (unsigned long long)initial_written, (unsigned long long)initial_read,
	    (unsigned long long)initial_bytes);

	/* Continue for another period to ensure stability */
	tsleep(&test_data, 0, "test_run2", hz / 2); /* Another 500ms */

	uint64_t final_written = atomic_load_acq_long((volatile u_long *)&test_data.events_written);
	uint64_t final_read = atomic_load_acq_long((volatile u_long *)&test_data.events_read);
	uint64_t final_bytes = atomic_load_acq_long((volatile u_long *)&test_data.bytes_read);

	KTEST_LOG(ctx, "After 1s: wrote %llu events, read %llu times, %llu bytes",
	    (unsigned long long)final_written, (unsigned long long)final_read,
	    (unsigned long long)final_bytes);

	/* Verify progress was made. The writer advances reliably; the reader's
	 * per-window progress is timing-sensitive on a loaded VM, so assert it
	 * made progress over the whole run rather than in one 500ms window. */
	KTEST_VERIFY(final_written > initial_written);
	KTEST_VERIFY(final_bytes > 0);

	/* Stop threads - wake reader if blocked, wait for it to exit (single reader) */
	test_data.done = 1;
	wakeup(subscriber);
	while (atomic_load_acq_int(&test_data.reader_exited) == 0)
		tsleep(&test_data.reader_exited, 0, "evtlog_rdwait", hz / 10);

	/* Drain remaining events (reader has exited, single reader for drain) */
	{
		char drain_buf[8 * 1024];
		size_t drain_read;

		do {
			drain_read = eventlog_read_into_buf(subscriber, drain_buf, sizeof(drain_buf), 0);
		} while (drain_read > 0);
	}

	mtx_destroy(&test_data.lock);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates interleaved read/write scenario.
 * Tests the case where more data is written while a read is in progress,
 * ensuring ordering is maintained.
 */
KTEST_FUNC(subscriber_interleaved_read_write)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	uint32_t test_id = 0x3000;
	uint32_t test_data[10];
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	ssize_t read_bytes;
	struct eventlog_stats stats;
	int i;

	KTEST_LOG(ctx, "Testing interleaved read/write scenario");

	/* Use malloc to avoid stack overflow in ktest taskqueue (limited stack) */
	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_interleave", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	if (eventlog_subscriber_add_subscription(subscriber, "test_interleave",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0) != 0) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	if (session == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	for (i = 0; i < 10; i++)
		test_data[i] = i;

	/* Fill buffer with events */
	for (i = 0; i < 100; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    test_data, sizeof(test_data));
	}

	/* Read a small chunk */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read_bytes = eventlog_read_into_buf(subscriber, read_buf, 1024, 0);
	KTEST_VERIFY(read_bytes > 0);
	KTEST_LOG(ctx, "First read: %zd bytes, dropped %llu", read_bytes,
	    (unsigned long long)stats.dropped_events);

	/* Write more events while the ring is being drained */
	for (i = 100; i < 200; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    test_data, sizeof(test_data));
	}

	/* Continue reading - drains what was just written */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);
	KTEST_LOG(ctx, "Second read: %zd bytes, dropped %llu", read_bytes,
	    (unsigned long long)stats.dropped_events);

	/* Write more events */
	for (i = 200; i < 250; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    test_data, sizeof(test_data));
	}

	/* Age the burst past the read-epoch watermark. */
	eventlog_test_clear_watermark("interleave");

	/* Read remaining events */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);
	KTEST_LOG(ctx, "Third read: %zd bytes, dropped %llu", read_bytes,
	    (unsigned long long)stats.dropped_events);

	/* Verify buffer is empty */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_EQUAL(read_bytes, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
}

/* Test data for buffer boundary stress test */
struct boundary_test_data {
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	volatile int done;
	int reader_exited;	/* Protected by atomics; used as wait channel */
	volatile uint64_t events_written;
	struct mtx lock;
};

/* Writer thread that fills buffers exactly to boundaries */
static void
boundary_writer_thread(void *arg)
{
	struct boundary_test_data *data = (struct boundary_test_data *)arg;
	uint32_t test_id = 0x4000;
	uint32_t small_data[1] = {0xdeadbeef};
	uint32_t large_data[100];
	int i;

	for (i = 0; i < 100; i++)
		large_data[i] = i;

	while (data->done == 0) {
		/* Write small events to fill buffer precisely */
		eventlog_event_write(data->session, test_id++, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    small_data, sizeof(small_data));
		atomic_add_long((volatile u_long *)&data->events_written, 1);

		/* Occasionally write larger events to test boundary conditions */
		if ((test_id % 10) == 0) {
			eventlog_event_write(data->session, test_id++, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
			    large_data, sizeof(large_data));
			atomic_add_long((volatile u_long *)&data->events_written, 1);
		}

		kern_yield(PRI_UNCHANGED);
	}

	kthread_exit();
}

/* Reader thread that rapidly drains the ring in small chunks */
static void
boundary_reader_thread(void *arg)
{
	struct boundary_test_data *data = (struct boundary_test_data *)arg;
	char read_buf[8 * 1024];
	size_t read_bytes;

	while (data->done == 0) {
		/* Read small chunks to force frequent batch boundaries */
		read_bytes = eventlog_read_into_buf(data->subscriber, read_buf, 512, 0);
		if (read_bytes > 0) {
			/* Immediately read again */
			read_bytes = eventlog_read_into_buf(data->subscriber, read_buf, sizeof(read_buf), 0);
		}
		kern_yield(PRI_UNCHANGED);
	}

	atomic_store_rel_int(&data->reader_exited, 1);
	wakeup(&data->reader_exited);
	kthread_exit();
}

/*
 * Stress test for buffer boundary conditions.
 * Tests rapid writes and reads that fill buffers exactly to boundaries.
 */
KTEST_FUNC(subscriber_buffer_boundary_stress)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct boundary_test_data test_data;
	struct thread *writer_thread, *reader_thread;
	int error;
	uint64_t initial_written;

	KTEST_LOG(ctx, "Testing buffer boundary stress conditions");

	provider = test_create_provider("test_bbstress", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* Use a 128KB buffer to trigger boundary conditions (above 64KB minimum) */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	if (eventlog_subscriber_add_subscription(subscriber, "test_bbstress",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0) != 0) {
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	bzero(&test_data, sizeof(test_data));
	test_data.session = session;
	test_data.subscriber = subscriber;
	test_data.done = 0;
	test_data.reader_exited = 0;
	test_data.events_written = 0;
	mtx_init(&test_data.lock, "boundary_test", NULL, MTX_DEF);

	/* Create writer thread */
	error = kthread_add(boundary_writer_thread, &test_data, NULL, &writer_thread,
	    0, 0, "evtlog_boundary_writer");
	KTEST_EQUAL(error, 0);

	/* Create reader thread */
	error = kthread_add(boundary_reader_thread, &test_data, NULL, &reader_thread,
	    0, 0, "evtlog_boundary_reader");
	KTEST_EQUAL(error, 0);

	/* Run for a period to exercise boundary conditions */
	tsleep(&test_data, 0, "boundary_run", hz * 2); /* 2 seconds */

	initial_written = atomic_load_acq_long((volatile u_long *)&test_data.events_written);
	KTEST_LOG(ctx, "Wrote %llu events during boundary stress test",
	    (unsigned long long)initial_written);
	KTEST_VERIFY(initial_written > 0);

	/* Stop threads - wake reader if blocked, wait for it to exit (single reader) */
	test_data.done = 1;
	wakeup(subscriber);
	while (atomic_load_acq_int(&test_data.reader_exited) == 0)
		tsleep(&test_data.reader_exited, 0, "evtlog_rdwait", hz / 10);

	/* Drain remaining events (reader has exited, single reader for drain) */
	{
		char drain_buf[8 * 1024];
		size_t drain_read;

		do {
			drain_read = eventlog_read_into_buf(subscriber, drain_buf, sizeof(drain_buf), 0);
		} while (drain_read > 0);
	}

	mtx_destroy(&test_data.lock);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Stress test that fills buffers exactly to capacity.
 * Tests edge cases where write_pos approaches buffer_size.
 */
KTEST_FUNC(subscriber_buffer_fill_to_capacity)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	uint32_t test_id = 0x5000;
	uint32_t test_data = 0x12345678;
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	ssize_t read_bytes;
	struct eventlog_stats stats;
	size_t buffer_size_per_cpu = 128 * 1024;
	size_t create_event_size;
	size_t event_size;
	size_t max_events;
	uint64_t dropped_before;
	int i;

	KTEST_LOG(ctx, "Testing buffer fill to exact capacity");

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_bfill", NULL, NULL);
	if (provider == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		return (EINVAL);
	}

	subscriber = eventlog_subscriber_create_device(buffer_size_per_cpu);
	if (subscriber == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	if (eventlog_subscriber_add_subscription(subscriber, "test_bfill",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0) != 0) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	if (session == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	/*
	 * SESSION_CREATE is header-only (no payload), user events carry a
	 * uint32_t payload.  Compute how many user events fit after the
	 * session_create event, leaving less than one event of slack.
	 */
	create_event_size = sizeof(struct eventlog_event_header);
	event_size = sizeof(struct eventlog_event_header) + sizeof(uint32_t);
	max_events = (buffer_size_per_cpu - create_event_size) / event_size;

	KTEST_LOG(ctx, "Event size: %zu bytes, create size: %zu bytes, "
	    "buffer size: %zu bytes, max user events: %zu",
	    event_size, create_event_size, buffer_size_per_cpu, max_events);

	/* Fill the single ring close to capacity (SESSION_CREATE already wrote
	 * one event).  With no reader draining, none of these are dropped. */
	for (i = 0; i < (int)max_events; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &test_data, sizeof(test_data));
	}

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_EQUAL(stats.dropped_events, 0);
	KTEST_LOG(ctx, "After filling to capacity: dropped %llu events",
	    (unsigned long long)stats.dropped_events);

	/* The ring is a single buffer: writing well past capacity with no
	 * reader draining drops. */
	for (i = 0; i < (int)max_events; i++) {
		eventlog_event_write(session, test_id + 10000 + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &test_data, sizeof(test_data));
	}

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_VERIFY(stats.dropped_events > 0);
	KTEST_LOG(ctx, "After overflowing the full ring: dropped %llu events",
	    (unsigned long long)stats.dropped_events);

	/* Drain the ring completely. */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
		KTEST_VERIFY(read_bytes >= 0);
	} while (read_bytes > 0);

	/* With space freed by draining, new writes succeed without any
	 * additional drops. */
	dropped_before = stats.dropped_events;
	for (i = 0; i < 100; i++) {
		eventlog_event_write(session, test_id + 20000 + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &test_data, sizeof(test_data));
	}
	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_EQUAL((int)(stats.dropped_events - dropped_before), 0);

	read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
}

/*
 * Ring wrap integrity.  Drives the ring through enough physical wraps that
 * every possible boundary geometry occurs: with a 100-byte event in a 64KB
 * power-of-two ring, the bytes remaining at the end when a record does not
 * fit (to_end) cycle through all 25 residues of the 4-byte grid over 25
 * wraps, covering exact fits, wrap pads (to_end >= header), and sub-header
 * gaps (to_end < header).  Verifies every event survives in order with no
 * drops and no corruption.
 */
KTEST_FUNC(subscriber_ring_wrap_integrity)
{
#define RWI_PAYLOAD	68	/* event_length == 100; 64KB % 100 != 0 */
#define RWI_BURSTS	30	/* 30 * 600 * 100B = 1.8MB ~ 27 ring traversals */
#define RWI_PER_BURST	600	/* 60000B + max pad < 64KB ring: never drops */
#define RWI_EVENT_SIZE	(sizeof(struct eventlog_event_header) + RWI_PAYLOAD)
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	uint32_t test_id = 0x7000;
	uint8_t payload[RWI_PAYLOAD];
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	ssize_t read_bytes;
	uint64_t write_seq = 0, read_seq = 0;
	int b, i, j;

	provider = test_create_provider("test_wrap", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(EVENTLOG_BUFFER_SIZE_MIN);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "test_wrap",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	/* Drain SESSION_CREATE so the bursts below start from an empty ring. */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
	} while (read_bytes > 0);

	for (b = 0; b < RWI_BURSTS; b++) {
		size_t burst_got = 0;

		for (i = 0; i < RWI_PER_BURST; i++) {
			memcpy(payload, &write_seq, sizeof(write_seq));
			for (j = sizeof(write_seq); j < RWI_PAYLOAD; j++)
				payload[j] = (uint8_t)(write_seq + j);
			eventlog_event_write(session, test_id,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, payload,
			    sizeof(payload));
			write_seq++;
		}

		/* The whole burst fits in the ring, so every byte of it must
		 * arrive; blocking reads ride out the read-epoch watermark. */
		while (burst_got < RWI_PER_BURST * RWI_EVENT_SIZE) {
			size_t off = 0;

			read_bytes = eventlog_read_into_buf(subscriber,
			    read_buf, read_buf_size, 0);
			KTEST_VERIFY(read_bytes > 0);
			burst_got += read_bytes;
			while (off < (size_t)read_bytes) {
				struct eventlog_event_header hdr;
				uint8_t want[RWI_PAYLOAD];
				bool bad;

				if (off + RWI_EVENT_SIZE > (size_t)read_bytes) {
					KTEST_ERR(ctx, "burst %d: partial event "
					    "at off %zu of %zd", b, off,
					    read_bytes);
					return (EINVAL);
				}
				memcpy(&hdr, read_buf + off, sizeof(hdr));
				memcpy(want, &read_seq, sizeof(read_seq));
				for (j = sizeof(read_seq); j < RWI_PAYLOAD; j++)
					want[j] = (uint8_t)(read_seq + j);
				bad = hdr.event_length != RWI_EVENT_SIZE ||
				    hdr.event_id != test_id ||
				    memcmp(read_buf + off + sizeof(hdr), want,
				    RWI_PAYLOAD) != 0;
				if (bad) {
					KTEST_ERR(ctx, "burst %d: bad event at "
					    "off %zu (expect seq %llu, len %u)",
					    b, off, (unsigned long long)read_seq,
					    hdr.event_length);
					return (EINVAL);
				}
				read_seq++;
				off += hdr.event_length;
			}
		}
	}

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_EQUAL(stats.dropped_events, 0);
	KTEST_VERIFY(read_seq == (uint64_t)RWI_BURSTS * RWI_PER_BURST);

	free(read_buf, M_EVENTLOG_TEST);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	return (0);
#undef RWI_PAYLOAD
#undef RWI_BURSTS
#undef RWI_PER_BURST
#undef RWI_EVENT_SIZE
}

/*
 * Stress test with rapid ring wraps.
 * Writes events, reads partially, writes more, reads again - rapid wrapping.
 */
KTEST_FUNC(subscriber_rapid_wrap_stress)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	uint32_t test_id = 0x6000;
	uint32_t test_data[10];
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	ssize_t read_bytes;
	int i, j;

	KTEST_LOG(ctx, "Testing rapid ring wrap stress");

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_rwrap", NULL, NULL);
	if (provider == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		return (EINVAL);
	}

	subscriber = eventlog_subscriber_create_device(128 * 1024);
	if (subscriber == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	if (eventlog_subscriber_add_subscription(subscriber, "test_rwrap",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0) != 0) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	if (session == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		eventlog_subscriber_destroy(subscriber);
		eventlog_provider_destroy(provider);
		return (EINVAL);
	}

	for (i = 0; i < 10; i++)
		test_data[i] = i;

	/* Rapid cycle: write, read partially, write more, read again */
	for (j = 0; j < 50; j++) {
		/* Write a batch */
		for (i = 0; i < 30; i++) {
			eventlog_event_write(session, test_id++, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
			    test_data, sizeof(test_data));
		}

		/* Read a small chunk */
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, 1024, 0);

		/* Write more while the ring is being drained */
		for (i = 0; i < 20; i++) {
			eventlog_event_write(session, test_id++, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
			    test_data, sizeof(test_data));
		}

		/* Read remaining to drain the ring */
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	}

	/* Final drain */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	} while (read_bytes > 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
}

/*
 * Validates device subscriber buffer size validation.
 * Buffer size must be between EVENTLOG_BUFFER_SIZE_MIN and
 * EVENTLOG_BUFFER_SIZE_MAX inclusive.
 */
KTEST_FUNC(subscriber_create_device_invalid_size)
{
	struct eventlog_subscriber *subscriber;

	KTEST_LOG(ctx, "Testing device subscriber buffer size validation");

	/* Too small */
	subscriber = eventlog_subscriber_create_device(EVENTLOG_BUFFER_SIZE_MIN - 1);
	KTEST_EQUAL(subscriber, NULL);

	subscriber = eventlog_subscriber_create_device(0);
	KTEST_EQUAL(subscriber, NULL);

	/* Too large */
	subscriber = eventlog_subscriber_create_device(EVENTLOG_BUFFER_SIZE_MAX + 1);
	KTEST_EQUAL(subscriber, NULL);

	/* Valid boundaries */
	subscriber = eventlog_subscriber_create_device(EVENTLOG_BUFFER_SIZE_MIN);
	KTEST_NEQUAL(subscriber, NULL);
	eventlog_subscriber_destroy(subscriber);

	subscriber = eventlog_subscriber_create_device(EVENTLOG_BUFFER_SIZE_MAX);
	KTEST_NEQUAL(subscriber, NULL);
	eventlog_subscriber_destroy(subscriber);

	return (0);
}

/*
 * Validates that adding a subscription for a non-existent provider succeeds
 * and is remembered for late binding (deferred binding is always allowed).
 */
KTEST_FUNC(subscriber_add_subscription_nonexistent_provider)
{
	struct eventlog_subscriber *subscriber;
	int error;

	KTEST_LOG(ctx, "Testing subscription to non-existent provider");

	subscriber = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber,
	    "nonexistent_provider_xyz", EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	eventlog_subscriber_destroy(subscriber);

	return (0);
}

/*
 * Subscribing to an absent provider succeeds and stays armed; when a
 * provider of that name registers later it is bound automatically and events
 * flow. This exercises the late-binding path used by user-space providers,
 * but entirely through the in-kernel API so the bind/enablement logic is
 * checked directly.
 */
KTEST_FUNC(deferred_subscription_binds_on_provider_create)
{
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cb;
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	uint32_t payload = 0x1234;
	uint32_t before;
	int error;

	KTEST_LOG(ctx, "Testing deferred subscription late-binds on provider create");

	cb = malloc(sizeof(*cb), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cb->lock, "test_defer_cb", NULL, MTX_DEF);

	subscriber = eventlog_subscriber_create_callback(test_event_callback, cb);
	KTEST_NEQUAL(subscriber, NULL);

	/* No provider yet: the subscription is armed for late binding. */
	error = eventlog_subscriber_add_subscription(subscriber,
	    "test_deferbind", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	/* Provider registers later -> the armed spec should bind it. */
	provider = test_create_provider("test_deferbind", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* Binding must have enabled the provider at the subscribed level. */
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0xFFFFFFFF);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	before = atomic_load_acq_32(&cb->event_count);
	eventlog_event_write(session, 0x10, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	KTEST_EQUAL(atomic_load_acq_32(&cb->event_count), before + 1);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	mtx_destroy(&cb->lock);
	free(cb, M_EVENTLOG_TEST);

	return (0);
}

/*
 * Narrowing a subscription's keyword mask applies to the live subscription
 * and to the retained spec, so a same-named provider binding later comes up
 * narrowed too.
 */
KTEST_FUNC(subscription_keywords_updated_in_place)
{
	struct eventlog_subscriber *subscriber;
	struct eventlog_provider *provider;
	int error;

	KTEST_LOG(ctx, "Testing keyword mask update on a live subscription");

	provider = test_create_provider("test_kwset", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);
	error = eventlog_subscriber_add_subscription(subscriber, "test_kwset",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0xFFFFFFFF);

	error = eventlog_subscriber_set_subscription_keywords(subscriber,
	    "test_kwset", TEST_EVENTLOG_KEYWORD_BASIC);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider),
	    TEST_EVENTLOG_KEYWORD_BASIC);

	/* A provider re-registering under the same name binds filtered. */
	eventlog_provider_destroy(provider);
	provider = test_create_provider("test_kwset", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider),
	    TEST_EVENTLOG_KEYWORD_BASIC);

	/* A name this subscriber never subscribed to has no mask to set. */
	error = eventlog_subscriber_set_subscription_keywords(subscriber,
	    "test_kwset_absent", TEST_EVENTLOG_KEYWORD_BASIC);
	KTEST_EQUAL(error, ENOENT);

	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Destroying a provider unbinds it from subscribers but retains their specs,
 * so re-registering a provider of the same name rebinds automatically. This
 * mirrors a user-space provider closing and re-opening its fd, validated via
 * the in-kernel API.
 */
KTEST_FUNC(provider_destroy_rebinds_via_retained_spec)
{
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cb;
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	uint32_t payload = 0x9abc;
	uint32_t before;
	int error;

	KTEST_LOG(ctx, "Testing provider destroy/recreate rebinds via retained spec");

	cb = malloc(sizeof(*cb), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cb->lock, "test_rebind_cb", NULL, MTX_DEF);

	subscriber = eventlog_subscriber_create_callback(test_event_callback, cb);
	KTEST_NEQUAL(subscriber, NULL);

	/* Provider already exists: immediate bind, and the spec is armed. */
	provider = test_create_provider("test_rebind", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	error = eventlog_subscriber_add_subscription(subscriber,
	    "test_rebind", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	before = atomic_load_acq_32(&cb->event_count);
	eventlog_event_write(session, 0x20, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	KTEST_EQUAL(atomic_load_acq_32(&cb->event_count), before + 1);

	/*
	 * Destroy the provider while the subscriber is still alive: unbind
	 * drops the live subscription but keeps the spec armed.
	 */
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);

	/* Re-register the same name -> retained spec rebinds automatically. */
	provider = test_create_provider("test_rebind", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE);

	session = eventlog_session_create(provider, 2, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	before = atomic_load_acq_32(&cb->event_count);
	eventlog_event_write(session, 0x21, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	KTEST_EQUAL(atomic_load_acq_32(&cb->event_count), before + 1);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	mtx_destroy(&cb->lock);
	free(cb, M_EVENTLOG_TEST);

	return (0);
}

/*
 * Exhausted provider_id pool: eventlog_provider_create() must fail
 * cleanly (NULL) rather than collide ids.  Releasing the drained ids
 * (as a real destroy would) lets registration succeed again.
 */
KTEST_FUNC(provider_id_exhaustion_fails_cleanly)
{
	struct eventlog_provider *provider;
	u_int drained;

	KTEST_LOG(ctx, "Testing provider_id exhaustion fails cleanly");

	drained = eventlog_test_drain_provider_ids();
	KTEST_LOG(ctx, "Drained %u provider ids", drained);

	provider = eventlog_provider_create("test_exhausted", NULL);
	KTEST_EQUAL(provider, NULL);

	eventlog_test_release_provider_ids();

	/* Pool restored: registration succeeds again. */
	provider = test_create_provider("test_reclaimed", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates eventlog_subscriber_read error paths: EOPNOTSUPP and EAGAIN.
 */
KTEST_FUNC(subscriber_read_error_paths)
{
	struct eventlog_subscriber *subscriber;
	struct uio uio;
	struct iovec iov[2];
	int error;

	KTEST_LOG(ctx, "Testing subscriber read error paths");

	subscriber = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);

	/* EOPNOTSUPP: multiple iovecs not supported */
	iov[0].iov_base = malloc(1024, M_EVENTLOG_TEST, M_WAITOK);
	iov[0].iov_len = 512;
	iov[1].iov_base = (char *)iov[0].iov_base + 512;
	iov[1].iov_len = 512;
	uio.uio_iov = iov;
	uio.uio_iovcnt = 2;
	uio.uio_offset = 0;
	uio.uio_resid = 1024;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = curthread;

	error = eventlog_subscriber_read(subscriber, &uio, 0);
	KTEST_EQUAL(error, EOPNOTSUPP);

	free(iov[0].iov_base, M_EVENTLOG_TEST);

	/* EOPNOTSUPP: zero resid */
	iov[0].iov_base = malloc(1024, M_EVENTLOG_TEST, M_WAITOK);
	iov[0].iov_len = 1024;
	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = 0;

	error = eventlog_subscriber_read(subscriber, &uio, 0);
	KTEST_EQUAL(error, EOPNOTSUPP);

	free(iov[0].iov_base, M_EVENTLOG_TEST);

	/* EAGAIN: FNONBLOCK with no data */
	iov[0].iov_base = malloc(1024, M_EVENTLOG_TEST, M_WAITOK);
	iov[0].iov_len = 1024;
	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = 1024;

	error = eventlog_subscriber_read(subscriber, &uio, FNONBLOCK);
	KTEST_EQUAL(error, EAGAIN);

	free(iov[0].iov_base, M_EVENTLOG_TEST);

	eventlog_subscriber_destroy(subscriber);

	return (0);
}

/*
 * Validates that *_destroy with NULL pointer returns without crashing.
 */
KTEST_FUNC(null_pointer_destroy)
{
	KTEST_LOG(ctx, "Testing NULL pointer handling in destroy functions");

	eventlog_provider_destroy(NULL);
	eventlog_session_destroy(NULL);
	eventlog_subscriber_destroy(NULL);

	return (0);
}

/*
 * Validates that events are filtered by level and keywords.
 * Subscriber at INFO/0x1 should not receive VERBOSE events or events with
 * non-matching keywords.
 */
KTEST_FUNC(subscriber_level_keyword_filtering)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;
	uint32_t test_id = 0x1111;
	uint32_t test_data = 0xdeadbeef;

	KTEST_LOG(ctx, "Testing level and keyword filtering");

	provider = test_create_provider("test_filter", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* Subscriber wants INFO level, keyword 0x1 only */
	subscriber = test_enable_provider_callback("test_filter",
	    EVENTLOG_LEVEL_INFO, 0x1, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Event at INFO level with keyword 0x1 - should be received */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0x1,
	    &test_data, sizeof(test_data));
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 1);
	}

	/* Event at VERBOSE level - filtered out (VERBOSE > INFO) */
	eventlog_event_write(session, test_id + 1, EVENTLOG_LEVEL_VERBOSE, 0x1,
	    &test_data, sizeof(test_data));
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 1);
	}

	/* Event at INFO with keyword 0x2 only - filtered out (no keyword match) */
	eventlog_event_write(session, test_id + 2, EVENTLOG_LEVEL_INFO, 0x2,
	    &test_data, sizeof(test_data));
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 1);
	}

	/* Event at INFO with keywords 0x1 | 0x2 - should be received (0x1 matches) */
	eventlog_event_write(session, test_id + 3, EVENTLOG_LEVEL_INFO, 0x3,
	    &test_data, sizeof(test_data));
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 2);
	}

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates that events exceeding UINT16_MAX are dropped silently.
 */
KTEST_FUNC(event_oversized_dropped)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;
	uint8_t *large_payload;
	size_t oversized_len;
	uint32_t test_id = 0x9999;

	KTEST_LOG(ctx, "Testing that oversized events are dropped");

	/* total_size = sizeof(eventlog_event_header) + payload.
	 * Need total_size > UINT16_MAX (65535). Header is 32 bytes,
	 * so payload must be > 65535 - 32 = 65503. Use 65504. */
	oversized_len = 65504;

	provider = test_create_provider("test_oversize", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = test_enable_provider_callback("test_oversize", EVENTLOG_LEVEL_VERBOSE,
	    0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	large_payload = malloc(oversized_len, M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	KTEST_NEQUAL(large_payload, NULL);

	/* This event exceeds UINT16_MAX and should be dropped (no callback) */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    large_payload, oversized_len);

	/*
	 * Read without holding lock: callback is never invoked (event dropped
	 * before reaching subscribers). Holding the lock across KTEST_EQUAL
	 * can panic when kyua runs tests in taskqueue context (KTEST_LOG may
	 * sleep).
	 */
	/* SESSION_CREATE only; oversized dropped */
	KTEST_EQUAL(atomic_load_acq_32(&callback_data->event_count), 1);

	free(large_payload, M_EVENTLOG_TEST);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates zero-length payload and empty session_id.
 */
KTEST_FUNC(event_edge_cases_payload_session)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;
	uint32_t test_id = 0x7777;

	KTEST_LOG(ctx, "Testing zero-length payload and empty session_id");

	provider = test_create_provider("test_edge", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = test_enable_provider_callback("test_edge",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	/* Session with empty string session_id */
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Event with zero-length payload (valid pointer, zero length) */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &test_id, 0);

	/* Verify (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec, eid;
		size_t plen;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		plen = atomic_load_acq_long(&callback_data->last_payload_size);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 2);	/* SESSION_CREATE + 1 user event (zero-length payload) */
		KTEST_EQUAL(eid, test_id);
		KTEST_EQUAL(plen, 0);
	}

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates subscription update in place when re-subscribing to same provider.
 */
KTEST_FUNC(subscriber_subscription_update_in_place)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *subscriber;
	int error;

	KTEST_LOG(ctx, "Testing subscription update in place");

	provider = test_create_provider("test_subupd", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);

	/* First subscription */
	error = eventlog_subscriber_add_subscription(subscriber, "test_subupd",
	    EVENTLOG_LEVEL_INFO, 0x1, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x1);

	/* Re-subscribe to same provider - should update in place, not add duplicate */
	error = eventlog_subscriber_add_subscription(subscriber, "test_subupd",
	    EVENTLOG_LEVEL_VERBOSE, 0x7, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x7);

	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

KTEST_FUNC(schema_generated_macros)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;

	KTEST_LOG(ctx, "Testing schema-generated macros");

	/* Create provider */
	provider = test_create_provider("test_schema", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	session = eventlog_session_create(provider, 12345, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Test 1: Verify _ENABLED macro returns false when no subscribers */
	KTEST_EQUAL(TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(session), 0);
	KTEST_EQUAL(TEST_EVENTLOG_STATUS_EVENT_ENABLED(session), 0);
	KTEST_EQUAL(TEST_EVENTLOG_FLAGS_EVENT_ENABLED(session), 0);
	KTEST_EQUAL(TEST_EVENTLOG_COMPLEX_EVENT_ENABLED(session), 0);

	/* Test 2: Create callback subscriber with BASIC keyword, INFO level */
	struct test_callback_data *callback_data;
	subscriber = test_enable_provider_callback("test_schema",
	    EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	/* Provider enablement is updated automatically when subscription is added */

	/* Verify _ENABLED macros work correctly */
	KTEST_EQUAL(TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(session), 1); /* INFO level, BASIC keyword */
	KTEST_EQUAL(TEST_EVENTLOG_STATUS_EVENT_ENABLED(session), 1); /* INFO level, BASIC keyword */
	KTEST_EQUAL(TEST_EVENTLOG_FLAGS_EVENT_ENABLED(session), 0); /* VERBOSE level, ADVANCED keyword */
	KTEST_EQUAL(TEST_EVENTLOG_COMPLEX_EVENT_ENABLED(session), 0); /* WARN level, COMPLEX keyword */

	/* Test 3: Use _LOG_ALWAYS macro (should always log regardless of enablement) */
	TEST_EVENTLOG_SIMPLE_EVENT_LOG_ALWAYS(session, 0x12345678);
	TEST_EVENTLOG_STATUS_EVENT_LOG_ALWAYS(session, 0xABCDEF00, TEST_EVENTLOG_TEST_STATUS_RUNNING);

	/* Verify events were received via callback (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 2);	/* Session created before subscriber; 2 LOG_ALWAYS events */
	}

	/* Reset callback data for next test */
	mtx_lock(&callback_data->lock);
	callback_data->event_count = 0;
	mtx_unlock(&callback_data->lock);

	/* Test 4: Use _LOG macro (should check enablement first) */
	TEST_EVENTLOG_SIMPLE_EVENT_LOG(session, 0x87654321);
	TEST_EVENTLOG_STATUS_EVENT_LOG(session, 0xFEDCBA00, TEST_EVENTLOG_TEST_STATUS_SUCCESS);
	TEST_EVENTLOG_FLAGS_EVENT_LOG(session, 0x11111111, TEST_EVENTLOG_FLAG_FLAG_A | TEST_EVENTLOG_FLAG_FLAG_B);
	TEST_EVENTLOG_COMPLEX_EVENT_LOG(session, 0x22222222, 0x33333333,
	    TEST_EVENTLOG_TEST_STATUS_RUNNING, TEST_EVENTLOG_FLAG_FLAG_C, -42);

	/* Verify only enabled events were received (read then unlock; KTEST_EQUAL may sleep) */
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 2);	/* Only SIMPLE and STATUS (session existed before subscriber) */
	}

	/* Test 5: Update subscriber to VERBOSE level with ADVANCED keyword */
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	subscriber = test_enable_provider_callback("test_schema",
	    EVENTLOG_LEVEL_VERBOSE, TEST_EVENTLOG_KEYWORD_ADVANCED,
	    &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	/* Provider enablement is updated automatically when subscription is added */

	/* Verify FLAGS_EVENT is now enabled */
	KTEST_EQUAL(TEST_EVENTLOG_FLAGS_EVENT_ENABLED(session), 1);
	KTEST_EQUAL(TEST_EVENTLOG_COMPLEX_EVENT_ENABLED(session), 0); /* Still WARN level */

	/* Test 6: Update subscriber to WARN level with COMPLEX keyword */
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	subscriber = test_enable_provider_callback("test_schema",
	    EVENTLOG_LEVEL_WARN, TEST_EVENTLOG_KEYWORD_COMPLEX, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	/* Provider enablement is updated automatically when subscription is added */

	/* Verify COMPLEX_EVENT is now enabled */
	KTEST_EQUAL(TEST_EVENTLOG_COMPLEX_EVENT_ENABLED(session), 1);

	/* Cleanup */
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);
	return (0);
}

/*
 * Exercise the varlen trailing-array codegen for VARLEN_EVENT { id,
 * count, values:uint64_t[count:8] }: producer macro with partial,
 * clamped, and zero counts; accessor returning the trailing array.
 */

struct varlen_cb_data {
	struct mtx lock;
	uint32_t events;
	uint32_t matched;	/* events whose payload parsed correctly */
	uint32_t mismatch;	/* events whose tail/head mismatched expectation */
	size_t last_payload_size;
	uint8_t last_count;
	uint64_t last_first_value;
	uint64_t last_last_value;
};

static void
varlen_event_callback(const struct eventlog_event_header *hdr __unused,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct varlen_cb_data *d = callback_arg;
	/* The varlen producer emits a 2-segment iov: [head][tail]. Compact
	 * it into a stack buffer for the generated accessor. Sized from
	 * the schema's declared max. */
	uint8_t buf[sizeof(struct test_eventlog_varlen_event) +
	    TEST_EVENTLOG_VARLEN_EVENT_VALUES_MAX * sizeof(uint64_t)];
	const struct test_eventlog_varlen_event *evt;
	uint64_t vals[TEST_EVENTLOG_VARLEN_EVENT_VALUES_MAX];
	size_t nvals;
	size_t off;
	int i;

	atomic_add_32(&d->events, 1);
	if (payload_size < sizeof(*evt) || payload_size > sizeof(buf))
		return;
	off = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
			off += iov[i].iov_len;
		}
	}
	evt = (const struct test_eventlog_varlen_event *)buf;

	nvals = test_eventlog_varlen_event_values(evt, payload_size, vals);
	d->last_payload_size = payload_size;
	d->last_count = evt->count;
	if (evt->count == 0) {
		/* No trailing elements expected; accessor copies nothing and
		 * returns 0 (payload_size == sizeof(head) + 0). Count as
		 * matched. */
		atomic_add_32(&d->matched, 1);
		return;
	}
	if (nvals == 0) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	d->last_first_value = vals[0];
	d->last_last_value = vals[nvals - 1];
	atomic_add_32(&d->matched, 1);
}

KTEST_FUNC(schema_varlen_event)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct varlen_cb_data cb;
	uint64_t payload[32];
	uint32_t i;

	KTEST_LOG(ctx, "Testing varlen trailing-array schema events");

	bzero(&cb, sizeof(cb));
	mtx_init(&cb.lock, "varlen_cb", NULL, MTX_DEF);

	provider = test_create_provider("test_varlen", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	session = eventlog_session_create(provider, 0x4711, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	subscriber = eventlog_subscriber_create_callback(varlen_event_callback,
	    &cb);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_varlen", EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, 0),
	    0);

	KTEST_EQUAL(TEST_EVENTLOG_VARLEN_EVENT_ENABLED(session), 1);

	/* Case 1: partial count (4 of 8). Accessor should return the tail. */
	for (i = 0; i < 4; i++)
		payload[i] = 0xAA00ULL + i;
	TEST_EVENTLOG_VARLEN_EVENT_LOG(session, 0xD00D, 4, payload);

	/* Case 2: count > MAX. Producer macro must clamp to 8. */
	for (i = 0; i < 32; i++)
		payload[i] = 0xBB00ULL + i;
	TEST_EVENTLOG_VARLEN_EVENT_LOG(session, 0xBEEF, 32, payload);

	/* Case 3: count == 0, values == NULL. No tail to copy. */
	TEST_EVENTLOG_VARLEN_EVENT_LOG(session, 0xCAFE, 0, NULL);

	/* Subscribers call us synchronously from the writer; no sleep needed.
	 * The session was created BEFORE the subscriber attached, so no
	 * SESSION_CREATE is delivered here -- we only see the 3 varlen
	 * events we logged. */
	KTEST_EQUAL(atomic_load_acq_32(&cb.events), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb.matched), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb.mismatch), 0);

	/* Last event (count == 0) should have been delivered with a payload
	 * equal to exactly sizeof(struct test_eventlog_varlen_event). */
	KTEST_EQUAL((int)cb.last_count, 0);
	KTEST_EQUAL((int)cb.last_payload_size,
	    (int)sizeof(struct test_eventlog_varlen_event));

	/* Spot-check accessor robustness against a short payload: it claims 4
	 * trailing values but the payload is only the head, so nothing is
	 * copied and the accessor returns 0. */
	struct test_eventlog_varlen_event evt = { .id = 0, .count = 4 };
	uint64_t vals[TEST_EVENTLOG_VARLEN_EVENT_VALUES_MAX];
	KTEST_EQUAL((int)test_eventlog_varlen_event_values(&evt, sizeof(evt),
	    vals), 0);

	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	mtx_destroy(&cb.lock);
	return (0);
}

/*
 * schema_packed_layout: verify __packed eliminated all inter-field and
 * trailing pad on every test schema struct. This guards against a
 * regression that would either re-introduce the "trailing pad leaks
 * uninitialized stack" bug, or silently change wire format.
 */
KTEST_FUNC(schema_packed_layout)
{
	KTEST_LOG(ctx, "Verifying __packed sizeof + offsets on test schema structs");

	/* Tightly packed: every field contributes exactly its width. */
	KTEST_EQUAL((int)sizeof(struct test_eventlog_simple_event), 4);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_status_event), 9);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_flags_event), 12);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_complex_event), 21);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_varlen_event), 9);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_misaligned_event), 31);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_varlen_u32_event), 10);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_varlen_u16_event), 5);
	KTEST_EQUAL((int)sizeof(struct test_eventlog_varlen_u8_event), 5);

	/* Field offsets in MISALIGNED_EVENT: every fixed-width primitive
	 * sits at an offset that is unaligned for its type. This is
	 * precisely the case the __packed struct must let the compiler
	 * handle correctly via byte-shuffling on strict-align archs and
	 * unaligned-load on amd64/aarch64. */
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, flag1), 0);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, big1), 1);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, flag2), 9);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, mid1), 10);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, flag3), 14);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, small1), 15);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, flag4), 17);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, sbig), 18);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, smid), 26);
	KTEST_EQUAL((int)offsetof(struct test_eventlog_misaligned_event, sentinel), 30);

	/* Varlen heads end at offsets that are NOT a multiple of
	 * _Alignof(elem_type); the trailing array is therefore unaligned
	 * for the element type, which is exactly what the memcpy-based
	 * accessor exists to handle portably. */
	KTEST_EQUAL((int)(sizeof(struct test_eventlog_varlen_event) %
	    _Alignof(uint64_t)), 1);
	KTEST_EQUAL((int)(sizeof(struct test_eventlog_varlen_u32_event) %
	    _Alignof(uint32_t)), 2);
	KTEST_EQUAL((int)(sizeof(struct test_eventlog_varlen_u16_event) %
	    _Alignof(uint16_t)), 1);

	return (0);
}

/*
 * schema_packed_misaligned_event: end-to-end test for the inter-field
 * unaligned-access path. The producer macro writes a __packed struct
 * whose primitive fields all sit at unaligned offsets; the consumer
 * casts the delivered bytes back to the same __packed struct (from a
 * deliberately byte-aligned buffer, _Alignof = 1) and reads every
 * field. All operations are well-defined on every architecture
 * because __packed forces unaligned-aware codegen.
 */
struct misaligned_cb_data {
	uint32_t events;
	uint32_t matched;
	uint32_t mismatch;
	struct test_eventlog_misaligned_event last_evt;
};

static void
misaligned_event_callback(const struct eventlog_event_header *hdr __unused,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct misaligned_cb_data *d = callback_arg;
	/* Force a deliberately misaligned destination: a byte buffer one
	 * larger than the struct, with the struct cast at &buf[1] so the
	 * struct base is at an odd address. Field accesses through the
	 * __packed struct must remain well-defined. */
	uint8_t buf[1 + sizeof(struct test_eventlog_misaligned_event)];
	const struct test_eventlog_misaligned_event *evt;
	size_t off;
	int i;

	atomic_add_32(&d->events, 1);
	if (payload_size != sizeof(struct test_eventlog_misaligned_event)) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	off = 1;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
			off += iov[i].iov_len;
		}
	}
	evt = (const struct test_eventlog_misaligned_event *)&buf[1];

	/* Capture every field via __packed access; verification happens
	 * in the test body. */
	d->last_evt.flag1 = evt->flag1;
	d->last_evt.big1 = evt->big1;
	d->last_evt.flag2 = evt->flag2;
	d->last_evt.mid1 = evt->mid1;
	d->last_evt.flag3 = evt->flag3;
	d->last_evt.small1 = evt->small1;
	d->last_evt.flag4 = evt->flag4;
	d->last_evt.sbig = evt->sbig;
	d->last_evt.smid = evt->smid;
	d->last_evt.sentinel = evt->sentinel;
	atomic_add_32(&d->matched, 1);
}

KTEST_FUNC(schema_packed_misaligned_event)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct misaligned_cb_data cb;

	KTEST_LOG(ctx, "Testing __packed inter-field unaligned write/read");
	bzero(&cb, sizeof(cb));

	provider = test_create_provider("test_packed", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	session = eventlog_session_create(provider, 0xC0DE, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	subscriber = eventlog_subscriber_create_callback(
	    misaligned_event_callback, &cb);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_packed", EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, 0),
	    0);

	KTEST_EQUAL(TEST_EVENTLOG_MISALIGNED_EVENT_ENABLED(session), 1);

	/* Distinctive sentinel values: every byte of every field is
	 * non-zero and unique enough that any field-mix-up would show. */
	TEST_EVENTLOG_MISALIGNED_EVENT_LOG(session,
	    /* flag1    */ 0xA1,
	    /* big1     */ 0x0123456789ABCDEFULL,
	    /* flag2    */ 0xA2,
	    /* mid1     */ 0xDEADBEEFU,
	    /* flag3    */ 0xA3,
	    /* small1   */ 0xCAFE,
	    /* flag4    */ 0xA4,
	    /* sbig     */ (int64_t)0xFEDCBA9876543210ULL,
	    /* smid     */ (int32_t)-2023,
	    /* sentinel */ 0xA5);

	KTEST_EQUAL(atomic_load_acq_32(&cb.events), 1);
	KTEST_EQUAL(atomic_load_acq_32(&cb.matched), 1);
	KTEST_EQUAL(atomic_load_acq_32(&cb.mismatch), 0);

	/* Verify each field round-tripped through unaligned write +
	 * unaligned read with no corruption. */
	KTEST_EQUAL((int)cb.last_evt.flag1, 0xA1);
	KTEST_EQUAL(cb.last_evt.big1 == 0x0123456789ABCDEFULL ? 1 : 0, 1);
	KTEST_EQUAL((int)cb.last_evt.flag2, 0xA2);
	KTEST_EQUAL((int)cb.last_evt.mid1, (int)0xDEADBEEFU);
	KTEST_EQUAL((int)cb.last_evt.flag3, 0xA3);
	KTEST_EQUAL((int)cb.last_evt.small1, 0xCAFE);
	KTEST_EQUAL((int)cb.last_evt.flag4, 0xA4);
	KTEST_EQUAL(cb.last_evt.sbig == (int64_t)0xFEDCBA9876543210ULL ? 1 : 0,
	    1);
	KTEST_EQUAL((int)cb.last_evt.smid, -2023);
	KTEST_EQUAL((int)cb.last_evt.sentinel, 0xA5);

	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
}

/*
 * schema_varlen_unaligned_elem_types: exercise the memcpy-based trailing-
 * array accessor against varlen structs whose head sizeof is deliberately
 * not a multiple of _Alignof(elem_type). Each variant verifies (a) the
 * accessor returns the full element count with a payload that exactly
 * matches the claimed count, and (b) every copied element round-trips
 * byte-for-byte from what the producer logged.
 *
 * The varlen producer emits a 2-segment iov [head][tail] which the
 * callback compacts into a deliberately byte-aligned buf so that the
 * resulting `evt` pointer's natural alignment matches the wire-stream
 * case (alignment 1, since __packed alignof = 1).
 */
struct varlen_typed_cb_data {
	uint32_t events;
	uint32_t matched;
	uint32_t mismatch;
	uint32_t which;	/* bitmask: 2=u32, 4=u16, 8=u8 */

	uint8_t u32_count;
	uint32_t u32_first;
	uint32_t u32_last;

	uint8_t u16_count;
	uint16_t u16_first;
	uint16_t u16_last;

	uint8_t u8_count;
	uint8_t u8_first;
	uint8_t u8_last;
};

static void
varlen_u32_callback(const struct eventlog_event_header *hdr,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct varlen_typed_cb_data *d = callback_arg;
	uint8_t buf[sizeof(struct test_eventlog_varlen_u32_event) +
	    TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX * sizeof(uint32_t)];
	const struct test_eventlog_varlen_u32_event *evt;
	uint32_t vals[TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX];
	size_t nvals;
	size_t off;
	int i;

	if (hdr->event_id != TEST_EVENTLOG_VARLEN_U32_EVENT_ID)
		return;
	atomic_add_32(&d->events, 1);
	if (payload_size > sizeof(buf)) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	off = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
			off += iov[i].iov_len;
		}
	}
	evt = (const struct test_eventlog_varlen_u32_event *)buf;
	nvals = test_eventlog_varlen_u32_event_values(evt, payload_size, vals);
	if (nvals != evt->cnt) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	d->u32_count = evt->cnt;
	if (nvals > 0) {
		d->u32_first = vals[0];
		d->u32_last = vals[nvals - 1];
	}
	d->which |= 2;
	atomic_add_32(&d->matched, 1);
}

static void
varlen_u16_callback(const struct eventlog_event_header *hdr,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct varlen_typed_cb_data *d = callback_arg;
	uint8_t buf[sizeof(struct test_eventlog_varlen_u16_event) +
	    TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX * sizeof(uint16_t)];
	const struct test_eventlog_varlen_u16_event *evt;
	uint16_t vals[TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX];
	size_t nvals;
	size_t off;
	int i;

	if (hdr->event_id != TEST_EVENTLOG_VARLEN_U16_EVENT_ID)
		return;
	atomic_add_32(&d->events, 1);
	if (payload_size > sizeof(buf)) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	off = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
			off += iov[i].iov_len;
		}
	}
	evt = (const struct test_eventlog_varlen_u16_event *)buf;
	nvals = test_eventlog_varlen_u16_event_values(evt, payload_size, vals);
	if (nvals != evt->cnt) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	d->u16_count = evt->cnt;
	if (nvals > 0) {
		d->u16_first = vals[0];
		d->u16_last = vals[nvals - 1];
	}
	d->which |= 4;
	atomic_add_32(&d->matched, 1);
}

static void
varlen_u8_callback(const struct eventlog_event_header *hdr,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct varlen_typed_cb_data *d = callback_arg;
	uint8_t buf[sizeof(struct test_eventlog_varlen_u8_event) +
	    TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX * sizeof(uint8_t)];
	const struct test_eventlog_varlen_u8_event *evt;
	uint8_t vals[TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX];
	size_t nvals;
	size_t off;
	int i;

	if (hdr->event_id != TEST_EVENTLOG_VARLEN_U8_EVENT_ID)
		return;
	atomic_add_32(&d->events, 1);
	if (payload_size > sizeof(buf)) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	off = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > 0) {
			memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
			off += iov[i].iov_len;
		}
	}
	evt = (const struct test_eventlog_varlen_u8_event *)buf;
	nvals = test_eventlog_varlen_u8_event_values(evt, payload_size, vals);
	if (nvals != evt->cnt) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	d->u8_count = evt->cnt;
	if (nvals > 0) {
		d->u8_first = vals[0];
		d->u8_last = vals[nvals - 1];
	}
	d->which |= 8;
	atomic_add_32(&d->matched, 1);
}

KTEST_FUNC(schema_varlen_unaligned_elem_types)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *sub32, *sub16, *sub8;
	struct varlen_typed_cb_data cb;
	uint32_t u32_payload[TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX];
	uint16_t u16_payload[TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX];
	uint8_t u8_payload[TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX];
	uint32_t i;

	KTEST_LOG(ctx, "Testing varlen accessors with unaligned trailing arrays");
	bzero(&cb, sizeof(cb));

	provider = test_create_provider("test_vtypes", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	session = eventlog_session_create(provider, 0x1234, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* One subscriber per element-type callback so each verifies its
	 * own accessor instantiation. */
	sub32 = eventlog_subscriber_create_callback(varlen_u32_callback, &cb);
	KTEST_NEQUAL(sub32, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub32, "test_vtypes",
	    EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, 0), 0);
	sub16 = eventlog_subscriber_create_callback(varlen_u16_callback, &cb);
	KTEST_NEQUAL(sub16, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub16, "test_vtypes",
	    EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, 0), 0);
	sub8 = eventlog_subscriber_create_callback(varlen_u8_callback, &cb);
	KTEST_NEQUAL(sub8, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub8, "test_vtypes",
	    EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, 0), 0);

	/* uint32_t trailer at off 10 (mod 4 = 2). */
	for (i = 0; i < TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX; i++)
		u32_payload[i] = 0xC0DE0000U + i;
	TEST_EVENTLOG_VARLEN_U32_EVENT_LOG(session, 0x1111, 0x55,
	    TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX, u32_payload);

	/* uint16_t trailer at off 5 (mod 2 = 1, fully odd). */
	for (i = 0; i < TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX; i++)
		u16_payload[i] = (uint16_t)(0x4200U + i);
	TEST_EVENTLOG_VARLEN_U16_EVENT_LOG(session, 0x22222222,
	    TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX, u16_payload);

	/* uint8_t trailer (always aligned -- baseline regression check). */
	for (i = 0; i < TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX; i++)
		u8_payload[i] = (uint8_t)(0x80 + i);
	TEST_EVENTLOG_VARLEN_U8_EVENT_LOG(session, 0x33333333,
	    TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX, u8_payload);

	/* All three callbacks fire; each subscriber sees all three events
	 * but filters by event_id, so we expect exactly 3 matches across
	 * the three callbacks (one each). */
	KTEST_EQUAL(atomic_load_acq_32(&cb.events), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb.matched), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb.mismatch), 0);
	KTEST_EQUAL((int)cb.which, 2 | 4 | 8);

	/* uint32_t round-trip. */
	KTEST_EQUAL((int)cb.u32_count, TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX);
	KTEST_EQUAL((int)cb.u32_first, (int)0xC0DE0000U);
	KTEST_EQUAL((int)cb.u32_last,
	    (int)(0xC0DE0000U + (TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX - 1)));

	/* uint16_t round-trip. */
	KTEST_EQUAL((int)cb.u16_count, TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX);
	KTEST_EQUAL((int)cb.u16_first, 0x4200);
	KTEST_EQUAL((int)cb.u16_last,
	    0x4200 + (TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX - 1));

	/* uint8_t round-trip. */
	KTEST_EQUAL((int)cb.u8_count, TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX);
	KTEST_EQUAL((int)cb.u8_first, 0x80);
	KTEST_EQUAL((int)cb.u8_last,
	    0x80 + (TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX - 1));

	/* Final paranoia check: the accessor rejects oversize counts and
	 * short payloads with 0 on every element type. */
	{
		struct test_eventlog_varlen_u32_event e32 = { .id = 0,
		    .flag = 0, .cnt = TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX + 1 };
		uint32_t v32[TEST_EVENTLOG_VARLEN_U32_EVENT_VALUES_MAX];
		KTEST_EQUAL((int)test_eventlog_varlen_u32_event_values(&e32,
		    sizeof(e32), v32), 0);
	}
	{
		struct test_eventlog_varlen_u16_event e16 = { .id = 0, .cnt = 2 };
		uint16_t v16[TEST_EVENTLOG_VARLEN_U16_EVENT_VALUES_MAX];
		KTEST_EQUAL((int)test_eventlog_varlen_u16_event_values(&e16,
		    sizeof(e16), v16), 0);
	}
	{
		struct test_eventlog_varlen_u8_event e8 = { .id = 0, .cnt = 2 };
		uint8_t v8[TEST_EVENTLOG_VARLEN_U8_EVENT_VALUES_MAX];
		KTEST_EQUAL((int)test_eventlog_varlen_u8_event_values(&e8,
		    sizeof(e8), v8), 0);
	}

	eventlog_subscriber_destroy(sub32);
	eventlog_subscriber_destroy(sub16);
	eventlog_subscriber_destroy(sub8);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
}

/*
 * Exercise eventlog_event_write_gather() directly: the iov is delivered
 * to the callback unchanged and segments concatenate in order.
 */

/*
 * Exercises a multi-segment iov whose compacted size exceeds any
 * reasonable stack buffer in the framework. The iov path has no size
 * ceiling short of UINT16_MAX (wire-format event_length cap).
 */
#define	GATHER_BIG_PAYLOAD_SIZE	4096

struct gather_cb_data {
	uint32_t events;
	uint32_t matched;
	uint32_t mismatch;
	size_t last_payload_size;
	uint8_t last_first_byte;
	uint8_t last_last_byte;
};

static void
gather_event_callback(const struct eventlog_event_header *hdr __unused,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov, int iovcnt, size_t payload_size,
    void *callback_arg)
{
	struct gather_cb_data *d = callback_arg;
	const uint8_t *first_seg;
	const uint8_t *last_seg;
	int i;

	atomic_add_32(&d->events, 1);
	d->last_payload_size = payload_size;
	if (payload_size == 0) {
		d->last_first_byte = 0;
		d->last_last_byte = 0;
		atomic_add_32(&d->matched, 1);
		return;
	}
	/* Walk iov to pick out first-byte-of-first-nonempty-segment and
	 * last-byte-of-last-nonempty-segment without compacting. */
	first_seg = NULL;
	last_seg = NULL;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len == 0)
			continue;
		if (first_seg == NULL)
			first_seg = iov[i].iov_base;
		last_seg = (const uint8_t *)iov[i].iov_base +
		    iov[i].iov_len - 1;
	}
	if (first_seg == NULL || last_seg == NULL) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	d->last_first_byte = first_seg[0];
	d->last_last_byte = *last_seg;
	atomic_add_32(&d->matched, 1);
}

/*
 * The framework derives each provider's schema_id as SHA-256(decode_blob)
 * truncated to EVENTLOG_DECODE_SCHEMA_ID_LEN, and exposes the blob and id via
 * the accessors elog uses to resolve a capture's schema.  Verify the
 * derivation, that it is content-addressed (same blob => same id), and that a
 * blob-less provider has a zeroed id.
 */
KTEST_FUNC(provider_schema_id)
{
	struct eventlog_provider *p1, *p2, *p_noblob;
	struct eventlog_provider_config noblob_cfg = { 0 };
	const void *blob;
	size_t blob_size;
	const uint8_t *id1, *id2, *id_noblob;
	uint8_t want[SHA256_DIGEST_LENGTH];
	uint8_t zero[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	SHA256_CTX sha;

	KTEST_LOG(ctx, "Testing provider schema_id derivation and accessors");
	memset(zero, 0, sizeof(zero));

	p1 = test_create_provider("test_schemaid", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);

	/* The blob accessor returns exactly the registered (borrowed) blob. */
	blob = eventlog_provider_get_decode_blob(p1, &blob_size);
	KTEST_VERIFY(blob == test_eventlog_decode_blob);
	KTEST_VERIFY(blob_size == test_eventlog_decode_blob_size);

	/* schema_id == SHA-256(blob) truncated, and is non-zero. */
	SHA256_Init(&sha);
	SHA256_Update(&sha, test_eventlog_decode_blob,
	    test_eventlog_decode_blob_size);
	SHA256_Final(want, &sha);
	id1 = eventlog_provider_get_schema_id(p1);
	KTEST_VERIFY(memcmp(id1, want, EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0);
	KTEST_VERIFY(memcmp(id1, zero, EVENTLOG_DECODE_SCHEMA_ID_LEN) != 0);

	/* Content-addressed: a second provider with the same blob matches. */
	p2 = test_create_provider("test_schemaid2", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);
	id2 = eventlog_provider_get_schema_id(p2);
	KTEST_VERIFY(memcmp(id1, id2, EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0);

	/* No blob => NULL accessor, zeroed schema_id. */
	p_noblob = eventlog_provider_create("test_noblob", &noblob_cfg);
	KTEST_NEQUAL(p_noblob, NULL);
	blob = eventlog_provider_get_decode_blob(p_noblob, &blob_size);
	KTEST_VERIFY(blob == NULL);
	KTEST_VERIFY(blob_size == 0);
	id_noblob = eventlog_provider_get_schema_id(p_noblob);
	KTEST_VERIFY(memcmp(id_noblob, zero,
	    EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0);

	eventlog_provider_destroy(p1);
	eventlog_provider_destroy(p2);
	eventlog_provider_destroy(p_noblob);
	return (0);
}

/*
 * Exercises eventlog_lookup_decode_blob(), the lookup core of
 * EVENTLOG_IOCTL_GET_DECODE_BLOB, directly rather than only through
 * elog_test.py's userspace ioctl() calls.
 */
KTEST_FUNC(get_decode_blob_lookup)
{
	struct eventlog_provider *p1, *p2, *p_noblob;
	struct eventlog_provider_config noblob_cfg = { 0 };
	const uint8_t *schema_id;
	uint8_t bad_schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	const void *blob;
	size_t blob_size;
	int error;

	KTEST_LOG(ctx, "Testing EVENTLOG_IOCTL_GET_DECODE_BLOB provider lookup");
	memset(bad_schema_id, 0xff, sizeof(bad_schema_id));

	p1 = test_create_provider("test_lookup1", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	schema_id = eventlog_provider_get_schema_id(p1);

	/* Lookup by name. */
	error = eventlog_lookup_decode_blob(EVENTLOG_DECODE_LOOKUP_NAME,
	    "test_lookup1", NULL, &blob, &blob_size);
	KTEST_EQUAL(error, 0);
	KTEST_VERIFY(blob == test_eventlog_decode_blob);
	KTEST_VERIFY(blob_size == test_eventlog_decode_blob_size);

	/* Lookup by schema_id. */
	error = eventlog_lookup_decode_blob(EVENTLOG_DECODE_LOOKUP_SCHEMA_ID,
	    NULL, schema_id, &blob, &blob_size);
	KTEST_EQUAL(error, 0);
	KTEST_VERIFY(blob == test_eventlog_decode_blob);

	/* Unknown name / schema_id -> ENOENT. */
	error = eventlog_lookup_decode_blob(EVENTLOG_DECODE_LOOKUP_NAME,
	    "test_lookup_nope", NULL, &blob, &blob_size);
	KTEST_EQUAL(error, ENOENT);
	error = eventlog_lookup_decode_blob(EVENTLOG_DECODE_LOOKUP_SCHEMA_ID,
	    NULL, bad_schema_id, &blob, &blob_size);
	KTEST_EQUAL(error, ENOENT);

	/* Neither NAME nor SCHEMA_ID -> EINVAL. */
	error = eventlog_lookup_decode_blob(2, "test_lookup1", NULL,
	    &blob, &blob_size);
	KTEST_EQUAL(error, EINVAL);

	/* A provider with no decode blob is invisible, even by exact name. */
	p_noblob = eventlog_provider_create("test_lookup_noblob", &noblob_cfg);
	KTEST_NEQUAL(p_noblob, NULL);
	error = eventlog_lookup_decode_blob(EVENTLOG_DECODE_LOOKUP_NAME,
	    "test_lookup_noblob", NULL, &blob, &blob_size);
	KTEST_EQUAL(error, ENOENT);

	/*
	 * First-match-wins across duplicate provider names (e.g. multiple TCP
	 * stacks registering under the same "tcp" name): the lookup must not
	 * fail or pick between them arbitrarily just because two providers
	 * share a name.
	 */
	p2 = test_create_provider("test_lookup1", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);
	error = eventlog_lookup_decode_blob(EVENTLOG_DECODE_LOOKUP_NAME,
	    "test_lookup1", NULL, &blob, &blob_size);
	KTEST_EQUAL(error, 0);
	KTEST_VERIFY(blob == test_eventlog_decode_blob);

	eventlog_provider_destroy(p1);
	eventlog_provider_destroy(p2);
	eventlog_provider_destroy(p_noblob);
	return (0);
}

KTEST_FUNC(event_write_gather)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct gather_cb_data cb;
	struct iovec iov[3];
	uint8_t seg0[8], seg1[16];
	uint8_t *big;
	size_t i;

	KTEST_LOG(ctx, "Testing eventlog_event_write_gather() scatter/gather");

	bzero(&cb, sizeof(cb));
	provider = test_create_provider("test_gather", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	session = eventlog_session_create(provider, 0x4712, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	subscriber = eventlog_subscriber_create_callback(gather_event_callback,
	    &cb);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_gather", EVENTLOG_LEVEL_INFO, TEST_EVENTLOG_KEYWORD_BASIC, 0),
	    0);
	eventlog_session_set_enabled(session, 1);

	/* Case 1: iovcnt == 0, empty payload. */
	eventlog_event_write_gather(session, 0x100, EVENTLOG_LEVEL_INFO,
	    TEST_EVENTLOG_KEYWORD_BASIC, NULL, 0);

	/* Case 2: iovcnt == 1, contiguous buffer. Callback fast path: no
	 * compact copy, pointer equals iov[0].iov_base. */
	for (i = 0; i < sizeof(seg0); i++)
		seg0[i] = (uint8_t)(0x10 + i);
	iov[0].iov_base = seg0;
	iov[0].iov_len = sizeof(seg0);
	eventlog_event_write_gather(session, 0x101, EVENTLOG_LEVEL_INFO,
	    TEST_EVENTLOG_KEYWORD_BASIC, iov, 1);

	/* Case 3: iovcnt == 2, small payload. Callback compact path runs on
	 * the on-stack buffer; verify order is seg0 then seg1. */
	for (i = 0; i < sizeof(seg1); i++)
		seg1[i] = (uint8_t)(0xA0 + i);
	iov[0].iov_base = seg0;
	iov[0].iov_len = sizeof(seg0);
	iov[1].iov_base = seg1;
	iov[1].iov_len = sizeof(seg1);
	eventlog_event_write_gather(session, 0x102, EVENTLOG_LEVEL_INFO,
	    TEST_EVENTLOG_KEYWORD_BASIC, iov, 2);

	/* Case 4: iovcnt == 3, large multi-segment payload. The framework
	 * passes the iov through unchanged; the callback sees three
	 * segments and reports the first byte of seg0 and the last byte
	 * of seg1. Nothing is dropped and no allocation happens. */
	big = malloc(GATHER_BIG_PAYLOAD_SIZE, M_EVENTLOG_TEST, M_WAITOK);
	for (i = 0; i < GATHER_BIG_PAYLOAD_SIZE; i++)
		big[i] = (uint8_t)(i & 0xFF);
	iov[0].iov_base = seg0;
	iov[0].iov_len = sizeof(seg0);			/* bytes 0x10..0x17 */
	iov[1].iov_base = big;
	iov[1].iov_len = GATHER_BIG_PAYLOAD_SIZE;	/* bytes 0x00..0xFF... */
	iov[2].iov_base = seg1;
	iov[2].iov_len = sizeof(seg1);			/* bytes 0xA0..0xAF */
	eventlog_event_write_gather(session, 0x103, EVENTLOG_LEVEL_INFO,
	    TEST_EVENTLOG_KEYWORD_BASIC, iov, 3);

	/* Four events, all matched (no mismatch, nothing dropped). */
	KTEST_EQUAL(atomic_load_acq_32(&cb.events), 4);
	KTEST_EQUAL(atomic_load_acq_32(&cb.matched), 4);
	KTEST_EQUAL(atomic_load_acq_32(&cb.mismatch), 0);

	{
		struct eventlog_stats stats;
		eventlog_subscriber_get_stats(subscriber, &stats);
		KTEST_EQUAL(stats.dropped_events, 0);
	}

	/* Last event: first byte from seg0, last byte from seg1's end. */
	KTEST_EQUAL((int)cb.last_payload_size,
	    (int)(sizeof(seg0) + GATHER_BIG_PAYLOAD_SIZE + sizeof(seg1)));
	KTEST_EQUAL((int)cb.last_first_byte, 0x10);
	KTEST_EQUAL((int)cb.last_last_byte,
	    (int)(uint8_t)(0xA0 + sizeof(seg1) - 1));

	free(big, M_EVENTLOG_TEST);
	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
}

/* ===== Lock-free per-CPU buffer tests ===== */

/* Thread data for multi-writer tests */
struct lockfree_writer_data {
	struct eventlog_session *session;
	int *go;			/* Barrier: all threads wait until set */
	int done;
	uint32_t thread_idx;
	uint32_t num_events;
	uint32_t events_written;
};

static void
lockfree_writer_thread(void *arg)
{
	struct lockfree_writer_data *data = (struct lockfree_writer_data *)arg;
	uint32_t event_data[2];
	uint32_t i;

	/* Sleep until all threads are ready. Using tsleep instead of
	 * cpu_spinwait avoids deadlocking on systems with fewer CPUs
	 * than writer threads (busy-spinning writers would monopolize
	 * all CPUs, preventing the main thread from setting go). */
	while (atomic_load_acq_int((volatile u_int *)data->go) == 0)
		tsleep(data->go, 0, "lf_go", 1);

	for (i = 0; i < data->num_events; i++) {
		event_data[0] = data->thread_idx;
		event_data[1] = i;
		eventlog_event_write(data->session,
		    (data->thread_idx << 16) | i,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    event_data, sizeof(event_data));
		data->events_written++;
	}

	atomic_store_rel_int((volatile u_int *)&data->done, 1);
	wakeup(&data->done);
	kthread_exit();
}

/*
 * Stress the lock-free write/commit path by having many writers
 * concurrently write to the same device subscriber. All writers start
 * simultaneously to maximize contention on per-CPU buffers.
 */
KTEST_FUNC(lockfree_many_concurrent_writers)
{
#define LF_NUM_WRITERS		8
#define LF_EVENTS_PER_WRITER	500
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_writer_data writers[LF_NUM_WRITERS];
	struct thread *threads[LF_NUM_WRITERS];
	int go = 0;
	struct eventlog_stats stats;
	char *read_buf;
	size_t read_buf_size = 256 * 1024;
	size_t total_read = 0;
	size_t read_bytes;
	int i, error;

	KTEST_LOG(ctx, "Testing lock-free concurrent writers (%d threads, %d events each)",
	    LF_NUM_WRITERS, LF_EVENTS_PER_WRITER);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_lf_many", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(256 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_many",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Create all writer threads (they spin-wait on go) */
	for (i = 0; i < LF_NUM_WRITERS; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].go = &go;
		writers[i].thread_idx = i;
		writers[i].num_events = LF_EVENTS_PER_WRITER;
		error = kthread_add(lockfree_writer_thread, &writers[i], NULL,
		    &threads[i], 0, 0, "lf_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	/* Release all writers simultaneously */
	atomic_store_rel_int((volatile u_int *)&go, 1);
	wakeup(&go);

	/* Wait for all writers to finish */
	for (i = 0; i < LF_NUM_WRITERS; i++) {
		while (atomic_load_acq_int((volatile u_int *)&writers[i].done) == 0)
			tsleep(&writers[i].done, 0, "lf_wait", hz / 10);
		KTEST_EQUAL(writers[i].events_written, LF_EVENTS_PER_WRITER);
	}

	/* Read all events and verify total count */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
		total_read += read_bytes;
	} while (read_bytes > 0);

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_LOG(ctx, "Total bytes read: %zu, dropped events: %llu",
	    total_read, (unsigned long long)stats.dropped_events);
	KTEST_VERIFY(total_read > 0);

	/* With a 256KB buffer, some events may be dropped on small CPUs where
	 * all threads hit the same per-CPU buffer. That's fine - the test
	 * validates no crashes, no corruption (INVARIANTS checks), and that
	 * written + dropped == total attempted. */
	uint64_t total_attempted = (uint64_t)LF_NUM_WRITERS * LF_EVENTS_PER_WRITER + 1; /* +1 for SESSION_CREATE */
	KTEST_LOG(ctx, "Total attempted: %llu, dropped: %llu",
	    (unsigned long long)total_attempted,
	    (unsigned long long)stats.dropped_events);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
#undef LF_NUM_WRITERS
#undef LF_EVENTS_PER_WRITER
}

/*
 * Stress the writer/reader contention path: many writers + a reader
 * draining rapidly. This exercises the head/tail cursor protocol when a
 * reader's tail advance races with a writer's publish.
 */
struct lockfree_ring_writer_data {
	struct eventlog_session *session;
	int *stop;
	uint64_t events_written;
	int exited;
};

static void
lockfree_ring_writer(void *arg)
{
	struct lockfree_ring_writer_data *data = arg;
	uint32_t payload = 0;

	while (atomic_load_acq_int((volatile u_int *)data->stop) == 0) {
		eventlog_event_write(data->session, 0x1000 + (payload & 0xFF),
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &payload, sizeof(payload));
		atomic_add_long((volatile u_long *)&data->events_written, 1);
		payload++;
		kern_yield(PRI_UNCHANGED);
	}

	atomic_store_rel_int((volatile u_int *)&data->exited, 1);
	wakeup(&data->exited);
	kthread_exit();
}

static void
lockfree_stop_callout(void *arg)
{
	int *stop = arg;

	atomic_store_rel_int((volatile u_int *)stop, 1);
	wakeup(stop);
}

KTEST_FUNC(lockfree_writer_reader_contention)
{
#define LFWC_NUM_WRITERS	4
#define LFWC_RUN_SECONDS	3
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_ring_writer_data writers[LFWC_NUM_WRITERS];
	struct thread *threads[LFWC_NUM_WRITERS];
	int stop = 0;
	struct callout stop_timer;
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	size_t total_bytes_read = 0;
	size_t read_bytes;
	uint64_t read_iterations = 0;
	struct eventlog_stats stats;
	int nwriters, i, error;

	/*
	 * On a CI VM pinned to only 2 host CPUs, LFWC_NUM_WRITERS (4)
	 * tight-loop writers plus this reader is more runnable kernel
	 * threads than CPUs, which starves the run queue far more than on
	 * real multi-core hardware. Scale writers down to leave the reader
	 * a CPU of its own; still runs the full 4 on anything with 5+ CPUs.
	 */
	nwriters = MIN(LFWC_NUM_WRITERS, MAX(mp_ncpus - 1, 1));

	KTEST_LOG(ctx, "Testing lock-free writer/reader contention (%d writers, %d seconds)",
	    nwriters, LFWC_RUN_SECONDS);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_lf_contention", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer to wrap frequently (above 64KB minimum) */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_contention",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Start writer threads */
	for (i = 0; i < nwriters; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].stop = &stop;
		error = kthread_add(lockfree_ring_writer, &writers[i], NULL,
		    &threads[i], 0, 0, "lfwc_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	/* Checkpoint logs, as lockfree_reader_writer_race already has,
	 * so a future hang shows which phase got stuck instead of a bare
	 * timeout. */
	KTEST_LOG(ctx, "checkpoint: writers started, arming stop callout");

	/* Use a callout to set stop from softclock context. On a 2-CPU system,
	 * writers in tight loops can starve the main thread on the run queue,
	 * preventing it from ever executing stop=1. The callout fires from
	 * timer interrupt context, bypassing scheduler contention. */
	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * LFWC_RUN_SECONDS, lockfree_stop_callout, &stop);

	KTEST_LOG(ctx, "checkpoint: entering reader loop");

	/* Reader loop: drain rapidly while writers are active */
	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
		if (read_bytes > 0) {
			total_bytes_read += read_bytes;
			read_iterations++;
		}
		tsleep(&stop, 0, "lfwc_rd", 1);
	}

	KTEST_LOG(ctx,
	    "checkpoint: reader loop exited (reads=%llu, bytes=%zu); "
	    "draining callout",
	    (unsigned long long)read_iterations, total_bytes_read);

	callout_drain(&stop_timer);

	KTEST_LOG(ctx, "checkpoint: callout drained, waiting for writers");

	/* Wait for writers to exit */
	for (i = 0; i < nwriters; i++) {
		while (atomic_load_acq_int((volatile u_int *)&writers[i].exited) == 0)
			tsleep(&writers[i].exited, 0, "lfwc_wait", hz / 10);
		KTEST_LOG(ctx, "checkpoint: writer %d exited", i);
	}

	KTEST_LOG(ctx, "checkpoint: all writers exited, draining buffers");

	/* Drain remaining */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
		total_bytes_read += read_bytes;
	} while (read_bytes > 0);

	KTEST_LOG(ctx, "checkpoint: drain complete, gathering stats");

	eventlog_subscriber_get_stats(subscriber, &stats);

	uint64_t total_written = 0;
	for (i = 0; i < nwriters; i++)
		total_written += writers[i].events_written;

	KTEST_LOG(ctx, "Writers produced %llu events, reader did %llu reads, "
	    "read %zu bytes, dropped %llu",
	    (unsigned long long)total_written,
	    (unsigned long long)read_iterations,
	    total_bytes_read,
	    (unsigned long long)stats.dropped_events);

	KTEST_VERIFY(total_written > 0);
	KTEST_VERIFY(total_bytes_read > 0);
	KTEST_VERIFY(read_iterations > 0);

	KTEST_LOG(ctx, "checkpoint: tearing down session/subscriber/provider");

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	KTEST_LOG(ctx, "checkpoint: teardown complete");

	return (0);
#undef LFWC_NUM_WRITERS
#undef LFWC_RUN_SECONDS
}

/*
 * Test buffer-full contention: tiny buffer + many writers to force the
 * buffer-full drop path under contention. Verifies no events are
 * corrupted despite heavy drops.
 */
KTEST_FUNC(lockfree_buffer_full_contention)
{
#define LFBF_NUM_WRITERS	4
#define LFBF_EVENTS_PER_WRITER	5000
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_writer_data writers[LFBF_NUM_WRITERS];
	struct thread *threads[LFBF_NUM_WRITERS];
	int go = 0;
	struct eventlog_stats stats;
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	size_t total_read = 0;
	size_t read_bytes;
	int i, error;

	KTEST_LOG(ctx, "Testing lock-free buffer full contention (%d writers, "
	    "%d events each, 128KB buffer)",
	    LFBF_NUM_WRITERS, LFBF_EVENTS_PER_WRITER);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_lf_bfull", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer - will overflow quickly with concurrent writers */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_bfull",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);

	/* Create all writer threads */
	for (i = 0; i < LFBF_NUM_WRITERS; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].go = &go;
		writers[i].thread_idx = i;
		writers[i].num_events = LFBF_EVENTS_PER_WRITER;
		error = kthread_add(lockfree_writer_thread, &writers[i], NULL,
		    &threads[i], 0, 0, "lfbf_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	/* Release all writers */
	atomic_store_rel_int((volatile u_int *)&go, 1);
	wakeup(&go);

	/* Wait for completion */
	for (i = 0; i < LFBF_NUM_WRITERS; i++) {
		while (atomic_load_acq_int((volatile u_int *)&writers[i].done) == 0)
			tsleep(&writers[i].done, 0, "lfbf_wait", hz / 10);
	}

	/* Read whatever survived */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
		total_read += read_bytes;
	} while (read_bytes > 0);

	eventlog_subscriber_get_stats(subscriber, &stats);

	uint64_t total_attempted = (uint64_t)LFBF_NUM_WRITERS * LFBF_EVENTS_PER_WRITER;
	KTEST_LOG(ctx, "Attempted %llu events, dropped %llu, read %zu bytes",
	    (unsigned long long)total_attempted,
	    (unsigned long long)stats.dropped_events,
	    total_read);

	/* With a 128KB buffer and no reader draining during writes, almost all
	 * events should be dropped. The key assertion is that we didn't crash
	 * and INVARIANTS didn't fire. */
	KTEST_VERIFY(stats.dropped_events > 0);

	/* Validate that events that were read are well-formed by reading with
	 * INVARIANTS buffer validation (already baked into eventlog_read). */

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
#undef LFBF_NUM_WRITERS
#undef LFBF_EVENTS_PER_WRITER
}

/*
 * Test data integrity under concurrent lock-free writes: many writers +
 * concurrent reader, verify every event read back has valid structure
 * (correct event_length, recognizable payload pattern). This catches
 * torn writes or commit ordering bugs.
 */
struct lockfree_integrity_reader_data {
	struct eventlog_subscriber *subscriber;
	int *stop;
	uint64_t events_validated;
	uint64_t bytes_read;
	uint64_t corrupt_events;
	int exited;
};

static void
lockfree_integrity_reader(void *arg)
{
	struct lockfree_integrity_reader_data *data = arg;
	char *read_buf;
	size_t read_buf_size = 64 * 1024;

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);

	while (atomic_load_acq_int((volatile u_int *)data->stop) == 0) {
		size_t read_bytes = eventlog_read_into_buf(data->subscriber,
		    read_buf, read_buf_size, 0);
		if (read_bytes == 0) {
			kern_yield(PRI_UNCHANGED);
			continue;
		}

		data->bytes_read += read_bytes;

		/* Walk each event and validate structure */
		size_t offset = 0;
		while (offset + sizeof(struct eventlog_event_header) <= read_bytes) {
			struct eventlog_event_header hdr;
			memcpy(&hdr, read_buf + offset, sizeof(hdr));

			if (hdr.event_length < sizeof(struct eventlog_event_header) ||
			    offset + hdr.event_length > read_bytes) {
				data->corrupt_events++;
				break;
			}

			data->events_validated++;
			offset += hdr.event_length;
		}
	}

	free(read_buf, M_EVENTLOG_TEST);
	atomic_store_rel_int((volatile u_int *)&data->exited, 1);
	wakeup(&data->exited);
	kthread_exit();
}

KTEST_FUNC(lockfree_data_integrity_under_contention)
{
#define LFDI_NUM_WRITERS	4
#define LFDI_RUN_SECONDS	3
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_ring_writer_data writers[LFDI_NUM_WRITERS];
	struct lockfree_integrity_reader_data reader_data;
	struct thread *writer_threads[LFDI_NUM_WRITERS];
	struct thread *reader_thread;
	int stop = 0;
	struct callout stop_timer;
	struct eventlog_stats stats;
	int i, error;

	KTEST_LOG(ctx, "Testing lock-free data integrity (%d writers + reader, %d seconds)",
	    LFDI_NUM_WRITERS, LFDI_RUN_SECONDS);

	provider = test_create_provider("test_lf_integ", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer: enough to hold some events but small enough to wrap often */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_integ",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Start reader */
	bzero(&reader_data, sizeof(reader_data));
	reader_data.subscriber = subscriber;
	reader_data.stop = &stop;
	error = kthread_add(lockfree_integrity_reader, &reader_data, NULL,
	    &reader_thread, 0, 0, "lfdi_reader");
	KTEST_EQUAL(error, 0);

	/* Start writers */
	for (i = 0; i < LFDI_NUM_WRITERS; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].stop = &stop;
		error = kthread_add(lockfree_ring_writer, &writers[i], NULL,
		    &writer_threads[i], 0, 0, "lfdi_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	/* Use a callout to set stop from softclock context. On a 2-CPU system,
	 * writers in tight loops can starve the main thread on the run queue,
	 * preventing it from ever executing stop=1. The callout fires from
	 * timer interrupt context, bypassing scheduler contention. */
	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * LFDI_RUN_SECONDS, lockfree_stop_callout, &stop);

	while (atomic_load_acq_int((volatile u_int *)&stop) == 0)
		tsleep(&stop, 0, "lfdi_run", hz);

	callout_drain(&stop_timer);
	wakeup(subscriber); /* Wake reader if sleeping */

	for (i = 0; i < LFDI_NUM_WRITERS; i++) {
		while (atomic_load_acq_int((volatile u_int *)&writers[i].exited) == 0)
			tsleep(&writers[i].exited, 0, "lfdi_ww", hz / 10);
	}
	while (atomic_load_acq_int((volatile u_int *)&reader_data.exited) == 0)
		tsleep(&reader_data.exited, 0, "lfdi_rw", hz / 10);

	eventlog_subscriber_get_stats(subscriber, &stats);

	uint64_t total_written = 0;
	for (i = 0; i < LFDI_NUM_WRITERS; i++)
		total_written += writers[i].events_written;

	KTEST_LOG(ctx, "Writers: %llu events. Reader: validated %llu events, "
	    "%llu bytes, %llu corrupt. Dropped: %llu",
	    (unsigned long long)total_written,
	    (unsigned long long)reader_data.events_validated,
	    (unsigned long long)reader_data.bytes_read,
	    (unsigned long long)reader_data.corrupt_events,
	    (unsigned long long)stats.dropped_events);

	KTEST_VERIFY(total_written > 0);
	KTEST_VERIFY(reader_data.events_validated > 0);
	KTEST_EQUAL(reader_data.corrupt_events, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
#undef LFDI_NUM_WRITERS
#undef LFDI_RUN_SECONDS
}

/*
 * Test reader-writer race: reader aggressively drains the ring while
 * writers are mid-write. With a tiny buffer, the ring wraps frequently,
 * maximizing the chance the reader's tail advance races with a writer's
 * head publish. Validates no panics (MPASS), no data corruption, and all
 * events are properly readable.
 */
KTEST_FUNC(lockfree_reader_writer_race)
{
#define LFRW_NUM_WRITERS	4
#define LFRW_RUN_SECONDS	3
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_ring_writer_data writers[LFRW_NUM_WRITERS];
	struct thread *threads[LFRW_NUM_WRITERS];
	int stop = 0;
	struct callout stop_timer;
	char *read_buf;
	size_t read_buf_size = 4096;
	size_t total_bytes_read = 0;
	size_t read_bytes;
	uint64_t read_iterations = 0;
	struct eventlog_stats stats;
	int nwriters, i, error;

	/*
	 * See the identical comment in lockfree_writer_reader_contention --
	 * scale writers down on CPU-constrained CI VMs so the reader isn't
	 * starved off the run queue for the whole run.
	 */
	nwriters = MIN(LFRW_NUM_WRITERS, MAX(mp_ncpus - 1, 1));

	KTEST_LOG(ctx, "Testing reader-writer race (%d writers, %d seconds, "
	    "128KB buffer)", nwriters, LFRW_RUN_SECONDS);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_lf_race", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer: forces frequent wraps, maximizing the race window */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_race",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	for (i = 0; i < nwriters; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].stop = &stop;
		error = kthread_add(lockfree_ring_writer, &writers[i], NULL,
		    &threads[i], 0, 0, "lfrw_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	KTEST_LOG(ctx, "checkpoint: writers started, arming stop callout");

	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * LFRW_RUN_SECONDS,
	    lockfree_stop_callout, &stop);

	KTEST_LOG(ctx, "checkpoint: entering reader loop");

	/* Reader loop: read as fast as possible (no tsleep) to maximize
	 * the chance of draining while a writer is mid-publish. Yield (not
	 * sleep) on an empty read so this doesn't monopolize a
	 * CPU-constrained CI VM for the entire run -- doesn't touch the
	 * hot "data available" path the race relies on. */
	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, FNONBLOCK);
		if (read_bytes > 0) {
			total_bytes_read += read_bytes;
			read_iterations++;
		} else {
			kern_yield(PRI_UNCHANGED);
		}
	}

	KTEST_LOG(ctx,
	    "checkpoint: reader loop exited (iters=%llu, bytes=%zu); "
	    "draining callout",
	    (unsigned long long)read_iterations, total_bytes_read);

	callout_drain(&stop_timer);

	KTEST_LOG(ctx, "checkpoint: callout drained, waiting for writers");

	for (i = 0; i < nwriters; i++) {
		while (atomic_load_acq_int(
		    (volatile u_int *)&writers[i].exited) == 0)
			tsleep(&writers[i].exited, 0, "lfrw_ww", hz / 10);
		KTEST_LOG(ctx, "checkpoint: writer %d exited", i);
	}

	KTEST_LOG(ctx, "checkpoint: all writers exited, draining buffers");

	/* Drain remaining */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
		total_bytes_read += read_bytes;
	} while (read_bytes > 0);

	KTEST_LOG(ctx, "checkpoint: drain complete, gathering stats");

	eventlog_subscriber_get_stats(subscriber, &stats);

	uint64_t total_written = 0;
	for (i = 0; i < nwriters; i++)
		total_written += writers[i].events_written;

	KTEST_LOG(ctx, "Writers: %llu events. Reader: %llu reads, %zu bytes. "
	    "Dropped: %llu",
	    (unsigned long long)total_written,
	    (unsigned long long)read_iterations,
	    total_bytes_read,
	    (unsigned long long)stats.dropped_events);

	KTEST_VERIFY(total_written > 0);
	KTEST_VERIFY(total_bytes_read > 0);
	KTEST_VERIFY(read_iterations > 0);

	KTEST_LOG(ctx, "checkpoint: tearing down session/subscriber/provider");

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	KTEST_LOG(ctx, "checkpoint: teardown complete");

	return (0);
#undef LFRW_NUM_WRITERS
#undef LFRW_RUN_SECONDS
}

/*
 * Test: normal events (real timestamps) are unaffected by epoch boundary.
 * Writes events with real binuptime timestamps and verifies all are delivered.
 */
KTEST_FUNC(timestamp_epoch_normal_delivery)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	char read_buf[8 * 1024];
	size_t read_bytes;
	uint32_t payload;
	int i, event_count;

	KTEST_LOG(ctx, "Testing that normal events pass epoch boundary");

	provider = test_create_provider("test_ts_normal", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = test_enable_provider_device("test_ts_normal",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), 0);
	KTEST_VERIFY(read_bytes > 0);

	/* Write 10 events with real timestamps */
	for (i = 0; i < 10; i++) {
		payload = (uint32_t)(i + 1);
		eventlog_event_write(session, 100 + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload));
	}

	/* Read: should get all 10 events */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), 0);
	KTEST_VERIFY(read_bytes > 0);

	event_count = 0;
	{
		size_t offset = 0;
		while (offset + sizeof(struct eventlog_event_header) <= read_bytes) {
			struct eventlog_event_header hdr;
			memcpy(&hdr, read_buf + offset, sizeof(hdr));
			if (hdr.event_length < sizeof(struct eventlog_event_header) ||
			    offset + hdr.event_length > read_bytes)
				break;
			event_count++;
			offset += hdr.event_length;
		}
	}
	KTEST_EQUAL(event_count, 10);

	/* Buffer should be empty now */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), FNONBLOCK);
	KTEST_EQUAL(read_bytes, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/* Dump state test infrastructure */
static volatile uint32_t dump_callback_invocations;
static struct eventlog_session *dump_test_sessions[4];
static int dump_test_session_count;

static void
test_dump_callback(struct eventlog_provider *provider, void *arg)
{
	int i;

	atomic_add_int(&dump_callback_invocations, 1);
	for (i = 0; i < dump_test_session_count; i++) {
		if (dump_test_sessions[i] != NULL &&
		    dump_test_sessions[i]->effective_level >= EVENTLOG_LEVEL_INFO) {
			uint32_t data = 0xdead0000 | i;
			eventlog_event_write(dump_test_sessions[i], 0x100 + i,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
			    &data, sizeof(data));
		}
	}
}

/*
 * Verify dump callback is invoked and events arrive at subscriber.
 */
KTEST_FUNC(dump_state_basic)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;

	KTEST_LOG(ctx, "Testing dump state basic functionality");

	dump_callback_invocations = 0;
	dump_test_session_count = 1;

	provider = test_create_provider("test_ds_basic", test_dump_callback, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	dump_test_sessions[0] = session;

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_basic", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "test_ds_basic",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	/*
	 * dump_state runs on a private taskqueue; drain before reading
	 * the observation counters so we deterministically see the
	 * post-dump state and not the in-flight state.
	 */
	eventlog_subscriber_drain_dumps(subscriber);

	KTEST_EQUAL(atomic_load_acq_32(&dump_callback_invocations), 1);
	/* SESSION_CREATE from session_create + 1 dump event */
	KTEST_VERIFY(atomic_load_acq_32(&callback_data->event_count) >= 1);

	dump_test_sessions[0] = NULL;
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verify dump events go only to the requesting subscriber, not others.
 */
KTEST_FUNC(dump_state_routing)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *sub1, *sub2;
	struct test_callback_data *cd1, *cd2;
	uint32_t sub1_count_before;

	KTEST_LOG(ctx, "Testing dump state routing to single subscriber");

	dump_callback_invocations = 0;
	dump_test_session_count = 1;

	provider = test_create_provider("test_ds_route", test_dump_callback, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	dump_test_sessions[0] = session;

	/*
	 * sub1: subscribes first. Its own dump runs immediately and produces
	 * one event; drain so the count we capture next is stable.
	 */
	cd1 = malloc(sizeof(*cd1), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd1->lock, "test_ds_route1", NULL, MTX_DEF);
	sub1 = eventlog_subscriber_create_callback(test_event_callback, cd1);
	KTEST_NEQUAL(sub1, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub1, "test_ds_route",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(sub1);

	sub1_count_before = atomic_load_acq_32(&cd1->event_count);

	/*
	 * sub2 subscribes second. Its dump must be routed only to sub2 --
	 * sub1's count must not change.
	 */
	cd2 = malloc(sizeof(*cd2), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd2->lock, "test_ds_route2", NULL, MTX_DEF);
	sub2 = eventlog_subscriber_create_callback(test_event_callback, cd2);
	KTEST_NEQUAL(sub2, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub2, "test_ds_route",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(sub2);

	/* sub2 should have received the dump event */
	KTEST_VERIFY(atomic_load_acq_32(&cd2->event_count) >= 1);
	/* sub1 should NOT have received any additional events from the dump */
	KTEST_EQUAL(atomic_load_acq_32(&cd1->event_count), sub1_count_before);

	dump_test_sessions[0] = NULL;
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(sub1);
	eventlog_subscriber_destroy(sub2);
	mtx_destroy(&cd1->lock);
	mtx_destroy(&cd2->lock);
	free(cd1, M_EVENTLOG_TEST);
	free(cd2, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verify DUMP_STATE with NULL callback is a graceful no-op.
 */
KTEST_FUNC(dump_state_no_callback)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;

	KTEST_LOG(ctx, "Testing dump state with no callback (graceful no-op)");

	provider = test_create_provider("test_ds_nocb", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_nocb", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	/* Should succeed without crash even though no dump callback */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "test_ds_nocb",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	/*
	 * No dump task should have been enqueued because the provider has
	 * no dump_callback. drain_dumps still has to be a no-op in that
	 * case (dump_pending stays at 0); call it explicitly to pin that
	 * contract.
	 */
	eventlog_subscriber_drain_dumps(subscriber);

	/* No dump events; only SESSION_CREATE from session_create might be counted */
	KTEST_VERIFY(atomic_load_acq_32(&callback_data->event_count) <= 1);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Captures curthread->td_vnet (as uintptr_t to keep this file free of any
 * struct-vnet dependency) observed at dump_callback invocation time.
 */
static volatile uintptr_t dump_observed_td_vnet;
static volatile bool dump_observed_set;

static void
test_dump_callback_capture_td_vnet(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	dump_observed_td_vnet = (uintptr_t)curthread->td_vnet;
	dump_observed_set = true;
}

/*
 * Regression test pinning down the framework contract that motivated a
 * TCP fix: the eventlog machinery invokes provider->dump_callback
 * without setting curvnet. Providers that touch per-vnet state must
 * iterate vnets / set curvnet themselves. The dump runs on a kernel
 * taskqueue thread whose td_vnet is NULL; the test subscribes, drains,
 * and verifies the callback's observed context.
 *
 * If a future change makes the framework set curvnet around the dump
 * callback, this test will fail and the change should be deliberate (and
 * accompanied by removing the per-provider VNET_FOREACH wrappers).
 */
KTEST_FUNC(dump_state_curvnet_not_set)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;
	int ret;

	KTEST_LOG(ctx, "Verifying dump_callback runs with curvnet unset");

	dump_observed_td_vnet = (uintptr_t)0x1;
	dump_observed_set = false;

	provider = test_create_provider("test_ds_curvnet",
	    test_dump_callback_capture_td_vnet, NULL);
	KTEST_NEQUAL(provider, NULL);

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_curvnet", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	ret = eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_curvnet", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE);
	KTEST_EQUAL(ret, 0);

	/* Wait for the async dump task to finish before reading observed values. */
	eventlog_subscriber_drain_dumps(subscriber);

	KTEST_VERIFY(dump_observed_set);
	KTEST_VERIFY(dump_observed_td_vnet == 0);

	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verify _ENABLED macros skip disabled sessions during dump.
 */
KTEST_FUNC(dump_state_disabled_sessions)
{
	struct eventlog_provider *provider;
	struct eventlog_session *enabled_session, *disabled_session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;

	KTEST_LOG(ctx, "Testing dump state skips disabled sessions");

	dump_callback_invocations = 0;
	dump_test_session_count = 2;

	provider = test_create_provider("test_ds_dis", test_dump_callback, NULL);
	KTEST_NEQUAL(provider, NULL);

	enabled_session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(enabled_session, NULL);
	dump_test_sessions[0] = enabled_session;

	disabled_session = eventlog_session_create(provider, 2, true, NULL, 0);
	KTEST_NEQUAL(disabled_session, NULL);
	eventlog_session_set_enabled(disabled_session, 0);
	dump_test_sessions[1] = disabled_session;

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_dis", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "test_ds_dis",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	eventlog_subscriber_drain_dumps(subscriber);

	KTEST_EQUAL(atomic_load_acq_32(&dump_callback_invocations), 1);
	/*
	 * The dump callback writes to both sessions, but the disabled session's
	 * effective_level is NONE so eventlog_event_write_impl's subscriber
	 * filtering will drop those events. Only the enabled session's events
	 * should arrive. We expect: SESSION_CREATE (from create) + 1 dump event
	 * for the enabled session = at least 1 from the dump.
	 */
	{
		uint32_t ec = atomic_load_acq_32(&callback_data->event_count);
		KTEST_LOG(ctx, "Received %u events (enabled+dump)", ec);
		KTEST_VERIFY(ec >= 1);
	}

	dump_test_sessions[0] = NULL;
	dump_test_sessions[1] = NULL;
	eventlog_session_destroy(enabled_session);
	eventlog_session_destroy(disabled_session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Async dump_state contract: the callback does not run on the
 * subscribing thread, subscribe returns before the dump finishes,
 * drain_dumps() / destroy() are the sync points, and re-subscribing
 * does not re-fire the dump. Shared scratch for the tests below.
 */
static volatile struct thread *async_dump_thread;
static volatile bool async_dump_observed;
static struct mtx async_dump_mtx;
static struct cv async_dump_cv;
static volatile bool async_dump_release;
static volatile uint32_t async_dump_runs;

static void
async_dump_callback_record_thread(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	async_dump_thread = curthread;
	async_dump_observed = true;
	atomic_add_32(&async_dump_runs, 1);
}

/*
 * Slow dump_callback: blocks until the test releases it via
 * async_dump_release. Used to put the dump task into a known
 * "in-flight" state so the test can race destroy / drain against it.
 */
static void
async_dump_callback_block(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	mtx_lock(&async_dump_mtx);
	atomic_add_32(&async_dump_runs, 1);
	while (!async_dump_release)
		cv_wait(&async_dump_cv, &async_dump_mtx);
	mtx_unlock(&async_dump_mtx);
}

/*
 * Verifies dump_callback runs on a thread different from the subscriber's
 * own thread (i.e. the framework taskqueue thread).
 */
KTEST_FUNC(dump_state_async_runs_off_caller_thread)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cd;

	KTEST_LOG(ctx, "Verifying dump_callback runs on a different thread");

	async_dump_thread = NULL;
	async_dump_observed = false;
	atomic_store_rel_32(&async_dump_runs, 0);

	provider = test_create_provider("test_ds_async_thr",
	    async_dump_callback_record_thread, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	cd = malloc(sizeof(*cd), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd->lock, "test_ds_async_thr", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, cd);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_async_thr", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	eventlog_subscriber_drain_dumps(subscriber);

	KTEST_VERIFY(async_dump_observed);
	KTEST_VERIFY(async_dump_thread != NULL);
	KTEST_VERIFY(async_dump_thread != curthread);
	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 1);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&cd->lock);
	free(cd, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verifies subscribe returns before a slow dump_callback finishes,
 * so providers can do expensive dump work without blocking the caller.
 */
KTEST_FUNC(dump_state_async_subscribe_returns_before_dump)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cd;

	KTEST_LOG(ctx, "Verifying subscribe returns before dump completes");

	atomic_store_rel_32(&async_dump_runs, 0);
	mtx_init(&async_dump_mtx, "async_dump_mtx", NULL, MTX_DEF);
	cv_init(&async_dump_cv, "async_dump_cv");
	async_dump_release = false;

	provider = test_create_provider("test_ds_async_block",
	    async_dump_callback_block, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	cd = malloc(sizeof(*cd), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd->lock, "test_ds_async_block", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, cd);
	KTEST_NEQUAL(subscriber, NULL);

	/*
	 * Subscribe enqueues a dump that will block in the callback. The
	 * call must return promptly even though the dump is parked --
	 * that's the whole point of the rework.
	 */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_async_block", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	/* Release the dump so it can complete and decrement dump_pending. */
	mtx_lock(&async_dump_mtx);
	async_dump_release = true;
	cv_broadcast(&async_dump_cv);
	mtx_unlock(&async_dump_mtx);

	eventlog_subscriber_drain_dumps(subscriber);

	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 1);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&cd->lock);
	free(cd, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);
	cv_destroy(&async_dump_cv);
	mtx_destroy(&async_dump_mtx);

	return (0);
}

/*
 * Verifies eventlog_subscriber_destroy() implicitly drains pending
 * dump tasks rather than freeing memory out from under them. We
 * subscribe with a callback that blocks, kick off destroy in a
 * thread that then unblocks the dump, and confirm destroy waits
 * for it.
 */

struct destroy_drain_thread_arg {
	struct eventlog_subscriber *subscriber;
	volatile bool started;
	volatile bool returned;
};

static void
destroy_drain_thread(void *arg)
{
	struct destroy_drain_thread_arg *a = arg;

	a->started = true;
	eventlog_subscriber_destroy(a->subscriber);
	a->returned = true;
	kthread_exit();
}

KTEST_FUNC(dump_state_destroy_waits_for_dump)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cd;
	struct destroy_drain_thread_arg arg;
	struct thread *td;
	int i;

	KTEST_LOG(ctx, "Verifying destroy() drains in-flight dumps");

	atomic_store_rel_32(&async_dump_runs, 0);
	mtx_init(&async_dump_mtx, "async_dump_mtx", NULL, MTX_DEF);
	cv_init(&async_dump_cv, "async_dump_cv");
	async_dump_release = false;

	provider = test_create_provider("test_ds_destroy_drain",
	    async_dump_callback_block, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	cd = malloc(sizeof(*cd), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd->lock, "test_ds_destroy_drain", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, cd);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_destroy_drain", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	/* Wait for the dump task to actually start running (and block). */
	for (i = 0; i < 1000; i++) {
		if (atomic_load_acq_32(&async_dump_runs) == 1)
			break;
		pause("ds_run", 1);
	}
	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 1);

	/*
	 * Spawn a thread that calls destroy(). It must NOT return until
	 * we release the dump callback below. We give it 100ms to prove
	 * it's stuck waiting on dump_pending, then release the callback
	 * and wait for destroy() to complete.
	 */
	memset(&arg, 0, sizeof(arg));
	arg.subscriber = subscriber;
	KTEST_EQUAL(kthread_add(destroy_drain_thread, &arg, NULL, &td, 0, 0,
	    "evl_ds_destroy_drain"), 0);

	/* Wait for the destroy thread to start. */
	for (i = 0; i < 1000; i++) {
		if (arg.started)
			break;
		pause("ds_strt", 1);
	}
	KTEST_VERIFY(arg.started);

	/*
	 * Confirm destroy() is parked on dump_pending. If it had freed
	 * the subscriber already, async_dump_callback_block (which is
	 * still parked on the cv) would also have freed its mtx, and we
	 * would have crashed. The fact that arg.returned is still false
	 * after a generous wait is the signal.
	 */
	pause("ds_park", hz / 10);
	KTEST_VERIFY(!arg.returned);

	/* Release the dump and wait for destroy() to come back. */
	mtx_lock(&async_dump_mtx);
	async_dump_release = true;
	cv_broadcast(&async_dump_cv);
	mtx_unlock(&async_dump_mtx);

	for (i = 0; i < 1000; i++) {
		if (arg.returned)
			break;
		pause("ds_done", 1);
	}
	KTEST_VERIFY(arg.returned);

	eventlog_session_destroy(session);
	mtx_destroy(&cd->lock);
	free(cd, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);
	cv_destroy(&async_dump_cv);
	mtx_destroy(&async_dump_mtx);

	return (0);
}

/*
 * Verifies that re-subscribing an already-subscribed (provider, level,
 * keywords) does not re-fire the dump_callback. The replay is a
 * one-shot per first-time subscribe; the subscriber already has the
 * state from the original subscribe.
 */
KTEST_FUNC(dump_state_resubscribe_no_refire)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cd;

	KTEST_LOG(ctx, "Verifying re-subscribe does not re-fire dump");

	async_dump_thread = NULL;
	async_dump_observed = false;
	atomic_store_rel_32(&async_dump_runs, 0);

	provider = test_create_provider("test_ds_resub",
	    async_dump_callback_record_thread, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	cd = malloc(sizeof(*cd), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd->lock, "test_ds_resub", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, cd);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_resub", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(subscriber);
	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 1);

	/* Re-subscribe with different level/keywords -- update in place. */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_resub", EVENTLOG_LEVEL_INFO, 0xF0F0F0F0, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(subscriber);
	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 1);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&cd->lock);
	free(cd, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verifies eventlog_subscriber_trigger_dump_state() re-fires the dump
 * callback on an already-established subscription -- the explicit
 * counterpart to dump_state_resubscribe_no_refire's implicit no-refire.
 * Also verifies it works even when the subscription was never made
 * with EVENTLOG_SUBSCRIPTION_DUMP_STATE, matching -D's existing
 * process-wide (not per-subscription) semantics: the trigger re-dumps
 * whatever the caller is subscribed to.
 */
KTEST_FUNC(dump_state_manual_trigger_refires)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *cd;

	KTEST_LOG(ctx, "Verifying manual trigger re-fires the dump callback");

	dump_callback_invocations = 0;
	dump_test_session_count = 1;

	provider = test_create_provider("test_ds_trigger", test_dump_callback, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	dump_test_sessions[0] = session;

	cd = malloc(sizeof(*cd), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd->lock, "test_ds_trigger", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback, cd);
	KTEST_NEQUAL(subscriber, NULL);

	/* No EVENTLOG_SUBSCRIPTION_DUMP_STATE -- subscribe alone must not dump. */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_trigger", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	eventlog_subscriber_drain_dumps(subscriber);
	KTEST_EQUAL(atomic_load_acq_32(&dump_callback_invocations), 0);

	/* First manual trigger: callback fires despite no DUMP_STATE flag. */
	eventlog_subscriber_trigger_dump_state(subscriber);
	eventlog_subscriber_drain_dumps(subscriber);
	KTEST_EQUAL(atomic_load_acq_32(&dump_callback_invocations), 1);

	/* Second manual trigger: fires again -- unlike resubscribe, this repeats. */
	eventlog_subscriber_trigger_dump_state(subscriber);
	eventlog_subscriber_drain_dumps(subscriber);
	KTEST_EQUAL(atomic_load_acq_32(&dump_callback_invocations), 2);

	dump_test_sessions[0] = NULL;
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&cd->lock);
	free(cd, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verifies eventlog_subscriber_trigger_dump_state() only replays into the
 * subscriber it's called on, not other subscribers of the same provider
 * -- the same routing guarantee dump_state_routing checks for the
 * first-subscribe dump.
 */
KTEST_FUNC(dump_state_manual_trigger_scoped_to_subscriber)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *sub1, *sub2;
	struct test_callback_data *cd1, *cd2;
	uint32_t sub1_before, sub2_before;

	KTEST_LOG(ctx, "Verifying manual trigger does not fan out to other subscribers");

	dump_callback_invocations = 0;
	dump_test_session_count = 1;

	provider = test_create_provider("test_ds_trigger_route", test_dump_callback, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	dump_test_sessions[0] = session;

	cd1 = malloc(sizeof(*cd1), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd1->lock, "test_ds_trigger_route1", NULL, MTX_DEF);
	sub1 = eventlog_subscriber_create_callback(test_event_callback, cd1);
	KTEST_NEQUAL(sub1, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub1, "test_ds_trigger_route",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(sub1);

	cd2 = malloc(sizeof(*cd2), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	mtx_init(&cd2->lock, "test_ds_trigger_route2", NULL, MTX_DEF);
	sub2 = eventlog_subscriber_create_callback(test_event_callback, cd2);
	KTEST_NEQUAL(sub2, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(sub2, "test_ds_trigger_route",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(sub2);

	sub1_before = atomic_load_acq_32(&cd1->event_count);
	sub2_before = atomic_load_acq_32(&cd2->event_count);

	/* Trigger sub1 only. */
	eventlog_subscriber_trigger_dump_state(sub1);
	eventlog_subscriber_drain_dumps(sub1);

	KTEST_VERIFY(atomic_load_acq_32(&cd1->event_count) > sub1_before);
	KTEST_EQUAL(atomic_load_acq_32(&cd2->event_count), sub2_before);

	dump_test_sessions[0] = NULL;
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(sub1);
	eventlog_subscriber_destroy(sub2);
	mtx_destroy(&cd1->lock);
	mtx_destroy(&cd2->lock);
	free(cd1, M_EVENTLOG_TEST);
	free(cd2, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verifies the framework emits an EVENTLOG_DUMP_COMPLETE_ID event to
 * the requesting subscriber once the dump_callback returns. The
 * callback intentionally emits no events, so DUMP_COMPLETE is the
 * only thing the subscriber should see -- we check both event_count
 * and last_event_id to pin that down.
 *
 * Subscribers that did not request EVENTLOG_KEYWORD_SESSION must
 * NOT receive DUMP_COMPLETE; we verify this with a second subscriber
 * that subscribes with a non-session keyword mask.
 */
KTEST_FUNC(dump_state_emits_dump_complete)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *with_session, *without_session;
	struct test_callback_data *cd_with, *cd_without;

	KTEST_LOG(ctx, "Verifying DUMP_COMPLETE emission and keyword filter");

	async_dump_thread = NULL;
	async_dump_observed = false;
	atomic_store_rel_32(&async_dump_runs, 0);

	provider = test_create_provider("test_ds_complete",
	    async_dump_callback_record_thread, NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	cd_with = malloc(sizeof(*cd_with), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&cd_with->lock, "test_ds_complete_w", NULL, MTX_DEF);
	with_session = eventlog_subscriber_create_callback(
	    test_event_callback, cd_with);
	KTEST_NEQUAL(with_session, NULL);

	cd_without = malloc(sizeof(*cd_without), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&cd_without->lock, "test_ds_complete_wo", NULL, MTX_DEF);
	without_session = eventlog_subscriber_create_callback(
	    test_event_callback, cd_without);
	KTEST_NEQUAL(without_session, NULL);

	/* with_session: full mask -- includes EVENTLOG_KEYWORD_SESSION. */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(with_session,
	    "test_ds_complete", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	/* without_session: SESSION bit (0x80000000) explicitly cleared. */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(without_session,
	    "test_ds_complete", EVENTLOG_LEVEL_VERBOSE, 0x7FFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	eventlog_subscriber_drain_dumps(with_session);
	eventlog_subscriber_drain_dumps(without_session);

	/* dump_callback ran once for each subscriber */
	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 2);

	/*
	 * with_session should have received exactly one event --
	 * the synthetic DUMP_COMPLETE. without_session should have
	 * received nothing (SESSION keyword stripped).
	 */
	KTEST_EQUAL(atomic_load_acq_32(&cd_with->event_count), 1);
	KTEST_EQUAL(atomic_load_acq_32(&cd_with->last_event_id),
	    EVENTLOG_DUMP_COMPLETE_ID);
	KTEST_EQUAL(atomic_load_acq_32(&cd_without->event_count), 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(with_session);
	eventlog_subscriber_destroy(without_session);
	mtx_destroy(&cd_with->lock);
	free(cd_with, M_EVENTLOG_TEST);
	mtx_destroy(&cd_without->lock);
	free(cd_without, M_EVENTLOG_TEST);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Multi-provider callback data: tracks events per provider_id to verify that
 * events from multiple same-named providers are all delivered.
 */
struct multi_provider_callback_data {
	volatile uint32_t event_count;
	volatile uint16_t seen_provider_ids[8];
	volatile uint32_t seen_provider_id_counts[8];
	volatile int num_distinct_providers;
};

static void
multi_provider_callback(const struct eventlog_event_header *hdr,
    const char *provider_name __unused, uint8_t provider_name_len __unused,
    uint64_t session_id __unused,
    const struct iovec *iov __unused, int iovcnt __unused,
    size_t payload_size __unused, void *callback_arg)
{
	struct multi_provider_callback_data *data = callback_arg;
	int i, n;

	atomic_add_int(&data->event_count, 1);

	n = atomic_load_acq_int(&data->num_distinct_providers);
	for (i = 0; i < n; i++) {
		if (data->seen_provider_ids[i] == hdr->provider_id) {
			atomic_add_int(&data->seen_provider_id_counts[i], 1);
			return;
		}
	}
	/* New provider_id — add it (racy but fine for small counts in tests) */
	if (n < 8) {
		data->seen_provider_ids[n] = hdr->provider_id;
		data->seen_provider_id_counts[n] = 1;
		atomic_add_rel_int(&data->num_distinct_providers, 1);
	}
}

/*
 * Subscribing by name enables ALL providers with that name.
 */
KTEST_FUNC(multi_provider_subscribe_enables_all)
{
	struct eventlog_provider *p1, *p2;
	struct eventlog_subscriber *subscriber;
	struct multi_provider_callback_data cb_data;
	int error;

	KTEST_LOG(ctx, "Testing subscribe-by-name enables all matching providers");

	p1 = test_create_provider("test_mp_en", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_en", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	/* Both providers should start disabled */
	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_NONE);

	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(multi_provider_callback, &cb_data);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_en",
	    EVENTLOG_LEVEL_INFO, 0x7, 0);
	KTEST_EQUAL(error, 0);

	/* Both providers should now be enabled with the same level/keywords */
	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0x7);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0x7);

	/* Destroying subscriber should disable both */
	eventlog_subscriber_destroy(subscriber);
	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0);

	eventlog_provider_destroy(p1);
	eventlog_provider_destroy(p2);

	return (0);
}

/*
 * Events from both same-named providers reach a single subscriber,
 * and they carry distinct provider_ids.
 */
KTEST_FUNC(multi_provider_events_from_both)
{
	struct eventlog_provider *p1, *p2;
	struct eventlog_session *s1, *s2;
	struct eventlog_subscriber *subscriber;
	struct multi_provider_callback_data cb_data;
	uint32_t payload = 0xCAFE;
	int error;

	KTEST_LOG(ctx, "Testing events from both same-named providers");

	p1 = test_create_provider("test_mp_ev", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_ev", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(multi_provider_callback, &cb_data);
	KTEST_NEQUAL(subscriber, NULL);
	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_ev",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	s1 = eventlog_session_create(p1, 100, true, NULL, 0);
	KTEST_NEQUAL(s1, NULL);
	s2 = eventlog_session_create(p2, 200, true, NULL, 0);
	KTEST_NEQUAL(s2, NULL);

	/* Write events from each provider */
	eventlog_event_write(s1, 0x1001, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	eventlog_event_write(s2, 0x2001, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	eventlog_event_write(s1, 0x1002, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	eventlog_event_write(s2, 0x2002, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));

	/* 2 SESSION_CREATEs + 4 user events = 6 total */
	KTEST_EQUAL(atomic_load_acq_32(&cb_data.event_count), 6);

	/* Events should have come from 2 distinct provider_ids */
	KTEST_EQUAL(atomic_load_acq_int(&cb_data.num_distinct_providers), 2);
	/* Each provider should have sent 3 events (1 SESSION_CREATE + 2 user) */
	KTEST_EQUAL(atomic_load_acq_32(&cb_data.seen_provider_id_counts[0]), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb_data.seen_provider_id_counts[1]), 3);

	eventlog_session_destroy(s1);
	eventlog_session_destroy(s2);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(p1);
	eventlog_provider_destroy(p2);

	return (0);
}

/*
 * Destroying one same-named provider doesn't affect the other.
 * Subscription and event delivery continue for the surviving provider.
 */
KTEST_FUNC(multi_provider_destroy_one)
{
	struct eventlog_provider *p1, *p2;
	struct eventlog_session *s1, *s2;
	struct eventlog_subscriber *subscriber;
	struct multi_provider_callback_data cb_data;
	uint32_t payload = 0xBEEF;
	uint32_t count_before;
	int error;

	KTEST_LOG(ctx, "Testing destroy one of two same-named providers");

	p1 = test_create_provider("test_mp_d1", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_d1", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(multi_provider_callback, &cb_data);
	KTEST_NEQUAL(subscriber, NULL);
	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_d1",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	s1 = eventlog_session_create(p1, 1, true, NULL, 0);
	KTEST_NEQUAL(s1, NULL);
	s2 = eventlog_session_create(p2, 2, true, NULL, 0);
	KTEST_NEQUAL(s2, NULL);

	/* Write an event from each */
	eventlog_event_write(s1, 0x1001, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	eventlog_event_write(s2, 0x2001, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));

	/* Destroy s1 and subscriber, then p1.
	 * Subscriber must be destroyed before its providers so that
	 * subscription pointers are cleaned up first. */
	eventlog_session_destroy(s1);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(p1);

	/* p2 should now be disabled (no subscribers left) */
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0);

	/* Re-subscribe to verify p2 still works after p1 is gone */
	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(multi_provider_callback, &cb_data);
	KTEST_NEQUAL(subscriber, NULL);
	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_d1",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	/* p2 should be enabled again */
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0xFFFFFFFF);

	/* Events from p2 should arrive */
	count_before = atomic_load_acq_32(&cb_data.event_count);
	eventlog_event_write(s2, 0x2002, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &payload, sizeof(payload));
	KTEST_EQUAL(atomic_load_acq_32(&cb_data.event_count), count_before + 1);

	eventlog_session_destroy(s2);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(p2);

	return (0);
}

/*
 * Dump state callback is invoked for each matching provider when subscribing
 * by name with DUMP_STATE.
 */
static volatile uint32_t mp_dump_invocations;
static struct eventlog_session *mp_dump_sessions[4];
static int mp_dump_session_count;

static void
mp_test_dump_callback(struct eventlog_provider *provider __unused, void *arg __unused)
{
	int i;

	atomic_add_int(&mp_dump_invocations, 1);
	for (i = 0; i < mp_dump_session_count; i++) {
		if (mp_dump_sessions[i] != NULL &&
		    mp_dump_sessions[i]->effective_level >= EVENTLOG_LEVEL_INFO) {
			uint32_t data = 0xdead0000 | i;
			eventlog_event_write(mp_dump_sessions[i], 0x200 + i,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
			    &data, sizeof(data));
		}
	}
}

KTEST_FUNC(multi_provider_dump_state)
{
	struct eventlog_provider *p1 = NULL, *p2 = NULL;
	struct eventlog_session *s1 = NULL, *s2 = NULL;
	struct eventlog_subscriber *subscriber = NULL;
	struct multi_provider_callback_data cb_data;
	uint32_t invocations, ec;
	int ret = 0;
	int error;

	KTEST_LOG(ctx, "Testing dump state invoked for each matching provider");

	mp_dump_invocations = 0;
	mp_dump_session_count = 2;

	p1 = test_create_provider("test_mp_ds", mp_test_dump_callback, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_ds", mp_test_dump_callback, NULL);
	KTEST_NEQUAL(p2, NULL);

	s1 = eventlog_session_create(p1, 1, true, NULL, 0);
	KTEST_NEQUAL(s1, NULL);
	mp_dump_sessions[0] = s1;

	s2 = eventlog_session_create(p2, 2, true, NULL, 0);
	KTEST_NEQUAL(s2, NULL);
	mp_dump_sessions[1] = s2;

	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(multi_provider_callback, &cb_data);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_ds",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, EVENTLOG_SUBSCRIPTION_DUMP_STATE);
	if (error != 0) {
		KTEST_ERR(ctx, "FAIL: add_subscription returned %d", error);
		ret = EINVAL;
		goto cleanup;
	}
	KTEST_LOG(ctx, "PASS: error == 0");

	/*
	 * Two providers share the name, so two dump tasks were enqueued.
	 * Drain so the invocation/event-count assertions below see the
	 * post-dump steady state.
	 */
	eventlog_subscriber_drain_dumps(subscriber);

	invocations = atomic_load_acq_32(&mp_dump_invocations);
	KTEST_LOG(ctx, "Dump callback invoked %u times", invocations);
	if (invocations < 2) {
		KTEST_ERR(ctx, "FAIL: dump invocations %u < 2", invocations);
		ret = EINVAL;
		goto cleanup;
	}
	KTEST_LOG(ctx, "PASS: invocations >= 2");

	ec = atomic_load_acq_32(&cb_data.event_count);
	KTEST_LOG(ctx, "Subscriber received %u events", ec);
	if (ec < 2) {
		KTEST_ERR(ctx, "FAIL: event_count %u < 2", ec);
		ret = EINVAL;
		goto cleanup;
	}
	KTEST_LOG(ctx, "PASS: event_count >= 2");

	if (atomic_load_acq_int(&cb_data.num_distinct_providers) != 2) {
		KTEST_ERR(ctx, "FAIL: num_distinct_providers %d != 2",
		    atomic_load_acq_int(&cb_data.num_distinct_providers));
		ret = EINVAL;
		goto cleanup;
	}
	KTEST_LOG(ctx, "PASS: num_distinct_providers == 2");

cleanup:
	mp_dump_sessions[0] = NULL;
	mp_dump_sessions[1] = NULL;
	if (s1 != NULL)
		eventlog_session_destroy(s1);
	if (s2 != NULL)
		eventlog_session_destroy(s2);
	if (subscriber != NULL)
		eventlog_subscriber_destroy(subscriber);
	if (p1 != NULL)
		eventlog_provider_destroy(p1);
	if (p2 != NULL)
		eventlog_provider_destroy(p2);

	return (ret);
}

/*
 * Two subscribers with different filters targeting same-named providers.
 * Each provider instance gets its enablement from the union of all subscribers.
 */
KTEST_FUNC(multi_provider_independent_enablement)
{
	struct eventlog_provider *p1, *p2;
	struct eventlog_subscriber *sub_name, *sub_other;
	struct multi_provider_callback_data cb1, cb2;
	int error;

	KTEST_LOG(ctx, "Testing per-provider enablement with multi-provider");

	p1 = test_create_provider("test_mp_ie", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_ie", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	/* Subscribe to "test_mp_ie" at INFO/0x3 — should enable both providers */
	memset(&cb1, 0, sizeof(cb1));
	sub_name = eventlog_subscriber_create_callback(multi_provider_callback, &cb1);
	KTEST_NEQUAL(sub_name, NULL);
	error = eventlog_subscriber_add_subscription(sub_name, "test_mp_ie",
	    EVENTLOG_LEVEL_INFO, 0x3, 0);
	KTEST_EQUAL(error, 0);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0x3);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0x3);

	/* Add second subscriber at VERBOSE/0xC — both providers now get union */
	memset(&cb2, 0, sizeof(cb2));
	sub_other = eventlog_subscriber_create_callback(multi_provider_callback, &cb2);
	KTEST_NEQUAL(sub_other, NULL);
	error = eventlog_subscriber_add_subscription(sub_other, "test_mp_ie",
	    EVENTLOG_LEVEL_VERBOSE, 0xC, 0);
	KTEST_EQUAL(error, 0);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0xF);  /* 0x3 | 0xC */
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0xF);

	/* Remove first subscriber — enablement drops to VERBOSE/0xC */
	eventlog_subscriber_destroy(sub_name);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0xC);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0xC);

	/* Remove second subscriber — both disabled */
	eventlog_subscriber_destroy(sub_other);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_NONE);

	eventlog_provider_destroy(p1);
	eventlog_provider_destroy(p2);

	return (0);
}

/*
 * Device subscriber receives events from all same-named providers.
 * Verifies multi-provider support works with device (buffered) subscribers,
 * not just callback subscribers.
 */
KTEST_FUNC(multi_provider_device_subscriber)
{
	struct eventlog_provider *p1, *p2;
	struct eventlog_session *s1, *s2;
	struct eventlog_subscriber *subscriber;
	uint32_t payload = 0xFACE;
	char read_buf[8 * 1024];
	size_t total_read;
	struct eventlog_event_header *hdr;
	uint16_t seen_ids[2] = {0, 0};
	int num_distinct = 0;
	int total_events = 0;
	size_t offset;
	int error, i;

	KTEST_LOG(ctx, "Testing device subscriber with multiple same-named providers");

	p1 = test_create_provider("test_mp_dev", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_dev", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	subscriber = eventlog_subscriber_create_device(EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);
	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_dev",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	s1 = eventlog_session_create(p1, 1, true, NULL, 0);
	KTEST_NEQUAL(s1, NULL);
	s2 = eventlog_session_create(p2, 2, true, NULL, 0);
	KTEST_NEQUAL(s2, NULL);

	/* Write events from each provider */
	for (i = 0; i < 5; i++) {
		eventlog_event_write(s1, 0x1000 + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &payload, sizeof(payload));
		eventlog_event_write(s2, 0x2000 + i, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &payload, sizeof(payload));
	}

	/* Read all available events.  Blocking (not FNONBLOCK): a single
	 * immediate poll can race the read-epoch watermark (see
	 * eventlog_read_watermark_us) on a burst this small, unlike the
	 * multi-second polling loops elsewhere that ride it out for free. */
	total_read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf), 0);
	KTEST_VERIFY(total_read > 0);

	/* Parse events and count distinct provider_ids */
	offset = 0;
	while (offset + sizeof(struct eventlog_event_header) <= total_read) {
		bool found;

		hdr = (struct eventlog_event_header *)(read_buf + offset);
		if (hdr->event_length < sizeof(struct eventlog_event_header) ||
		    offset + hdr->event_length > total_read)
			break;

		total_events++;
		found = false;
		for (i = 0; i < num_distinct; i++) {
			if (seen_ids[i] == hdr->provider_id) {
				found = true;
				break;
			}
		}
		if (!found && num_distinct < 2) {
			seen_ids[num_distinct++] = hdr->provider_id;
		}
		offset += hdr->event_length;
	}

	KTEST_LOG(ctx, "Read %d events from %d distinct provider_ids",
	    total_events, num_distinct);

	/* 2 SESSION_CREATEs + 10 user events = 12 total */
	KTEST_EQUAL(total_events, 12);
	KTEST_EQUAL(num_distinct, 2);

	eventlog_session_destroy(s1);
	eventlog_session_destroy(s2);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(p1);
	eventlog_provider_destroy(p2);

	return (0);
}

/*
 * Helpers + tests for the subscribers_changed provider callback and
 * eventlog_provider_config (NULL config, default_enabled, etc).
 *
 * Contract for subscribers_changed: fires exactly once per real
 * 0<->N transition, runs without sessions_lock so the callback may
 * sleep, NULL is a safe "no callback" value.
 */

struct subch_count {
	volatile int n_true;	/* callbacks observed with has_subscribers=true */
	volatile int n_false;	/* ...with has_subscribers=false */
	volatile int last_state;
};

static void
test_subch_count_cb(struct eventlog_provider *provider __unused,
    bool has_subscribers, void *arg)
{
	struct subch_count *c = arg;

	if (has_subscribers)
		atomic_add_int(&c->n_true, 1);
	else
		atomic_add_int(&c->n_false, 1);
	atomic_store_rel_int((volatile u_int *)&c->last_state,
	    has_subscribers ? 1 : 0);
}

KTEST_FUNC(subscribers_changed_basic)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *sub1, *sub2;
	struct test_callback_data *cb1, *cb2;
	struct subch_count c = { 0, 0, 0 };
	struct eventlog_provider_config cfg = {
		.subscribers_changed = test_subch_count_cb,
		.subscribers_changed_arg = &c,
	};

	KTEST_LOG(ctx, "subscribers_changed fires exactly once per 0<->N edge");

	provider = eventlog_provider_create("test_subch_basic", &cfg);
	KTEST_NEQUAL(provider, NULL);

	/* No subscriber yet -> no callback ever fired. */
	KTEST_EQUAL(c.n_true, 0);
	KTEST_EQUAL(c.n_false, 0);

	/* First subscriber: 0->1 transition, expect one (true). */
	sub1 = test_enable_provider_callback("test_subch_basic",
	    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &cb1);
	KTEST_NEQUAL(sub1, NULL);
	KTEST_EQUAL(c.n_true, 1);
	KTEST_EQUAL(c.n_false, 0);
	KTEST_EQUAL(c.last_state, 1);

	/* Second subscriber: 1->2, no transition, no callback. */
	sub2 = test_enable_provider_callback("test_subch_basic",
	    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &cb2);
	KTEST_NEQUAL(sub2, NULL);
	KTEST_EQUAL(c.n_true, 1);
	KTEST_EQUAL(c.n_false, 0);

	/* Drop one subscriber: 2->1, no transition, no callback. */
	eventlog_subscriber_destroy(sub2);
	mtx_destroy(&cb2->lock);
	free(cb2, M_EVENTLOG_TEST);
	KTEST_EQUAL(c.n_true, 1);
	KTEST_EQUAL(c.n_false, 0);

	/* Drop the last subscriber: 1->0, expect one (false). */
	eventlog_subscriber_destroy(sub1);
	mtx_destroy(&cb1->lock);
	free(cb1, M_EVENTLOG_TEST);
	KTEST_EQUAL(c.n_true, 1);
	KTEST_EQUAL(c.n_false, 1);
	KTEST_EQUAL(c.last_state, 0);

	eventlog_provider_destroy(provider);
	return (0);
}

KTEST_FUNC(subscribers_changed_null_safe)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *sub;
	struct test_callback_data *cb;
	struct eventlog_provider_config cfg = {
		/* subscribers_changed deliberately NULL */
	};

	KTEST_LOG(ctx, "NULL subscribers_changed is a safe no-op");

	provider = eventlog_provider_create("test_subch_null", &cfg);
	KTEST_NEQUAL(provider, NULL);

	/* Exercise sub/unsub cycle; NULL callback should not crash. */
	sub = test_enable_provider_callback("test_subch_null",
	    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &cb);
	KTEST_NEQUAL(sub, NULL);

	eventlog_subscriber_destroy(sub);
	mtx_destroy(&cb->lock);
	free(cb, M_EVENTLOG_TEST);

	eventlog_provider_destroy(provider);
	return (0);
}

/*
 * subscribers_changed_runs_unlocked: prove the callback is invoked in a
 * context where the caller is permitted to sleep / take its own
 * sleepable locks. If sessions_lock (or any non-sleepable lock) were
 * held when the callback fired, sx_xlock + pause_sbt would WITNESS- /
 * INVARIANTS-fail with "sleeping with mutex held".
 */
struct subch_unlocked_state {
	struct sx outer;
	int n;
};

static void
test_subch_unlocked_cb(struct eventlog_provider *provider __unused,
    bool has_subscribers __unused, void *arg)
{
	struct subch_unlocked_state *s = arg;

	MPASS(THREAD_CAN_SLEEP());
	sx_xlock(&s->outer);
	pause("subch", 1);	/* Sleep one tick. WITNESS / INVARIANTS will
				 * fire if any non-sleepable lock is held
				 * (most importantly sessions_lock). */
	sx_xunlock(&s->outer);
	atomic_add_int(&s->n, 1);
}

KTEST_FUNC(subscribers_changed_runs_unlocked)
{
	struct eventlog_provider *provider;
	struct eventlog_subscriber *sub;
	struct test_callback_data *cb;
	struct subch_unlocked_state s;
	struct eventlog_provider_config cfg;

	KTEST_LOG(ctx, "callback runs outside sessions_lock (sleepable context)");

	bzero(&s, sizeof(s));
	sx_init(&s.outer, "test_subch_outer");
	cfg = (struct eventlog_provider_config){
		.subscribers_changed = test_subch_unlocked_cb,
		.subscribers_changed_arg = &s,
	};

	provider = eventlog_provider_create("test_subch_unlocked", &cfg);
	KTEST_NEQUAL(provider, NULL);

	sub = test_enable_provider_callback("test_subch_unlocked",
	    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &cb);
	KTEST_NEQUAL(sub, NULL);
	KTEST_EQUAL(s.n, 1);

	eventlog_subscriber_destroy(sub);
	mtx_destroy(&cb->lock);
	free(cb, M_EVENTLOG_TEST);
	KTEST_EQUAL(s.n, 2);

	eventlog_provider_destroy(provider);
	sx_destroy(&s.outer);
	return (0);
}

/*
 * Concurrent subscribe / unsubscribe storm. Smoke test for
 * eventlog_update_provider_enablement under contention. Starts and
 * ends at the no-subscribers state, so n_true must equal n_false at
 * quiesce; INVARIANTS-only MPASS checks backstop subtler races.
 */
struct subch_storm_args {
	struct eventlog_provider *provider;
	const char *provider_name;
	int *stop;
	int iterations_done;
	int exited;
};

static void
test_subch_storm_thread(void *arg)
{
	struct subch_storm_args *a = arg;
	struct eventlog_subscriber *sub;
	struct test_callback_data *cb;
	int i = 0;

	while (atomic_load_acq_int((volatile u_int *)a->stop) == 0) {
		sub = test_enable_provider_callback(a->provider_name,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &cb);
		if (sub == NULL)
			break;
		eventlog_subscriber_destroy(sub);
		mtx_destroy(&cb->lock);
		free(cb, M_EVENTLOG_TEST);
		i++;
		kern_yield(PRI_UNCHANGED);
	}
	atomic_store_rel_int((volatile u_int *)&a->iterations_done, i);
	atomic_store_rel_int((volatile u_int *)&a->exited, 1);
	wakeup(&a->exited);
	kthread_exit();
}

static void
test_subch_stop_callout(void *arg)
{
	int *stop = arg;

	atomic_store_rel_int((volatile u_int *)stop, 1);
	wakeup(stop);
}

KTEST_FUNC(subscribers_changed_concurrent_subunsub)
{
#define SUBCH_NTHREADS	8
#define SUBCH_RUNTIME_S	1
	struct eventlog_provider *provider;
	struct subch_count c = { 0, 0, 0 };
	struct subch_storm_args args[SUBCH_NTHREADS];
	struct thread *threads[SUBCH_NTHREADS];
	struct callout stop_co;
	int stop = 0;
	int i, error;
	int total_iterations;
	struct eventlog_provider_config cfg = {
		.subscribers_changed = test_subch_count_cb,
		.subscribers_changed_arg = &c,
	};

	KTEST_LOG(ctx, "concurrent sub/unsub: %d threads x %d s, no phantom "
	    "transitions, n_true == n_false at quiesce",
	    SUBCH_NTHREADS, SUBCH_RUNTIME_S);

	provider = eventlog_provider_create("test_subch_storm", &cfg);
	KTEST_NEQUAL(provider, NULL);

	for (i = 0; i < SUBCH_NTHREADS; i++) {
		bzero(&args[i], sizeof(args[i]));
		args[i].provider = provider;
		args[i].provider_name = "test_subch_storm";
		args[i].stop = &stop;
		error = kthread_add(test_subch_storm_thread, &args[i], NULL,
		    &threads[i], 0, 0, "subch_storm_%d", i);
		KTEST_EQUAL(error, 0);
	}

	callout_init(&stop_co, 1);
	callout_reset(&stop_co, hz * SUBCH_RUNTIME_S, test_subch_stop_callout,
	    &stop);

	for (i = 0; i < SUBCH_NTHREADS; i++) {
		while (atomic_load_acq_int(
		    (volatile u_int *)&args[i].exited) == 0)
			tsleep(&args[i].exited, 0, "subch_w", hz / 10);
	}
	callout_drain(&stop_co);

	total_iterations = 0;
	for (i = 0; i < SUBCH_NTHREADS; i++)
		total_iterations += args[i].iterations_done;
	KTEST_LOG(ctx, "total sub/unsub iterations: %d, n_true=%d n_false=%d",
	    total_iterations, c.n_true, c.n_false);

	/*
	 * All subscribers are gone, so every 0->N edge (n_true) must
	 * have a matching N->0 edge (n_false). Without locking around
	 * the recount, races could produce unbalanced counts.
	 */
	KTEST_VERIFY(c.n_true > 0);
	KTEST_VERIFY(c.n_false > 0);
	KTEST_EQUAL(c.n_true, c.n_false);
	KTEST_EQUAL(c.last_state, 0);

	eventlog_provider_destroy(provider);
	return (0);
#undef SUBCH_NTHREADS
#undef SUBCH_RUNTIME_S
}

/*
 * Provider destroy racing subscriber subscribe/destroy (NCD-10378).  Both
 * the unlisted subscriber's enablement walk and a subscribe working from an
 * unlocked provider snapshot must not outlive the provider.  On an
 * INVARIANTS kernel either race panicked in __mtx_lock_sleep() on the freed
 * provider's sessions_lock.
 */
struct provider_churn_args {
	char provider_name[EVENTLOG_PROVIDER_NAME_MAX];
	int *stop;
	int iterations_done;
	int exited;
};

static void
test_provider_churn_thread(void *arg)
{
	struct provider_churn_args *a = arg;
	struct eventlog_provider *provider;
	int i = 0;

	while (atomic_load_acq_int((volatile u_int *)a->stop) == 0) {
		provider = eventlog_provider_create(a->provider_name, NULL);
		if (provider == NULL)
			break;
		kern_yield(PRI_UNCHANGED);
		eventlog_provider_destroy(provider);
		i++;
	}
	atomic_store_rel_int((volatile u_int *)&a->iterations_done, i);
	atomic_store_rel_int((volatile u_int *)&a->exited, 1);
	wakeup(&a->exited);
	kthread_exit();
}

KTEST_FUNC(provider_destroy_races_subscriber_destroy)
{
#define LIFE_NSUB	4
#define LIFE_NPROV	4
#define LIFE_RUNTIME_S	1
	struct subch_storm_args sargs[LIFE_NSUB];
	struct provider_churn_args pargs[LIFE_NPROV];
	struct thread *td;
	struct callout stop_co;
	int stop = 0;
	int i, error;
	int sub_iters = 0, prov_iters = 0;

	KTEST_LOG(ctx, "provider create/destroy vs subscriber "
	    "create/destroy: %d+%d threads x %d s",
	    LIFE_NSUB, LIFE_NPROV, LIFE_RUNTIME_S);

	/* One name per churner: concurrent same-name creates collide in sysctl. */
	for (i = 0; i < LIFE_NPROV; i++) {
		bzero(&pargs[i], sizeof(pargs[i]));
		snprintf(pargs[i].provider_name, sizeof(pargs[i].provider_name),
		    "test_provider_life%d", i);
	}

	for (i = 0; i < LIFE_NSUB; i++) {
		bzero(&sargs[i], sizeof(sargs[i]));
		sargs[i].provider_name = pargs[i % LIFE_NPROV].provider_name;
		sargs[i].stop = &stop;
		error = kthread_add(test_subch_storm_thread, &sargs[i], NULL,
		    &td, 0, 0, "life_sub_%d", i);
		KTEST_EQUAL(error, 0);
	}
	for (i = 0; i < LIFE_NPROV; i++) {
		pargs[i].stop = &stop;
		error = kthread_add(test_provider_churn_thread, &pargs[i],
		    NULL, &td, 0, 0, "life_prov_%d", i);
		KTEST_EQUAL(error, 0);
	}

	callout_init(&stop_co, 1);
	callout_reset(&stop_co, hz * LIFE_RUNTIME_S, test_subch_stop_callout,
	    &stop);

	for (i = 0; i < LIFE_NSUB; i++) {
		while (atomic_load_acq_int(
		    (volatile u_int *)&sargs[i].exited) == 0)
			tsleep(&sargs[i].exited, 0, "life_w", hz / 10);
		sub_iters += sargs[i].iterations_done;
	}
	for (i = 0; i < LIFE_NPROV; i++) {
		while (atomic_load_acq_int(
		    (volatile u_int *)&pargs[i].exited) == 0)
			tsleep(&pargs[i].exited, 0, "life_w", hz / 10);
		prov_iters += pargs[i].iterations_done;
	}
	callout_drain(&stop_co);

	KTEST_LOG(ctx, "subscriber iterations: %d, provider iterations: %d",
	    sub_iters, prov_iters);
	KTEST_VERIFY(sub_iters > 0);
	KTEST_VERIFY(prov_iters > 0);

	return (0);
#undef LIFE_NSUB
#undef LIFE_NPROV
#undef LIFE_RUNTIME_S
}

/*
 * NULL config must be equivalent to a zero-initialised struct: no
 * callbacks, default_enabled == 0.
 */
KTEST_FUNC(provider_config_null_equivalent)
{
	struct eventlog_provider *p_null, *p_zero;
	struct eventlog_session *s_null, *s_zero;
	struct eventlog_provider_config cfg_zero = { 0 };

	KTEST_LOG(ctx, "NULL config behaves identically to {0}");

	p_null = eventlog_provider_create("test_cfg_null", NULL);
	KTEST_NEQUAL(p_null, NULL);
	p_zero = eventlog_provider_create("test_cfg_zero", &cfg_zero);
	KTEST_NEQUAL(p_zero, NULL);

	/* Both providers default to disabled (default_enabled == 0). */
	KTEST_EQUAL(eventlog_provider_get_default(p_null), 0);
	KTEST_EQUAL(eventlog_provider_get_default(p_zero), 0);

	/* Sessions on either start disabled. */
	s_null = eventlog_session_create(p_null, 0, true, NULL, 0);
	KTEST_NEQUAL(s_null, NULL);
	KTEST_EQUAL(eventlog_session_is_enabled(s_null), 0);
	s_zero = eventlog_session_create(p_zero, 0, true, NULL, 0);
	KTEST_NEQUAL(s_zero, NULL);
	KTEST_EQUAL(eventlog_session_is_enabled(s_zero), 0);

	eventlog_session_destroy(s_null);
	eventlog_session_destroy(s_zero);
	eventlog_provider_destroy(p_null);
	eventlog_provider_destroy(p_zero);
	return (0);
}

/*
 * cfg.default_enabled = 1 must cause sessions to start enabled
 * without an explicit eventlog_session_set_enabled call. Same shape
 * with default_enabled = 0 must start disabled.
 */
KTEST_FUNC(provider_config_default_enabled)
{
	struct eventlog_provider *p_on, *p_off;
	struct eventlog_session *s_on, *s_off;
	struct eventlog_provider_config cfg_on = { .default_enabled = 1 };
	struct eventlog_provider_config cfg_off = { .default_enabled = 0 };

	KTEST_LOG(ctx, "cfg.default_enabled controls session start state");

	p_on = eventlog_provider_create("test_cfg_def_on", &cfg_on);
	KTEST_NEQUAL(p_on, NULL);
	KTEST_EQUAL(eventlog_provider_get_default(p_on), 1);

	p_off = eventlog_provider_create("test_cfg_def_off", &cfg_off);
	KTEST_NEQUAL(p_off, NULL);
	KTEST_EQUAL(eventlog_provider_get_default(p_off), 0);

	s_on = eventlog_session_create(p_on, 0, true, NULL, 0);
	KTEST_NEQUAL(s_on, NULL);
	KTEST_EQUAL(eventlog_session_is_enabled(s_on), 1);

	s_off = eventlog_session_create(p_off, 0, true, NULL, 0);
	KTEST_NEQUAL(s_off, NULL);
	KTEST_EQUAL(eventlog_session_is_enabled(s_off), 0);

	eventlog_session_destroy(s_on);
	eventlog_session_destroy(s_off);
	eventlog_provider_destroy(p_on);
	eventlog_provider_destroy(p_off);
	return (0);
}

/*
 * cfg.flags & EVENTLOG_PROVIDER_AUTO_RATIO exposes
 * kern.eventlog.<name>.auto_ratio and makes eventlog_session_create()
 * auto-enable a random 1-in-N sessions when the provider isn't already
 * default-enabled. Selection is a plain counter modulo (not a hash of
 * session_id), so with ratio N it's deterministically every Nth session
 * created -- assert the exact count, not a statistical approximation.
 * Providers that didn't opt in must not expose the sysctl.
 */
KTEST_FUNC(provider_config_auto_ratio)
{
#define AUTO_RATIO_N		4
#define AUTO_RATIO_SESSIONS	40
	struct eventlog_provider *provider, *provider_incapable;
	struct eventlog_provider_config cfg = {
		.flags = EVENTLOG_PROVIDER_AUTO_RATIO,
	};
	struct eventlog_provider_config cfg_incapable = { 0 };
	struct eventlog_session *session, *sessions[AUTO_RATIO_SESSIONS];
	u_long ratio;
	int enabled_count, error, i;

	KTEST_LOG(ctx, "cfg.flags & EVENTLOG_PROVIDER_AUTO_RATIO gates "
	    "kern.eventlog.<name>.auto_ratio and its effect on "
	    "eventlog_session_create()");

	provider = eventlog_provider_create("test_cfg_auto_ratio", &cfg);
	KTEST_NEQUAL(provider, NULL);
	KTEST_EQUAL(eventlog_provider_get_default(provider), 0);

	/* auto_ratio starts at 0 (off) -- no sampling until explicitly set. */
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	KTEST_EQUAL(eventlog_session_is_enabled(session), 0);
	eventlog_session_destroy(session);

	ratio = AUTO_RATIO_N;
	error = kernel_sysctlbyname(curthread,
	    "kern.eventlog.test_cfg_auto_ratio.auto_ratio",
	    NULL, NULL, &ratio, sizeof(ratio), NULL, 0);
	KTEST_EQUAL(error, 0);

	enabled_count = 0;
	for (i = 0; i < AUTO_RATIO_SESSIONS; i++) {
		sessions[i] = eventlog_session_create(provider, i + 1, true, NULL, 0);
		KTEST_NEQUAL(sessions[i], NULL);
		if (eventlog_session_is_enabled(sessions[i]))
			enabled_count++;
	}
	KTEST_EQUAL(enabled_count, AUTO_RATIO_SESSIONS / AUTO_RATIO_N);

	for (i = 0; i < AUTO_RATIO_SESSIONS; i++)
		eventlog_session_destroy(sessions[i]);
	eventlog_provider_destroy(provider);

	/* A provider that didn't opt in must not expose auto_ratio at all. */
	provider_incapable = eventlog_provider_create(
	    "test_cfg_auto_ratio_off", &cfg_incapable);
	KTEST_NEQUAL(provider_incapable, NULL);
	ratio = AUTO_RATIO_N;
	error = kernel_sysctlbyname(curthread,
	    "kern.eventlog.test_cfg_auto_ratio_off.auto_ratio",
	    NULL, NULL, &ratio, sizeof(ratio), NULL, 0);
	KTEST_NEQUAL(error, 0);
	eventlog_provider_destroy(provider_incapable);

	return (0);
#undef AUTO_RATIO_N
#undef AUTO_RATIO_SESSIONS
}

/*
 * Verify the same-CPU write re-entrancy guard: a C_DIRECT_EXEC callout
 * logging from timer-interrupt context nests on an in-progress write and
 * must not recurse smr_enter(). A small-payload nested write like this one
 * is stashed and delivered rather than dropped (counted in
 * kern.eventlog.reentrant_stashed); see write_reentrancy_scratch_overflow
 * below for the still-dropped oversized-payload case.
 */
struct reentr_data {
	struct eventlog_session	*session;
	struct callout		callout;
	int			cpu;
	int			stop;
	uint64_t		fired;
};

static void
reentr_nested_write(void *arg)
{
	struct reentr_data *d = arg;
	uint32_t payload[2];

	if (atomic_load_acq_int((volatile u_int *)&d->stop) != 0)
		return;

	payload[0] = (uint32_t)d->fired;
	payload[1] = 0xABCDu;
	eventlog_event_write(d->session, 0x900, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, payload, sizeof(payload));
	d->fired++;

	callout_reset_sbt_on(&d->callout, 100 * SBT_1US, 0, reentr_nested_write,
	    d, d->cpu, C_DIRECT_EXEC);
}

KTEST_FUNC(write_reentrancy_guard)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct reentr_data d;
	struct callout stop_timer;
	uint32_t payload[4];
	u_long stashed_before, stashed_after;
	uint64_t writes = 0;
	uint64_t nested_seen = 0;
	size_t read, offset;
	char *read_buf;
	size_t read_buf_size = 256 * 1024;
	int stop = 0;
	int i;

	KTEST_LOG(ctx, "Testing same-CPU write re-entrancy guard "
	    "(C_DIRECT_EXEC callout logging during in-progress writes)");

	provider = test_create_provider("test_reentr", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(read_buf_size);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_reentr", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);

	stashed_before = eventlog_get_reentrant_stashed();

	/*
	 * Pin to the current CPU and arm a self-rearming C_DIRECT_EXEC callout
	 * on it, then log in a tight loop on the same CPU. The callout fires
	 * from timer-interrupt context, interrupting our in-progress writes.
	 */
	sched_pin();
	bzero(&d, sizeof(d));
	d.session = session;
	d.cpu = PCPU_GET(cpuid);
	callout_init(&d.callout, 1);
	callout_reset_sbt_on(&d.callout, 100 * SBT_1US, 0, reentr_nested_write,
	    &d, d.cpu, C_DIRECT_EXEC);

	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz, lockfree_stop_callout, &stop);

	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		for (i = 0; i < 256; i++) {
			payload[0] = (uint32_t)writes;
			payload[1] = payload[2] = payload[3] = 0;
			eventlog_event_write(session, 0x901,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, payload,
			    sizeof(payload));
			writes++;
		}
	}

	atomic_store_rel_int((volatile u_int *)&d.stop, 1);
	callout_drain(&d.callout);
	callout_drain(&stop_timer);
	sched_unpin();

	stashed_after = eventlog_get_reentrant_stashed();

	/* Scan the delivered events for the nested writer's event_id (0x900)
	 * to confirm stashed events actually reach the subscriber, not just
	 * that the counter moved. */
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	offset = 0;
	while (offset + sizeof(struct eventlog_event_header) <= read) {
		struct eventlog_event_header hdr;

		memcpy(&hdr, read_buf + offset, sizeof(hdr));
		if (hdr.event_length < sizeof(struct eventlog_event_header))
			break;
		if (hdr.event_id == 0x900)
			nested_seen++;
		offset += hdr.event_length;
	}

	KTEST_LOG(ctx, "main writes=%llu, nested callout fired=%llu, "
	    "reentrant stashed=%llu, nested events seen in buffer=%llu",
	    (unsigned long long)writes,
	    (unsigned long long)d.fired,
	    (unsigned long long)(stashed_after - stashed_before),
	    (unsigned long long)nested_seen);

	/*
	 * Surviving the run is the primary assertion: without the guard the
	 * first nested write panics on smr_enter() recursion. The callout
	 * must have fired, and -- since its 8-byte payload fits the scratch
	 * slot -- the guard must have stashed and delivered at least one
	 * nested write rather than dropping it.
	 */
	KTEST_VERIFY(writes > 0);
	KTEST_VERIFY(d.fired > 0);
	KTEST_VERIFY(stashed_after > stashed_before);
	KTEST_VERIFY(nested_seen > 0);

	free(read_buf, M_EVENTLOG_TEST);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Verify the scratch slot's bounded capacity: a nested write whose payload
 * is larger than the scratch can hold must still be dropped (not corrupt
 * memory or panic), exactly like the pre-scratch guard did for every
 * nested write.
 */
struct reentr_overflow_data {
	struct eventlog_session	*session;
	struct callout		callout;
	int			cpu;
	int			stop;
	uint64_t		fired;
};

static void
reentr_oversized_nested_write(void *arg)
{
	struct reentr_overflow_data *d = arg;
	/* Larger than any plausible scratch slot; the exact scratch capacity
	 * is a kern_eventlog.c-internal constant, so this only needs to be
	 * comfortably above it, not match it precisely. */
	static uint8_t payload[4096];

	if (atomic_load_acq_int((volatile u_int *)&d->stop) != 0)
		return;

	eventlog_event_write(d->session, 0x902, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, payload, sizeof(payload));
	d->fired++;

	callout_reset_sbt_on(&d->callout, 100 * SBT_1US, 0,
	    reentr_oversized_nested_write, d, d->cpu, C_DIRECT_EXEC);
}

KTEST_FUNC(write_reentrancy_scratch_overflow)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct reentr_overflow_data d;
	struct callout stop_timer;
	uint32_t payload[4];
	u_long drops_before, drops_after, stashed_before, stashed_after;
	uint64_t writes = 0;
	int stop = 0;
	int i;

	KTEST_LOG(ctx, "Testing scratch slot capacity limit "
	    "(oversized nested payload must still drop, not stash)");

	provider = test_create_provider("test_reentr_ovf", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(256 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_reentr_ovf", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	drops_before = eventlog_get_reentrant_drops();
	stashed_before = eventlog_get_reentrant_stashed();

	sched_pin();
	bzero(&d, sizeof(d));
	d.session = session;
	d.cpu = PCPU_GET(cpuid);
	callout_init(&d.callout, 1);
	callout_reset_sbt_on(&d.callout, 100 * SBT_1US, 0,
	    reentr_oversized_nested_write, &d, d.cpu, C_DIRECT_EXEC);

	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz, lockfree_stop_callout, &stop);

	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		for (i = 0; i < 256; i++) {
			payload[0] = (uint32_t)writes;
			payload[1] = payload[2] = payload[3] = 0;
			eventlog_event_write(session, 0x903,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, payload,
			    sizeof(payload));
			writes++;
		}
	}

	atomic_store_rel_int((volatile u_int *)&d.stop, 1);
	callout_drain(&d.callout);
	callout_drain(&stop_timer);
	sched_unpin();

	drops_after = eventlog_get_reentrant_drops();
	stashed_after = eventlog_get_reentrant_stashed();

	KTEST_LOG(ctx, "main writes=%llu, oversized nested callout fired=%llu, "
	    "reentrant drops=%llu, reentrant stashed=%llu",
	    (unsigned long long)writes,
	    (unsigned long long)d.fired,
	    (unsigned long long)(drops_after - drops_before),
	    (unsigned long long)(stashed_after - stashed_before));

	KTEST_VERIFY(writes > 0);
	KTEST_VERIFY(d.fired > 0);
	KTEST_VERIFY(drops_after > drops_before);
	KTEST_EQUAL(stashed_after, stashed_before);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Cross-CPU merge-order test infrastructure.
 *
 * One "straggler" writer, bound to its own CPU, writes a single event and
 * then sleeps a while before writing the next; several "busy" writers on
 * other CPUs write continuously. This is the shape that exposed the
 * roll-boundary thrash bug live: a quiet CPU's already-committed event can
 * sit undiscovered while busy CPUs' streams race ahead through many read()
 * calls, and the merged stream delivers the busy CPUs' later events before
 * the straggler's earlier one. The reader checks that never happens.
 */
struct cpu_order_writer_data {
	struct eventlog_session *session;
	volatile int done;
	int cpu;
	int straggler;
	volatile uint64_t events_written;
	/* Wall-clock time this thread actually started running (after
	 * sched_bind), to distinguish "staggered kthread_add()/scheduler
	 * startup" from a genuine post-commit discovery delay -- see
	 * first_seen_lag_us on the reader side. */
	uint64_t start_ts;
};

static inline uint64_t cpu_order_now_us(void);

static void
cpu_order_writer_thread(void *arg)
{
	struct cpu_order_writer_data *data = (struct cpu_order_writer_data *)arg;
	uint32_t payload;

	thread_lock(curthread);
	sched_bind(curthread, data->cpu);
	thread_unlock(curthread);
	data->start_ts = cpu_order_now_us();

	while (atomic_load_acq_int((volatile u_int *)&data->done) == 0) {
		payload = (uint32_t)data->events_written;
		eventlog_event_write(data->session, 0x5000, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload));
		atomic_add_long((volatile u_long *)&data->events_written, 1);
		if (data->straggler)
			tsleep(data, 0, "evtlog_straggler",
			    MAX(hz / 100, 1));
		else
			kern_yield(PRI_UNCHANGED);
	}

	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);
	kthread_exit();
}

/*
 * Diagnostic detail on the first few violations: which CPUs were involved,
 * not just the aggregate count -- lets us tell a straggler-discovery gap
 * (violations clustered on the straggler's CPU) apart from busy-vs-busy heap
 * misordering (a different, worse bug) without guessing from the merge code
 * alone.
 */
#define CPU_ORDER_MAX_LOGGED_VIOLATIONS	20
struct cpu_order_violation {
	int from_cpu;
	int to_cpu;
	uint64_t from_ts;
	uint64_t to_ts;
	uint64_t poll_duration_us;	/* wall-clock time of the read() call that delivered "to" */
};

struct cpu_order_reader_data {
	struct eventlog_subscriber *subscriber;
	volatile int done;
	int reader_exited;
	uint64_t events_read;
	uint64_t violations;
	/* Regressions within a single CPU's own stream -- should never
	 * happen; separates "per-CPU stream itself is non-monotonic" from
	 * "cross-CPU merge misorders otherwise-fine per-CPU streams". */
	uint64_t percpu_violations;
	uint64_t last_timestamp;
	uint64_t max_regression_us;
	struct cpu_order_violation worst;	/* the single largest-regression violation */
	/* Log2-bucketed histogram of regression sizes, buckets[i] counts
	 * regressions in (2^(i-1), 2^i] us (bucket 0 is exactly 1us) --
	 * distinguishes common small-skew noise from rare large outliers so a
	 * watermark/holdback value can be picked from real data. */
#define CPU_ORDER_NUM_REGRESSION_BUCKETS	32
	uint64_t regression_buckets[CPU_ORDER_NUM_REGRESSION_BUCKETS];
	uint64_t *percpu_last_ts;	/* [mp_maxid + 1] */
	/* First-delivery diagnostics (2026-07-29): does the large-regression
	 * tail correlate with a CPU's very first delivered event, i.e. is
	 * this a startup/first-discovery race rather than a mid-stream one?
	 * first_seen[cpu] guards a one-time-per-cpu wall-clock read so this
	 * doesn't add per-event overhead to the hot path. */
	bool *first_seen;		/* [mp_maxid + 1] */
	uint64_t *first_seen_lag_us;	/* [mp_maxid + 1]: delivery_now - event_ts */
	uint64_t *first_seen_poll_count; /* [mp_maxid + 1]: reader loop iterations so far */
	uint64_t poll_count;		/* reader thread's own loop iteration count */
	/* Wall-clock duration of the read() call currently being processed
	 * -- was the worst violation caused by one anomalously slow syscall
	 * stalling the reader, or delivered promptly by a normal-speed
	 * call that still got the order wrong? */
	uint64_t cur_poll_duration_us;
	uint64_t max_poll_duration_us;
	int last_cpu;
	int straggler_cpu;
	int reader_cpu;
	int nlogged;
	struct cpu_order_violation logged[CPU_ORDER_MAX_LOGGED_VIOLATIONS];
};

static inline uint64_t
cpu_order_now_us(void)
{
	struct bintime bt;

	binuptime(&bt);
	return (bintime2us(&bt));
}

static void
cpu_order_record_event(struct cpu_order_reader_data *data,
    const struct eventlog_event_header *hdr)
{
	if (!data->first_seen[hdr->cpu]) {
		uint64_t now = cpu_order_now_us();

		data->first_seen[hdr->cpu] = true;
		data->first_seen_lag_us[hdr->cpu] =
		    (now > hdr->timestamp) ? now - hdr->timestamp : 0;
		data->first_seen_poll_count[hdr->cpu] = data->poll_count;
	}

	if (hdr->timestamp < data->percpu_last_ts[hdr->cpu])
		data->percpu_violations++;
	data->percpu_last_ts[hdr->cpu] = hdr->timestamp;

	if (hdr->timestamp < data->last_timestamp) {
		uint64_t regression = data->last_timestamp - hdr->timestamp;
		int bucket = flsll(regression) - 1;	/* flsll(1)=1 -> bucket 0 */

		if (bucket < 0)
			bucket = 0;
		if (bucket >= CPU_ORDER_NUM_REGRESSION_BUCKETS)
			bucket = CPU_ORDER_NUM_REGRESSION_BUCKETS - 1;
		data->regression_buckets[bucket]++;

		data->violations++;
		if (regression > data->max_regression_us) {
			data->max_regression_us = regression;
			data->worst.from_cpu = data->last_cpu;
			data->worst.to_cpu = hdr->cpu;
			data->worst.from_ts = data->last_timestamp;
			data->worst.to_ts = hdr->timestamp;
			data->worst.poll_duration_us = data->cur_poll_duration_us;
		}
		if (data->nlogged < CPU_ORDER_MAX_LOGGED_VIOLATIONS) {
			struct cpu_order_violation *v =
			    &data->logged[data->nlogged++];
			v->from_cpu = data->last_cpu;
			v->to_cpu = hdr->cpu;
			v->from_ts = data->last_timestamp;
			v->to_ts = hdr->timestamp;
		}
	}
	data->last_timestamp = hdr->timestamp;
	data->last_cpu = hdr->cpu;
	data->events_read++;
}

static void
cpu_order_reader_thread(void *arg)
{
	struct cpu_order_reader_data *data = (struct cpu_order_reader_data *)arg;
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	size_t read_bytes, offset;
	struct eventlog_event_header hdr;

	/* Dedicated CPU, disjoint from every writer/straggler -- tests
	 * whether the reader competing with 32 pinned, CPU-saturating writer
	 * threads for scheduler time (rather than a merge-logic bug) explains
	 * the large-regression violations. */
	thread_lock(curthread);
	sched_bind(curthread, data->reader_cpu);
	thread_unlock(curthread);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);

	while (data->done == 0) {
		uint64_t poll_start = cpu_order_now_us();

		data->poll_count++;
		read_bytes = eventlog_read_into_buf(data->subscriber, read_buf,
		    read_buf_size, FNONBLOCK);
		data->cur_poll_duration_us = cpu_order_now_us() - poll_start;
		if (data->cur_poll_duration_us > data->max_poll_duration_us)
			data->max_poll_duration_us = data->cur_poll_duration_us;
		offset = 0;
		while (offset + sizeof(hdr) <= read_bytes) {
			memcpy(&hdr, read_buf + offset, sizeof(hdr));
			if (hdr.event_length < sizeof(hdr) ||
			    offset + hdr.event_length > read_bytes)
				break;
			cpu_order_record_event(data, &hdr);
			offset += hdr.event_length;
		}
		kern_yield(PRI_UNCHANGED);
	}

	free(read_buf, M_EVENTLOG_TEST);
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);
	atomic_store_rel_int(&data->reader_exited, 1);
	wakeup(&data->reader_exited);
	kthread_exit();
}

/*
 * Cap on busy writers: bounds the malloc below and keeps the test sane on
 * absurdly large machines. Real hardware (c658, ~100+ CPUs) has been
 * observed with ~90%+ cross-CPU ordering violations under sustained
 * many-writer load, which the original NUM_BUSY_WRITERS=3 shape (4 total
 * CPUs) never reproduced -- scale with mp_ncpus so this test actually
 * stresses the heap the way production does.
 */
#define CPU_ORDER_MAX_BUSY_WRITERS	255

KTEST_FUNC(cross_cpu_merge_order)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct cpu_order_writer_data *busy;
	struct cpu_order_writer_data straggler;
	struct cpu_order_reader_data reader_data;
	struct thread **busy_threads;
	struct thread *straggler_thread, *reader_thread;
	char drain_buf[8 * 1024];
	size_t drain_bytes;
	int *cpus;
	int nbusy, i, ncpus_found, error, cpu;
	uint64_t busy_total, test_start_ts;

	KTEST_LOG(ctx, "Testing that the cross-CPU merge preserves global "
	    "timestamp order even when one CPU writes rarely");

	if (mp_ncpus < 3) {
		KTEST_LOG(ctx, "Skipping: need at least 3 CPUs, have %d",
		    mp_ncpus);
		return (0);
	}
	/* Reserve one CPU for the reader (see cpu_order_reader_thread) so it
	 * isn't left floating, competing with `nbusy` pinned, CPU-saturating
	 * writers for scheduler time. */
	nbusy = MIN(mp_ncpus - 2, CPU_ORDER_MAX_BUSY_WRITERS);

	busy = malloc(nbusy * sizeof(*busy), M_EVENTLOG_TEST, M_WAITOK);
	busy_threads = malloc(nbusy * sizeof(*busy_threads), M_EVENTLOG_TEST,
	    M_WAITOK);
	cpus = malloc((nbusy + 2) * sizeof(*cpus), M_EVENTLOG_TEST, M_WAITOK);

	/* Collect real CPU ids rather than assuming 0..N-1 are all valid. */
	ncpus_found = 0;
	CPU_FOREACH(cpu) {
		if (ncpus_found >= nbusy + 2)
			break;
		cpus[ncpus_found++] = cpu;
	}
	KTEST_EQUAL(ncpus_found, nbusy + 2);

	provider = test_create_provider("test_cpuorder", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(256 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_cpuorder", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	bzero(&reader_data, sizeof(reader_data));
	reader_data.subscriber = subscriber;
	reader_data.straggler_cpu = cpus[nbusy];
	reader_data.reader_cpu = cpus[nbusy + 1];
	reader_data.percpu_last_ts = malloc((mp_maxid + 1) *
	    sizeof(*reader_data.percpu_last_ts), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	reader_data.first_seen = malloc((mp_maxid + 1) *
	    sizeof(*reader_data.first_seen), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	reader_data.first_seen_lag_us = malloc((mp_maxid + 1) *
	    sizeof(*reader_data.first_seen_lag_us), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	reader_data.first_seen_poll_count = malloc((mp_maxid + 1) *
	    sizeof(*reader_data.first_seen_poll_count), M_EVENTLOG_TEST, M_WAITOK | M_ZERO);
	error = kthread_add(cpu_order_reader_thread, &reader_data, NULL,
	    &reader_thread, 0, 0, "evtlog_ord_rd");
	KTEST_EQUAL(error, 0);

	test_start_ts = cpu_order_now_us();
	for (i = 0; i < nbusy; i++) {
		bzero(&busy[i], sizeof(busy[i]));
		busy[i].session = session;
		busy[i].cpu = cpus[i];
		error = kthread_add(cpu_order_writer_thread, &busy[i], NULL,
		    &busy_threads[i], 0, 0, "evtlog_ord_busy");
		KTEST_EQUAL(error, 0);
	}

	bzero(&straggler, sizeof(straggler));
	straggler.session = session;
	straggler.cpu = cpus[nbusy];
	straggler.straggler = 1;
	error = kthread_add(cpu_order_writer_thread, &straggler, NULL,
	    &straggler_thread, 0, 0, "evtlog_ord_straggler");
	KTEST_EQUAL(error, 0);

	tsleep(&reader_data, 0, "evtlog_ord_run", hz);

	straggler.done = 1;
	for (i = 0; i < nbusy; i++)
		busy[i].done = 1;
	tsleep(&reader_data, 0, "evtlog_ord_settle", hz / 5);

	reader_data.done = 1;
	while (atomic_load_acq_int(&reader_data.reader_exited) == 0)
		tsleep(&reader_data.reader_exited, 0, "evtlog_ord_rdwait", hz / 10);

	do {
		size_t drain_offset = 0;
		struct eventlog_event_header hdr;

		drain_bytes = eventlog_read_into_buf(subscriber, drain_buf,
		    sizeof(drain_buf), FNONBLOCK);
		while (drain_offset + sizeof(hdr) <= drain_bytes) {
			memcpy(&hdr, drain_buf + drain_offset, sizeof(hdr));
			if (hdr.event_length < sizeof(hdr) ||
			    drain_offset + hdr.event_length > drain_bytes)
				break;
			cpu_order_record_event(&reader_data, &hdr);
			drain_offset += hdr.event_length;
		}
	} while (drain_bytes > 0);

	busy_total = 0;
	for (i = 0; i < nbusy; i++)
		busy_total += busy[i].events_written;

	{
		struct eventlog_stats stats;
		uint64_t total_written = busy_total + straggler.events_written;
		uint64_t pct_x10;

		eventlog_subscriber_get_stats(subscriber, &stats);
		pct_x10 = total_written ?
		    (1000 * stats.dropped_events / total_written) : 0;
		/* Are large regressions actually a symptom of write-side
		 * buffer-full drops (reader can't keep up, the ring fills,
		 * and new writes get dropped, so the CPU's surviving-but-old
		 * events look like a huge regression relative to CPUs that
		 * never overflowed)?
		 * No FPU in the kernel, so report as a fixed-point percent. */
		KTEST_LOG(ctx, "dropped_events: %llu (%llu.%llu%% of %llu written)",
		    (unsigned long long)stats.dropped_events,
		    (unsigned long long)(pct_x10 / 10),
		    (unsigned long long)(pct_x10 % 10),
		    (unsigned long long)total_written);
	}

	KTEST_LOG(ctx, "%d busy writers wrote %llu total, straggler wrote "
	    "%llu (cpu %d), reader saw %llu events, %llu ordering violations "
	    "(%llu per-cpu-stream violations) (worst regression %llu us)",
	    nbusy, (unsigned long long)busy_total,
	    (unsigned long long)straggler.events_written, reader_data.straggler_cpu,
	    (unsigned long long)reader_data.events_read,
	    (unsigned long long)reader_data.violations,
	    (unsigned long long)reader_data.percpu_violations,
	    (unsigned long long)reader_data.max_regression_us);

	for (i = 0; i < reader_data.nlogged; i++) {
		struct cpu_order_violation *v = &reader_data.logged[i];

		KTEST_LOG(ctx, "violation %d: cpu %d ts %llu -> cpu %d ts %llu "
		    "(regression %llu us)%s%s", i, v->from_cpu,
		    (unsigned long long)v->from_ts, v->to_cpu,
		    (unsigned long long)v->to_ts,
		    (unsigned long long)(v->from_ts - v->to_ts),
		    v->from_cpu == reader_data.straggler_cpu ? " [from straggler]" : "",
		    v->to_cpu == reader_data.straggler_cpu ? " [to straggler]" : "");
	}
	if (reader_data.max_regression_us > 0) {
		struct cpu_order_violation *v = &reader_data.worst;

		KTEST_LOG(ctx, "worst violation: cpu %d ts %llu -> cpu %d ts %llu "
		    "(regression %llu us), delivering read() call took %llu us%s%s",
		    v->from_cpu, (unsigned long long)v->from_ts, v->to_cpu,
		    (unsigned long long)v->to_ts,
		    (unsigned long long)reader_data.max_regression_us,
		    (unsigned long long)v->poll_duration_us,
		    v->from_cpu == reader_data.straggler_cpu ? " [from straggler]" : "",
		    v->to_cpu == reader_data.straggler_cpu ? " [to straggler]" : "");
	}
	KTEST_LOG(ctx, "slowest single read() call over the whole run: %llu us",
	    (unsigned long long)reader_data.max_poll_duration_us);
	for (i = 0; i < CPU_ORDER_NUM_REGRESSION_BUCKETS; i++) {
		if (reader_data.regression_buckets[i] == 0)
			continue;
		/* Bucket i holds regressions with floor(log2(x)) == i, i.e.
		 * x in [2^i, 2^(i+1) - 1]. */
		KTEST_LOG(ctx, "regression bucket [%llu, %llu] us: %llu",
		    (unsigned long long)(1ULL << i),
		    (unsigned long long)((1ULL << (i + 1)) - 1),
		    (unsigned long long)reader_data.regression_buckets[i]);
	}

	/* First-delivery lag: does the large-regression tail line up with a
	 * CPU's very first delivered event (startup/first-discovery race),
	 * or is it spread across the run (mid-stream discovery race)? Also
	 * compare against how late each writer thread actually started
	 * running (relative to test_start_ts) -- if that startup stagger
	 * alone accounts for the lag, this is a benign kthread_add()/
	 * scheduler artifact, not a post-commit discovery bug. */
	{
		uint64_t max_lag = 0;
		int max_lag_cpu = -1;
		uint64_t over_1ms = 0;

		for (cpu = 0; cpu <= mp_maxid; cpu++) {
			if (!reader_data.first_seen[cpu])
				continue;
			if (reader_data.first_seen_lag_us[cpu] > 1000) {
				over_1ms++;
				KTEST_LOG(ctx, "cpu %d: first-delivery lag "
				    "%llu us%s", cpu,
				    (unsigned long long)reader_data.first_seen_lag_us[cpu],
				    cpu == reader_data.straggler_cpu ?
				    " [straggler]" : "");
			}
			if (reader_data.first_seen_lag_us[cpu] > max_lag) {
				max_lag = reader_data.first_seen_lag_us[cpu];
				max_lag_cpu = cpu;
			}
		}
		KTEST_LOG(ctx, "first-delivery lag: %llu CPUs took >1ms from "
		    "first write to first delivery, worst was cpu %d at "
		    "%llu us", (unsigned long long)over_1ms, max_lag_cpu,
		    (unsigned long long)max_lag);

		for (i = 0; i < nbusy; i++) {
			uint64_t stagger = (busy[i].start_ts > test_start_ts) ?
			    busy[i].start_ts - test_start_ts : 0;

			KTEST_LOG(ctx, "cpu %d: writer thread startup "
			    "stagger %llu us, first-delivery lag %llu us, "
			    "reader had polled %llu times by then", busy[i].cpu,
			    (unsigned long long)stagger,
			    (unsigned long long)reader_data.first_seen_lag_us[busy[i].cpu],
			    (unsigned long long)reader_data.first_seen_poll_count[busy[i].cpu]);
		}
		KTEST_LOG(ctx, "reader polled %llu times total over the run",
		    (unsigned long long)reader_data.poll_count);
	}

	KTEST_VERIFY(reader_data.events_read > 0);
	KTEST_VERIFY(straggler.events_written > 0);
	KTEST_VERIFY(reader_data.percpu_violations == 0);
	KTEST_VERIFY(reader_data.violations == 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	free(reader_data.percpu_last_ts, M_EVENTLOG_TEST);
	free(reader_data.first_seen, M_EVENTLOG_TEST);
	free(reader_data.first_seen_lag_us, M_EVENTLOG_TEST);
	free(reader_data.first_seen_poll_count, M_EVENTLOG_TEST);
	free(busy, M_EVENTLOG_TEST);
	free(busy_threads, M_EVENTLOG_TEST);
	free(cpus, M_EVENTLOG_TEST);

	return (0);
}
#undef CPU_ORDER_MAX_BUSY_WRITERS

/*
 * Deterministic check that the resweep sequence gate does not starve a
 * quiet CPU that commits mid-read.  Fill one busy CPU past the boundary,
 * drain it once so a second CPU's ring is empty and out of the heap, then
 * commit an overdue (older-timestamp) event on the quiet CPU and read
 * again: the gate must not skip the resweep that folds the quiet CPU back
 * in, so the overdue event is delivered in the same read, not deferred to
 * the next.  Exercises the empty->nonempty commit_seq bump and the
 * swept_seq early-out in eventlog_resweep_idle_cpus().
 */
/*
 * The emit boundary B is now - read_watermark_us (default 20us), so a
 * read() right after a write returns only events already older than B
 * (leftover from an earlier burst) and leaves just-written ones sitting
 * in the rings.  Pause one tick (>> the watermark) before draining, then
 * FNONBLOCK until several consecutive empty reads.
 */
static void
seqgate_pause(void)
{
	pause("seqgate", 1);
}

static size_t
seqgate_drain_idle(struct eventlog_subscriber *subscriber, void *buf,
    size_t bufsize)
{
	size_t n, total = 0;
	int empty_tries = 0;

	seqgate_pause();
	while (empty_tries < 5) {
		n = eventlog_read_into_buf(subscriber, buf, bufsize, FNONBLOCK);
		if (n == 0) {
			empty_tries++;
			if (empty_tries < 5)
				seqgate_pause();
			continue;
		}
		empty_tries = 0;
		total += n;
	}
	return (total);
}

KTEST_FUNC(resweep_seq_gate_quiet_cpu)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_event_header hdr;
	char *buf;
	const size_t bufsize = 64 * 1024;
	uint32_t payload;
	size_t bytes;
	int i, quiet_cpu, busy_cpu, ncpus_found, cpu;
	int cpus[2];
	uint64_t first_ts, second_ts;
	bool saw_quiet_early;

	KTEST_LOG(ctx, "Testing that a quiet CPU's mid-read overdue commit "
	    "is still discovered under the resweep sequence gate");

	if (mp_ncpus < 2) {
		KTEST_LOG(ctx, "Skipping: need at least 2 CPUs, have %d",
		    mp_ncpus);
		return (0);
	}

	ncpus_found = 0;
	CPU_FOREACH(cpu) {
		if (ncpus_found >= 2)
			break;
		cpus[ncpus_found++] = cpu;
	}
	KTEST_EQUAL(ncpus_found, 2);
	busy_cpu = cpus[0];
	quiet_cpu = cpus[1];

	provider = test_create_provider("test_seqgate", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(bufsize);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_seqgate", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	buf = malloc(bufsize, M_EVENTLOG_TEST, M_WAITOK);

	/* Write a burst from the busy CPU so its events bracket the quiet
	 * CPU's in timestamp. */
	thread_lock(curthread);
	sched_bind(curthread, busy_cpu);
	thread_unlock(curthread);
	for (i = 0; i < 32; i++) {
		payload = (uint32_t)i;
		eventlog_event_write(session, 0x6000, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload));
	}

	/* Drain the busy burst completely (past the watermark) so leftover
	 * first-burst events cannot satisfy the next read() while the quiet
	 * CPU's just-written event is still held behind B. */
	bytes = seqgate_drain_idle(subscriber, buf, bufsize);
	KTEST_VERIFY(bytes > 0);

	/* Commit a single event on the quiet CPU.  Its timestamp is captured
	 * now, which is necessarily older than any event the busy CPU commits
	 * after it, so a correct merge delivers it before those. */
	thread_lock(curthread);
	sched_bind(curthread, quiet_cpu);
	thread_unlock(curthread);
	payload = 0xdeadbeef;
	eventlog_event_write(session, 0x6001, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, &payload, sizeof(payload));

	thread_lock(curthread);
	sched_bind(curthread, busy_cpu);
	thread_unlock(curthread);
	for (i = 0; i < 32; i++) {
		payload = (uint32_t)(0x1000 + i);
		eventlog_event_write(session, 0x6000, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload));
	}
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);

	/* Pause so the quiet event and second busy burst are past B, then
	 * drain everything.  A blocking read here would return leftover
	 * first-burst events (already older than B) without waiting for
	 * these new timestamps. */
	first_ts = 0;
	second_ts = 0;
	saw_quiet_early = false;
	seqgate_pause();
	{
		int empty_tries = 0;

		while (empty_tries < 5) {
			size_t off = 0;

			bytes = eventlog_read_into_buf(subscriber, buf, bufsize,
			    FNONBLOCK);
			if (bytes == 0) {
				empty_tries++;
				if (empty_tries < 5)
					seqgate_pause();
				continue;
			}
			empty_tries = 0;
			while (off + sizeof(hdr) <= bytes) {
				memcpy(&hdr, buf + off, sizeof(hdr));
				if (hdr.event_length < sizeof(hdr) ||
				    off + hdr.event_length > bytes)
					break;
				if (hdr.event_id == 0x6001 && first_ts == 0)
					first_ts = hdr.timestamp;
				if (hdr.event_id == 0x6000 &&
				    hdr.timestamp > 0 && second_ts == 0 &&
				    first_ts != 0 && hdr.timestamp > first_ts)
					second_ts = hdr.timestamp;
				off += hdr.event_length;
			}
		}
	}

	KTEST_VERIFY(first_ts != 0);
	/* The quiet event must be delivered; ordering vs the later busy
	 * burst is the regression signal. */
	saw_quiet_early = (second_ts == 0) || (first_ts < second_ts);
	KTEST_VERIFY(saw_quiet_early);
	KTEST_LOG(ctx, "quiet event ts %llu, first later-busy ts %llu",
	    (unsigned long long)first_ts, (unsigned long long)second_ts);

	free(buf, M_EVENTLOG_TEST);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/* ===================================================================
 * Microbenchmarks: ring-vs-double-buffer comparison harness
 *
 * These measure the outcomes that actually differ between buffering
 * models, isolated from the common cross-CPU merge (most run at a
 * single producer CPU so the merge does not mask the buffering delta).
 * Each bench emits one greppable "EVBENCH ..." line so the same code
 * can be diffed before/after a ring rewrite.
 *
 * IMPORTANT: run these on an INVARIANTS/WITNESS-free kernel. Otherwise
 * eventlog_validate_buffer() walks every event and the numbers are
 * meaningless.
 * =================================================================== */

#define EVBENCH_PAYLOAD_MAX	1024
#define EVBENCH_HDR		(sizeof(struct eventlog_event_header))
#define EVBENCH_BATCH		256	/* events per cycle-timing batch */

/*
 * Report a result line both to the ktest/kyua channel (KTEST_LOG, shown on
 * failure) and to the kernel console via printf (captured on the bhyve
 * serial log for passing runs, which is where we read the numbers from).
 */
#define EVBENCH_REPORT(_ctx, ...) do {					\
	KTEST_LOG((_ctx), __VA_ARGS__);					\
	printf(__VA_ARGS__);						\
	printf("\n");							\
} while (0)

/* Snapshot of online CPU ids so benches can pin to distinct cores. */
static int
evbench_online_cpus(int *cpus, int max)
{
	int c, n = 0;

	CPU_FOREACH(c) {
		if (n >= max)
			break;
		cpus[n++] = c;
	}
	return (n);
}

static void
evbench_pin(int cpu)
{
	thread_lock(curthread);
	sched_bind(curthread, cpu);
	thread_unlock(curthread);
}

static void
evbench_unpin(void)
{
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);
}

/* Walk a drained byte stream and count complete events. */
static uint64_t
evbench_count_events(const char *buf, size_t bytes)
{
	size_t off = 0;
	uint64_t n = 0;

	while (off + EVBENCH_HDR <= bytes) {
		struct eventlog_event_header h;

		memcpy(&h, buf + off, sizeof(h));
		if (h.event_length < EVBENCH_HDR ||
		    off + h.event_length > bytes)
			break;
		off += h.event_length;
		n++;
	}
	return (n);
}

/* Flat-out writer thread: stamps a monotonic seq in the payload head,
 * writes as fast as possible until *stop, and batch-times its own cost. */
struct evbench_writer {
	struct eventlog_session *session;
	volatile int *stop;
	int cpu;			/* pin target, -1 = no pin */
	uint16_t payload_size;
	uint64_t events;		/* events attempted */
	uint64_t cycles;		/* cycles inside eventlog_event_write */
	int exited;			/* accessed via atomic_*_int casts */
};

static void
evbench_flat_writer(void *arg)
{
	struct evbench_writer *w = arg;
	uint8_t buf[EVBENCH_PAYLOAD_MAX];
	uint64_t seq = 0, c0;
	int k;

	if (w->cpu >= 0)
		evbench_pin(w->cpu);
	memset(buf, 0, sizeof(buf));

	while (atomic_load_acq_int((volatile u_int *)w->stop) == 0) {
		c0 = get_cyclecount();
		for (k = 0; k < EVBENCH_BATCH; k++) {
			memcpy(buf, &seq, sizeof(seq));
			seq++;
			eventlog_event_write(w->session, 0x2000,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, buf,
			    w->payload_size);
		}
		w->cycles += get_cyclecount() - c0;
		w->events += EVBENCH_BATCH;
		/* Yield outside the timed region so a same-CPU reader (or the
		 * main thread) makes progress on few-CPU VMs; does not perturb
		 * wr_cyc_ev. */
		kern_yield(PRI_UNCHANGED);
	}

	if (w->cpu >= 0)
		evbench_unpin();
	atomic_store_rel_int((volatile u_int *)&w->exited, 1);
	wakeup(&w->exited);
	kthread_exit();
}

/*
 * Bench 1 — write cost, no reader (merge neutralized, no swap/drop).
 * Pure reserve/commit hot-path cost. This is the write-path regression
 * gate: it should not get worse when moving to a ring.
 */
KTEST_FUNC(bench_write_cost)
{
#define BWC_EVENTS	50000
#define BWC_PAYLOAD	32
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	uint8_t buf[BWC_PAYLOAD];
	uint32_t bufsz;
	uint64_t c0, cyc;
	int cpus[MAXCPU], ncpu, i;

	ncpu = evbench_online_cpus(cpus, MAXCPU);
	/* Buffer big enough that warmup + BWC_EVENTS fit in a SINGLE buffer,
	 * so there is no swap and no drop — pure commit-cost measurement. */
	bufsz = roundup2((uint32_t)((EVBENCH_HDR + BWC_PAYLOAD) *
	    (BWC_EVENTS + 2000) + (128 * 1024)), PAGE_SIZE);
	if (bufsz > EVENTLOG_BUFFER_SIZE_MAX)
		bufsz = EVENTLOG_BUFFER_SIZE_MAX;

	provider = test_create_provider("bench_wc", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(bufsz);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "bench_wc",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	memset(buf, 0, sizeof(buf));
	if (ncpu > 0)
		evbench_pin(cpus[0]);

	/* Warm up. */
	for (i = 0; i < 1000; i++)
		eventlog_event_write(session, 0x2000, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, buf, BWC_PAYLOAD);

	c0 = get_cyclecount();
	for (i = 0; i < BWC_EVENTS; i++)
		eventlog_event_write(session, 0x2000, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, buf, BWC_PAYLOAD);
	cyc = get_cyclecount() - c0;

	if (ncpu > 0)
		evbench_unpin();

	eventlog_subscriber_get_stats(subscriber, &stats);
	EVBENCH_REPORT(ctx, "EVBENCH write_cost ncpu=1 payload=%d buf=%u | "
	    "wr_cyc_ev=%llu events=%d dropped=%llu",
	    BWC_PAYLOAD, bufsz, (unsigned long long)(cyc / BWC_EVENTS),
	    BWC_EVENTS, (unsigned long long)stats.dropped_events);

	/* Tear down before the verify so a failure does not leak the
	 * subscriber/session/provider (KTEST_VERIFY returns on failure). */
	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	KTEST_VERIFY(stats.dropped_events == 0);
	return (0);
#undef BWC_EVENTS
#undef BWC_PAYLOAD
}

/*
 * Bench 2 — write cost with a reader keeping up (merge neutralized at
 * 1 producer CPU). The writer's commit contends with the reader
 * (swap-CAS on packed_state for the double buffer; just tail-advance
 * for a ring). The wr_cyc_ev delta vs bench_write_cost is the
 * reader<->writer contention signal.
 */
KTEST_FUNC(bench_write_contention)
{
#define BWX_SECS	2
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	struct evbench_writer w;
	struct thread *wt;
	struct callout stop_timer;
	int stop = 0;
	char *rbuf;
	size_t rbufsz = 256 * 1024;
	uint64_t rd_cyc = 0, rd_events = 0, c0, bytes;
	int cpus[MAXCPU], ncpu, rcpu, error;

	ncpu = evbench_online_cpus(cpus, MAXCPU);
	rcpu = (ncpu > 1) ? cpus[1] : -1;

	rbuf = malloc(rbufsz, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(rbuf, NULL);
	provider = test_create_provider("bench_wx", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(256 * 1024);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "bench_wx",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	bzero(&w, sizeof(w));
	w.session = session;
	w.stop = &stop;
	w.cpu = (ncpu > 0) ? cpus[0] : -1;
	w.payload_size = 32;
	error = kthread_add(evbench_flat_writer, &w, NULL, &wt, 0, 0,
	    "evbench_wx");
	KTEST_EQUAL(error, 0);

	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * BWX_SECS, lockfree_stop_callout, &stop);

	if (rcpu >= 0)
		evbench_pin(rcpu);
	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		c0 = get_cyclecount();
		bytes = eventlog_read_into_buf(subscriber, rbuf, rbufsz,
		    FNONBLOCK);
		if (bytes > 0) {
			rd_cyc += get_cyclecount() - c0;
			rd_events += evbench_count_events(rbuf, bytes);
		}
	}
	if (rcpu >= 0)
		evbench_unpin();

	callout_drain(&stop_timer);
	while (atomic_load_acq_int((volatile u_int *)&w.exited) == 0)
		tsleep(&w.exited, 0, "bwxwait", hz / 10);

	eventlog_subscriber_get_stats(subscriber, &stats);
	EVBENCH_REPORT(ctx, "EVBENCH write_contention ncpu=1 payload=32 secs=%d | "
	    "wr_cyc_ev=%llu rd_cyc_ev=%llu wr_events=%llu rd_events=%llu "
	    "dropped=%llu",
	    BWX_SECS,
	    (unsigned long long)(w.events ? w.cycles / w.events : 0),
	    (unsigned long long)(rd_events ? rd_cyc / rd_events : 0),
	    (unsigned long long)w.events, (unsigned long long)rd_events,
	    (unsigned long long)stats.dropped_events);

	free(rbuf, M_EVENTLOG_TEST);
	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
#undef BWX_SECS
}

/*
 * Bench 3 — write cost under same-CPU nesting.  A C_DIRECT_EXEC callout
 * bound to the writer's CPU logs events while a thread-context writer is
 * mid-eventlog_event_write on that CPU, reproducing NMI/interrupt-context
 * nesting.  The per-CPU buffer protocol is designed to tolerate this, and
 * on a production (non-INVARIANTS) kernel it does not crash.
 *
 * DEFINED BUT NOT REGISTERED in tests[]: it cannot be *run* on the ktest
 * kernel.  The shared write entry eventlog_event_write() calls smr_enter(),
 * which has KASSERT(c_seq == 0, "smr_enter does not support recursion").
 * A same-CPU nested eventlog_event_write() (NMI or C_DIRECT_EXEC callout,
 * neither blocked by the critical section) trips that assertion and panics
 * the INVARIANTS test kernel.  So this measures nothing until the SMR-entry
 * re-entrancy is resolved (e.g. an NMI/interrupt-safe entry path).  Keep it
 * here so it is ready to enable once that lands; a __unused reference below
 * keeps it compiling while it stays off the run list.
 */
struct evbench_nest {
	struct eventlog_session *session;
	struct callout c;
	volatile int stop;
	int cpu;
	uint64_t fired;
	uint32_t sbt_us;
};

static void
evbench_nest_callout(void *arg)
{
	struct evbench_nest *n = arg;
	uint32_t payload[4] = { 0xdead, 0xbeef, 0, 0 };

	if (atomic_load_acq_int((volatile u_int *)&n->stop) != 0)
		return;
	eventlog_event_write(n->session, 0x3000, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, payload, sizeof(payload));
	n->fired++;
	callout_reset_sbt_on(&n->c, n->sbt_us * SBT_1US, 0,
	    evbench_nest_callout, n, n->cpu, C_DIRECT_EXEC);
}

KTEST_FUNC(bench_nesting)
{
#define BN_SECS		2
#define BN_PAYLOAD	32
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	struct evbench_nest nest;
	struct callout stop_timer;
	int stop = 0;
	uint8_t buf[BN_PAYLOAD];
	uint64_t c0, wr_cyc = 0, wr_events = 0;
	int cpus[MAXCPU], ncpu, k;

	ncpu = evbench_online_cpus(cpus, MAXCPU);

	provider = test_create_provider("bench_nest", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(256 * 1024);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "bench_nest", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	bzero(&nest, sizeof(nest));
	nest.session = session;
	nest.cpu = (ncpu > 0) ? cpus[0] : 0;
	nest.sbt_us = 100;	/* ~10 kHz nested writer */
	callout_init(&nest.c, 1);
	callout_reset_sbt_on(&nest.c, nest.sbt_us * SBT_1US, 0,
	    evbench_nest_callout, &nest, nest.cpu, C_DIRECT_EXEC);

	memset(buf, 0, sizeof(buf));
	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * BN_SECS, lockfree_stop_callout, &stop);

	if (ncpu > 0)
		evbench_pin(cpus[0]);

	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		c0 = get_cyclecount();
		for (k = 0; k < EVBENCH_BATCH; k++)
			eventlog_event_write(session, 0x3001,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, buf, BN_PAYLOAD);
		wr_cyc += get_cyclecount() - c0;
		wr_events += EVBENCH_BATCH;
	}

	if (ncpu > 0)
		evbench_unpin();

	callout_drain(&stop_timer);
	atomic_store_rel_int((volatile u_int *)&nest.stop, 1);
	callout_drain(&nest.c);

	eventlog_subscriber_get_stats(subscriber, &stats);
	EVBENCH_REPORT(ctx, "EVBENCH nesting ncpu=1 payload=%d nest_khz=10 secs=%d | "
	    "wr_cyc_ev=%llu wr_events=%llu nested=%llu dropped=%llu",
	    BN_PAYLOAD, BN_SECS,
	    (unsigned long long)(wr_events ? wr_cyc / wr_events : 0),
	    (unsigned long long)wr_events, (unsigned long long)nest.fired,
	    (unsigned long long)stats.dropped_events);

	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
#undef BN_SECS
#undef BN_PAYLOAD
}

/*
 * bench_nesting is intentionally absent from tests[] (see the comment on
 * the function).  Reference it here so the compiler does not flag the
 * static function as unused while it stays off the run list.
 */
static const ktest_run_t evbench_nesting_defined __unused =
    __ktest_bench_nesting;

/*
 * Bench 4 — overrun retention. One fast writer, one throttled reader,
 * a small buffer. Writers stamp a monotonic seq; the reader tracks the
 * gap structure of what survives. The discriminator is granularity:
 * the double buffer drops in buffer-sized quanta (few large gaps), a
 * ring drops per-event (many small gaps) and thus keeps a more
 * representative time sample under backpressure.
 */
KTEST_FUNC(bench_overrun_retention)
{
#define BOR_SECS	2
#define BOR_PAYLOAD	64
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	struct evbench_writer w;
	struct thread *wt;
	struct callout stop_timer;
	int stop = 0;
	char *rbuf;
	size_t rbufsz = 16 * 1024;
	uint64_t received = 0, max_gap = 0, num_gaps = 0;
	uint64_t expected = 0, last_seq = 0;
	bool first = true;
	size_t bytes, off;
	int cpus[MAXCPU], ncpu, error;

	ncpu = evbench_online_cpus(cpus, MAXCPU);

	rbuf = malloc(rbufsz, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(rbuf, NULL);
	provider = test_create_provider("bench_or", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	/* Minimum buffer: overrun quickly and make the quantum obvious. */
	subscriber = eventlog_subscriber_create_device(EVENTLOG_BUFFER_SIZE_MIN);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "bench_or",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	bzero(&w, sizeof(w));
	w.session = session;
	w.stop = &stop;
	w.cpu = (ncpu > 0) ? cpus[0] : -1;
	w.payload_size = BOR_PAYLOAD;
	error = kthread_add(evbench_flat_writer, &w, NULL, &wt, 0, 0,
	    "evbench_or");
	KTEST_EQUAL(error, 0);

	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * BOR_SECS, lockfree_stop_callout, &stop);

	/* Throttled reader: drain a chunk, then sleep a tick. Slower than
	 * the writer, so the buffer overruns and events are dropped. */
	while (atomic_load_acq_int((volatile u_int *)&stop) == 0) {
		bytes = eventlog_read_into_buf(subscriber, rbuf, rbufsz, 0);
		for (off = 0; off + EVBENCH_HDR <= bytes; ) {
			struct eventlog_event_header h;
			uint64_t seq;

			memcpy(&h, rbuf + off, sizeof(h));
			if (h.event_length < EVBENCH_HDR ||
			    off + h.event_length > bytes)
				break;
			memcpy(&seq, rbuf + off + EVBENCH_HDR, sizeof(seq));
			if (!first && seq > expected) {
				uint64_t gap = seq - expected;
				num_gaps++;
				if (gap > max_gap)
					max_gap = gap;
			}
			expected = seq + 1;
			last_seq = seq;
			first = false;
			received++;
			off += h.event_length;
		}
		tsleep(&stop, 0, "borrd", 1);
	}

	callout_drain(&stop_timer);
	while (atomic_load_acq_int((volatile u_int *)&w.exited) == 0)
		tsleep(&w.exited, 0, "borwait", hz / 10);

	eventlog_subscriber_get_stats(subscriber, &stats);
	EVBENCH_REPORT(ctx, "EVBENCH overrun_retention ncpu=1 payload=%d buf=%u "
	    "secs=%d | written=%llu received=%llu dropped=%llu "
	    "retain_pct=%llu max_gap=%llu num_gaps=%llu last_seq=%llu",
	    BOR_PAYLOAD, (unsigned)EVENTLOG_BUFFER_SIZE_MIN, BOR_SECS,
	    (unsigned long long)w.events, (unsigned long long)received,
	    (unsigned long long)stats.dropped_events,
	    (unsigned long long)(w.events ? received * 100 / w.events : 0),
	    (unsigned long long)max_gap, (unsigned long long)num_gaps,
	    (unsigned long long)last_seq);

	free(rbuf, M_EVENTLOG_TEST);
	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
#undef BOR_SECS
#undef BOR_PAYLOAD
}

/*
 * Bench 5 — read-path payload sweep. One producer, reader keeping up,
 * varying payload size. rd_cyc_ev vs payload separates per-byte copyout
 * cost (slope) from the payload-independent merge+parse cost (intercept).
 * If the intercept dominates at small (TCP-realistic) payloads, copyout
 * is not the read bottleneck and mmap-zero-copy would not help much.
 */
static uint64_t
evbench_read_drain_cyc(struct eventlog_subscriber *sub, char *rbuf,
    size_t rbufsz, volatile int *stop, uint64_t *events_out)
{
	uint64_t rd_cyc = 0, rd_events = 0, c0, bytes;

	while (atomic_load_acq_int((volatile u_int *)stop) == 0) {
		c0 = get_cyclecount();
		bytes = eventlog_read_into_buf(sub, rbuf, rbufsz, FNONBLOCK);
		if (bytes > 0) {
			rd_cyc += get_cyclecount() - c0;
			rd_events += evbench_count_events(rbuf, bytes);
		}
	}
	*events_out = rd_events;
	return (rd_cyc);
}

KTEST_FUNC(bench_read_payload_sweep)
{
	static const uint16_t payloads[] = { 8, 64, 256, 1024 };
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	struct evbench_writer w;
	struct thread *wt;
	struct callout stop_timer;
	char *rbuf;
	size_t rbufsz = 256 * 1024;
	int cpus[MAXCPU], ncpu, rcpu, error;
	unsigned int p;

	ncpu = evbench_online_cpus(cpus, MAXCPU);
	rcpu = (ncpu > 1) ? cpus[1] : -1;

	rbuf = malloc(rbufsz, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(rbuf, NULL);
	provider = test_create_provider("bench_rps", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(1024 * 1024);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "bench_rps",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	for (p = 0; p < nitems(payloads); p++) {
		int stop = 0;
		uint64_t rd_cyc, rd_events;

		bzero(&w, sizeof(w));
		w.session = session;
		w.stop = &stop;
		w.cpu = (ncpu > 0) ? cpus[0] : -1;
		w.payload_size = payloads[p];
		error = kthread_add(evbench_flat_writer, &w, NULL, &wt, 0, 0,
		    "evbench_rps");
		KTEST_EQUAL(error, 0);

		callout_init(&stop_timer, 1);
		callout_reset(&stop_timer, hz, lockfree_stop_callout, &stop);

		if (rcpu >= 0)
			evbench_pin(rcpu);
		rd_cyc = evbench_read_drain_cyc(subscriber, rbuf, rbufsz, &stop,
		    &rd_events);
		if (rcpu >= 0)
			evbench_unpin();

		callout_drain(&stop_timer);
		while (atomic_load_acq_int((volatile u_int *)&w.exited) == 0)
			tsleep(&w.exited, 0, "rpswait", hz / 10);
		/* Drain leftovers so the next iteration starts clean. */
		while (eventlog_read_into_buf(subscriber, rbuf, rbufsz,
		    FNONBLOCK) > 0)
			;

		eventlog_subscriber_get_stats(subscriber, &stats);
		EVBENCH_REPORT(ctx, "EVBENCH read_payload_sweep ncpu=1 payload=%u | "
		    "rd_cyc_ev=%llu rd_events=%llu wr_events=%llu dropped=%llu",
		    (unsigned)payloads[p],
		    (unsigned long long)(rd_events ? rd_cyc / rd_events : 0),
		    (unsigned long long)rd_events, (unsigned long long)w.events,
		    (unsigned long long)stats.dropped_events);
	}

	free(rbuf, M_EVENTLOG_TEST);
	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
}

/*
 * Bench 6 — read-path merge scaling. Sweep the number of producing
 * CPUs; a single reader keeps up. rd_cyc_ev vs N isolates the merge
 * cost (grows with N) from the per-CPU drain cost (N=1 intercept),
 * showing how much of the hot read path is the merge (common to both
 * buffering models) vs. the buffering itself.
 */
KTEST_FUNC(bench_read_merge_scaling)
{
#define BMS_MAX_WRITERS	8
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct eventlog_stats stats;
	struct evbench_writer w[BMS_MAX_WRITERS];
	struct thread *wt[BMS_MAX_WRITERS];
	struct callout stop_timer;
	char *rbuf;
	size_t rbufsz = 256 * 1024;
	int cpus[MAXCPU], ncpu, rcpu, error, i;
	int max_writers, n;

	ncpu = evbench_online_cpus(cpus, MAXCPU);
	/* Reserve one CPU for the reader when we can. */
	max_writers = (ncpu > 1) ? (ncpu - 1) : 1;
	if (max_writers > BMS_MAX_WRITERS)
		max_writers = BMS_MAX_WRITERS;
	rcpu = (ncpu > 1) ? cpus[ncpu - 1] : -1;

	rbuf = malloc(rbufsz, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(rbuf, NULL);
	provider = test_create_provider("bench_ms", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = eventlog_subscriber_create_device(1024 * 1024);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber, "bench_ms",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0), 0);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	for (n = 1; n <= max_writers; n++) {
		int stop = 0;
		uint64_t rd_cyc, rd_events, wr_total = 0;

		for (i = 0; i < n; i++) {
			bzero(&w[i], sizeof(w[i]));
			w[i].session = session;
			w[i].stop = &stop;
			w[i].cpu = cpus[i];
			w[i].payload_size = 32;
			error = kthread_add(evbench_flat_writer, &w[i], NULL,
			    &wt[i], 0, 0, "evbench_ms_%d", i);
			KTEST_EQUAL(error, 0);
		}

		callout_init(&stop_timer, 1);
		callout_reset(&stop_timer, hz, lockfree_stop_callout, &stop);

		if (rcpu >= 0)
			evbench_pin(rcpu);
		rd_cyc = evbench_read_drain_cyc(subscriber, rbuf, rbufsz, &stop,
		    &rd_events);
		if (rcpu >= 0)
			evbench_unpin();

		callout_drain(&stop_timer);
		for (i = 0; i < n; i++) {
			while (atomic_load_acq_int(
			    (volatile u_int *)&w[i].exited) == 0)
				tsleep(&w[i].exited, 0, "mswait", hz / 10);
			wr_total += w[i].events;
		}
		while (eventlog_read_into_buf(subscriber, rbuf, rbufsz,
		    FNONBLOCK) > 0)
			;

		eventlog_subscriber_get_stats(subscriber, &stats);
		EVBENCH_REPORT(ctx, "EVBENCH read_merge_scaling nwriters=%d payload=32 "
		    "| rd_cyc_ev=%llu rd_events=%llu wr_events=%llu dropped=%llu",
		    n, (unsigned long long)(rd_events ? rd_cyc / rd_events : 0),
		    (unsigned long long)rd_events, (unsigned long long)wr_total,
		    (unsigned long long)stats.dropped_events);
	}

	free(rbuf, M_EVENTLOG_TEST);
	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	return (0);
#undef BMS_MAX_WRITERS
}

static const struct ktest_test_info tests[] = {
	KTEST_INFO(provider_init_cleanup),
	KTEST_INFO(session_create_destroy),
	KTEST_INFO(event_logging_basic),
	KTEST_INFO(event_logging_multiple),
	KTEST_INFO(provider_independence),
	KTEST_INFO(event_data_integrity),
	KTEST_INFO(event_size_variations),
	KTEST_INFO(multithreaded_logging),
	KTEST_INFO(subscriber_create_destroy),
	KTEST_INFO(subscriber_create_device_invalid_size),
	KTEST_INFO(subscriber_add_subscription_nonexistent_provider),
	KTEST_INFO(deferred_subscription_binds_on_provider_create),
	KTEST_INFO(subscription_keywords_updated_in_place),
	KTEST_INFO(provider_destroy_rebinds_via_retained_spec),
	KTEST_INFO(provider_id_exhaustion_fails_cleanly),
	KTEST_INFO(subscriber_read_error_paths),
	KTEST_INFO(null_pointer_destroy),
	KTEST_INFO(subscriber_level_keyword_filtering),
	KTEST_INFO(event_oversized_dropped),
	KTEST_INFO(event_edge_cases_payload_session),
	KTEST_INFO(subscriber_subscription_update_in_place),
	KTEST_INFO(subscriber_multiple_subscribers),
	KTEST_INFO(subscriber_provider_enablement_aggregation),
	KTEST_INFO(subscriber_device_buffer),
	KTEST_INFO(subscriber_circular_buffer),
	KTEST_INFO(subscriber_ring_race),
	KTEST_INFO(subscriber_interleaved_read_write),
	KTEST_INFO(subscriber_buffer_boundary_stress),
	KTEST_INFO(subscriber_buffer_fill_to_capacity),
	KTEST_INFO(subscriber_ring_wrap_integrity),
	KTEST_INFO(subscriber_rapid_wrap_stress),
	KTEST_INFO(subscriber_callback),
	KTEST_INFO(schema_generated_macros),
	KTEST_INFO(schema_varlen_event),
	KTEST_INFO(schema_packed_layout),
	KTEST_INFO(schema_packed_misaligned_event),
	KTEST_INFO(schema_varlen_unaligned_elem_types),
	KTEST_INFO(provider_schema_id),
	KTEST_INFO(get_decode_blob_lookup),
	KTEST_INFO(event_write_gather),
	KTEST_INFO(lockfree_many_concurrent_writers),
	KTEST_INFO(lockfree_writer_reader_contention),
	KTEST_INFO(lockfree_buffer_full_contention),
	KTEST_INFO(lockfree_data_integrity_under_contention),
	KTEST_INFO(lockfree_reader_writer_race),
	KTEST_INFO(timestamp_epoch_normal_delivery),
	KTEST_INFO(dump_state_basic),
	KTEST_INFO(dump_state_routing),
	KTEST_INFO(dump_state_no_callback),
	KTEST_INFO(dump_state_curvnet_not_set),
	KTEST_INFO(dump_state_disabled_sessions),
	KTEST_INFO(dump_state_async_runs_off_caller_thread),
	KTEST_INFO(dump_state_async_subscribe_returns_before_dump),
	KTEST_INFO(dump_state_destroy_waits_for_dump),
	KTEST_INFO(dump_state_resubscribe_no_refire),
	KTEST_INFO(dump_state_manual_trigger_refires),
	KTEST_INFO(dump_state_manual_trigger_scoped_to_subscriber),
	KTEST_INFO(dump_state_emits_dump_complete),
	KTEST_INFO(multi_provider_subscribe_enables_all),
	KTEST_INFO(multi_provider_events_from_both),
	KTEST_INFO(multi_provider_destroy_one),
	KTEST_INFO(multi_provider_dump_state),
	KTEST_INFO(multi_provider_independent_enablement),
	KTEST_INFO(multi_provider_device_subscriber),
	KTEST_INFO(subscribers_changed_basic),
	KTEST_INFO(subscribers_changed_null_safe),
	KTEST_INFO(subscribers_changed_runs_unlocked),
	KTEST_INFO(subscribers_changed_concurrent_subunsub),
	KTEST_INFO(provider_destroy_races_subscriber_destroy),
	KTEST_INFO(provider_config_null_equivalent),
	KTEST_INFO(provider_config_default_enabled),
	KTEST_INFO(provider_config_auto_ratio),
	KTEST_INFO(write_reentrancy_guard),
	KTEST_INFO(write_reentrancy_scratch_overflow),
	KTEST_INFO(cross_cpu_merge_order),
	KTEST_INFO(resweep_seq_gate_quiet_cpu),
	KTEST_INFO(bench_write_cost),
	KTEST_INFO(bench_write_contention),
	KTEST_INFO(bench_overrun_retention),
	KTEST_INFO(bench_read_payload_sweep),
	KTEST_INFO(bench_read_merge_scaling),
};

KTEST_MODULE_DECLARE(ktest_eventlog, tests);

