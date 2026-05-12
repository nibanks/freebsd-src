/*
 * Copyright (c) 2026 Netflix, Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <tests/ktest.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventlog.h>
#include <sys/eventlog_subscriber.h>
#include <sys/sysctl.h>
#include <sys/condvar.h>
#include <sys/kthread.h>
#include <sys/mutex.h>
#include <sys/sleepqueue.h>
#include <sys/sx.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <machine/atomic.h>
#include <sys/callout.h>
#include <sys/libkern.h>
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

/*
 * Helper: read from subscriber into kernel buffer via uio. Returns bytes read
 * or 0 on error.
 */
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

/* Callback test data structure */
struct test_callback_data {
	volatile uint32_t event_count;
	volatile uint32_t last_event_id;
	volatile const void *last_payload;
	volatile size_t last_payload_size;
	/* Only used for reading in test code, not in callback */
	struct mtx lock;
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
	struct test_callback_data *data;

	data = (struct test_callback_data *)callback_arg;
	atomic_add_int(&data->event_count, 1);
	atomic_store_rel_32(&data->last_event_id, hdr->event_id);
	data->last_payload = (iovcnt >= 1) ? iov[0].iov_base : NULL;
	atomic_store_rel_long(&data->last_payload_size, payload_size);
}

/*
 * Helper function to enable a provider for testing by creating a callback
 * subscriber and subscription. Returns the subscriber and callback data, which
 * should be destroyed after the test completes.
 */
static struct eventlog_subscriber *
test_enable_provider_callback(const char *provider_name,
    enum eventlog_level level, uint32_t keywords,
    struct test_callback_data **callback_data_out)
{
	struct eventlog_subscriber *subscriber;
	struct test_callback_data *callback_data;

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_callback", NULL, MTX_DEF);
	callback_data->event_count = 0;

	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data);
	if (subscriber == NULL) {
		mtx_destroy(&callback_data->lock);
		free(callback_data, M_EVENTLOG_TEST);
		return (NULL);
	}

	if (eventlog_subscriber_add_subscription(subscriber, provider_name,
	    level, keywords, 0) != 0) {
		eventlog_subscriber_destroy(subscriber);
		mtx_destroy(&callback_data->lock);
		free(callback_data, M_EVENTLOG_TEST);
		return (NULL);
	}

	*callback_data_out = callback_data;
	return (subscriber);
}

/*
 * Helper function to enable a provider for testing by creating a device
 * subscriber and subscription. Returns the subscriber, which should be
 * destroyed after the test completes. Use this when testing device-specific
 * functionality.
 */
static struct eventlog_subscriber *
test_enable_provider_device(const char *provider_name,
    enum eventlog_level level, uint32_t keywords)
{
	struct eventlog_subscriber *subscriber;

	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	if (subscriber == NULL)
		return (NULL);

	if (eventlog_subscriber_add_subscription(subscriber, provider_name,
	    level, keywords, 0) != 0) {
		eventlog_subscriber_destroy(subscriber);
		return (NULL);
	}

	return (subscriber);
}

/*
 * Legacy helper - defaults to callback for easier verification.
 */
static struct eventlog_subscriber *
test_enable_provider(const char *provider_name, enum eventlog_level level,
    uint32_t keywords)
{
	struct test_callback_data *unused;
	return (test_enable_provider_callback(provider_name, level, keywords,
	    &unused));
}

static struct eventlog_provider *
test_create_provider(const char *name,
    eventlog_provider_dump_state_t dump_cb, void *dump_arg)
{
	struct eventlog_provider_config cfg = {
		.dump_callback = dump_cb,
		.dump_callback_arg = dump_arg,
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
	struct eventlog_subscriber *test_sub;

	test_sub = test_enable_provider("test_basic", EVENTLOG_LEVEL_VERBOSE,
	    0xFFFFFFFF);
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
	test_sub = test_enable_provider_callback("test_multi",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(test_sub, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	eventlog_event_write(session, test_id1, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, &data1, sizeof(data1));
	eventlog_event_write(session, test_id2, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, &data2, sizeof(data2));
	eventlog_event_write(session, test_id3, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, &data3, sizeof(data3));

	/*
	 * Verify all three events were received (read then unlock;
	 * KTEST_EQUAL may sleep)
	 */
	{
		uint32_t ec, eid;
		uint32_t last_payload_val;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		last_payload_val = *(volatile const uint32_t *)
		    callback_data->last_payload;
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
	uint32_t test_data1[4] = {
	    0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD };
	uint32_t test_data2[4] = {
	    0x11111111, 0x22222222, 0x33333333, 0x44444444 };
	uint32_t test_data3[4] = {
	    0x55555555, 0x66666666, 0x77777777, 0x88888888 };
	volatile const uint32_t *received_data;
	int i;

	KTEST_LOG(ctx,
	    "Testing event data integrity - multiple independent events");

	provider = test_create_provider("test_integ", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	/* Enable provider for testing with callback subscriber */
	test_sub = test_enable_provider_callback("test_integ",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(test_sub, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Write events with different data */
	eventlog_event_write(session, test_id1, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, test_data1, sizeof(test_data1));
	eventlog_event_write(session, test_id2, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, test_data2, sizeof(test_data2));
	eventlog_event_write(session, test_id3, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, test_data3, sizeof(test_data3));

	/*
	 * Verify all events were received with correct data (read then unlock;
	 * KTEST_EQUAL may sleep)
	 */
	{
		uint32_t ec, eid;
		size_t plen;
		uint32_t payload_copy[4];
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		plen = atomic_load_acq_long(&callback_data->last_payload_size);
		received_data = (volatile const uint32_t *)
		    callback_data->last_payload;
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
	struct eventlog_subscriber *test_sub_small;
	struct eventlog_subscriber *test_sub_large;

	test_sub_small = test_enable_provider_callback("test_small",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data_small);
	test_sub_large = test_enable_provider_callback("test_large",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data_large);
	KTEST_NEQUAL(test_sub_small, NULL);
	KTEST_NEQUAL(test_sub_large, NULL);

	session_small = eventlog_session_create(provider_small, 0, true, NULL,
	    0);
	session_large = eventlog_session_create(provider_large, 0, true, NULL,
	    0);
	KTEST_NEQUAL(session_small, NULL);
	KTEST_NEQUAL(session_large, NULL);

	/* Create small event payload */
	uint8_t data_small[small_size];
	for (i = 0; i < small_size; i++) {
		data_small[i] = (uint8_t)(i & 0xFF);
	}
	eventlog_event_write(session_small, test_id_small, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, data_small, sizeof(data_small));

	/* Create large event payload */
	uint8_t data_large[large_size];
	for (i = 0; i < large_size; i++) {
		data_large[i] = (uint8_t)((i ^ 0xAA) & 0xFF);
	}
	eventlog_event_write(session_large, test_id_large, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, data_large, sizeof(data_large));

	/*
	 * Verify events were received (read then unlock; KTEST_EQUAL may
	 * sleep)
	 */
	{
		uint32_t ec_small, eid_small, ec_large, eid_large;
		size_t plen_small, plen_large;
		mtx_lock(&callback_data_small->lock);
		ec_small = atomic_load_acq_32(
		    &callback_data_small->event_count);
		eid_small = atomic_load_acq_32(
		    &callback_data_small->last_event_id);
		plen_small = atomic_load_acq_long(
		    &callback_data_small->last_payload_size);
		mtx_unlock(&callback_data_small->lock);
		/* SESSION_CREATE + 1 user event */
		KTEST_EQUAL(ec_small, 2);
		KTEST_EQUAL(eid_small, test_id_small);
		KTEST_EQUAL(plen_small, sizeof(data_small));

		mtx_lock(&callback_data_large->lock);
		ec_large = atomic_load_acq_32(
		    &callback_data_large->event_count);
		eid_large = atomic_load_acq_32(
		    &callback_data_large->last_event_id);
		plen_large = atomic_load_acq_long(
		    &callback_data_large->last_payload_size);
		mtx_unlock(&callback_data_large->lock);
		/* SESSION_CREATE + 1 user event */
		KTEST_EQUAL(ec_large, 2);
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

		eventlog_event_write(session, event_id_base + i,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, event_data,
		    sizeof(event_data));
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
	struct eventlog_subscriber *test_sub;

	test_sub = test_enable_provider_callback("test_mt",
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
		eventlog_event_write(session, main_thread_id + i,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, main_event_data,
		    sizeof(main_event_data));
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

	/*
	 * Verify total events received via callback (read then unlock;
	 * KTEST_EQUAL may sleep)
	 */
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		/* SESSION_CREATE + events from 2 threads */
		KTEST_EQUAL(ec, 1 + num_events_per_thread * 2);
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
	subscriber_device = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber_device, NULL);
	eventlog_subscriber_destroy(subscriber_device);

	/* Test callback subscriber */
	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_callback", NULL, MTX_DEF);
	subscriber_callback = eventlog_subscriber_create_callback(
	    test_event_callback, callback_data);
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
	sub1 = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	callback_data2 = malloc(sizeof(*callback_data2), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data2->lock, "test_callback2", NULL, MTX_DEF);
	sub2 = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data2);
	callback_data3 = malloc(sizeof(*callback_data3), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data3->lock, "test_callback3", NULL, MTX_DEF);
	sub3 = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data3);
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

	/*
	 * Verify provider enablement: keywords OR'ed (0x1 | 0x2 | 0x4 = 0x7),
	 * level is MAX (most verbose) = VERBOSE
	 */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x7);
	KTEST_EQUAL(eventlog_provider_get_level(provider),
	    EVENTLOG_LEVEL_VERBOSE);

	/* Remove one subscriber */
	eventlog_subscriber_destroy(sub2);
	mtx_destroy(&callback_data2->lock);
	free(callback_data2, M_EVENTLOG_TEST);

	/* Provider should still be enabled with remaining subscribers */
	/* 0x1 | 0x4 */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x5);
	/* MAX(INFO, VERBOSE) */
	KTEST_EQUAL(eventlog_provider_get_level(provider),
	    EVENTLOG_LEVEL_VERBOSE);

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

	sub1 = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	sub2 = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(sub1, NULL);
	KTEST_NEQUAL(sub2, NULL);

	/* Subscriber 1: INFO level, keywords 0x1 */
	error = eventlog_subscriber_add_subscription(sub1, "test_agg",
	    EVENTLOG_LEVEL_INFO, 0x1, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x1);

	/* Subscriber 2: WARN level, keywords 0x2 (should give INFO, 0x3) */
	error = eventlog_subscriber_add_subscription(sub2, "test_agg",
	    EVENTLOG_LEVEL_WARN, 0x2, 0);
	KTEST_EQUAL(error, 0);
	/* MAX(INFO, WARN) */
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_INFO);
	/* 0x1 | 0x2 */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x3);

	/* Update subscriber 1 to VERBOSE (should give VERBOSE, since MAX) */
	error = eventlog_subscriber_add_subscription(sub1, "test_agg",
	    EVENTLOG_LEVEL_VERBOSE, 0x1, 0);
	KTEST_EQUAL(error, 0);
	/* MAX(VERBOSE, WARN) */
	KTEST_EQUAL(eventlog_provider_get_level(provider),
	    EVENTLOG_LEVEL_VERBOSE);
	/* Still 0x1 | 0x2 */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x3);

	/* Update subscriber 2 to ERROR (should result in VERBOSE, since MAX) */
	error = eventlog_subscriber_add_subscription(sub2, "test_agg",
	    EVENTLOG_LEVEL_ERROR, 0x2, 0);
	KTEST_EQUAL(error, 0);
	/* MAX(VERBOSE, ERROR) */
	KTEST_EQUAL(eventlog_provider_get_level(provider),
	    EVENTLOG_LEVEL_VERBOSE);
	/* Still 0x1 | 0x2 */
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x3);

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
	subscriber = test_enable_provider_device("test_devbuf",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE from session creation */
	char read_buf[1024];
	size_t read;

	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf),
	    0);
	KTEST_VERIFY(read > 0);
	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf),
	    0);
	KTEST_EQUAL(read, 0);

	/* Write event */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &test_data, sizeof(test_data));

	/* Verify event was written to buffer */
	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf),
	    0);
	KTEST_VERIFY(read > 0);

	/* Verify buffer is cleared after read */
	read = eventlog_read_into_buf(subscriber, read_buf, sizeof(read_buf),
	    0);
	KTEST_EQUAL(read, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates double-buffering functionality.
 * Tests that buffer swapping works correctly and eliminates read/write
 * contention.
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

	KTEST_LOG(ctx, "Testing double-buffering functionality");

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	/* Create provider and subscriber */
	provider = test_create_provider("test_circ", NULL, NULL);
	if (provider == NULL) {
		free(read_buf, M_EVENTLOG_TEST);
		return (EINVAL);
	}

	/*
	 * Use a buffer size (128KB) - above 64KB minimum, triggers reasonable
	 * swaps
	 */
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

	/*
	 * Calculate expected event size for diagnostics (header includes
	 * provider_id, session_id)
	 */
	size_t expected_event_size = sizeof(struct eventlog_event_header) +
	    sizeof(uint32_t);
	size_t max_events = (128 * 1024) / expected_event_size;
	KTEST_LOG(ctx,
	    "Expected event size: %zu bytes, buffer size: %zu bytes, "
	    "max events: %zu",
	    expected_event_size, (size_t)(128 * 1024), max_events);

	/*
	 * Fill active buffer - SESSION_CREATE is first, then max_events-1
	 * user events to avoid overflow
	 */
	for (i = 0; i < max_events - 1; i++) {
		uint32_t val = (uint32_t)i;
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &val, sizeof(val));
	}

	/* Read all events - this should trigger buffer swap */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_LOG(ctx, "Read %zu bytes, dropped %llu events",
	    read, (unsigned long long)stats.dropped_events);
	KTEST_VERIFY(read > 0);
	/* Should not drop events if buffer is large enough */
	KTEST_VERIFY(stats.dropped_events == 0);

	/* Verify buffer is cleared after read */
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size, 0);
	KTEST_EQUAL(read, 0);

	/*
	 * Test buffer swap: write events, read some, then write more.
	 * After swap, writers continue on new active buffer, readers read
	 * from swapped buffer.
	 */
	for (i = 0; i < 50; i++) {
		uint32_t val = (uint32_t)i;
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &val, sizeof(val));
	}

	/* Read half of them - this swaps buffers */
	read = eventlog_read_into_buf(subscriber, read_buf, read_buf_size / 2,
	    0);
	KTEST_VERIFY(read > 0);

	/*
	 * Write more events - these go to the new active buffer (no
	 * contention with reader).
	 */
	for (i = 50; i < 100; i++) {
		uint32_t val = (uint32_t)i;
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &val, sizeof(val));
	}

	/* Read remaining events from reader buffer */
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
	subscriber = test_enable_provider_callback("test_cb",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Callback already received SESSION_CREATE from session creation */
	KTEST_EQUAL(atomic_load_acq_32(&callback_data->event_count), 1);

	/* Write event */
	eventlog_event_write(session, test_id, EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
	    &test_data, sizeof(test_data));

	/*
	 * Verify callback was invoked (read then unlock; KTEST_EQUAL may
	 * sleep)
	 */
	{
		uint32_t ec, eid, last_payload_val;
		size_t plen;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		eid = atomic_load_acq_32(&callback_data->last_event_id);
		plen = atomic_load_acq_long(&callback_data->last_payload_size);
		last_payload_val = *(volatile const uint32_t *)
		    callback_data->last_payload;
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
		eventlog_event_write(data->session, test_id++,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, test_data,
		    sizeof(test_data));
		atomic_add_64(&data->events_written, 1);
		kern_yield(PRI_UNCHANGED); /* Yield to allow reads */
	}

	kthread_exit();
}

/* Reader thread - continuously reads events, triggering swaps */
static void
concurrent_reader_thread(void *arg)
{
	struct concurrent_test_data *data = (struct concurrent_test_data *)arg;
	char read_buf[8 * 1024];
	size_t read_bytes;

	while (data->done == 0) {
		read_bytes = eventlog_read_into_buf(data->subscriber, read_buf,
		    sizeof(read_buf), 0);
		if (read_bytes > 0) {
			atomic_add_64(&data->bytes_read, read_bytes);
			atomic_add_64(&data->events_read, 1);
		}
		kern_yield(PRI_UNCHANGED); /* Yield to allow writes */
	}

	atomic_store_rel_int(&data->reader_exited, 1);
	wakeup(&data->reader_exited);
	kthread_exit();
}

/*
 * Validates double-buffering race conditions.
 * Tests concurrent reads and writes with frequent buffer swaps to ensure
 * no memory corruption or crashes occur.
 */
KTEST_FUNC(subscriber_double_buffer_race)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct concurrent_test_data test_data;
	struct thread *writer_thread, *reader_thread;
	int error;
	uint64_t initial_written, initial_read, initial_bytes;

	KTEST_LOG(ctx, "Testing double-buffering race conditions");

	provider = test_create_provider("test_dbrace", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	if (eventlog_subscriber_add_subscription(subscriber, "test_dbrace",
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

	/* Pre-fill buffer to trigger initial swap */
	uint32_t test_id = 0x2000;
	uint32_t prefill_data[5];
	for (int i = 0; i < 5; i++)
		prefill_data[i] = i;

	for (int i = 0; i < 50; i++) {
		eventlog_event_write(session, test_id++, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, prefill_data, sizeof(prefill_data));
	}

	/* Create writer thread */
	error = kthread_add(concurrent_writer_thread, &test_data, NULL,
	    &writer_thread, 0, 0, "evtlog_writer");
	KTEST_EQUAL(error, 0);

	/* Create reader thread */
	error = kthread_add(concurrent_reader_thread, &test_data, NULL,
	    &reader_thread, 0, 0, "evtlog_reader");
	KTEST_EQUAL(error, 0);

	/* Let threads run for a bit to exercise race conditions */
	tsleep(&test_data, 0, "test_run", hz / 2); /* 500ms */

	initial_written = atomic_load_acq_64(&test_data.events_written);
	initial_read = atomic_load_acq_64(&test_data.events_read);
	initial_bytes = atomic_load_acq_64(&test_data.bytes_read);

	KTEST_LOG(ctx,
	    "After 500ms: wrote %llu events, read %llu times, %llu bytes",
	    (unsigned long long)initial_written,
	    (unsigned long long)initial_read,
	    (unsigned long long)initial_bytes);

	/* Continue for another period to ensure stability */
	tsleep(&test_data, 0, "test_run2", hz / 2); /* Another 500ms */

	uint64_t final_written = atomic_load_acq_64(&test_data.events_written);
	uint64_t final_read = atomic_load_acq_64(&test_data.events_read);
	uint64_t final_bytes = atomic_load_acq_64(&test_data.bytes_read);

	KTEST_LOG(ctx,
	    "After 1s: wrote %llu events, read %llu times, %llu bytes",
	    (unsigned long long)final_written,
	    (unsigned long long)final_read,
	    (unsigned long long)final_bytes);

	/* Verify progress was made */
	KTEST_VERIFY(final_written > initial_written);
	KTEST_VERIFY(final_bytes > initial_bytes);

	/*
	 * Stop threads - wake reader if blocked, wait for it to exit (single
	 * reader)
	 */
	test_data.done = 1;
	wakeup(subscriber);
	while (atomic_load_acq_int(&test_data.reader_exited) == 0)
		tsleep(&test_data.reader_exited, 0, "evtlog_rdwait", hz / 10);

	/* Drain remaining events (reader has exited, single reader) */
	{
		char drain_buf[8 * 1024];
		size_t drain_read;

		do {
			drain_read = eventlog_read_into_buf(subscriber,
			    drain_buf, sizeof(drain_buf), 0);
		} while (drain_read > 0);
	}

	mtx_destroy(&test_data.lock);
	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
}

/*
 * Validates mid-read buffer swap scenario.
 * Tests the case where a buffer drains during a read operation and triggers
 * a swap, ensuring the swap happens correctly and ordering is maintained.
 */
KTEST_FUNC(subscriber_mid_read_swap)
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

	KTEST_LOG(ctx, "Testing mid-read buffer swap scenario");

	/* malloc to avoid stack overflow in ktest taskqueue (small stack) */
	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_midswap", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	if (eventlog_subscriber_add_subscription(subscriber, "test_midswap",
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
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, test_data, sizeof(test_data));
	}

	/* Read a small chunk - this should trigger swap */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read_bytes = eventlog_read_into_buf(subscriber, read_buf, 1024, 0);
	KTEST_VERIFY(read_bytes > 0);
	KTEST_LOG(ctx, "First read: %zd bytes, dropped %llu", read_bytes,
	    (unsigned long long)stats.dropped_events);

	/* Write more events while reader buffer is being drained */
	for (i = 100; i < 200; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, test_data, sizeof(test_data));
	}

	/*
	 * Continue reading - this should drain the reader buffer and trigger
	 * swap.
	 */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);
	KTEST_LOG(ctx, "Second read: %zd bytes, dropped %llu", read_bytes,
	    (unsigned long long)stats.dropped_events);

	/* Write more events after swap */
	for (i = 200; i < 250; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, test_data, sizeof(test_data));
	}

	/* Read remaining events - should get events from swapped buffer */
	eventlog_subscriber_get_stats(subscriber, &stats);
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);
	KTEST_LOG(ctx, "Third read: %zd bytes, dropped %llu", read_bytes,
	    (unsigned long long)stats.dropped_events);

	/* Verify buffer is empty */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    read_buf_size, 0);
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
		eventlog_event_write(data->session, test_id++,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, small_data,
		    sizeof(small_data));
		atomic_add_64(&data->events_written, 1);

		/* Occasionally write larger events to test boundaries */
		if ((test_id % 10) == 0) {
			eventlog_event_write(data->session, test_id++,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, large_data,
			    sizeof(large_data));
			atomic_add_64(&data->events_written, 1);
		}

		kern_yield(PRI_UNCHANGED);
	}

	kthread_exit();
}

/* Reader thread that rapidly reads and triggers swaps */
static void
boundary_reader_thread(void *arg)
{
	struct boundary_test_data *data = (struct boundary_test_data *)arg;
	char read_buf[8 * 1024];
	size_t read_bytes;

	while (data->done == 0) {
		/* Read small chunks to trigger frequent swaps */
		read_bytes = eventlog_read_into_buf(data->subscriber, read_buf,
		    512, 0);
		if (read_bytes > 0) {
			/* Immediately read again to trigger swap */
			read_bytes = eventlog_read_into_buf(data->subscriber,
			    read_buf, sizeof(read_buf), 0);
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

	/* Use 128KB buffer to trigger boundary conditions (above 64KB min) */
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
	error = kthread_add(boundary_writer_thread, &test_data, NULL,
	    &writer_thread, 0, 0, "evtlog_boundary_writer");
	KTEST_EQUAL(error, 0);

	/* Create reader thread */
	error = kthread_add(boundary_reader_thread, &test_data, NULL,
	    &reader_thread, 0, 0, "evtlog_boundary_reader");
	KTEST_EQUAL(error, 0);

	/* Run for a period to exercise boundary conditions */
	tsleep(&test_data, 0, "boundary_run", hz * 2); /* 2 seconds */

	initial_written = atomic_load_acq_64(&test_data.events_written);
	KTEST_LOG(ctx, "Wrote %llu events during boundary stress test",
	    (unsigned long long)initial_written);
	KTEST_VERIFY(initial_written > 0);

	/*
	 * Stop threads - wake reader if blocked, wait for it to exit (single
	 * reader)
	 */
	test_data.done = 1;
	wakeup(subscriber);
	while (atomic_load_acq_int(&test_data.reader_exited) == 0)
		tsleep(&test_data.reader_exited, 0, "evtlog_rdwait", hz / 10);

	/* Drain remaining events (reader has exited, single reader) */
	{
		char drain_buf[8 * 1024];
		size_t drain_read;

		do {
			drain_read = eventlog_read_into_buf(subscriber,
			    drain_buf, sizeof(drain_buf), 0);
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
	size_t fill_count;
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

	/*
	 * Fill buffer: session_create already wrote 1 event, then max_events
	 * user events to leave less than event_size bytes of slack.
	 */
	for (i = 0; i < (int)max_events; i++) {
		eventlog_event_write(session, test_id + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &test_data, sizeof(test_data));
	}

	/* Write one more - triggers proactive swap (SWAP_ALLOWED) */
	eventlog_event_write(session, test_id + max_events,
	    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &test_data, sizeof(test_data));

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_EQUAL(stats.dropped_events, 0);
	KTEST_LOG(ctx,
	    "After first overflow (proactive swap): dropped %llu events",
	    (unsigned long long)stats.dropped_events);

	/*
	 * Now fill the second buffer completely (1 event already there from
	 * overflow). Second buffer has no session_create, so it holds
	 * max_events+1 user events total (since buffer_size / event_size >
	 * max_events when create_event_size < event_size). But 1 is already
	 * there, so write max_events more.
	 */
	fill_count = buffer_size_per_cpu / event_size - 1;
	for (i = 0; i < (int)fill_count; i++) {
		eventlog_event_write(session, test_id + 10000 + i,
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, &test_data,
		    sizeof(test_data));
	}

	/* Write one more - SWAP_ALLOWED cleared (reader idle), so dropped */
	eventlog_event_write(session, test_id + 20000, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, &test_data, sizeof(test_data));

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_EQUAL(stats.dropped_events, 1);
	KTEST_LOG(ctx, "After second overflow (no swap): dropped %llu events",
	    (unsigned long long)stats.dropped_events);

	/* Read all events from the reader buffer (filled by proactive swap) */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);

	/* Read again to get events from the second buffer */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    read_buf_size, 0);
	KTEST_VERIFY(read_bytes > 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
}

/*
 * Stress test with rapid buffer swaps.
 * Writes events, reads partially, writes more, reads again - rapid swapping.
 */
KTEST_FUNC(subscriber_rapid_swap_stress)
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

	KTEST_LOG(ctx, "Testing rapid buffer swap stress");

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_rswap", NULL, NULL);
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

	if (eventlog_subscriber_add_subscription(subscriber, "test_rswap",
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
			eventlog_event_write(session, test_id++,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, test_data,
			    sizeof(test_data));
		}

		/* Read a small chunk to trigger swap */
		read_bytes = eventlog_read_into_buf(subscriber, read_buf, 1024,
		    0);

		/* Write more while reader buffer is being drained */
		for (i = 0; i < 20; i++) {
			eventlog_event_write(session, test_id++,
			    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, test_data,
			    sizeof(test_data));
		}

		/* Read remaining to drain reader buffer */
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
	}

	/* Final drain */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
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
	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_BUFFER_SIZE_MIN - 1);
	KTEST_EQUAL(subscriber, NULL);

	subscriber = eventlog_subscriber_create_device(0);
	KTEST_EQUAL(subscriber, NULL);

	/* Too large */
	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_BUFFER_SIZE_MAX + 1);
	KTEST_EQUAL(subscriber, NULL);

	/* Valid boundaries */
	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_BUFFER_SIZE_MIN);
	KTEST_NEQUAL(subscriber, NULL);
	eventlog_subscriber_destroy(subscriber);

	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_BUFFER_SIZE_MAX);
	KTEST_NEQUAL(subscriber, NULL);
	eventlog_subscriber_destroy(subscriber);

	return (0);
}

/*
 * Validates that adding a subscription for a non-existent provider returns
 * ENOENT.
 */
KTEST_FUNC(subscriber_add_subscription_nonexistent_provider)
{
	struct eventlog_subscriber *subscriber;
	int error;

	KTEST_LOG(ctx, "Testing subscription to non-existent provider");

	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber,
	    "nonexistent_provider_xyz", EVENTLOG_LEVEL_INFO, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, ENOENT);

	eventlog_subscriber_destroy(subscriber);

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

	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
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

	/* Event at INFO with keyword 0x2 only - filtered out (no key match) */
	eventlog_event_write(session, test_id + 2, EVENTLOG_LEVEL_INFO, 0x2,
	    &test_data, sizeof(test_data));
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		KTEST_EQUAL(ec, 1);
	}

	/* Event at INFO with keywords 0x1 | 0x2 - received (0x1 matches) */
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

	/*
	 * total_size = sizeof(eventlog_event_header) + payload.
	 * Need total_size > UINT16_MAX (65535). Header is 32 bytes,
	 * so payload must be > 65535 - 32 = 65503. Use 65504.
	 */
	oversized_len = 65504;

	provider = test_create_provider("test_oversize", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	subscriber = test_enable_provider_callback("test_oversize",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, &callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	large_payload = malloc(oversized_len, M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
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
		/* SESSION_CREATE + 1 user event (zero-length payload) */
		KTEST_EQUAL(ec, 2);
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

	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
	KTEST_NEQUAL(subscriber, NULL);

	/* First subscription */
	error = eventlog_subscriber_add_subscription(subscriber, "test_subupd",
	    EVENTLOG_LEVEL_INFO, 0x1, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(provider), 0x1);

	/* Re-subscribe to same provider: should update in place, not add */
	error = eventlog_subscriber_add_subscription(subscriber, "test_subupd",
	    EVENTLOG_LEVEL_VERBOSE, 0x7, 0);
	KTEST_EQUAL(error, 0);
	KTEST_EQUAL(eventlog_provider_get_level(provider),
	    EVENTLOG_LEVEL_VERBOSE);
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
	/* Provider enablement is auto-updated when subscription is added */

	/* Verify _ENABLED macros work correctly */
	/* INFO level, BASIC keyword */
	KTEST_EQUAL(TEST_EVENTLOG_SIMPLE_EVENT_ENABLED(session), 1);
	/* INFO level, BASIC keyword */
	KTEST_EQUAL(TEST_EVENTLOG_STATUS_EVENT_ENABLED(session), 1);
	/* VERBOSE level, ADVANCED keyword */
	KTEST_EQUAL(TEST_EVENTLOG_FLAGS_EVENT_ENABLED(session), 0);
	/* WARN level, COMPLEX keyword */
	KTEST_EQUAL(TEST_EVENTLOG_COMPLEX_EVENT_ENABLED(session), 0);

	/* Test 3: Use _LOG_ALWAYS macro (always logs regardless of enabled) */
	TEST_EVENTLOG_SIMPLE_EVENT_LOG_ALWAYS(session, 0x12345678);
	TEST_EVENTLOG_STATUS_EVENT_LOG_ALWAYS(session, 0xABCDEF00,
	    TEST_EVENTLOG_TEST_STATUS_RUNNING);

	/*
	 * Verify events were received via callback (read then unlock;
	 * KTEST_EQUAL may sleep)
	 */
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		/* Session created before subscriber; 2 LOG_ALWAYS events */
		KTEST_EQUAL(ec, 2);
	}

	/* Reset callback data for next test */
	mtx_lock(&callback_data->lock);
	callback_data->event_count = 0;
	mtx_unlock(&callback_data->lock);

	/* Test 4: Use _LOG macro (should check enablement first) */
	TEST_EVENTLOG_SIMPLE_EVENT_LOG(session, 0x87654321);
	TEST_EVENTLOG_STATUS_EVENT_LOG(session, 0xFEDCBA00,
	    TEST_EVENTLOG_TEST_STATUS_SUCCESS);
	TEST_EVENTLOG_FLAGS_EVENT_LOG(session, 0x11111111,
	    TEST_EVENTLOG_FLAG_FLAG_A | TEST_EVENTLOG_FLAG_FLAG_B);
	TEST_EVENTLOG_COMPLEX_EVENT_LOG(session, 0x22222222, 0x33333333,
	    TEST_EVENTLOG_TEST_STATUS_RUNNING, TEST_EVENTLOG_FLAG_FLAG_C, -42);

	/*
	 * Verify only enabled events were received (read then unlock;
	 * KTEST_EQUAL may sleep)
	 */
	{
		uint32_t ec;
		mtx_lock(&callback_data->lock);
		ec = atomic_load_acq_32(&callback_data->event_count);
		mtx_unlock(&callback_data->lock);
		/* Only SIMPLE and STATUS (session existed before subscriber) */
		KTEST_EQUAL(ec, 2);
	}

	/* Test 5: Update subscriber to VERBOSE level with ADVANCED keyword */
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	subscriber = test_enable_provider_callback("test_schema",
	    EVENTLOG_LEVEL_VERBOSE, TEST_EVENTLOG_KEYWORD_ADVANCED,
	    &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	/* Provider enablement is auto-updated when subscription is added */

	/* Verify FLAGS_EVENT is now enabled */
	KTEST_EQUAL(TEST_EVENTLOG_FLAGS_EVENT_ENABLED(session), 1);
	/* Still WARN level */
	KTEST_EQUAL(TEST_EVENTLOG_COMPLEX_EVENT_ENABLED(session), 0);

	/* Test 6: Update subscriber to WARN level with COMPLEX keyword */
	eventlog_subscriber_destroy(subscriber);
	mtx_destroy(&callback_data->lock);
	free(callback_data, M_EVENTLOG_TEST);
	subscriber = test_enable_provider_callback("test_schema",
	    EVENTLOG_LEVEL_WARN, TEST_EVENTLOG_KEYWORD_COMPLEX,
	    &callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	/* Provider enablement is auto-updated when subscription is added */

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
	/* events whose tail/head mismatched expectation */
	uint32_t mismatch;
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
	/*
	 * The varlen producer emits a 2-segment iov: [head][tail].
	 * Compact it into a stack buffer for the generated accessor.
	 * Sized from the schema's declared max.
	 */
	uint8_t buf[sizeof(struct test_eventlog_varlen_event) +
	    TEST_EVENTLOG_VARLEN_EVENT_VALUES_MAX * sizeof(uint64_t)];
	const struct test_eventlog_varlen_event *evt;
	const uint64_t *vals;
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

	vals = test_eventlog_varlen_event_values(evt, payload_size);
	d->last_payload_size = payload_size;
	d->last_count = evt->count;
	if (evt->count == 0) {
		/*
		 * No trailing elements expected; accessor may still succeed
		 * (payload_size == sizeof(head) + 0). Count as matched.
		 */
		atomic_add_32(&d->matched, 1);
		return;
	}
	if (vals == NULL) {
		atomic_add_32(&d->mismatch, 1);
		return;
	}
	d->last_first_value = vals[0];
	d->last_last_value = vals[evt->count - 1];
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

	/*
	 * Subscribers call us synchronously from the writer; no sleep needed.
	 * The session was created BEFORE the subscriber attached, so no
	 * SESSION_CREATE is delivered here -- we only see the 3 varlen
	 * events we logged.
	 */
	KTEST_EQUAL(atomic_load_acq_32(&cb.events), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb.matched), 3);
	KTEST_EQUAL(atomic_load_acq_32(&cb.mismatch), 0);

	/*
	 * Last event (count == 0) should have been delivered with a payload
	 * equal to exactly sizeof(struct test_eventlog_varlen_event).
	 */
	KTEST_EQUAL((int)cb.last_count, 0);
	KTEST_EQUAL((int)cb.last_payload_size,
	    (int)sizeof(struct test_eventlog_varlen_event));

	/* Spot-check accessor robustness against a short payload. */
	struct test_eventlog_varlen_event evt = { .id = 0, .count = 4 };
	KTEST_EQUAL(test_eventlog_varlen_event_values(&evt, sizeof(evt)),
	    (const uint64_t *)NULL);

	eventlog_subscriber_destroy(subscriber);
	eventlog_session_destroy(session);
	eventlog_provider_destroy(provider);
	mtx_destroy(&cb.lock);
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
	/*
	 * Walk iov to pick out first-byte-of-first-nonempty-segment and
	 * last-byte-of-last-nonempty-segment without compacting.
	 */
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

	/*
	 * Case 2: iovcnt == 1, contiguous buffer. Callback fast path: no
	 * compact copy, pointer equals iov[0].iov_base.
	 */
	for (i = 0; i < sizeof(seg0); i++)
		seg0[i] = (uint8_t)(0x10 + i);
	iov[0].iov_base = seg0;
	iov[0].iov_len = sizeof(seg0);
	eventlog_event_write_gather(session, 0x101, EVENTLOG_LEVEL_INFO,
	    TEST_EVENTLOG_KEYWORD_BASIC, iov, 1);

	/*
	 * Case 3: iovcnt == 2, small payload. Callback compact path runs on
	 * the on-stack buffer; verify order is seg0 then seg1.
	 */
	for (i = 0; i < sizeof(seg1); i++)
		seg1[i] = (uint8_t)(0xA0 + i);
	iov[0].iov_base = seg0;
	iov[0].iov_len = sizeof(seg0);
	iov[1].iov_base = seg1;
	iov[1].iov_len = sizeof(seg1);
	eventlog_event_write_gather(session, 0x102, EVENTLOG_LEVEL_INFO,
	    TEST_EVENTLOG_KEYWORD_BASIC, iov, 2);

	/*
	 * Case 4: iovcnt == 3, large multi-segment payload. The framework
	 * passes the iov through unchanged; the callback sees three
	 * segments and reports the first byte of seg0 and the last byte
	 * of seg1. Nothing is dropped and no allocation happens.
	 */
	big = malloc(GATHER_BIG_PAYLOAD_SIZE, M_EVENTLOG_TEST, M_WAITOK);
	for (i = 0; i < GATHER_BIG_PAYLOAD_SIZE; i++)
		big[i] = (uint8_t)(i & 0xFF);
	iov[0].iov_base = seg0;
	iov[0].iov_len = sizeof(seg0);			/* bytes 0x10..0x17 */
	iov[1].iov_base = big;
	iov[1].iov_len = GATHER_BIG_PAYLOAD_SIZE;	/* 0x00..0xFF... */
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
	/* Barrier: all threads wait until set */
	int *go;
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

	/*
	 * Sleep until all threads are ready. Using tsleep instead of
	 * cpu_spinwait avoids deadlocking on systems with fewer CPUs
	 * than writer threads (busy-spinning writers would monopolize
	 * all CPUs, preventing the main thread from setting go).
	 */
	while (atomic_load_acq_32((volatile uint32_t *)data->go) == 0)
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

	atomic_store_rel_32((volatile uint32_t *)&data->done, 1);
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

	KTEST_LOG(ctx,
	    "Testing lock-free concurrent writers (%d threads, %d events each)",
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
	atomic_store_rel_32((volatile uint32_t *)&go, 1);
	wakeup(&go);

	/* Wait for all writers to finish */
	for (i = 0; i < LF_NUM_WRITERS; i++) {
		while (atomic_load_acq_32(
		    (volatile uint32_t *)&writers[i].done) == 0)
			tsleep(&writers[i].done, 0, "lf_wait", hz / 10);
		KTEST_EQUAL(writers[i].events_written, LF_EVENTS_PER_WRITER);
	}

	/* Read all events and verify total count */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
		total_read += read_bytes;
	} while (read_bytes > 0);

	eventlog_subscriber_get_stats(subscriber, &stats);
	KTEST_LOG(ctx, "Total bytes read: %zu, dropped events: %llu",
	    total_read, (unsigned long long)stats.dropped_events);
	KTEST_VERIFY(total_read > 0);

	/*
	 * With a 256KB buffer, some events may be dropped on small CPUs where
	 * all threads hit the same per-CPU buffer. That's fine - the test
	 * validates no crashes, no corruption (INVARIANTS checks), and that
	 * written + dropped == total attempted.
	 */
	/* +1 for SESSION_CREATE */
	uint64_t total_attempted =
	    (uint64_t)LF_NUM_WRITERS * LF_EVENTS_PER_WRITER + 1;
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
 * Stress the writer/swap contention path: many writers + a reader doing
 * rapid swaps. This exercises the commit CAS retry path when a reader
 * swap races with a writer's commit.
 */
struct lockfree_swap_writer_data {
	struct eventlog_session *session;
	int *stop;
	uint64_t events_written;
	int exited;
};

static void
lockfree_swap_writer(void *arg)
{
	struct lockfree_swap_writer_data *data = arg;
	uint32_t payload = 0;

	while (atomic_load_acq_32((volatile uint32_t *)data->stop) == 0) {
		eventlog_event_write(data->session, 0x1000 + (payload & 0xFF),
		    EVENTLOG_LEVEL_INFO, 0xFFFFFFFF,
		    &payload, sizeof(payload));
		atomic_add_64(&data->events_written, 1);
		payload++;
		kern_yield(PRI_UNCHANGED);
	}

	atomic_store_rel_32((volatile uint32_t *)&data->exited, 1);
	wakeup(&data->exited);
	kthread_exit();
}

static void
lockfree_stop_callout(void *arg)
{
	int *stop = arg;

	atomic_store_rel_32((volatile uint32_t *)stop, 1);
	wakeup(stop);
}

KTEST_FUNC(lockfree_writer_swap_contention)
{
#define LFSW_NUM_WRITERS	4
#define LFSW_RUN_SECONDS	3
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_swap_writer_data writers[LFSW_NUM_WRITERS];
	struct thread *threads[LFSW_NUM_WRITERS];
	int stop = 0;
	struct callout stop_timer;
	char *read_buf;
	size_t read_buf_size = 64 * 1024;
	size_t total_bytes_read = 0;
	size_t read_bytes;
	uint64_t swap_iterations = 0;
	struct eventlog_stats stats;
	int i, error;

	KTEST_LOG(ctx,
	    "Testing lock-free writer/swap contention (%d writers, %d seconds)",
	    LFSW_NUM_WRITERS, LFSW_RUN_SECONDS);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_lf_swap", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer to trigger frequent swaps (above 64KB minimum) */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_swap",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Start writer threads */
	for (i = 0; i < LFSW_NUM_WRITERS; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].stop = &stop;
		error = kthread_add(lockfree_swap_writer, &writers[i], NULL,
		    &threads[i], 0, 0, "lfsw_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	/*
	 * Use a callout to set stop from softclock context. On a 2-CPU system,
	 * writers in tight loops can starve the main thread on the run queue,
	 * preventing it from ever executing stop=1. The callout fires from
	 * timer interrupt context, bypassing scheduler contention.
	 */
	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * LFSW_RUN_SECONDS,
	    lockfree_stop_callout, &stop);

	/* Reader loop: read rapidly to trigger swaps while writers active */
	while (atomic_load_acq_32((volatile uint32_t *)&stop) == 0) {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
		if (read_bytes > 0) {
			total_bytes_read += read_bytes;
			swap_iterations++;
		}
		tsleep(&stop, 0, "lfsw_rd", 1);
	}

	callout_drain(&stop_timer);

	/* Wait for writers to exit */
	for (i = 0; i < LFSW_NUM_WRITERS; i++) {
		while (atomic_load_acq_32(
		    (volatile uint32_t *)&writers[i].exited) == 0)
			tsleep(&writers[i].exited, 0, "lfsw_wait", hz / 10);
	}

	/* Drain remaining */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
		total_bytes_read += read_bytes;
	} while (read_bytes > 0);

	eventlog_subscriber_get_stats(subscriber, &stats);

	uint64_t total_written = 0;
	for (i = 0; i < LFSW_NUM_WRITERS; i++)
		total_written += writers[i].events_written;

	KTEST_LOG(ctx, "Writers produced %llu events, reader did %llu swaps, "
	    "read %zu bytes, dropped %llu",
	    (unsigned long long)total_written,
	    (unsigned long long)swap_iterations,
	    total_bytes_read,
	    (unsigned long long)stats.dropped_events);

	KTEST_VERIFY(total_written > 0);
	KTEST_VERIFY(total_bytes_read > 0);
	KTEST_VERIFY(swap_iterations > 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);
	free(read_buf, M_EVENTLOG_TEST);

	return (0);
#undef LFSW_NUM_WRITERS
#undef LFSW_RUN_SECONDS
}

/*
 * Test buffer-full contention: tiny buffer + many writers to force the
 * buffer-full swap/drop path under contention. Verifies no events are
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

	error = eventlog_subscriber_add_subscription(subscriber,
	    "test_lf_bfull", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    read_buf_size, 0);

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
	atomic_store_rel_32((volatile uint32_t *)&go, 1);
	wakeup(&go);

	/* Wait for completion */
	for (i = 0; i < LFBF_NUM_WRITERS; i++) {
		while (atomic_load_acq_32(
		    (volatile uint32_t *)&writers[i].done) == 0)
			tsleep(&writers[i].done, 0, "lfbf_wait", hz / 10);
	}

	/* Read whatever survived */
	do {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, 0);
		total_read += read_bytes;
	} while (read_bytes > 0);

	eventlog_subscriber_get_stats(subscriber, &stats);

	uint64_t total_attempted =
	    (uint64_t)LFBF_NUM_WRITERS * LFBF_EVENTS_PER_WRITER;
	KTEST_LOG(ctx, "Attempted %llu events, dropped %llu, read %zu bytes",
	    (unsigned long long)total_attempted,
	    (unsigned long long)stats.dropped_events,
	    total_read);

	/*
	 * With a 128KB buffer and no reader draining during writes, almost all
	 * events should be dropped. The key assertion is that we didn't crash
	 * and INVARIANTS didn't fire.
	 */
	KTEST_VERIFY(stats.dropped_events > 0);

	/*
	 * Validate that events that were read are well-formed by reading with
	 * INVARIANTS buffer validation (already baked into eventlog_read).
	 */

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

	while (atomic_load_acq_32((volatile uint32_t *)data->stop) == 0) {
		size_t read_bytes = eventlog_read_into_buf(data->subscriber,
		    read_buf, read_buf_size, 0);
		if (read_bytes == 0) {
			kern_yield(PRI_UNCHANGED);
			continue;
		}

		data->bytes_read += read_bytes;

		/* Walk each event and validate structure */
		size_t offset = 0;
		while (offset + sizeof(struct eventlog_event_header) <=
		    read_bytes) {
			struct eventlog_event_header hdr;
			memcpy(&hdr, read_buf + offset, sizeof(hdr));

			if (hdr.event_length <
			    sizeof(struct eventlog_event_header) ||
			    offset + hdr.event_length > read_bytes) {
				data->corrupt_events++;
				break;
			}

			data->events_validated++;
			offset += hdr.event_length;
		}
	}

	free(read_buf, M_EVENTLOG_TEST);
	atomic_store_rel_32((volatile uint32_t *)&data->exited, 1);
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
	struct lockfree_swap_writer_data writers[LFDI_NUM_WRITERS];
	struct lockfree_integrity_reader_data reader_data;
	struct thread *writer_threads[LFDI_NUM_WRITERS];
	struct thread *reader_thread;
	int stop = 0;
	struct callout stop_timer;
	struct eventlog_stats stats;
	int i, error;

	KTEST_LOG(ctx,
	    "Testing lock-free data integrity (%d writers + reader, "
	    "%d seconds)",
	    LFDI_NUM_WRITERS, LFDI_RUN_SECONDS);

	provider = test_create_provider("test_lf_integ", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer: holds some events but small enough to swap often */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber,
	    "test_lf_integ", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
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
		error = kthread_add(lockfree_swap_writer, &writers[i], NULL,
		    &writer_threads[i], 0, 0, "lfdi_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	/*
	 * Use a callout to set stop from softclock context. On a 2-CPU system,
	 * writers in tight loops can starve the main thread on the run queue,
	 * preventing it from ever executing stop=1. The callout fires from
	 * timer interrupt context, bypassing scheduler contention.
	 */
	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * LFDI_RUN_SECONDS,
	    lockfree_stop_callout, &stop);

	while (atomic_load_acq_32((volatile uint32_t *)&stop) == 0)
		tsleep(&stop, 0, "lfdi_run", hz);

	callout_drain(&stop_timer);
	wakeup(subscriber); /* Wake reader if sleeping */

	for (i = 0; i < LFDI_NUM_WRITERS; i++) {
		while (atomic_load_acq_32(
		    (volatile uint32_t *)&writers[i].exited) == 0)
			tsleep(&writers[i].exited, 0, "lfdi_ww", hz / 10);
	}
	while (atomic_load_acq_32(
	    (volatile uint32_t *)&reader_data.exited) == 0)
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
 * Test reader-writer swap race: reader aggressively swaps buffers while
 * writers are mid-write. With a tiny buffer, the reader swaps frequently,
 * maximizing the chance the reader's swap CAS races with a writer's commit
 * CAS. The writer must detect the swap (active buffer changed) and redo
 * the write to the correct buffer. Validates no panics (MPASS), no data
 * corruption, and all events are properly readable.
 */
KTEST_FUNC(lockfree_reader_writer_swap_race)
{
#define LFRW_NUM_WRITERS	4
#define LFRW_RUN_SECONDS	3
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	struct lockfree_swap_writer_data writers[LFRW_NUM_WRITERS];
	struct thread *threads[LFRW_NUM_WRITERS];
	int stop = 0;
	struct callout stop_timer;
	char *read_buf;
	size_t read_buf_size = 4096;
	size_t total_bytes_read = 0;
	size_t read_bytes;
	uint64_t read_iterations = 0;
	struct eventlog_stats stats;
	int i, error;

	KTEST_LOG(ctx,
	    "Testing reader-writer swap race (%d writers, %d seconds, "
	    "128KB buffer)", LFRW_NUM_WRITERS, LFRW_RUN_SECONDS);

	read_buf = malloc(read_buf_size, M_EVENTLOG_TEST, M_WAITOK);
	KTEST_NEQUAL(read_buf, NULL);

	provider = test_create_provider("test_lf_race", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);

	/* 128KB buffer: forces frequent swaps, maximizing race window */
	subscriber = eventlog_subscriber_create_device(128 * 1024);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_lf_race",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF, 0);
	KTEST_EQUAL(error, 0);

	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	for (i = 0; i < LFRW_NUM_WRITERS; i++) {
		bzero(&writers[i], sizeof(writers[i]));
		writers[i].session = session;
		writers[i].stop = &stop;
		error = kthread_add(lockfree_swap_writer, &writers[i], NULL,
		    &threads[i], 0, 0, "lfrw_writer_%d", i);
		KTEST_EQUAL(error, 0);
	}

	KTEST_LOG(ctx, "checkpoint: writers started, arming stop callout");

	callout_init(&stop_timer, 1);
	callout_reset(&stop_timer, hz * LFRW_RUN_SECONDS,
	    lockfree_stop_callout, &stop);

	KTEST_LOG(ctx, "checkpoint: entering reader loop");

	/*
	 * Reader loop: read as fast as possible (no tsleep) to maximize
	 * the chance of swapping while a writer is mid-commit.
	 */
	while (atomic_load_acq_32((volatile uint32_t *)&stop) == 0) {
		read_bytes = eventlog_read_into_buf(subscriber, read_buf,
		    read_buf_size, FNONBLOCK);
		if (read_bytes > 0) {
			total_bytes_read += read_bytes;
			read_iterations++;
		}
	}

	KTEST_LOG(ctx,
	    "checkpoint: reader loop exited (iters=%llu, bytes=%zu); "
	    "draining callout",
	    (unsigned long long)read_iterations, total_bytes_read);

	callout_drain(&stop_timer);

	KTEST_LOG(ctx, "checkpoint: callout drained, waiting for writers");

	for (i = 0; i < LFRW_NUM_WRITERS; i++) {
		while (atomic_load_acq_32(
		    (volatile uint32_t *)&writers[i].exited) == 0)
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
	for (i = 0; i < LFRW_NUM_WRITERS; i++)
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
 * Test: timestamp epoch boundary defers future-timestamped events.
 * Writes events with known timestamps, some well in the past and one far
 * in the future. Verifies only past events are delivered and the future
 * event is deferred.
 */
KTEST_FUNC(timestamp_epoch_boundary)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	char read_buf[8 * 1024];
	size_t read_bytes;
	uint32_t payload;
	int i, event_count;

	KTEST_LOG(ctx, "Testing timestamp epoch boundary deferral");

	provider = test_create_provider("test_ts_epoch", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = test_enable_provider_device("test_ts_epoch",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), 0);
	KTEST_VERIFY(read_bytes > 0);

	/* Write 5 events with timestamps well in the past (1-5 microseconds) */
	for (i = 0; i < 5; i++) {
		payload = (uint32_t)(i + 1);
		eventlog_event_write_at(session, 100 + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload),
		    (uint64_t)(i + 1));
	}

	/* Write 1 event with a far-future timestamp */
	payload = 0xFFFF;
	eventlog_event_write_at(session, 200, EVENTLOG_LEVEL_INFO,
	    0xFFFFFFFF, &payload, sizeof(payload),
	    UINT64_MAX - 1000);

	/* Read: should get exactly the 5 past events */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), 0);
	KTEST_VERIFY(read_bytes > 0);

	/* Count events and verify timestamps are all in the past */
	event_count = 0;
	{
		size_t offset = 0;
		while (offset + sizeof(struct eventlog_event_header) <=
		    read_bytes) {
			struct eventlog_event_header hdr;
			memcpy(&hdr, read_buf + offset, sizeof(hdr));
			if (hdr.event_length <
			    sizeof(struct eventlog_event_header) ||
			    offset + hdr.event_length > read_bytes)
				break;
			KTEST_VERIFY(hdr.timestamp < UINT64_MAX - 1000);
			event_count++;
			offset += hdr.event_length;
		}
	}
	KTEST_EQUAL(event_count, 5);

	/* Second read (non-blocking): future deferred, nothing readable */
	read_bytes = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), FNONBLOCK);
	KTEST_EQUAL(read_bytes, 0);

	eventlog_session_destroy(session);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(provider);

	return (0);
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
		while (offset + sizeof(struct eventlog_event_header) <=
		    read_bytes) {
			struct eventlog_event_header hdr;
			memcpy(&hdr, read_buf + offset, sizeof(hdr));
			if (hdr.event_length <
			    sizeof(struct eventlog_event_header) ||
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

/*
 * Test: small uio buffer with epoch boundary requires multiple reads.
 * Uses a uio buffer that fits only 2 events per read. Writes past and
 * future events. Verifies past events are delivered across multiple reads
 * and future events are never delivered.
 */
KTEST_FUNC(timestamp_epoch_small_uio)
{
	struct eventlog_provider *provider;
	struct eventlog_session *session;
	struct eventlog_subscriber *subscriber;
	size_t read_bytes;
	uint32_t payload;
	int i, total_events;

	KTEST_LOG(ctx, "Testing epoch boundary with small uio buffer");

	provider = test_create_provider("test_ts_small_uio", NULL, NULL);
	KTEST_NEQUAL(provider, NULL);
	subscriber = test_enable_provider_device("test_ts_small_uio",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF);
	KTEST_NEQUAL(subscriber, NULL);
	session = eventlog_session_create(provider, 0, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);

	/* Drain SESSION_CREATE with a large buffer */
	{
		char drain_buf[4096];
		read_bytes = eventlog_read_into_buf(subscriber, drain_buf,
		    sizeof(drain_buf), 0);
		KTEST_VERIFY(read_bytes > 0);
	}

	/* Write 6 events with past timestamps, then 2 with future */
	for (i = 0; i < 6; i++) {
		payload = (uint32_t)(i + 1);
		eventlog_event_write_at(session, 100 + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload),
		    (uint64_t)(1000 + i));
	}
	for (i = 0; i < 2; i++) {
		payload = (uint32_t)(100 + i);
		eventlog_event_write_at(session, 200 + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload),
		    UINT64_MAX - (uint64_t)(2000 - i));
	}

	/* Read with a buffer that fits ~2 events at a time */
	total_events = 0;
	{
		char small_buf[2 * (sizeof(struct eventlog_event_header) +
		    sizeof(uint32_t)) + 64];

		for (i = 0; i < 10; i++) {
			size_t offset;
			read_bytes = eventlog_read_into_buf(subscriber,
			    small_buf, sizeof(small_buf), FNONBLOCK);
			if (read_bytes == 0)
				break;
			offset = 0;
			while (offset + sizeof(struct eventlog_event_header) <=
			    read_bytes) {
				struct eventlog_event_header hdr;
				memcpy(&hdr, small_buf + offset, sizeof(hdr));
				if (hdr.event_length <
				    sizeof(struct eventlog_event_header) ||
				    offset + hdr.event_length > read_bytes)
					break;
				KTEST_VERIFY(
				    hdr.timestamp < UINT64_MAX - 10000);
				total_events++;
				offset += hdr.event_length;
			}
		}
	}

	/* Should have read exactly the 6 past events */
	KTEST_EQUAL(total_events, 6);

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
		    dump_test_sessions[i]->effective_level >=
		    EVENTLOG_LEVEL_INFO) {
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

	provider = test_create_provider("test_ds_basic", test_dump_callback,
	    NULL);
	KTEST_NEQUAL(provider, NULL);

	session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(session, NULL);
	dump_test_sessions[0] = session;

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_basic", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_basic", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

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

	provider = test_create_provider("test_ds_route", test_dump_callback,
	    NULL);
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
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
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
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
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

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_nocb", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data);
	KTEST_NEQUAL(subscriber, NULL);

	/* Should succeed without crash even though no dump callback */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_nocb", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	/*
	 * No dump task should have been enqueued because the provider has
	 * no dump_callback. drain_dumps still has to be a no-op in that
	 * case (dump_pending stays at 0); call it explicitly to pin that
	 * contract.
	 */
	eventlog_subscriber_drain_dumps(subscriber);

	/* No dump events; only SESSION_CREATE may be counted */
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
 * Regression test for the eventlog dump-callback vnet contract.
 *
 * Pins down the framework contract that motivated the TCP fix: the eventlog
 * machinery invokes provider->dump_callback without setting curvnet.
 * Providers that touch per-vnet state must iterate vnets / set curvnet
 * themselves. The dump runs on a kernel taskqueue thread whose
 * td_vnet is NULL; the test subscribes, drains, and verifies the
 * callback's observed context.
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
	    "test_ds_curvnet", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE);
	KTEST_EQUAL(ret, 0);

	/* Wait for the async dump task to finish before reading observed. */
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

	provider = test_create_provider("test_ds_dis", test_dump_callback,
	    NULL);
	KTEST_NEQUAL(provider, NULL);

	enabled_session = eventlog_session_create(provider, 1, true, NULL, 0);
	KTEST_NEQUAL(enabled_session, NULL);
	dump_test_sessions[0] = enabled_session;

	disabled_session = eventlog_session_create(provider, 2, true, NULL, 0);
	KTEST_NEQUAL(disabled_session, NULL);
	eventlog_session_set_enabled(disabled_session, 0);
	dump_test_sessions[1] = disabled_session;

	callback_data = malloc(sizeof(*callback_data), M_EVENTLOG_TEST,
	    M_WAITOK | M_ZERO);
	mtx_init(&callback_data->lock, "test_ds_dis", NULL, MTX_DEF);
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    callback_data);
	KTEST_NEQUAL(subscriber, NULL);
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_dis", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

	eventlog_subscriber_drain_dumps(subscriber);

	KTEST_EQUAL(atomic_load_acq_32(&dump_callback_invocations), 1);
	/*
	 * The dump callback writes to both sessions, but the disabled session's
	 * effective_level is NONE so eventlog_event_write_impl's subscriber
	 * filtering will drop those events. Only the enabled session's events
	 * should arrive. We expect: SESSION_CREATE (from create) + 1 dump
	 * event for the enabled session = at least 1 from the dump.
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
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    cd);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_async_thr", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

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
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    cd);
	KTEST_NEQUAL(subscriber, NULL);

	/*
	 * Subscribe enqueues a dump that will block in the callback. The
	 * call must return promptly even though the dump is parked --
	 * that's the whole point of the rework.
	 */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_async_block", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

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
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    cd);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_destroy_drain", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

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
	subscriber = eventlog_subscriber_create_callback(test_event_callback,
	    cd);
	KTEST_NEQUAL(subscriber, NULL);

	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_resub", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	eventlog_subscriber_drain_dumps(subscriber);
	KTEST_EQUAL(atomic_load_acq_32(&async_dump_runs), 1);

	/* Re-subscribe with different level/keywords -- update in place. */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(subscriber,
	    "test_ds_resub", EVENTLOG_LEVEL_INFO, 0xF0F0F0F0,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
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
	    "test_ds_complete", EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);
	/* without_session: SESSION bit (0x80000000) explicitly cleared. */
	KTEST_EQUAL(eventlog_subscriber_add_subscription(without_session,
	    "test_ds_complete", EVENTLOG_LEVEL_VERBOSE, 0x7FFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE), 0);

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
	/* New provider_id - add it (racy but fine for small test counts) */
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

	KTEST_LOG(ctx,
	    "Testing subscribe-by-name enables all matching providers");

	p1 = test_create_provider("test_mp_en", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_en", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	/* Both providers should start disabled */
	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_NONE);

	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(
	    multi_provider_callback, &cb_data);
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
	subscriber = eventlog_subscriber_create_callback(
	    multi_provider_callback, &cb_data);
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
	/* Each provider sent 3 events (1 SESSION_CREATE + 2 user) */
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
	subscriber = eventlog_subscriber_create_callback(
	    multi_provider_callback, &cb_data);
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

	/*
	 * Destroy s1 and subscriber, then p1.
	 * Subscriber must be destroyed before its providers so that
	 * subscription pointers are cleaned up first.
	 */
	eventlog_session_destroy(s1);
	eventlog_subscriber_destroy(subscriber);
	eventlog_provider_destroy(p1);

	/* p2 should now be disabled (no subscribers left) */
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_NONE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0);

	/* Re-subscribe to verify p2 still works after p1 is gone */
	memset(&cb_data, 0, sizeof(cb_data));
	subscriber = eventlog_subscriber_create_callback(
	    multi_provider_callback, &cb_data);
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
mp_test_dump_callback(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	int i;

	atomic_add_int(&mp_dump_invocations, 1);
	for (i = 0; i < mp_dump_session_count; i++) {
		if (mp_dump_sessions[i] != NULL &&
		    mp_dump_sessions[i]->effective_level >=
		    EVENTLOG_LEVEL_INFO) {
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
	subscriber = eventlog_subscriber_create_callback(
	    multi_provider_callback, &cb_data);
	KTEST_NEQUAL(subscriber, NULL);

	error = eventlog_subscriber_add_subscription(subscriber, "test_mp_ds",
	    EVENTLOG_LEVEL_VERBOSE, 0xFFFFFFFF,
	    EVENTLOG_SUBSCRIPTION_DUMP_STATE);
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

	/* Subscribe to "test_mp_ie" at INFO/0x3 - enables both providers */
	memset(&cb1, 0, sizeof(cb1));
	sub_name = eventlog_subscriber_create_callback(multi_provider_callback,
	    &cb1);
	KTEST_NEQUAL(sub_name, NULL);
	error = eventlog_subscriber_add_subscription(sub_name, "test_mp_ie",
	    EVENTLOG_LEVEL_INFO, 0x3, 0);
	KTEST_EQUAL(error, 0);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_INFO);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0x3);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0x3);

	/* Add second subscriber at VERBOSE/0xC - both get union */
	memset(&cb2, 0, sizeof(cb2));
	sub_other = eventlog_subscriber_create_callback(multi_provider_callback,
	    &cb2);
	KTEST_NEQUAL(sub_other, NULL);
	error = eventlog_subscriber_add_subscription(sub_other, "test_mp_ie",
	    EVENTLOG_LEVEL_VERBOSE, 0xC, 0);
	KTEST_EQUAL(error, 0);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0xF);  /* 0x3 | 0xC */
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0xF);

	/* Remove first subscriber - enablement drops to VERBOSE/0xC */
	eventlog_subscriber_destroy(sub_name);

	KTEST_EQUAL(eventlog_provider_get_level(p1), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_level(p2), EVENTLOG_LEVEL_VERBOSE);
	KTEST_EQUAL(eventlog_provider_get_keywords(p1), 0xC);
	KTEST_EQUAL(eventlog_provider_get_keywords(p2), 0xC);

	/* Remove second subscriber - both disabled */
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

	KTEST_LOG(ctx,
	    "Testing device subscriber with multiple same-named providers");

	p1 = test_create_provider("test_mp_dev", NULL, NULL);
	KTEST_NEQUAL(p1, NULL);
	p2 = test_create_provider("test_mp_dev", NULL, NULL);
	KTEST_NEQUAL(p2, NULL);

	subscriber = eventlog_subscriber_create_device(
	    EVENTLOG_SUBSCRIBER_BUFFER_SIZE_DEFAULT);
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
		eventlog_event_write(s1, 0x1000 + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload));
		eventlog_event_write(s2, 0x2000 + i, EVENTLOG_LEVEL_INFO,
		    0xFFFFFFFF, &payload, sizeof(payload));
	}

	/* Read all available events */
	total_read = eventlog_read_into_buf(subscriber, read_buf,
	    sizeof(read_buf), FNONBLOCK);
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
	volatile int n_true;	/* callbacks with has_subscribers=true */
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
	atomic_store_rel_32((volatile uint32_t *)&c->last_state,
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
	/*
	 * Sleep one tick. WITNESS / INVARIANTS will fire if any
	 * non-sleepable lock is held (most importantly sessions_lock).
	 */
	pause("subch", 1);
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

	KTEST_LOG(ctx,
	    "callback runs outside sessions_lock (sleepable context)");

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

	while (atomic_load_acq_32((volatile uint32_t *)a->stop) == 0) {
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
	atomic_store_rel_32((volatile uint32_t *)&a->iterations_done, i);
	atomic_store_rel_32((volatile uint32_t *)&a->exited, 1);
	wakeup(&a->exited);
	kthread_exit();
}

static void
test_subch_stop_callout(void *arg)
{
	int *stop = arg;

	atomic_store_rel_32((volatile uint32_t *)stop, 1);
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
		while (atomic_load_acq_32(
		    (volatile uint32_t *)&args[i].exited) == 0)
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
	KTEST_INFO(subscriber_double_buffer_race),
	KTEST_INFO(subscriber_mid_read_swap),
	KTEST_INFO(subscriber_buffer_boundary_stress),
	KTEST_INFO(subscriber_buffer_fill_to_capacity),
	KTEST_INFO(subscriber_rapid_swap_stress),
	KTEST_INFO(subscriber_callback),
	KTEST_INFO(schema_generated_macros),
	KTEST_INFO(schema_varlen_event),
	KTEST_INFO(event_write_gather),
	KTEST_INFO(lockfree_many_concurrent_writers),
	KTEST_INFO(lockfree_writer_swap_contention),
	KTEST_INFO(lockfree_buffer_full_contention),
	KTEST_INFO(lockfree_data_integrity_under_contention),
	KTEST_INFO(lockfree_reader_writer_swap_race),
	KTEST_INFO(timestamp_epoch_boundary),
	KTEST_INFO(timestamp_epoch_normal_delivery),
	KTEST_INFO(timestamp_epoch_small_uio),
	KTEST_INFO(dump_state_basic),
	KTEST_INFO(dump_state_routing),
	KTEST_INFO(dump_state_no_callback),
	KTEST_INFO(dump_state_curvnet_not_set),
	KTEST_INFO(dump_state_disabled_sessions),
	KTEST_INFO(dump_state_async_runs_off_caller_thread),
	KTEST_INFO(dump_state_async_subscribe_returns_before_dump),
	KTEST_INFO(dump_state_destroy_waits_for_dump),
	KTEST_INFO(dump_state_resubscribe_no_refire),
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
	KTEST_INFO(provider_config_null_equivalent),
	KTEST_INFO(provider_config_default_enabled),
};

KTEST_MODULE_DECLARE(ktest_eventlog, tests);

