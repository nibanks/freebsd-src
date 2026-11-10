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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/eventlog.h>
#include <sys/eventlog_dev.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <sys/sysctl.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <zlib.h>
#include <sha256.h>

/*
 * Events are decoded at runtime from a provider "decode blob" (see
 * sys/sys/eventlog_decode.h) rather than from compiled-in generated C.
 */
#include "decode.h"

#include <libelog_user_symbols.h>
#include <libelog_source_lines.h>

#include "machine_metadata.h"

/* Room for a '|'-separated keyword-name list, NUL terminated. */
#define ELOG_KEYWORD_NAMES_MAX	128

struct subscription {
	char provider_name[EVENTLOG_PROVIDER_NAME_MAX];
	enum eventlog_level level;
	uint32_t keywords;
	/*
	 * Keyword names whose provider had not registered yet, so there was
	 * no decode blob to resolve them against.  The subscription goes in
	 * unfiltered; resolve_pending_keywords() narrows it later.
	 */
	char pending_names[ELOG_KEYWORD_NAMES_MAX];
};

static struct subscription *subscriptions = NULL;
static int subscription_count = 0;
static int subscription_capacity = 0;
/* Subscriptions still carrying unresolved keyword names; usually zero. */
static int pending_keyword_filters = 0;
/* Schema keyword n (1-based) -> its keyword filter bit. */
#define ELOG_KW(n)	(1u << ((n) - 1))
static uint32_t buffer_size_per_cpu = 512 * 1024; /* Default 512K */
static bool buffer_size_explicit = false; /* -b/--buffer-size given on the cmdline */
/*
 * symbols/process's dump-on-subscribe callback walks every process's
 * full VM map and resolves symbols synchronously from a single thread,
 * which can burst enough events onto one CPU's buffer to overrun the
 * 512K default before the reader can drain it. Skipped if the caller
 * passed -b explicitly.
 */
#define ELOG_AUTO_BUFFER_SIZE_FOR_DUMP_PROVIDERS	(8 * 1024 * 1024)
/*
 * When > 0, elog raises SIGALRM after this many seconds so it self-
 * exits cleanly — same code path as SIGINT/SIGTERM: flush binary
 * output, update the file header with final event/drop counts, and
 * close. Intended for scripted captures (oca.py get capture, cron,
 * etc.) that want a fixed-duration recording without needing an
 * external pkill.
 */
static unsigned int duration_sec = 0;
static volatile bool done = false;
static int eventlog_fd = -1; /* File descriptor for eventlog device (for stats) */
/*
 * -U / --user-symbols: when set, the libelog_user_symbols hook turns
 * symbols.USER_FILE events into a stream of synthesised
 * symbols.USER_SYMBOL_RANGE events (one per STT_FUNC / STT_GNU_IFUNC
 * symbol in the backing binary). Off by default so a plain
 * elog -c symbols capture stays cheap.
 *
 * --symbol-mode=refs: reference-mode fleet capture. Narrows the symbols
 * subscription to KERNEL_META/USER_META/REFS (kernel emits LINKER_FILE /
 * USER_FILE / SYMBOL_PACK_REF, no SYMBOL_RANGE) and puts -U in ref mode
 * (one SYMBOL_PACK_REF per user file carrying a build-id note).
 * Note-less files keep the inline walk. A Go binary
 * (.note.go.buildid) also emits its .gopclntab ranges beside the
 * ref. Pack bytes come from the symbol catalog at download time.
 */
static bool user_symbols_enabled = false;
/*
 * -L / --embed-source-lines: when set, libelog_source_lines resolves
 * each unique PC in sampled stacks against on-disk DWARF and emits
 * symbols.SOURCE_FILE / symbols.SOURCE_LINE so offline consumers can
 * annotate source without a matching local ELF. Off by default.
 */
static bool source_lines_enabled = false;
static bool symbol_mode_refs = false;
static volatile bool stats_printed = false; /* Track if stats have been printed */
static uint64_t events_received = 0; /* Count of events received */
static bool verbose_stats = false; /* Print detailed stats on exit */
static const char *binary_input_file = NULL; /* Input file for binary read mode */

/* For read mode: base timestamps from file header for UTC calculation */
static uint64_t read_capture_start = 0;
static uint64_t read_start_utc_us = 0;
static bool show_date = false; /* Show full date in timestamps (default: time only) */
static bool show_event_number = false; /* Print serial number at beginning of each line */
static bool show_providers = false; /* Print all provider names at beginning of output */
static bool show_event_name = false; /* Print event name after session ID */
static bool show_relative_time = false; /* Show time relative to first event */
static bool show_delta_time = false; /* Show time since previous event */
static uint64_t first_event_ts = 0;
static uint64_t prev_event_ts = 0;
static bool dump_state = false; /* Request providers dump current state on subscribe */
static char *output_dir = NULL; /* When set, write one file per session under this directory */
static bool format_tcp = false; /* Rename per-session files with TCP connection metadata */

/*
 * Tracks which providers / decode-blob schema_ids have already been
 * committed to one output file's provider table / blob section, whether at
 * that file's initial header write or via a later in-band announcement (see
 * write_provider_announcement()). One instance per output file, since each
 * file's table is independent.
 *
 * Providers are matched by full identity (struct eventlog_provider_info),
 * not just provider_id: the kernel allocates ids via alloc_unr(9), so a
 * provider_id is recycled as soon as its previous owner unregisters, and a
 * later registrant reusing that id is a different provider needing its own
 * announcement.
 */
struct embedded_set {
	struct eventlog_provider_info *providers;
	uint32_t	 provider_count;
	uint32_t	 provider_cap;
	uint8_t		(*schema_ids)[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	uint32_t	 schema_count;
	uint32_t	 schema_cap;
};

static bool
embedded_set_has_provider(const struct embedded_set *set,
    const struct eventlog_provider_info *pi)
{
	uint32_t i;

	for (i = 0; i < set->provider_count; i++)
		if (memcmp(&set->providers[i], pi, sizeof(*pi)) == 0)
			return (true);
	return (false);
}

static void
embedded_set_add_provider(struct embedded_set *set,
    const struct eventlog_provider_info *pi)
{
	if (embedded_set_has_provider(set, pi))
		return;
	if (set->provider_count >= set->provider_cap) {
		uint32_t newcap = set->provider_cap ? set->provider_cap * 2 : 16;

		set->providers = reallocarray(set->providers, newcap,
		    sizeof(*set->providers));
		if (set->providers == NULL)
			err(1, "reallocarray(embedded_set providers)");
		set->provider_cap = newcap;
	}
	set->providers[set->provider_count++] = *pi;
}

static bool
embedded_set_has_schema(const struct embedded_set *set,
    const uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN])
{
	uint32_t i;

	for (i = 0; i < set->schema_count; i++)
		if (memcmp(set->schema_ids[i], schema_id,
		    EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0)
			return (true);
	return (false);
}

static void
embedded_set_add_schema(struct embedded_set *set,
    const uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN])
{
	if (embedded_set_has_schema(set, schema_id))
		return;
	if (set->schema_count >= set->schema_cap) {
		uint32_t newcap = set->schema_cap ? set->schema_cap * 2 : 16;

		set->schema_ids = reallocarray(set->schema_ids, newcap,
		    sizeof(*set->schema_ids));
		if (set->schema_ids == NULL)
			err(1, "reallocarray(embedded_set schemas)");
		set->schema_cap = newcap;
	}
	memcpy(set->schema_ids[set->schema_count++], schema_id,
	    EVENTLOG_DECODE_SCHEMA_ID_LEN);
}

/* Free an embedded_set's storage and zero it, ready for reuse by the next
 * file (rolling reuses one static struct per rolled file). */
static void
embedded_set_reset(struct embedded_set *set)
{
	free(set->providers);
	free(set->schema_ids);
	memset(set, 0, sizeof(*set));
}

/* Per-session file state for -o dir= mode */
struct session_file {
	STAILQ_ENTRY(session_file) link;
	char *session_id;
	char *filepath;
	FILE *fp;
	bool header_written;
	uint64_t capture_start;
	uint64_t start_utc_us;
	uint64_t event_count;
	/* TCP connection metadata for file rename */
	char log_id[64];
	char remote_ip[INET6_ADDRSTRLEN];
	uint16_t local_port;
	uint16_t remote_port;
	bool has_log_id;
	bool has_conn_info;
	/* Providers/blobs already committed to this file (see write_provider_announcement()). */
	struct embedded_set embedded;
};
static STAILQ_HEAD(, session_file) session_files = STAILQ_HEAD_INITIALIZER(session_files);
static struct session_file single_output; /* Binary output state for single-file mode */
static char *single_output_path;	/* strdup'd path for -o <file> */

#define ELOG_GZIP_DEFAULT_LEVEL	6
static int output_gzip_level;		/* 0 = off; 1-9 when --gzip is set */

/*
 * Rolling single-stream output: -o dir=<path> plus --roll-size and/or
 * --roll-time.  Unlike per-session mode, all events go to one current file
 * that is rolled to a fresh file on a size cap and/or a time interval
 * (aligned to the UTC epoch by event timestamp, so no file spans an
 * interval boundary).  Each rolled file is a complete, self-contained
 * .elog; the in-progress file is a ".tmp.*" dotfile renamed to its final
 * name on close, so a directory watcher only ever sees finished captures.
 *
 * Bucketing is by event time: a file for interval N contains only events
 * whose timestamps fall in N, so finding events for N means reading only
 * N's file(s) -- never the tail of N-1 or the head of N+1 (see
 * write_roll_event() for why per-CPU event delivery can be relied on to be
 * timestamp-ordered).  An interval's file is finalized when an event for a
 * later interval arrives, when the wall clock passes the interval's end
 * plus a short grace (roll_idle_close(), so a quiet capture still
 * publishes), or at exit.  A straggler at or before the last idle-closed
 * interval opens that interval's next sequence file.  An interval with no
 * events produces no file.
 */
static bool roll_enabled = false;
static uint64_t roll_size_bytes = 0;	/* size trigger (uncompressed); 0 = off */
static uint64_t roll_time_us = 0;	/* time-interval trigger in us; 0 = off */
static const char *roll_prefix = "eventlog"; /* rolled-file name prefix */
static bool roll_prefix_set = false;	/* --roll-prefix was given explicitly */
static unsigned int roll_keep = 0;	/* retain at most N finalized files; 0 = unlimited */
static bool roll_keep_set = false;	/* --roll-keep was given explicitly */

/*
 * One boot->UTC anchor read at the first drain, so every file's time
 * bucket and header timestamps derive from a single consistent mapping.
 */
static uint64_t roll_base_ts = 0;
static uint64_t roll_base_utc_us = 0;
static bool roll_base_set = false;

struct roll_file {
	FILE *fp;			/* NULL when no file is open */
	char tmp_path[PATH_MAX];
	char final_path[PATH_MAX];
	uint64_t capture_start;		/* first event ts (us since boot) */
	uint64_t start_utc_us;		/* wall-clock us for first event */
	uint64_t event_count;
	uint64_t bytes;			/* bytes written (header + events) */
	uint64_t bucket;		/* time-interval bucket (epoch us / interval) */
	unsigned int seq;		/* size-split sequence within the bucket */
	/* Providers/blobs already committed to this file (see write_provider_announcement()). */
	struct embedded_set embedded;
};
static struct roll_file rollf;
static uint64_t roll_prev_bucket = 0;	/* last closed file's time bucket */
static unsigned int roll_prev_seq = 0;	/* last closed file's seq */
static bool roll_prev_valid = false;
static bool roll_resume_loaded = false;
static bool roll_resume_valid = false;	/* roll_resume_* from a prior run */
static uint64_t roll_resume_bucket = 0;
static unsigned int roll_resume_seq = 0;

/* Wall-clock grace past an interval's end before roll_idle_close() acts. */
#define	ELOG_ROLL_IDLE_GRACE_US	(10ULL * 1000000)

/*
 * Observability for the roll-boundary dump_state re-trigger (see
 * write_roll_event()): counts issued and completed, plus the most
 * recently observed issue->DUMP_COMPLETE lag, so a slow dump_callback
 * lagging past a roll boundary is visible in --verbose-stats instead of
 * silent.
 */
static uint64_t roll_dump_triggers_issued = 0;
static uint64_t roll_dump_completes_seen = 0;
static uint64_t roll_dump_trigger_issued_at = 0; /* monotonic us; 0 = none pending */
static uint64_t roll_dump_trigger_lag_us = 0;

struct gzip_job {
	char		 src_path[PATH_MAX];
	struct gzip_job *next;
};

static pthread_mutex_t	gzip_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	gzip_cond = PTHREAD_COND_INITIALIZER;
static struct gzip_job *gzip_head;
static struct gzip_job *gzip_tail;
static bool		gzip_shutdown;
static bool		gzip_started;
static pthread_t	gzip_thread;
static int		gzip_pending;
static int		gzip_errors;

static void
gzip_path_for_src(const char *src, char *dst, size_t dstlen)
{

	if (snprintf(dst, dstlen, "%s.gz", src) >= (int)dstlen)
		errx(1, "gzip output path too long");
}

/*
 * Compress into a dotfile beside the final name and rename(2) into place,
 * the same publish rule as roll_close(). The ".tmp." prefix keeps the
 * in-progress object out of roll_prune() and the uploader, which both
 * require the roll prefix at the start of the name.
 */
static void
gzip_tmp_path(const char *dst, char *tmp, size_t tmplen)
{
	const char *base;
	size_t dirlen;

	base = strrchr(dst, '/');
	if (base == NULL) {
		if (snprintf(tmp, tmplen, ".tmp.%s", dst) >= (int)tmplen)
			errx(1, "gzip temp path too long");
		return;
	}
	dirlen = (size_t)(base - dst);
	base++;
	if (snprintf(tmp, tmplen, "%.*s/.tmp.%s", (int)dirlen, dst, base) >=
	    (int)tmplen)
		errx(1, "gzip temp path too long");
}

static bool
gzip_file(const char *src_path, int level)
{
	char dst_path[PATH_MAX];
	char tmp_path[PATH_MAX];
	gzFile out;
	FILE *in;
	unsigned char buf[128 * 1024];
	size_t n;

	gzip_path_for_src(src_path, dst_path, sizeof(dst_path));
	gzip_tmp_path(dst_path, tmp_path, sizeof(tmp_path));
	unlink(tmp_path);

	in = fopen(src_path, "rb");
	if (in == NULL)
		return (false);

	out = gzopen(tmp_path, "wb");
	if (out == NULL) {
		fclose(in);
		return (false);
	}
	if (gzsetparams(out, level, Z_DEFAULT_STRATEGY) != Z_OK) {
		gzclose(out);
		fclose(in);
		unlink(tmp_path);
		return (false);
	}

	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (gzwrite(out, buf, (unsigned)n) != (int)n) {
			gzclose(out);
			fclose(in);
			unlink(tmp_path);
			return (false);
		}
	}
	if (ferror(in)) {
		gzclose(out);
		fclose(in);
		unlink(tmp_path);
		return (false);
	}
	fclose(in);
	if (gzclose(out) != Z_OK) {
		unlink(tmp_path);
		return (false);
	}
	if (rename(tmp_path, dst_path) != 0) {
		unlink(tmp_path);
		return (false);
	}
	if (unlink(src_path) != 0 && errno != ENOENT) {
		unlink(dst_path);
		return (false);
	}
	return (true);
}

static void *
gzip_worker(void *arg __unused)
{

	for (;;) {
		struct gzip_job *job;

		pthread_mutex_lock(&gzip_mutex);
		while (gzip_head == NULL && !gzip_shutdown)
			pthread_cond_wait(&gzip_cond, &gzip_mutex);
		if (gzip_head == NULL) {
			pthread_mutex_unlock(&gzip_mutex);
			break;
		}
		job = gzip_head;
		gzip_head = job->next;
		if (gzip_head == NULL)
			gzip_tail = NULL;
		pthread_mutex_unlock(&gzip_mutex);

		if (!gzip_file(job->src_path, output_gzip_level)) {
			pthread_mutex_lock(&gzip_mutex);
			gzip_errors++;
			pthread_mutex_unlock(&gzip_mutex);
			warnx("gzip failed for %s", job->src_path);
		}
		free(job);

		pthread_mutex_lock(&gzip_mutex);
		gzip_pending--;
		pthread_cond_broadcast(&gzip_cond);
		pthread_mutex_unlock(&gzip_mutex);
	}
	return (NULL);
}

static void
gzip_worker_start(void)
{

	if (gzip_started)
		return;
	if (pthread_create(&gzip_thread, NULL, gzip_worker, NULL) != 0)
		err(1, "pthread_create(gzip_worker)");
	gzip_started = true;
}

static void
gzip_enqueue(const char *src_path)
{
	struct gzip_job *job;

	job = malloc(sizeof(*job));
	if (job == NULL)
		err(1, "malloc");
	if (strlcpy(job->src_path, src_path, sizeof(job->src_path)) >=
	    sizeof(job->src_path)) {
		free(job);
		errx(1, "gzip source path too long");
	}
	job->next = NULL;

	gzip_worker_start();
	pthread_mutex_lock(&gzip_mutex);
	gzip_pending++;
	if (gzip_tail != NULL)
		gzip_tail->next = job;
	else
		gzip_head = job;
	gzip_tail = job;
	pthread_cond_signal(&gzip_cond);
	pthread_mutex_unlock(&gzip_mutex);
}

static void
gzip_drain(void)
{

	if (!gzip_started)
		return;
	pthread_mutex_lock(&gzip_mutex);
	while (gzip_pending > 0)
		pthread_cond_wait(&gzip_cond, &gzip_mutex);
	gzip_shutdown = true;
	pthread_cond_signal(&gzip_cond);
	pthread_mutex_unlock(&gzip_mutex);
	pthread_join(gzip_thread, NULL);
	gzip_started = false;

	if (gzip_errors > 0)
		warnx("gzip failed for %d capture file(s)", gzip_errors);
}

static uint64_t
monotonic_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

/*
 * Read both clocks together: capture_start and start_utc_us have to name
 * one instant.  The first drained event can't supply the boot side -- a
 * provider that registered before elog attached leaves its identity record
 * in the ring, backdating the anchor by that provider's uptime.
 * CLOCK_MONOTONIC is nanouptime(), the clock events are stamped from.
 */
static void
capture_anchor(uint64_t *ts, uint64_t *utc_us)
{
	struct timeval tv;

	*ts = monotonic_us();
	gettimeofday(&tv, NULL);
	*utc_us = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static inline bool
binary_output_mode(void)
{
	return (output_dir != NULL || single_output.fp != NULL);
}

/*
 * Provider id->name map (from GET_PROVIDERS or file header).  Grown on
 * demand: a subscriber may bind a large number of same-name providers.
 */
#define ELOG_PROVIDER_MAP_SANE_MAX	65536u
static struct eventlog_provider_info *provider_map = NULL;
static uint32_t provider_map_count = 0;
static uint32_t provider_map_cap = 0;

static void
provider_map_ensure(uint32_t n)
{
	if (n <= provider_map_cap)
		return;
	provider_map = reallocarray(provider_map, n, sizeof(*provider_map));
	if (provider_map == NULL)
		err(1, "reallocarray(provider_map)");
	provider_map_cap = n;
}

/*
 * When true (binary output only), the decode blobs for the captured
 * providers are written into the .elog file so it can be decoded later
 * without the originating kernel. On by default; --no-embed-decode opts out
 * for a smaller file when the live kernel will remain available to decode.
 */
static bool embed_decode = true;

/* Set when --no-embed-decode is explicitly given, for flag-combo validation. */
static bool no_embed_decode_requested = false;

/*
 * Runtime decode-blob registry, keyed by schema_id (the content-addressed
 * SHA-256-truncation of the blob bytes; see sys/sys/eventlog_decode.h). Blobs
 * are fetched from /dev/eventlog (live) or read back from a v2+ .elog file,
 * parsed once, and reused for every event whose provider maps to that schema.
 * Keying on content means identical schemas registered under different
 * provider names (or ids) collapse to a single entry. provider_name is kept
 * only as a human-readable label.
 */
struct decode_entry {
	uint8_t			 schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	char			 provider_name[EVENTLOG_PROVIDER_NAME_MAX];
	unsigned char		*blob;		/* raw bytes (for embedding) */
	size_t			 blob_size;
	struct decode_provider	*dp;
};
/*
 * Distinct decode blobs elog caches at once.  Entries are content-addressed by
 * schema_id and deduplicated, so this bounds the number of distinct schemas in
 * play (one per provider type), not the number of bound providers -- those are
 * reported by the variable-length GET_PROVIDERS and collapse to one cache entry
 * per schema.
 */
#define	ELOG_DECODE_REGISTRY_MAX	64
static struct decode_entry decode_entries[ELOG_DECODE_REGISTRY_MAX];
static uint32_t decode_entry_count = 0;
static int blob_query_fd = -1;		/* lazily opened /dev/eventlog */

/* Compute a blob's schema_id: SHA-256(blob) truncated, matching the kernel. */
static void
compute_schema_id(const unsigned char *blob, size_t size,
    uint8_t out[EVENTLOG_DECODE_SCHEMA_ID_LEN])
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, blob, size);
	SHA256_Final(digest, &ctx);
	memcpy(out, digest, EVENTLOG_DECODE_SCHEMA_ID_LEN);
}

static bool
schema_id_is_zero(const uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN])
{
	uint8_t zero[EVENTLOG_DECODE_SCHEMA_ID_LEN] = {0};

	return (memcmp(schema_id, zero, sizeof(zero)) == 0);
}

static struct decode_entry *
decode_registry_find_by_schema(const uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN])
{
	uint32_t i;

	for (i = 0; i < decode_entry_count; i++) {
		if (memcmp(decode_entries[i].schema_id, schema_id,
		    EVENTLOG_DECODE_SCHEMA_ID_LEN) == 0)
			return (&decode_entries[i]);
	}
	return (NULL);
}

/*
 * True for bytes that are safe to write to a terminal as-is: tab, newline,
 * printable ASCII, and high-bit bytes (UTF-8 continuation/lead bytes). C0
 * controls, DEL, and the C1 range are not -- see fputs_safe() and
 * escape_untrusted() below, which both use this to keep their escaping
 * behavior in sync.
 */
static bool
byte_is_terminal_safe(unsigned char c)
{
	return (c == '\t' || c == '\n' || (c >= 0x20 && c <= 0x7e) ||
	    c >= 0xa0);
}

/*
 * Escape an untrusted, NUL-terminated string (e.g. a provider name read from
 * a capture file) for interpolation into a warnx()/errx() message, the same
 * way fputs_safe() escapes decoded output lines. Returns a pointer to a
 * static buffer good until the next call; truncates rather than growing
 * unbounded, since callers only ever pass short, informational strings.
 */
static const char *
escape_untrusted(const char *s)
{
	static char buf[4 * EVENTLOG_PROVIDER_NAME_MAX];
	const unsigned char *p;
	size_t pos = 0;

	for (p = (const unsigned char *)s; *p != '\0' && pos + 4 < sizeof(buf);
	    p++) {
		if (byte_is_terminal_safe(*p))
			buf[pos++] = (char)*p;
		else
			pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos,
			    "\\%03o", *p);
	}
	buf[pos] = '\0';
	return (buf);
}

static struct decode_entry *
decode_registry_find_by_name(const char *name)
{
	uint32_t i;

	for (i = 0; i < decode_entry_count; i++) {
		if (strcmp(decode_entries[i].provider_name, name) == 0)
			return (&decode_entries[i]);
	}
	return (NULL);
}

/*
 * Take ownership of blob; parse and register it keyed by its content-derived
 * schema_id. name is an optional label. expect_schema_id, when non-NULL, is
 * verified against the recomputed schema_id (rejecting a blob that does not
 * hash to the id it was filed under, e.g. a corrupt embedded section).
 */
static struct decode_provider *
decode_registry_add(const uint8_t *expect_schema_id, const char *name,
    unsigned char *blob, size_t size)
{
	uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	struct decode_entry *e;
	struct decode_provider *dp;

	compute_schema_id(blob, size, schema_id);
	if (expect_schema_id != NULL &&
	    memcmp(expect_schema_id, schema_id,
	    EVENTLOG_DECODE_SCHEMA_ID_LEN) != 0) {
		warnx("decode blob for '%s' does not match its schema_id; "
		    "ignoring", escape_untrusted(name != NULL ? name : "?"));
		free(blob);
		return (NULL);
	}
	e = decode_registry_find_by_schema(schema_id);
	if (e != NULL) {
		free(blob);
		return (e->dp);
	}
	if (decode_entry_count >= ELOG_DECODE_REGISTRY_MAX) {
		free(blob);
		return (NULL);
	}
	dp = decode_provider_parse(blob, size);
	if (dp == NULL) {
		free(blob);
		return (NULL);
	}
	e = &decode_entries[decode_entry_count++];
	memcpy(e->schema_id, schema_id, EVENTLOG_DECODE_SCHEMA_ID_LEN);
	if (name != NULL)
		strlcpy(e->provider_name, name, sizeof(e->provider_name));
	e->blob = blob;
	e->blob_size = size;
	e->dp = dp;
	return (dp);
}

/*
 * Fetch a provider's decode blob from an eventlog device fd using the
 * two-call size-probe protocol. lookup is by name (lookup_kind=NAME) when
 * schema_id is NULL, else by schema_id. Returns a malloc'd buffer (caller
 * owns) and sets *size_out, or NULL if no match / on error.
 */
static unsigned char *
fetch_blob_from_device(int fd, const char *provider,
    const uint8_t *schema_id, size_t *size_out)
{
	struct eventlog_get_decode_blob_req req;
	unsigned char *blob;

	memset(&req, 0, sizeof(req));
	if (schema_id != NULL) {
		req.lookup_kind = EVENTLOG_DECODE_LOOKUP_SCHEMA_ID;
		memcpy(req.schema_id, schema_id, sizeof(req.schema_id));
	} else {
		req.lookup_kind = EVENTLOG_DECODE_LOOKUP_NAME;
		strlcpy(req.provider_name, provider, sizeof(req.provider_name));
	}
	if (ioctl(fd, EVENTLOG_IOCTL_GET_DECODE_BLOB, &req) != 0)
		return (NULL);
	if (req.blob_size == 0)
		return (NULL);
	blob = malloc(req.blob_size);
	if (blob == NULL)
		return (NULL);
	req.buf = (uint64_t)(uintptr_t)blob;
	req.buf_size = req.blob_size;
	if (ioctl(fd, EVENTLOG_IOCTL_GET_DECODE_BLOB, &req) != 0) {
		free(blob);
		return (NULL);
	}
	*size_out = req.blob_size;
	return (blob);
}

static int
ensure_blob_query_fd(void)
{
	if (blob_query_fd < 0)
		blob_query_fd = open("/dev/eventlog", O_RDONLY);
	return (blob_query_fd);
}

/*
 * Ensure a decode blob for the named provider is registered, fetching it by
 * name from the live kernel (lazily opening /dev/eventlog) if necessary. Used
 * for pre-subscription keyword resolution, where only the name is known.
 * Returns the parsed provider or NULL if unavailable.
 */
static struct decode_provider *
ensure_blob_registered(const char *provider)
{
	struct decode_entry *e = decode_registry_find_by_name(provider);
	unsigned char *blob;
	size_t size;

	if (e != NULL)
		return (e->dp);
	if (ensure_blob_query_fd() < 0)
		return (NULL);
	blob = fetch_blob_from_device(blob_query_fd, provider, NULL, &size);
	if (blob == NULL)
		return (NULL);
	return (decode_registry_add(NULL, provider, blob, size));
}

/*
 * Ensure a decode blob for the given schema_id is registered, fetching it by
 * schema_id from the live kernel if necessary. This is the durable decode
 * path: it resolves the exact schema that produced a captured event. name is
 * an optional label for any newly-registered entry.
 */
static struct decode_provider *
ensure_blob_registered_by_schema(const uint8_t *schema_id, const char *name)
{
	struct decode_entry *e = decode_registry_find_by_schema(schema_id);
	unsigned char *blob;
	size_t size;

	if (e != NULL)
		return (e->dp);
	if (ensure_blob_query_fd() < 0)
		return (NULL);
	blob = fetch_blob_from_device(blob_query_fd, NULL, schema_id, &size);
	if (blob == NULL)
		return (NULL);
	return (decode_registry_add(schema_id, name, blob, size));
}

static void fputs_safe(const char *s, FILE *fp);

static void
print_provider_names(void)
{
	if (!show_providers || provider_map_count == 0)
		return;
	fprintf(stderr, "[Providers] %u registered:", provider_map_count);
	for (uint32_t i = 0; i < provider_map_count; i++) {
		/* Provider names come from the (untrusted) capture/blob. */
		putc(' ', stderr);
		fputs_safe(provider_map[i].name, stderr);
	}
	fprintf(stderr, "\n");
}

static struct eventlog_provider_info *provider_map_lookup(uint16_t id);

/*
 * Fetch the current provider table via GET_PROVIDERS2 and upsert into
 * provider_map. Entries are kept across refreshes so in-flight events
 * from a just-unregistered producer still decode; a reused alloc_unr(9)
 * id overwrites the stale name/schema. Two-call size probe (same pattern
 * as GET_DECODE_BLOB) — no IOCPARM_LEN cap. Returns false (provider_map
 * unchanged) on ioctl failure.
 */
static bool
fetch_provider_map(int fd)
{
	struct eventlog_get_providers2_req req;
	struct eventlog_provider_info *buf = NULL;
	struct eventlog_provider_info *existing;
	uint32_t total, i;
	size_t bytes;

	memset(&req, 0, sizeof(req));
	if (ioctl(fd, EVENTLOG_IOCTL_GET_PROVIDERS2, &req) != 0)
		return (false);
	total = req.count;
	if (total == 0)
		return (true);

	for (;;) {
		bytes = (size_t)total * sizeof(*buf);
		buf = malloc(bytes);
		if (buf == NULL)
			err(1, "malloc(providers)");
		memset(&req, 0, sizeof(req));
		req.buf = (uint64_t)(uintptr_t)buf;
		req.buf_size = (uint32_t)bytes;
		if (ioctl(fd, EVENTLOG_IOCTL_GET_PROVIDERS2, &req) == 0)
			break;
		if (errno != ENOSPC) {
			free(buf);
			return (false);
		}
		/* Grew between probe and fetch; retry with the new total. */
		free(buf);
		buf = NULL;
		total = req.count;
		if (total == 0)
			return (true);
	}
	total = req.count;
	for (i = 0; i < total; i++) {
		existing = provider_map_lookup(buf[i].provider_id);
		if (existing != NULL) {
			*existing = buf[i];
			continue;
		}
		provider_map_ensure(provider_map_count + 1);
		provider_map[provider_map_count++] = buf[i];
	}
	free(buf);
	return (true);
}

/*
 * A provider can register after we've already subscribed (late-binding: the
 * name didn't exist yet at subscribe time), so provider_map -- a
 * subscribe-time snapshot -- may be missing its id. Worse, provider_id is
 * kernel-allocated via alloc_unr(9) (lowest free number), so an id can be
 * reused by a completely different provider the moment its previous owner
 * unregisters -- a *hit* against provider_map is therefore not proof the
 * entry is still current, not just a miss. get_provider_entry() refreshes
 * via GET_PROVIDERS2 on every call, hit or miss, but rate-limited so a
 * steady stream of events (bogus id or not) can't turn into an ioctl storm.
 * A miss forces one out-of-band refresh (once per distinct id) so a
 * just-bound provider is learned before its first event is written.
 */
#define PROVIDER_MAP_REFRESH_MIN_INTERVAL_US	(100 * 1000) /* 100ms */
static uint64_t provider_map_last_refresh_us = 0;
/* Events whose provider_id was still missing from provider_map after a
 * forced GET_PROVIDERS2 refresh. Warned at exit. */
static uint64_t unknown_provider_events = 0;

/* Pure lookup, no refresh: NULL if provider_map doesn't currently have it. */
static struct eventlog_provider_info *
provider_map_lookup(uint16_t id)
{
	uint32_t i;

	for (i = 0; i < provider_map_count; i++) {
		if (provider_map[i].provider_id == id)
			return (&provider_map[i]);
	}
	return (NULL);
}

static struct eventlog_provider_info *
get_provider_entry(uint16_t id)
{
	struct eventlog_provider_info *pi;
	uint64_t now;
	/* Ids for which a miss already forced a refresh (so a steady stream
	 * of still-unknown events can't become an ioctl storm). Tiny; a
	 * ring that forgets old ids is fine — the rate-limited path covers
	 * them. */
	static uint16_t forced_miss_ids[32];
	static uint32_t forced_miss_count = 0;
	uint32_t i;
	bool already_forced = false;

	if (id == ELOG_MACHINE_PROVIDER_ID && machine_metadata_enabled())
		return (__DECONST(struct eventlog_provider_info *,
		    machine_metadata_provider()));
	if (eventlog_fd >= 0) {
		now = monotonic_us();
		if (now - provider_map_last_refresh_us >=
		    PROVIDER_MAP_REFRESH_MIN_INTERVAL_US) {
			provider_map_last_refresh_us = now;
			(void)fetch_provider_map(eventlog_fd);
		}
	}
	pi = provider_map_lookup(id);
	if (pi != NULL || eventlog_fd < 0)
		return (pi);
	for (i = 0; i < forced_miss_count && i < nitems(forced_miss_ids); i++) {
		if (forced_miss_ids[i] == id) {
			already_forced = true;
			break;
		}
	}
	if (already_forced)
		return (NULL);
	/* First miss for this id: force one refresh now. */
	provider_map_last_refresh_us = monotonic_us();
	(void)fetch_provider_map(eventlog_fd);
	if (forced_miss_count < nitems(forced_miss_ids))
		forced_miss_ids[forced_miss_count++] = id;
	return (provider_map_lookup(id));
}

/*
 * When every -c subscription names the same provider, unknown ids (a
 * worker that unregistered, or GET_PROVIDERS truncated) still decode
 * with that schema. Returns NULL if there is no unique name.
 */
static const char *
unique_subscription_name(void)
{
	int i;

	if (subscription_count < 1)
		return (NULL);
	for (i = 1; i < subscription_count; i++) {
		if (strcmp(subscriptions[i].provider_name,
		    subscriptions[0].provider_name) != 0)
			return (NULL);
	}
	return (subscriptions[0].provider_name);
}

static const char *
get_provider_name(uint16_t id)
{
	struct eventlog_provider_info *pi;
	const char *fallback;

	if (id == ELOG_MACHINE_PROVIDER_ID && machine_metadata_enabled())
		return ("machine");
	pi = get_provider_entry(id);
	if (pi != NULL)
		return (pi->name);
	fallback = unique_subscription_name();
	return (fallback != NULL ? fallback : "?");
}

/*
 * Resolve the decode provider for a captured event's provider_id. The durable
 * key is the schema_id recorded in the capture's provider table: look it up in
 * the registry, else fetch it live by schema_id. A provider that recorded no
 * schema_id registered no decode blob, so its events cannot be decoded.
 */
static struct decode_provider *
provider_dp_by_id(uint16_t id)
{
	struct eventlog_provider_info *pi = get_provider_entry(id);
	const char *fallback;

	if (pi != NULL && !schema_id_is_zero(pi->schema_id))
		return (ensure_blob_registered_by_schema(pi->schema_id,
		    pi->name));
	fallback = unique_subscription_name();
	if (fallback != NULL)
		return (ensure_blob_registered(fallback));
	return (NULL);
}

/* Binary file format structures */
#define ELOG_BINARY_MAGIC "ELOG"
/*
 * Version 3 carries a per-provider schema_id in the provider table, an
 * optional embedded decode-blob section after it (omitted with
 * --no-embed-decode), and the header counter array below. Version 2
 * (schema_id + blob section, but a scalar dropped_events field instead of
 * the counter array) already shipped in a release, so its on-disk layout
 * can no longer be redefined in place -- this is a real version bump, not
 * another rewrite of what "version 2" means. Version 1 (no schema_id, no
 * blob section) is obsolete and not read.
 */
#define ELOG_BINARY_VERSION 3
/* Oldest on-disk version this build still reads; see read_binary_file(). */
#define ELOG_BINARY_VERSION_MIN_READ 2

struct elog_binary_header {
	char magic[4];           /* "ELOG" */
	uint32_t version;        /* File format version */
	uint64_t capture_start;  /* Timestamp when capture started (microseconds since boot) */
	uint64_t start_utc_us;   /* UTC at capture start (microseconds since epoch) for event time display */
	uint64_t event_count;    /* Total number of events in file */
	uint32_t counter_count;  /* Number of trailing uint64_t counters (see ELOG_COUNTER_*) */
} __packed;
/* counter_count x uint64_t counters[] immediately follows, written/read
 * separately since it's not part of this fixed-size struct. */

/*
 * Prefix through event_count, identical in every version this build reads;
 * everything after it is version-specific.
 */
#define ELOG_BINARY_HEADER_COMMON_LEN \
	offsetof(struct elog_binary_header, counter_count)

/*
 * Indices into the header's trailing counters[] array. Append-only: an
 * index's meaning must never change or be reused, so old and new readers
 * can each safely ignore indices they don't recognize (a reader clamps to
 * min(file's counter_count, its own ELOG_COUNTER_COUNT); missing trailing
 * counters in an older file read as 0).
 */
#define ELOG_COUNTER_KERNEL_DROPPED       0 /* Kernel per-CPU buffer-full drops */
#define ELOG_COUNTER_USER_DROPPED_FULL    1 /* User-stream buffer-full drops */
#define ELOG_COUNTER_USER_DROPPED_PREJOIN 2 /* User events older than the join point */
#define ELOG_COUNTER_USER_DROPPED_LATE    3 /* User events older than their stream's last delivered */
#define ELOG_COUNTER_COUNT                4 /* Number of counters this build writes */
/* Defensive cap on counter_count read back from a file; unrelated to
 * ELOG_COUNTER_COUNT above, just bounds a corrupt/malicious file's claimed
 * count so replay can't be forced into an unbounded read loop. */
#define ELOG_HEADER_COUNTER_SANE_MAX 1024

/*
 * Event-ID sentinels elog(1) itself writes into a binary capture file's
 * event stream -- never emitted by the kernel, never seen on the live
 * /dev/eventlog stream. They let a provider that registers after a file's
 * header (and its provider table / decode-blob section) was already
 * committed still get embedded, in-band, the moment its first event is
 * about to be written to that file (see write_provider_announcement()).
 * This is the same "repeat sighting replaces the earlier one" idea elog(5)
 * already documents for identity/metadata events re-emitted at roll
 * boundaries, applied to provider-table/decode-blob content instead.
 * ELOG_EVENT_PROVIDER_INFO_ID's payload is a struct eventlog_provider_info
 * (the same 50-byte entry the provider table uses); ELOG_EVENT_PROVIDER_BLOB_ID's
 * is schema_id[16] + uint32_t size + that many raw decode-blob bytes.
 * Aliases of the kernel reserved IDs (eventlog.h); the kernel also emits
 * these at late-bind time into a subscriber's stream.
 */
#define ELOG_EVENT_PROVIDER_INFO_ID	EVENTLOG_PROVIDER_INFO_ID
#define ELOG_EVENT_PROVIDER_BLOB_ID	EVENTLOG_PROVIDER_BLOB_ID
/* Max decode blob embeddable in one ELOG_EVENT_PROVIDER_BLOB_ID record:
 * event_length is a uint16_t covering the whole record. No shipped provider
 * is anywhere close; a bigger blob is simply not embedded this way and
 * replay falls back to the live kernel by schema_id, same as -N. */
#define ELOG_INBAND_BLOB_MAX	(UINT16_MAX - \
	    sizeof(struct eventlog_event_header) - \
	    EVENTLOG_DECODE_SCHEMA_ID_LEN - sizeof(uint32_t))

static void
usage(void)
{
	fprintf(stderr, "usage: elog [options]\n");
	fprintf(stderr, "  -c, --capture <provider> [level] [keywords]\n");
	fprintf(stderr, "                      Capture events from provider\n");
	fprintf(stderr, "                      provider: Provider name (e.g., tcp)\n");
	fprintf(stderr, "                      level:    Optional level "
	    "(NONE/0, ERROR/1, WARN/2, INFO/3, VERBOSE/4, TRACE/5)\n");
	fprintf(stderr, "                               Default: VERBOSE\n");
	fprintf(stderr, "                      keywords: Optional keyword filter "
	    "(hex e.g., 0x3F or names e.g., CC|RX|TX)\n");
	fprintf(stderr, "                               Prefix a name with '^' to exclude it (e.g., ^CC|^RX)\n");
	fprintf(stderr, "                               Default: 0xFFFFFFFF (all flags)\n");
	fprintf(stderr, "  -S, --scenario <name> Apply a named capture preset; may be combined with -c\n");
	fprintf(stderr, "                        Multiple presets: -S cpu|net  (also -S cpu -S net)\n");
	fprintf(stderr, "                        cpu: -c cpu -c process -c symbols -D -U\n");
	fprintf(stderr, "                        net: -c if -c tcp SAMPLE|SAMPLE_HIST -D  (alias: network)\n");
	fprintf(stderr, "  -b, --buffer-size <size>  Set per-CPU buffer size (default: 512K)\n");
	fprintf(stderr, "                        Size can be specified as bytes, or with K/M/G suffix\n");
	fprintf(stderr, "                        Examples: 65536, 64K, 1M, 256K\n");
	fprintf(stderr, "                        Rounded up to a power of two; valid range:\n");
	fprintf(stderr, "                        %uKB to %uMB per CPU\n",
	    EVENTLOG_BUFFER_SIZE_MIN / 1024,
	    EVENTLOG_BUFFER_SIZE_MAX / (1024 * 1024));
	fprintf(stderr, "      --duration <sec>  Self-exit after <sec> seconds (SIGALRM). Same\n");
	fprintf(stderr, "                        cleanup path as SIGINT/SIGTERM. 0 = no timeout.\n");
	fprintf(stderr, "  -d, --date            Show full date (YYYY-MM-DD) in timestamps\n");
	fprintf(stderr, "  -e, --event-name      Show event name (e.g. IN, OUT) after session ID\n");
	fprintf(stderr, "  -n, --event-number    Print event serial number at beginning of each line\n");
	fprintf(stderr, "  -p, --providers       Print all provider names at beginning of output\n");
	fprintf(stderr, "  -s, --stats           Print detailed statistics on exit\n");
	fprintf(stderr, "  -o, --output <file>   Write output to file in binary format (default: stdout)\n");
	fprintf(stderr, "  -o dir=<path>         Write one file per session under <path> (binary format)\n");
	fprintf(stderr, "                        Uses buffered I/O for efficiency\n");
	fprintf(stderr, "      --roll-size <size>    Roll to a new file after <size> uncompressed bytes\n");
	fprintf(stderr, "                        (K/M/G suffix). Requires -o dir=<path>.\n");
	fprintf(stderr, "      --roll-time <ival>    Roll to a new file every <ival> (s/m/h/d suffix,\n");
	fprintf(stderr, "                        default s), aligned to the UTC epoch by event time so\n");
	fprintf(stderr, "                        no file spans a boundary. Requires -o dir=<path>.\n");
	fprintf(stderr, "      --roll-prefix <name>  Prefix for rolled files (default: eventlog).\n");
	fprintf(stderr, "                        Names: <prefix>-YYYY-MM-DDTHHMMSSZ-<seq>.elog\n");
	fprintf(stderr, "      --roll-keep <count>   Keep at most <count> finalized files, deleting the\n");
	fprintf(stderr, "                        oldest as needed (default: unlimited).\n");
	fprintf(stderr, "      --gzip[=level]      Gzip binary captures after close (level 1-9, default %d).\n",
	    ELOG_GZIP_DEFAULT_LEVEL);
	fprintf(stderr, "                        Rolling mode compresses in a background worker so the\n");
	fprintf(stderr, "                        event drain loop stays unblocked.\n");
	fprintf(stderr, "  -r, --read-binary <file>  Read binary file and convert to text (.gz supported)\n");
	fprintf(stderr, "      --no-metadata     Skip synthesising machine metadata events into\n");
	fprintf(stderr, "                        binary captures (on by default for -o output)\n");
	fprintf(stderr, "  -N, --no-embed-decode Skip embedding provider decode blobs into the\n");
	fprintf(stderr, "                        output file (binary -o output only). Blobs are\n");
	fprintf(stderr, "                        embedded by default so the file can be decoded\n");
	fprintf(stderr, "                        later without the live kernel\n");
	fprintf(stderr, "  -f, --format <type>   Rename per-session files with connection metadata\n");
	fprintf(stderr, "                        Supported types: tcp\n");
	fprintf(stderr, "                        Format: <log_id>_<local_port>_<remote_ip>_<remote_port>.elog\n");
	fprintf(stderr, "                        Requires -o dir=<path>\n");
	fprintf(stderr, "  -t, --relative-time   Show time relative to first event (e.g., +1.234567)\n");
	fprintf(stderr, "      --delta-time      Show time since previous event (e.g., d0.000015)\n");
	fprintf(stderr, "  -D, --dump-state      Request providers replay their current state on subscribe\n");
	fprintf(stderr, "  --symbol-mode <mode>  inline (default): full SYMBOL_RANGE / USER_SYMBOL_RANGE\n");
	fprintf(stderr, "                        refs: identity rows + SYMBOL_PACK_REF for build-id\n");
	fprintf(stderr, "                        binaries (note-less stay inline); the symbol\n");
	fprintf(stderr, "                        catalog supplies ranges at read time\n");
	fprintf(stderr, "  -U, --user-symbols    Resolve user-mode functions: parse each streamed\n");
	fprintf(stderr, "                        symbols.USER_FILE and emit symbols.USER_SYMBOL_RANGE\n");
	fprintf(stderr, "                        events (one per function). Cannot be used with -r.\n");
	fprintf(stderr, "  -L, --embed-source-lines  Resolve sampled stack PCs to DWARF source lines:\n");
	fprintf(stderr, "                        emit symbols.SOURCE_FILE / SOURCE_LINE from on-disk\n");
	fprintf(stderr, "                        debug info. Cannot be used with -r.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  Multiple captures can be specified:\n");
	fprintf(stderr, "    elog -c tcp\n");
	fprintf(stderr, "    elog -c tcp INFO\n");
	fprintf(stderr, "    elog -c tcp INFO 0x3F\n");
	fprintf(stderr, "    elog -c tcp INFO '^RX|^TX'  # All TCP events except RX/TX\n");
	fprintf(stderr, "    elog -c tcp -c hpts WARN\n");
	fprintf(stderr, "    elog -S cpu\n");
	fprintf(stderr, "    elog -S net\n");
	fprintf(stderr, "    elog -S cpu|net\n");
	fprintf(stderr, "    elog -S cpu -c tcp\n");
	fprintf(stderr, "    elog -c tcp -o /tmp/events.bin  # Write binary to file\n");
	fprintf(stderr, "    elog -r /tmp/events.bin  # Read binary and convert to text\n");
	exit(1);
}

static bool
try_parse_level(const char *str, enum eventlog_level *out)
{
	long num;
	char *endptr;

	if (strcasecmp(str, "NONE") == 0) {
		*out = EVENTLOG_LEVEL_NONE;
		return (true);
	}
	if (strcasecmp(str, "ERROR") == 0) {
		*out = EVENTLOG_LEVEL_ERROR;
		return (true);
	}
	if (strcasecmp(str, "WARN") == 0) {
		*out = EVENTLOG_LEVEL_WARN;
		return (true);
	}
	if (strcasecmp(str, "INFO") == 0) {
		*out = EVENTLOG_LEVEL_INFO;
		return (true);
	}
	if (strcasecmp(str, "VERBOSE") == 0) {
		*out = EVENTLOG_LEVEL_VERBOSE;
		return (true);
	}
	if (strcasecmp(str, "TRACE") == 0) {
		*out = EVENTLOG_LEVEL_TRACE;
		return (true);
	}

	num = strtol(str, &endptr, 10);
	if (*endptr == '\0' && num >= EVENTLOG_LEVEL_NONE &&
	    num <= EVENTLOG_LEVEL_TRACE) {
		*out = (enum eventlog_level)num;
		return (true);
	}
	return (false);
}

/*
 * True for a '|'-separated list of identifier tokens, the shape a KEYWORD
 * name has. Anything else is not a keywords operand at all.
 */
static bool
keyword_names_wellformed(const char *str)
{
	size_t toklen = 0;
	const char *p;
	bool at_tok_start = true;

	for (p = str; ; p++) {
		if (*p == '|' || *p == '\0') {
			if (toklen == 0)
				return (false);
			if (*p == '\0')
				return (true);
			toklen = 0;
			at_tok_start = true;
			continue;
		}
		if (*p == '^' && at_tok_start) {
			at_tok_start = false;
			continue;
		}
		at_tok_start = false;
		if (!isalnum((unsigned char)*p) && *p != '_')
			return (false);
		toklen++;
	}
}

/*
 * Resolve a '|'-separated keyword-name list against a provider's decode
 * blob. The first name the provider does not declare is reported in
 * unknown_out; callers differ on whether that is fatal.
 * '^NAME' excludes that keyword. Negations-only lists start from all
 * keywords; mixed lists subtract exclusions from the positives.
 */
static uint32_t
resolve_keyword_names(const struct decode_provider *dp, const char *str,
    char *unknown_out, size_t unknown_size)
{
	char *copy, *token, *saveptr;
	const char *name;
	uint32_t include = 0, exclude = 0, kw;
	bool negated;

	unknown_out[0] = '\0';
	copy = strdup(str);
	if (copy == NULL)
		err(1, "strdup");
	for (token = strtok_r(copy, "|", &saveptr); token != NULL;
	    token = strtok_r(NULL, "|", &saveptr)) {
		negated = (token[0] == '^');
		name = negated ? token + 1 : token;
		kw = decode_keyword_from_string(dp, name);
		if (kw == 0) {
			if (unknown_out[0] == '\0')
				strlcpy(unknown_out, name, unknown_size);
			continue;
		}
		if (negated)
			exclude |= kw;
		else
			include |= kw;
	}
	free(copy);
	if (include == 0 && exclude != 0)
		include = 0xFFFFFFFF;
	return (include & ~exclude);
}

/*
 * Parse a keywords operand: a hex mask, or a '|'-separated keyword-name
 * list resolved against the provider's decode blob. Returns false if the
 * operand is not a keywords argument, leaving it for the next option.
 *
 * A provider that has not registered yet has no blob, so its names go to
 * names_out and *out stays wide until resolve_pending_keywords() narrows
 * it. Filtering a provider that appears later is a normal use, not an
 * error. A provider registered without a blob looks the same from here and
 * gets the same treatment; it simply never narrows.
 */
static bool
try_parse_keywords(const char *provider, const char *str, uint32_t *out,
    char *names_out, size_t names_size)
{
	char unknown[ELOG_KEYWORD_NAMES_MAX];
	struct decode_provider *dp;

	if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
		*out = (uint32_t)strtoul(str, NULL, 0);
		names_out[0] = '\0';
		return (true);
	}

	if (!keyword_names_wellformed(str))
		return (false);

	dp = ensure_blob_registered(provider);
	if (dp != NULL) {
		*out = resolve_keyword_names(dp, str, unknown,
		    sizeof(unknown));
		if (unknown[0] != '\0')
			errx(1, "provider '%s' has no keyword named '%s'",
			    provider, unknown);
		if (*out == 0)
			errx(1, "keyword filter '%s' excludes every keyword",
			    str);
		names_out[0] = '\0';
		return (true);
	}
	if (strlen(str) >= names_size)
		errx(1, "keyword list too long: maximum is %zu bytes",
		    names_size - 1);

	warnx("provider '%s' has no decode blob yet; keywords apply once it "
	    "does", provider);
	strlcpy(names_out, str, names_size);
	*out = 0xFFFFFFFF;
	pending_keyword_filters++;
	return (true);
}

/*
 * Narrow any subscription still carrying unresolved keyword names, once its
 * provider registers and publishes a decode blob. Until that happens the
 * subscription is unfiltered, so a provider that emits as it registers can
 * land a few events outside the filter.
 */
static void
resolve_pending_keywords(void)
{
	char unknown[ELOG_KEYWORD_NAMES_MAX];
	struct eventlog_set_subscription_keywords_req req;
	struct subscription *sub;
	struct decode_provider *dp;
	uint32_t keywords;
	int i;

	for (i = 0; i < subscription_count; i++) {
		sub = &subscriptions[i];
		if (sub->pending_names[0] == '\0')
			continue;
		dp = ensure_blob_registered(sub->provider_name);
		if (dp == NULL)
			continue;

		keywords = resolve_keyword_names(dp, sub->pending_names,
		    unknown, sizeof(unknown));
		if (unknown[0] != '\0')
			warnx("provider '%s' has no keyword named '%s'; "
			    "ignoring it", sub->provider_name, unknown);
		if (keywords == 0) {
			warnx("keyword filter '%s' excludes every keyword",
			    sub->pending_names);
			sub->pending_names[0] = '\0';
			pending_keyword_filters--;
			continue;
		}
		keywords |= EVENTLOG_KEYWORD_SESSION;

		memset(&req, 0, sizeof(req));
		strlcpy(req.provider_name, sub->provider_name,
		    sizeof(req.provider_name));
		req.keywords = keywords;
		/*
		 * A failure here is permanent -- a kernel without the ioctl,
		 * or a name this fd never subscribed to -- so say what the
		 * capture gets instead and stop retrying it every pass.
		 */
		if (ioctl(eventlog_fd,
		    EVENTLOG_IOCTL_SET_SUBSCRIPTION_KEYWORDS, &req) != 0)
			warn("provider '%s': keywords stay unfiltered",
			    sub->provider_name);

		sub->pending_names[0] = '\0';
		pending_keyword_filters--;
	}
}

static size_t
parse_size(const char *size_str)
{
	char *endptr;
	unsigned long long size;
	char unit;

	size = strtoull(size_str, &endptr, 0);
	if (endptr == size_str)
		errx(1, "invalid buffer size: %s", size_str);

	/* Skip whitespace */
	while (*endptr == ' ' || *endptr == '\t')
		endptr++;

	/* Check for unit suffix */
	unit = *endptr;
	if (unit != '\0') {
		endptr++; /* Skip the unit character */
		/* Check for any remaining characters */
		while (*endptr == ' ' || *endptr == '\t')
			endptr++;
		if (*endptr != '\0')
			errx(1, "invalid buffer size: trailing characters after unit");

		switch (unit) {
		case 'K':
		case 'k':
			size *= 1024;
			break;
		case 'M':
		case 'm':
			size *= 1024 * 1024;
			break;
		case 'G':
		case 'g':
			size *= 1024 * 1024 * 1024;
			break;
		default:
			errx(1, "invalid buffer size unit: %c (use K, M, or G)", unit);
		}
	}

	if (size < EVENTLOG_BUFFER_SIZE_MIN)
		errx(1, "buffer size too small: minimum is %u bytes",
		    EVENTLOG_BUFFER_SIZE_MIN);
	if (size > EVENTLOG_BUFFER_SIZE_MAX)
		errx(1, "buffer size too large: maximum is %u bytes",
		    EVENTLOG_BUFFER_SIZE_MAX);

	return ((size_t)size);
}

/*
 * Format timestamp. If base_ts and base_utc_us are set (e.g. from file header),
 * computes UTC. With show_date, formats as YYYY-MM-DD HH:MM:SS.uuuuuu;
 * otherwise just HH:MM:SS.uuuuuu. Falls back to uptime HH:MM:SS.uuuuuu.
 */
static void
format_timestamp(uint64_t us, char *buf, size_t bufsize,
    uint64_t base_ts, uint64_t base_utc_us)
{
	if (base_utc_us != 0) {
		int64_t delta = (int64_t)us - (int64_t)base_ts;
		uint64_t utc_us = (uint64_t)((int64_t)base_utc_us + delta);
		time_t sec = (time_t)(utc_us / 1000000);
		unsigned long usec = (unsigned long)(utc_us % 1000000);
		struct tm *tm = gmtime(&sec);
		if (tm != NULL) {
			if (show_date)
				snprintf(buf, bufsize,
				    "%04d-%02d-%02d %02d:%02d:%02d.%06lu",
				    tm->tm_year + 1900, tm->tm_mon + 1,
				    tm->tm_mday, tm->tm_hour, tm->tm_min,
				    tm->tm_sec, usec);
			else
				snprintf(buf, bufsize, "%02d:%02d:%02d.%06lu",
				    tm->tm_hour, tm->tm_min, tm->tm_sec,
				    usec);
			return;
		}
	}
	/* Fallback: uptime format */
	{
		uint64_t seconds = us / 1000000;
		uint64_t microseconds = us % 1000000;
		uint64_t hours = seconds / 3600;
		uint64_t minutes = (seconds % 3600) / 60;
		uint64_t secs = seconds % 60;
		snprintf(buf, bufsize, "%02llu:%02llu:%02llu.%06llu",
		    (unsigned long long)hours,
		    (unsigned long long)minutes,
		    (unsigned long long)secs,
		    (unsigned long long)microseconds);
	}
}

/* Forward declarations */
static void write_binary_header_to_file(FILE *fp, uint64_t capture_start_time,
    uint64_t start_utc_time_us, struct embedded_set *emb);
static size_t parse_and_print_events(const unsigned char *data, size_t len);

/*
 * Get or create the output file for a session when using -o dir= mode.
 * Returns NULL if output_dir is not set (single-file mode).
 */
#define SESSION_ID_STR_MAX 32

static FILE *
get_session_output_file(const char *session_id)
{
	struct session_file *sf;
	char sanitized[SESSION_ID_STR_MAX];
	char fullpath[PATH_MAX];
	size_t i, j;

	if (output_dir == NULL)
		return (NULL);

	STAILQ_FOREACH(sf, &session_files, link) {
		if (strcmp(sf->session_id, session_id) == 0)
			return (sf->fp);
	}

	for (i = 0, j = 0; session_id[i] != '\0' && j < (sizeof(sanitized) - 1); i++) {
		char c = session_id[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_')
			sanitized[j++] = c;
		else if (c == '/' || c == '\\')
			sanitized[j++] = '_';
	}
	sanitized[j] = '\0';
	if (j == 0)
		snprintf(sanitized, sizeof(sanitized), "global");

	sf = calloc(1, sizeof(*sf));
	if (sf == NULL)
		err(1, "calloc(session_file)");
	sf->session_id = strdup(session_id);
	if (sf->session_id == NULL)
		err(1, "strdup");
	if (snprintf(fullpath, sizeof(fullpath), "%s/%s.elog", output_dir, sanitized) >= (int)sizeof(fullpath))
		errx(1, "path too long");
	sf->filepath = strdup(fullpath);
	if (sf->filepath == NULL)
		err(1, "strdup");
	sf->fp = fopen(fullpath, "wb");
	if (sf->fp == NULL)
		err(1, "fopen(%s)", fullpath);
	STAILQ_INSERT_TAIL(&session_files, sf, link);
	return (sf->fp);
}

/*
 * Find session_file by session_id (for updating header).
 */
static struct session_file *
find_session_file(const char *session_id)
{
	struct session_file *sf;

	STAILQ_FOREACH(sf, &session_files, link) {
		if (strcmp(sf->session_id, session_id) == 0)
			return (sf);
	}
	return (NULL);
}

/* Fresh drop-counter snapshot, or all-zero if the device isn't open. */
static void
fetch_eventlog_stats(struct eventlog_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	if (eventlog_fd >= 0)
		(void)ioctl(eventlog_fd, EVENTLOG_IOCTL_GET_STATS, stats);
}

static void
init_binary_header(struct elog_binary_header *hdr, uint64_t capture_start,
    uint64_t start_utc_us, uint64_t event_count)
{
	memcpy(hdr->magic, ELOG_BINARY_MAGIC, 4);
	hdr->version = ELOG_BINARY_VERSION;
	hdr->capture_start = capture_start;
	hdr->start_utc_us = start_utc_us;
	hdr->event_count = event_count;
	hdr->counter_count = ELOG_COUNTER_COUNT;
}

/* Fill the header's trailing counters array from a stats snapshot, or
 * all-zero if stats is NULL (the initial placeholder-header write before
 * any events exist). */
static void
fill_binary_header_counters(uint64_t counters[ELOG_COUNTER_COUNT],
    const struct eventlog_stats *stats)
{
	counters[ELOG_COUNTER_KERNEL_DROPPED] =
	    stats != NULL ? stats->dropped_events : 0;
	counters[ELOG_COUNTER_USER_DROPPED_FULL] =
	    stats != NULL ? stats->user_dropped_full : 0;
	counters[ELOG_COUNTER_USER_DROPPED_PREJOIN] =
	    stats != NULL ? stats->user_dropped_prejoin : 0;
	counters[ELOG_COUNTER_USER_DROPPED_LATE] =
	    stats != NULL ? stats->user_dropped_late : 0;
}

static void
rewrite_binary_header(FILE *fp, uint64_t capture_start,
    uint64_t start_utc_us, uint64_t event_count,
    const struct eventlog_stats *stats)
{
	struct elog_binary_header hdr;
	uint64_t counters[ELOG_COUNTER_COUNT];

	init_binary_header(&hdr, capture_start, start_utc_us, event_count);
	fill_binary_header_counters(counters, stats);
	if (fseek(fp, 0, SEEK_SET) != 0)
		err(1, "fseek");
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(binary header)");
	if (fwrite(counters, sizeof(counters), 1, fp) != 1)
		err(1, "fwrite(binary header counters)");
}

/*
 * Extract TCP connection metadata from events for file rename (-f tcp).
 * Only captures the first log_id and first connection address seen per session.
 *
 * Matches events/fields by the name strings the "tcp" provider's decode blob
 * declares (CONN_SET_IP_V4/V6, LOG_ID, src_port/dst_port/dst_addr/log_id),
 * defined in FreeBSD/include/eventlog/tcp_eventlog_schema.src. Unlike the old
 * compile-time C decoders, nothing here is checked at build time: renaming or
 * removing one of these in the schema silently stops -f tcp from classifying
 * sessions instead of failing to compile. Keep the two in sync by hand.
 */
static void
extract_tcp_metadata(struct session_file *sf,
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	struct decode_provider *dp;
	const char *evname;
	struct decode_value sport, dport, daddr, lid;

	if (sf == NULL || (sf->has_log_id && sf->has_conn_info) ||
	    strcmp(get_provider_name(hdr->provider_id), "tcp") != 0)
		return;

	dp = provider_dp_by_id(hdr->provider_id);
	if (dp == NULL)
		return;
	evname = decode_event_id_to_name(dp, hdr->event_id);
	if (evname == NULL)
		return;

	if (strcmp(evname, "CONN_SET_IP_V4") == 0 ||
	    strcmp(evname, "CONN_SET_IP_V6") == 0) {
		int af;

		if (sf->has_conn_info)
			return;
		if (!decode_get_field(dp, hdr->event_id, "src_port", payload,
		    payload_size, &sport) ||
		    !decode_get_field(dp, hdr->event_id, "dst_port", payload,
		    payload_size, &dport) ||
		    !decode_get_field(dp, hdr->event_id, "dst_addr", payload,
		    payload_size, &daddr))
			return;
		af = (strcmp(evname, "CONN_SET_IP_V4") == 0) ? AF_INET :
		    AF_INET6;
		sf->local_port = ntohs((uint16_t)sport.u);
		sf->remote_port = ntohs((uint16_t)dport.u);
		inet_ntop(af, daddr.ptr, sf->remote_ip, sizeof(sf->remote_ip));
		sf->has_conn_info = true;
	} else if (strcmp(evname, "LOG_ID") == 0) {
		if (sf->has_log_id)
			return;
		if (!decode_get_field(dp, hdr->event_id, "log_id", payload,
		    payload_size, &lid))
			return;
		snprintf(sf->log_id, sizeof(sf->log_id), "%.*s",
		    (int)lid.len, (const char *)lid.ptr);
		if (sf->log_id[0] != '\0')
			sf->has_log_id = true;
	}
}

/*
 * Rename a session file based on captured TCP metadata.
 * Format: <log_id>_<local_port>_<remote_ip>_<remote_port>.elog
 * Missing fields are replaced with "unknown". If no metadata at all, skip rename.
 */
static void
rename_session_file(struct session_file *sf)
{
	char newpath[PATH_MAX];
	const char *log_id_str, *remote_ip_str;
	char local_port_str[8], remote_port_str[8];

	if (!format_tcp || sf == NULL || sf->filepath == NULL ||
	    output_dir == NULL)
		return;
	if (!sf->has_log_id && !sf->has_conn_info)
		return;

	log_id_str = sf->has_log_id ? sf->log_id : "unknown";
	remote_ip_str = sf->has_conn_info ? sf->remote_ip : "unknown";
	if (sf->has_conn_info) {
		snprintf(local_port_str, sizeof(local_port_str), "%u",
		    sf->local_port);
		snprintf(remote_port_str, sizeof(remote_port_str), "%u",
		    sf->remote_port);
	} else {
		strlcpy(local_port_str, "unknown", sizeof(local_port_str));
		strlcpy(remote_port_str, "unknown", sizeof(remote_port_str));
	}

	if (snprintf(newpath, sizeof(newpath), "%s/%s_%s_%s_%s.elog",
	    output_dir, log_id_str, local_port_str, remote_ip_str,
	    remote_port_str) >= (int)sizeof(newpath))
		return;

	if (rename(sf->filepath, newpath) == 0) {
		free(sf->filepath);
		sf->filepath = strdup(newpath);
	}
}

static void
close_session_file(const char *session_id)
{
	struct session_file *sf, *sf_next;

	for (sf = STAILQ_FIRST(&session_files); sf != NULL; sf = sf_next) {
		sf_next = STAILQ_NEXT(sf, link);
		if (strcmp(sf->session_id, session_id) == 0) {
			if (sf->header_written) {
				struct eventlog_stats stats;

				fetch_eventlog_stats(&stats);
				rewrite_binary_header(sf->fp, sf->capture_start,
				    sf->start_utc_us, sf->event_count, &stats);
			}
			fflush(sf->fp);
			fclose(sf->fp);
			sf->fp = NULL;
			rename_session_file(sf);
			STAILQ_REMOVE(&session_files, sf, session_file, link);
			free(sf->filepath);
			free(sf->session_id);
			embedded_set_reset(&sf->embedded);
			free(sf);
			return;
		}
	}
}

static void
write_binary_header_to_file(FILE *fp, uint64_t capture_start_time,
    uint64_t start_utc_time_us, struct embedded_set *emb)
{
	struct elog_binary_header hdr;
	uint64_t counters[ELOG_COUNTER_COUNT];
	uint32_t i;

	uint32_t nproviders;

	init_binary_header(&hdr, capture_start_time, start_utc_time_us, 0);
	fill_binary_header_counters(counters, NULL);
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(binary header)");
	if (fwrite(counters, sizeof(counters), 1, fp) != 1)
		err(1, "fwrite(binary header counters)");
	nproviders = provider_map_count;
	if (machine_metadata_enabled())
		nproviders++;
	if (fwrite(&nproviders, sizeof(nproviders), 1, fp) != 1)
		err(1, "fwrite(provider count)");
	for (i = 0; i < provider_map_count; i++) {
		if (fwrite(&provider_map[i], sizeof(provider_map[i]), 1, fp) != 1)
			err(1, "fwrite(provider)");
		embedded_set_add_provider(emb, &provider_map[i]);
	}
	if (machine_metadata_enabled()) {
		const struct eventlog_provider_info *mpi;

		mpi = machine_metadata_provider();
		if (fwrite(mpi, sizeof(*mpi), 1, fp) != 1)
			err(1, "fwrite(machine provider)");
		embedded_set_add_provider(emb, mpi);
	}

	/*
	 * Decode-blob section, present since version 2. Always written; the
	 * count is zero if --no-embed-decode suppressed embedding. The registry is
	 * already deduplicated by schema_id, so each entry is written once as
	 * {schema_id, uint32 size, raw bytes}. A provider table entry binds its
	 * provider_id to one of these schema_ids.
	 */
	{
		uint32_t blob_count = 0;

		if (embed_decode) {
			for (i = 0; i < decode_entry_count; i++)
				if (decode_entries[i].blob != NULL)
					blob_count++;
		}
		if (fwrite(&blob_count, sizeof(blob_count), 1, fp) != 1)
			err(1, "fwrite(blob count)");
		if (!embed_decode)
			return;
		for (i = 0; i < decode_entry_count; i++) {
			struct decode_entry *e = &decode_entries[i];
			uint32_t sz;

			if (e->blob == NULL)
				continue;
			if (fwrite(e->schema_id, sizeof(e->schema_id), 1, fp) !=
			    1)
				err(1, "fwrite(blob schema_id)");
			sz = (uint32_t)e->blob_size;
			if (fwrite(&sz, sizeof(sz), 1, fp) != 1)
				err(1, "fwrite(blob size)");
			if (fwrite(e->blob, e->blob_size, 1, fp) != 1)
				err(1, "fwrite(blob)");
			embedded_set_add_schema(emb, e->schema_id);
		}
	}
}

/*
 * Ensure `provider_id` is embedded in this output file's provider table --
 * writing an ELOG_EVENT_PROVIDER_INFO_ID record, and (if embedding is on) an
 * ELOG_EVENT_PROVIDER_BLOB_ID record -- the first time it's seen for this
 * file. No-op if already embedded. *bytes, if non-NULL, accumulates bytes
 * written (for --roll-size).
 */
static void
write_provider_announcement(FILE *fp, struct embedded_set *emb,
    uint16_t provider_id, uint64_t timestamp, uint64_t *bytes)
{
	struct eventlog_provider_info *pi;
	struct eventlog_event_header hdr;
	struct decode_entry *e;
	uint32_t sz;

	/* get_provider_entry(), not provider_map_lookup(): a provider whose
	 * first event lands here before anything else has looked it up
	 * (e.g. --roll-* output, which never calls get_provider_name())
	 * still needs the refresh-on-miss to find it at all. */
	pi = get_provider_entry(provider_id);
	if (pi == NULL)
		return;
	if (embedded_set_has_provider(emb, pi))
		return;

	memset(&hdr, 0, sizeof(hdr));
	hdr.event_length = (uint16_t)(sizeof(hdr) + sizeof(*pi));
	hdr.provider_id = provider_id;
	hdr.timestamp = timestamp;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = ELOG_EVENT_PROVIDER_INFO_ID;
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(provider-info announcement header)");
	if (fwrite(pi, sizeof(*pi), 1, fp) != 1)
		err(1, "fwrite(provider-info announcement payload)");
	embedded_set_add_provider(emb, pi);
	if (bytes != NULL)
		*bytes += hdr.event_length;

	if (!embed_decode || schema_id_is_zero(pi->schema_id) ||
	    embedded_set_has_schema(emb, pi->schema_id))
		return;
	(void)ensure_blob_registered_by_schema(pi->schema_id, pi->name);
	e = decode_registry_find_by_schema(pi->schema_id);
	if (e == NULL || e->blob == NULL)
		return;
	if (e->blob_size > ELOG_INBAND_BLOB_MAX) {
		warnx("decode blob for provider '%s' is %zu bytes, too large "
		    "to embed for a provider that registered mid-capture "
		    "(max %u); replay will need the live kernel to decode it",
		    escape_untrusted(pi->name), e->blob_size,
		    (unsigned)ELOG_INBAND_BLOB_MAX);
		return;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.event_length = (uint16_t)(sizeof(hdr) + sizeof(e->schema_id) +
	    sizeof(sz) + e->blob_size);
	hdr.provider_id = provider_id;
	hdr.timestamp = timestamp;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = ELOG_EVENT_PROVIDER_BLOB_ID;
	sz = (uint32_t)e->blob_size;
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(provider-blob announcement header)");
	if (fwrite(e->schema_id, sizeof(e->schema_id), 1, fp) != 1)
		err(1, "fwrite(provider-blob announcement schema_id)");
	if (fwrite(&sz, sizeof(sz), 1, fp) != 1)
		err(1, "fwrite(provider-blob announcement size)");
	if (fwrite(e->blob, e->blob_size, 1, fp) != 1)
		err(1, "fwrite(provider-blob announcement blob)");
	embedded_set_add_schema(emb, pi->schema_id);
	if (bytes != NULL)
		*bytes += hdr.event_length;
}

static void
write_capture_metadata(FILE *fp, struct embedded_set *emb, uint64_t ts,
    uint64_t *bytes, uint64_t *event_count)
{

	if (!machine_metadata_enabled())
		return;
	machine_metadata_write_events(fp, emb, ts, bytes, event_count,
	    write_provider_announcement);
}

/* Map an event timestamp (us since boot) to UTC us via the global anchor. */
static uint64_t
roll_event_utc_us(uint64_t event_ts)
{
	int64_t delta = (int64_t)event_ts - (int64_t)roll_base_ts;
	return ((uint64_t)((int64_t)roll_base_utc_us + delta));
}

/*
 * Open a new rolling file for the given time bucket, starting the filename
 * search at `seq` and skipping any names already on disk (e.g. a prior run
 * within the same bucket whose captures have not been drained).  Writes to
 * a ".tmp.*" name; roll_close() renames it to the final name.
 */
static void
roll_open(uint64_t bucket, unsigned int seq, uint64_t first_ts,
    uint64_t first_utc_us)
{
	time_t tsec;
	struct tm tmv;
	char stamp[24];
	int fd;

	/*
	 * Name by the aligned interval start when time-rolling, otherwise by
	 * the first event's wall-clock time (size-only rolling).
	 */
	if (roll_time_us > 0)
		tsec = (time_t)((bucket * roll_time_us) / 1000000ULL);
	else
		tsec = (time_t)(first_utc_us / 1000000ULL);
	gmtime_r(&tsec, &tmv);
	strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H%M%S", &tmv);

	for (;;) {
		if (snprintf(rollf.final_path, sizeof(rollf.final_path),
		    "%s/%s-%sZ-%05u.elog", output_dir, roll_prefix, stamp,
		    seq) >= (int)sizeof(rollf.final_path))
			errx(1, "roll output path too long");
		if (snprintf(rollf.tmp_path, sizeof(rollf.tmp_path),
		    "%s/.tmp.%s-%sZ-%05u.elog", output_dir, roll_prefix, stamp,
		    seq) >= (int)sizeof(rollf.tmp_path))
			errx(1, "roll temp path too long");

		/* Skip a seq whose finished file already exists (undrained),
		 * so the rename() in roll_close() never clobbers one. */
		if (access(rollf.final_path, F_OK) == 0) {
			seq++;
			continue;
		}
		if (output_gzip_level > 0) {
			char gzpath[PATH_MAX];

			gzip_path_for_src(rollf.final_path, gzpath,
			    sizeof(gzpath));
			if (access(gzpath, F_OK) == 0) {
				seq++;
				continue;
			}
		}
		/* O_EXCL makes the "not present" test and the create atomic:
		 * a concurrent writer racing on the same tmp name fails here
		 * with EEXIST instead of silently truncating an in-progress
		 * file (which fopen("wb") would do). */
		fd = open(rollf.tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (fd >= 0)
			break;
		if (errno == EEXIST) {
			seq++;
			continue;
		}
		err(1, "open(%s)", rollf.tmp_path);
	}

	rollf.fp = fdopen(fd, "wb");
	if (rollf.fp == NULL)
		err(1, "fdopen(%s)", rollf.tmp_path);
	rollf.capture_start = first_ts;
	rollf.start_utc_us = first_utc_us;
	rollf.event_count = 0;
	rollf.bucket = bucket;
	rollf.seq = seq;
	/* Fresh per-file tracking: a provider embedded in a prior rolled file
	 * is not embedded in this one until announced/re-written here. */
	embedded_set_reset(&rollf.embedded);
	write_binary_header_to_file(rollf.fp, first_ts, first_utc_us,
	    &rollf.embedded);
	rollf.bytes = sizeof(struct elog_binary_header) +
	    sizeof(uint64_t) * ELOG_COUNTER_COUNT +
	    sizeof(uint32_t) +
	    (uint64_t)(provider_map_count +
	    (machine_metadata_enabled() ? 1 : 0)) *
	    sizeof(provider_map[0]);
	write_capture_metadata(rollf.fp, &rollf.embedded, first_ts,
	    &rollf.bytes, &rollf.event_count);
}

/*
 * True if `name` is a finalized rolled file this process would have created:
 * <prefix>-YYYY-MM-DDTHHMMSSZ-NNNNN.elog or the same with a ".gz" suffix.
 * Deliberately strict so pruning never touches the in-progress ".tmp.*"
 * dotfile or unrelated files that merely share the prefix.
 */
static bool
roll_owned_name(const char *name)
{
	static const char pat[] = "dddd-dd-ddTddddddZ-ddddd";
	size_t plen = strlen(roll_prefix);
	const char *p;
	const char *suffix;

	if (strncmp(name, roll_prefix, plen) != 0 || name[plen] != '-')
		return (false);
	p = name + plen + 1;
	for (size_t i = 0; pat[i] != '\0'; i++) {
		if (pat[i] == 'd') {
			if (p[i] < '0' || p[i] > '9')
				return (false);
		} else if (p[i] != pat[i])
			return (false);
	}
	suffix = p + strlen(pat);
	if (strcmp(suffix, ".elog") == 0)
		return (true);
	if (strcmp(suffix, ".elog.gz") == 0)
		return (true);
	return (false);
}

static int
roll_name_cmp(const void *a, const void *b)
{
	return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

/*
 * Enforce --roll-keep: after a file is finalized, delete the oldest of our
 * own finalized files until at most roll_keep remain.  Names sort
 * lexicographically in chronological order (fixed-width timestamp then
 * zero-padded seq), so the oldest are simply the first entries.  Scans the
 * directory each time so files left by a previous run are counted too.
 */
static void
roll_prune(void)
{
	DIR *d;
	struct dirent *de;
	char **names = NULL;
	size_t n = 0, cap = 0;

	if (roll_keep == 0)
		return;
	d = opendir(output_dir);
	if (d == NULL)
		err(1, "opendir(%s)", output_dir);
	while ((de = readdir(d)) != NULL) {
		if (!roll_owned_name(de->d_name))
			continue;
		if (n == cap) {
			cap = cap ? cap * 2 : 16;
			names = reallocarray(names, cap, sizeof(*names));
			if (names == NULL)
				err(1, "reallocarray");
		}
		names[n] = strdup(de->d_name);
		if (names[n] == NULL)
			err(1, "strdup");
		n++;
	}
	closedir(d);

	if (n > roll_keep) {
		qsort(names, n, sizeof(*names), roll_name_cmp);
		for (size_t i = 0; i < n - roll_keep; i++) {
			char path[PATH_MAX];
			size_t len = strlen(names[i]);

			if (snprintf(path, sizeof(path), "%s/%s", output_dir,
			    names[i]) >= (int)sizeof(path))
				continue;
			if (unlink(path) != 0 && errno != ENOENT)
				err(1, "unlink(%s)", path);
			if (len > 3 && strcmp(names[i] + len - 3, ".gz") == 0) {
				char rawname[NAME_MAX + 1];

				memcpy(rawname, names[i], len - 3);
				rawname[len - 3] = '\0';
				if (snprintf(path, sizeof(path), "%s/%s",
				    output_dir, rawname) < (int)sizeof(path))
					unlink(path);
			}
		}
	}
	for (size_t i = 0; i < n; i++)
		free(names[i]);
	free(names);
}

/*
 * <output_dir>/.<prefix>.seq records the last finalized file's bucket and
 * seq, so a restarted elog continues the interval's sequence. The uploader
 * deletes uploaded files, and a name reused within the interval would
 * otherwise collide with one already uploaded.
 */
static int
roll_seq_path(char *buf, size_t len, const char *tmp)
{
	return (snprintf(buf, len, "%s/.%s%s.seq", output_dir, tmp,
	    roll_prefix) < (int)len ? 0 : -1);
}

static void
roll_seq_save(uint64_t bucket, unsigned int seq)
{
	char path[PATH_MAX], tmp[PATH_MAX];
	FILE *fp;

	if (roll_seq_path(path, sizeof(path), "") != 0 ||
	    roll_seq_path(tmp, sizeof(tmp), "tmp.") != 0)
		return;
	fp = fopen(tmp, "w");
	if (fp == NULL) {
		warn("fopen(%s)", tmp);
		return;
	}
	fprintf(fp, "%ju %u\n", (uintmax_t)bucket, seq);
	if (fclose(fp) != 0 || rename(tmp, path) != 0) {
		warn("write(%s)", path);
		unlink(tmp);
	}
}

static void
roll_seq_load(void)
{
	char path[PATH_MAX];
	uintmax_t bucket;
	unsigned int seq;
	FILE *fp;

	roll_resume_loaded = true;
	if (roll_seq_path(path, sizeof(path), "") != 0)
		return;
	fp = fopen(path, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%ju %u", &bucket, &seq) == 2) {
		roll_resume_bucket = bucket;
		roll_resume_seq = seq;
		roll_resume_valid = true;
	}
	fclose(fp);
}

/* Finalize the current rolling file: backfill the header, then tmp->final. */
static void
roll_close(void)
{
	struct eventlog_stats stats;

	if (rollf.fp == NULL)
		return;
	fetch_eventlog_stats(&stats);
	rewrite_binary_header(rollf.fp, rollf.capture_start,
	    rollf.start_utc_us, rollf.event_count, &stats);
	/*
	 * The rename() below is the "file complete" signal to the directory
	 * watcher, so a silent flush/close write error (e.g. disk full) must
	 * not publish a truncated capture as finished: check both first.
	 */
	if (fflush(rollf.fp) != 0 || fclose(rollf.fp) != 0)
		err(1, "write(%s)", rollf.tmp_path);
	rollf.fp = NULL;
	if (rename(rollf.tmp_path, rollf.final_path) != 0)
		err(1, "rename(%s -> %s)", rollf.tmp_path, rollf.final_path);
	roll_prev_bucket = rollf.bucket;
	roll_prev_seq = rollf.seq;
	roll_prev_valid = true;
	if (roll_time_us > 0)
		roll_seq_save(rollf.bucket, rollf.seq);
	if (output_gzip_level > 0)
		gzip_enqueue(rollf.final_path);
	roll_prune();
}

/*
 * Finalize the open file once the wall clock is past its interval's end
 * plus a grace (a quarter interval, at most ELOG_ROLL_IDLE_GRACE_US), so a
 * capture that goes quiet still publishes its last interval.
 */
static void
roll_idle_close(void)
{
	uint64_t grace_us, now_utc_us;

	if (rollf.fp == NULL || roll_time_us == 0 || !roll_base_set)
		return;
	grace_us = MIN(roll_time_us / 4, ELOG_ROLL_IDLE_GRACE_US);
	now_utc_us = roll_event_utc_us(monotonic_us());
	if (now_utc_us < (rollf.bucket + 1) * roll_time_us + grace_us)
		return;
	if (getenv("ELOG_ROLL_DEBUG") != NULL)
		fprintf(stderr, "ROLL_DEBUG: idle close: bucket=%llu "
		    "event_count=%llu\n", (unsigned long long)rollf.bucket,
		    (unsigned long long)rollf.event_count);
	roll_close();
}

static void
write_roll_event(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	size_t event_length;
	uint64_t event_utc_us, bucket;

	event_length = sizeof(struct eventlog_event_header) + payload_size;
	if (event_length > UINT16_MAX)
		errx(1, "Event too large for binary format: %zu bytes",
		    event_length);

	if (!roll_base_set) {
		capture_anchor(&roll_base_ts, &roll_base_utc_us);
		roll_base_set = true;
	}

	event_utc_us = roll_event_utc_us(hdr->timestamp);
	bucket = (roll_time_us > 0) ? (event_utc_us / roll_time_us) : 0;

	/*
	 * A time-interval boundary (by event time) forces a fresh file so
	 * no file spans an interval; the size cap splits within an
	 * interval (seq++). Only a bucket *increase* rolls: some providers
	 * (periodic samplers like tcp/hpts/if) can still deliver a
	 * straggler timestamped just before the boundary after the merge
	 * has already crossed it by more than the read watermark absorbs.
	 * Reopening an old bucket for one straggler is worse than filing it
	 * under the current bucket, so a bucket decrease is just absorbed
	 * into whatever file is already open (see ELOG_ROLL_DEBUG below).
	 */
	if (rollf.fp != NULL && roll_time_us > 0 && bucket > rollf.bucket) {
		if (getenv("ELOG_ROLL_DEBUG") != NULL)
			fprintf(stderr, "ROLL_DEBUG: bucket-change close: "
			    "old_bucket=%llu new_bucket=%llu event_count=%llu "
			    "bytes=%llu\n", (unsigned long long)rollf.bucket,
			    (unsigned long long)bucket,
			    (unsigned long long)rollf.event_count,
			    (unsigned long long)rollf.bytes);
		roll_close();
	} else if (rollf.fp != NULL && roll_time_us > 0 &&
	    bucket < rollf.bucket) {
		if (getenv("ELOG_ROLL_DEBUG") != NULL)
			fprintf(stderr, "ROLL_DEBUG: straggler absorbed: "
			    "event_bucket=%llu open_bucket=%llu\n",
			    (unsigned long long)bucket,
			    (unsigned long long)rollf.bucket);
	} else if (rollf.fp != NULL && roll_size_bytes > 0 &&
	    rollf.event_count > 0 &&
	    rollf.bytes + event_length > roll_size_bytes) {
		if (getenv("ELOG_ROLL_DEBUG") != NULL)
			fprintf(stderr, "ROLL_DEBUG: size close: bucket=%llu "
			    "event_count=%llu bytes=%llu event_length=%zu "
			    "roll_size_bytes=%llu\n",
			    (unsigned long long)rollf.bucket,
			    (unsigned long long)rollf.event_count,
			    (unsigned long long)rollf.bytes, event_length,
			    (unsigned long long)roll_size_bytes);
		roll_close();
	}

	if (rollf.fp == NULL) {
		unsigned int seq = 0;
		bool bucket_changed;

		/* After an idle close, absorb an older straggler as above. */
		if (roll_prev_valid && bucket < roll_prev_bucket)
			bucket = roll_prev_bucket;
		bucket_changed = roll_prev_valid && bucket != roll_prev_bucket;

		if (roll_prev_valid && bucket == roll_prev_bucket)
			seq = roll_prev_seq + 1;
		else if (!roll_prev_valid && roll_time_us > 0) {
			if (!roll_resume_loaded)
				roll_seq_load();
			if (roll_resume_valid && bucket == roll_resume_bucket)
				seq = roll_resume_seq + 1;
		}
		roll_open(bucket, seq, hdr->timestamp, event_utc_us);

		/*
		 * Re-trigger dump_state at a genuine bucket boundary so
		 * this new file is self-contained, not just the first
		 * rolled file. Best-effort: a failed ioctl just means this
		 * file misses the refresh.
		 */
		if (bucket_changed) {
			if (ioctl(eventlog_fd,
			    EVENTLOG_IOCTL_TRIGGER_DUMP_STATE) == 0) {
				roll_dump_triggers_issued++;
				roll_dump_trigger_issued_at = monotonic_us();
			} else
				warn("ioctl(EVENTLOG_IOCTL_TRIGGER_DUMP_STATE)");
		}
	}

	write_provider_announcement(rollf.fp, &rollf.embedded,
	    hdr->provider_id, hdr->timestamp, &rollf.bytes);

	struct eventlog_event_header hdr_copy = *hdr;
	hdr_copy.event_length = (uint16_t)event_length;
	if (fwrite(&hdr_copy, sizeof(hdr_copy), 1, rollf.fp) != 1)
		err(1, "fwrite(event header)");
	if (payload_size > 0 && fwrite(payload, payload_size, 1, rollf.fp) != 1)
		err(1, "fwrite(payload)");
	rollf.event_count++;
	rollf.bytes += event_length;
}

/*
 * libelog_user_symbols emits one synthesised USER_SYMBOL_RANGE per
 * STT_FUNC by calling this trampoline; we just funnel back into the
 * normal write_binary_event() path so the synthetic events join the
 * stream on the same file as their parent USER_FILE.
 */
static void write_binary_event(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size);
static void
user_symbols_emit(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size, void *cookie __unused)
{
	write_binary_event(hdr, payload, payload_size);
}

/*
 * Hand an event to libelog_user_symbols *after* it lands on disk. The
 * library only acts on symbols.USER_FILE; for those it parses the
 * named binary and synthesises one symbols.USER_SYMBOL_RANGE per
 * STT_FUNC, calling user_symbols_emit() above to write them to the
 * same file. No-op when -U wasn't passed, so the subscriber-only path
 * costs only the function-call dispatch. Shared by both
 * write_binary_event() branches below (roll and non-roll) so -U works
 * under --roll-time too.
 */
static void
observe_user_symbols(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	const char *provider_name;

	if (!user_symbols_enabled)
		return;
	provider_name = get_provider_name(hdr->provider_id);
	elog_user_symbols_observe(provider_name, hdr, payload, payload_size,
	    user_symbols_emit, NULL);
}

static void
source_lines_emit(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size, void *cookie __unused)
{
	write_binary_event(hdr, payload, payload_size);
}

static void
observe_source_lines(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	const char *provider_name;

	if (!source_lines_enabled)
		return;
	provider_name = get_provider_name(hdr->provider_id);
	elog_source_lines_observe(provider_name, hdr, payload, payload_size);
}

/*
 * Format and print an eventlog event.
 */
static void
write_binary_event(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	char session_id_str[SESSION_ID_STR_MAX];
	FILE *out_fp;
	struct session_file *sf;
	size_t event_length;

	if (roll_enabled) {
		if (hdr->event_id == EVENTLOG_DUMP_COMPLETE_ID &&
		    roll_dump_trigger_issued_at != 0) {
			roll_dump_completes_seen++;
			roll_dump_trigger_lag_us =
			    monotonic_us() - roll_dump_trigger_issued_at;
			roll_dump_trigger_issued_at = 0;
		}
		write_roll_event(hdr, payload, payload_size);
		observe_user_symbols(hdr, payload, payload_size);
		observe_source_lines(hdr, payload, payload_size);
		return;
	}

	snprintf(session_id_str, sizeof(session_id_str), "%s_%lu",
	    get_provider_name(hdr->provider_id),
	    (unsigned long)hdr->session_id);

	if (output_dir != NULL) {
		out_fp = get_session_output_file(session_id_str);
		sf = find_session_file(session_id_str);
	} else {
		out_fp = single_output.fp;
		sf = &single_output;
	}

	if (sf != NULL) {
		if (!sf->header_written) {
			uint64_t ts, utc_us;

			capture_anchor(&ts, &utc_us);
			write_binary_header_to_file(out_fp, ts, utc_us,
			    &sf->embedded);
			write_capture_metadata(out_fp, &sf->embedded, ts,
			    NULL, &sf->event_count);
			sf->header_written = true;
			sf->capture_start = ts;
			sf->start_utc_us = utc_us;
		}
		write_provider_announcement(out_fp, &sf->embedded,
		    hdr->provider_id, hdr->timestamp, NULL);
		sf->event_count++;
	}

	event_length = sizeof(struct eventlog_event_header) + payload_size;
	if (event_length > UINT16_MAX)
		errx(1, "Event too large for binary format: %zu bytes", event_length);

	struct eventlog_event_header hdr_copy = *hdr;
	hdr_copy.event_length = (uint16_t)event_length;
	if (fwrite(&hdr_copy, sizeof(struct eventlog_event_header), 1, out_fp) != 1)
		err(1, "fwrite(event header)");
	if (payload_size > 0 && fwrite(payload, payload_size, 1, out_fp) != 1)
		err(1, "fwrite(payload)");

	if (output_dir != NULL) {
		if (format_tcp)
			extract_tcp_metadata(sf, hdr, payload, payload_size);
		if (hdr->event_id == EVENTLOG_SESSION_END_ID)
			close_session_file(session_id_str);
	}

	observe_user_symbols(hdr, payload, payload_size);
	observe_source_lines(hdr, payload, payload_size);
}

/*
 * Write a decoded text line to fp, escaping bytes that could drive a terminal.
 * Decoded lines splice in attacker-controlled bytes -- char[] payload fields,
 * plus schema-supplied provider/event/enum/flag names and format text that, on
 * a v2+ capture, come from an embedded (and therefore untrusted) decode blob --
 * so a crafted capture could otherwise emit ANSI/escape sequences when viewed.
 * Tab and newline pass through; printable ASCII and high-bit bytes (UTF-8) are
 * left intact; C0 controls, DEL, and the C1 range are rendered as octal \ooo.
 */
static void
fputs_safe(const char *s, FILE *fp)
{
	const unsigned char *p;

	for (p = (const unsigned char *)s; *p != '\0'; p++) {
		if (byte_is_terminal_safe(*p))
			putc((int)*p, fp);
		else
			fprintf(fp, "\\%03o", *p);
	}
}

/*
 * Apply an ELOG_EVENT_PROVIDER_INFO_ID announcement (from a capture file or
 * a kernel late-bind injection): upsert its struct eventlog_provider_info
 * payload into provider_map, exactly as a fresh GET_PROVIDERS2 entry would.
 */
static void
apply_provider_info_announcement(const void *payload, size_t payload_size)
{
	struct eventlog_provider_info info;
	struct eventlog_provider_info *existing;

	if (payload_size != sizeof(info)) {
		warnx("malformed provider-info announcement (%zu bytes, "
		    "expected %zu); ignoring", payload_size, sizeof(info));
		return;
	}
	memcpy(&info, payload, sizeof(info));
	info.name[sizeof(info.name) - 1] = '\0';

	existing = provider_map_lookup(info.provider_id);
	if (existing != NULL) {
		*existing = info;
		return;
	}
	provider_map_ensure(provider_map_count + 1);
	provider_map[provider_map_count++] = info;
}

/*
 * Embed `provider_id` into the currently-open binary output (rolled file
 * or single-file mode) via write_provider_announcement. No-op when no
 * binary file is open yet. Used when a kernel-injected PROVIDER_BLOB has
 * just populated the decode registry so the file gets the INFO+BLOB pair
 * immediately, without waiting for a later real event.
 */
static void
announce_provider_to_current_output(uint16_t provider_id, uint64_t timestamp)
{
	if (!binary_output_mode())
		return;
	if (roll_enabled) {
		if (rollf.fp != NULL)
			write_provider_announcement(rollf.fp, &rollf.embedded,
			    provider_id, timestamp, &rollf.bytes);
		return;
	}
	if (single_output.fp != NULL && single_output.header_written)
		write_provider_announcement(single_output.fp,
		    &single_output.embedded, provider_id, timestamp, NULL);
}

/*
 * Apply an ELOG_EVENT_PROVIDER_BLOB_ID announcement: schema_id[16] +
 * uint32_t size + that many raw decode-blob bytes. Registers it exactly as
 * the header's own decode-blob section does.
 */
static void
apply_provider_blob_announcement(const void *payload, size_t payload_size)
{
	uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
	uint32_t size;
	unsigned char *blob;
	const size_t prefix = sizeof(schema_id) + sizeof(size);

	if (payload_size < prefix) {
		warnx("truncated decode-blob announcement; ignoring");
		return;
	}
	memcpy(schema_id, payload, sizeof(schema_id));
	memcpy(&size, (const char *)payload + sizeof(schema_id), sizeof(size));
	if (size == 0 || size > EVENTLOG_DECODE_BLOB_MAX ||
	    payload_size != prefix + size) {
		warnx("malformed decode-blob announcement (size=%u); ignoring",
		    size);
		return;
	}
	blob = malloc(size);
	if (blob == NULL)
		err(1, "malloc(blob)");
	memcpy(blob, (const char *)payload + prefix, size);
	(void)decode_registry_add(schema_id, NULL, blob, size);
}

/*
 * Returns true if this was a real captured event (the caller should count
 * it), false if it was an elog(1)-internal bookkeeping record (an
 * ELOG_EVENT_PROVIDER_*_ID announcement) that was applied instead of shown.
 */
static bool
print_eventlog_event(const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	char log_line[2048];
	char formatted_buf[1024];
	char session_id_str[SESSION_ID_STR_MAX];
	char timestamp_str[32];
	char event_name_buf[64];
	char event_num_buf[32];
	char relative_buf[32];
	char delta_buf[32];
	const char *provider_name;
	struct decode_provider *dp;
	int formatted_len;

	if (hdr->event_id == ELOG_EVENT_PROVIDER_INFO_ID) {
		/*
		 * Kernel late-bind injection or a record being read back from
		 * a capture. Apply to the map; binary embedding waits for the
		 * matching BLOB (or the first real event) so the decode
		 * registry is populated first.
		 */
		apply_provider_info_announcement(payload, payload_size);
		return (false);
	}
	if (hdr->event_id == ELOG_EVENT_PROVIDER_BLOB_ID) {
		apply_provider_blob_announcement(payload, payload_size);
		/*
		 * Map has the INFO (just applied, or from an earlier record)
		 * and the registry now has the blob — embed both into the
		 * open binary file. Dedupes via embedded_set.
		 */
		announce_provider_to_current_output(hdr->provider_id,
		    hdr->timestamp);
		return (false);
	}

	if (binary_output_mode()) {
		/*
		 * Count events that remain unresolvable after get_provider_entry
		 * (rate-limited refresh + one forced refresh on miss). The
		 * write path still records them; the binding is simply absent.
		 */
		if (hdr->provider_id != ELOG_MACHINE_PROVIDER_ID &&
		    get_provider_entry(hdr->provider_id) == NULL)
			unknown_provider_events++;
		write_binary_event(hdr, payload, payload_size);
		return (true);
	}

	snprintf(session_id_str, sizeof(session_id_str), "%lu",
	    (unsigned long)hdr->session_id);
	provider_name = get_provider_name(hdr->provider_id);

	format_timestamp(hdr->timestamp, timestamp_str, sizeof(timestamp_str),
	    read_capture_start, read_start_utc_us);

	relative_buf[0] = '\0';
	if (show_relative_time) {
		if (first_event_ts == 0)
			first_event_ts = hdr->timestamp;
		uint64_t rel = hdr->timestamp - first_event_ts;
		snprintf(relative_buf, sizeof(relative_buf),
		    "+%llu.%06llu ",
		    (unsigned long long)(rel / 1000000),
		    (unsigned long long)(rel % 1000000));
	}

	delta_buf[0] = '\0';
	if (show_delta_time) {
		uint64_t delta = 0;
		if (prev_event_ts != 0)
			delta = hdr->timestamp - prev_event_ts;
		snprintf(delta_buf, sizeof(delta_buf),
		    "d%llu.%06llu ",
		    (unsigned long long)(delta / 1000000),
		    (unsigned long long)(delta % 1000000));
	}
	prev_event_ts = hdr->timestamp;

	dp = provider_dp_by_id(hdr->provider_id);
	if (dp == NULL)
		formatted_len = snprintf(formatted_buf, sizeof(formatted_buf),
		    "[no decode blob for provider %s; event %u]",
		    provider_name, hdr->event_id);
	else {
		formatted_len = decode_format_payload(dp, hdr->event_id,
		    payload, payload_size, formatted_buf,
		    sizeof(formatted_buf));
		if (formatted_len < 0)
			snprintf(formatted_buf, sizeof(formatted_buf),
			    "[UNKNOWN_EVENT_ID:%u]", hdr->event_id);
	}

	event_num_buf[0] = '\0';
	if (show_event_number)
		snprintf(event_num_buf, sizeof(event_num_buf),
		    "%-8llu ", (unsigned long long)(events_received + 1));

	event_name_buf[0] = '\0';
	if (show_event_name) {
		const char *name = (dp != NULL) ?
		    decode_event_id_to_name(dp, hdr->event_id) : NULL;
		if (name != NULL)
			snprintf(event_name_buf, sizeof(event_name_buf),
			    "[%s]", name);
		else
			snprintf(event_name_buf, sizeof(event_name_buf),
			    "[?%u]", hdr->event_id);
	}

	snprintf(log_line, sizeof(log_line),
	    "%s%s%s[%2u]%04x::%s [%s][%s]%s %s\n",
	    event_num_buf,
	    relative_buf,
	    delta_buf,
	    hdr->cpu,
	    (unsigned int)hdr->thread_id,
	    timestamp_str,
	    provider_name,
	    session_id_str,
	    event_name_buf,
	    formatted_buf);

	fputs_safe(log_line, stdout);
	return (true);
}

static void
update_binary_header(void)
{
	struct session_file *sf;
	struct eventlog_stats stats;

	/* Rolling files backfill their header at each roll_close(). */
	if (roll_enabled)
		return;

	fetch_eventlog_stats(&stats);

	if (output_dir != NULL) {
		STAILQ_FOREACH(sf, &session_files, link) {
			if (sf->header_written)
				rewrite_binary_header(sf->fp, sf->capture_start,
				    sf->start_utc_us, sf->event_count, &stats);
		}
		return;
	}

	if (!single_output.header_written)
		return;
	rewrite_binary_header(single_output.fp, single_output.capture_start,
	    single_output.start_utc_us, single_output.event_count, &stats);
}

static bool
has_gz_extension(const char *filename)
{
	size_t len = strlen(filename);
	return (len >= 3 && strcmp(filename + len - 3, ".gz") == 0);
}

/*
 * Thin wrappers to abstract FILE vs gzFile for the read path.
 */
struct elog_reader {
	FILE *fp;
	gzFile gz;
	bool is_gz;
};

static void
elog_reader_open(struct elog_reader *r, const char *filename)
{
	r->is_gz = has_gz_extension(filename);
	if (r->is_gz) {
		r->fp = NULL;
		r->gz = gzopen(filename, "rb");
		if (r->gz == NULL)
			err(1, "gzopen(%s)", filename);
	} else {
		r->gz = NULL;
		r->fp = fopen(filename, "rb");
		if (r->fp == NULL)
			err(1, "fopen(%s)", filename);
	}
}

static ssize_t
elog_reader_read(struct elog_reader *r, void *buf, size_t len)
{
	if (r->is_gz) {
		int ret = gzread(r->gz, buf, (unsigned)len);
		if (ret < 0) {
			int errnum;
			const char *msg = gzerror(r->gz, &errnum);
			errx(1, "gzread: %s", msg);
		}
		return ((ssize_t)ret);
	}
	return ((ssize_t)fread(buf, 1, len, r->fp));
}

static bool
elog_reader_eof(struct elog_reader *r)
{
	if (r->is_gz)
		return (gzeof(r->gz) != 0);
	return (feof(r->fp) != 0);
}

static void
elog_reader_close(struct elog_reader *r)
{
	if (r->is_gz)
		gzclose(r->gz);
	else
		fclose(r->fp);
}

/*
 * Read exactly 'len' bytes or fail. Returns true on success, false on EOF
 * (partial read at end of file).
 */
static bool
elog_reader_read_exact(struct elog_reader *r, void *buf, size_t len)
{
	size_t total = 0;

	while (total < len) {
		ssize_t n = elog_reader_read(r, (char *)buf + total, len - total);
		if (n <= 0) {
			if (total == 0)
				return (false);
			errx(1, "Unexpected end of file (read %zu of %zu bytes)",
			    total, len);
		}
		total += n;
	}
	return (true);
}

/*
 * Read the embedded decode-blob section (present since version 2) and
 * register each blob. The section
 * starts with a uint32 count, then for each blob: its schema_id, a uint32
 * size, and that many raw bytes. Blobs are keyed (and deduplicated) by
 * schema_id; the recorded id is verified against the blob's content on add.
 */
static void
read_embedded_decode_blobs(struct elog_reader *reader)
{
	uint32_t blob_count, k;

	if (!elog_reader_read_exact(reader, &blob_count, sizeof(blob_count)))
		err(1, "read(blob count)");
	/*
	 * Blobs are deduplicated by schema_id, so a well-formed file never
	 * needs more entries than there are distinct providers. Cap it (like
	 * the provider count above) rather than looping on an
	 * attacker-controlled count -- otherwise a crafted/corrupted file
	 * (trivially small once gzipped) could force many malloc/read/free
	 * cycles here.
	 */
	if (blob_count > ELOG_PROVIDER_MAP_SANE_MAX)
		errx(1, "Invalid embedded decode-blob count %u in file",
		    blob_count);
	for (k = 0; k < blob_count; k++) {
		uint8_t schema_id[EVENTLOG_DECODE_SCHEMA_ID_LEN];
		uint32_t sz;
		unsigned char *blob;

		if (!elog_reader_read_exact(reader, schema_id,
		    sizeof(schema_id)))
			err(1, "read(blob schema_id)");
		if (!elog_reader_read_exact(reader, &sz, sizeof(sz)))
			err(1, "read(blob size)");
		if (sz == 0 || sz > EVENTLOG_DECODE_BLOB_MAX)
			errx(1, "Invalid embedded decode-blob size %u", sz);
		blob = malloc(sz);
		if (blob == NULL)
			err(1, "malloc(blob)");
		if (!elog_reader_read_exact(reader, blob, sz))
			err(1, "read(blob)");
		(void)decode_registry_add(schema_id, NULL, blob, sz);
	}
}

/*
 * After the whole file -- header plus event stream, including any in-band
 * ELOG_EVENT_PROVIDER_INFO_ID/_BLOB_ID announcements -- has been read,
 * report on any provider that still has no decode blob: embedded/in-band
 * blobs win, otherwise fall back to the live kernel by schema_id (the
 * durable content-addressed key recorded in the capture). A provider that
 * recorded no schema_id registered no decode blob, so its events are
 * inherently undecodable -- as are a provider's events whose blob was too
 * large to embed (see ELOG_INBAND_BLOB_MAX) once the live kernel is gone
 * too. Deliberately runs at the end, not right after the header: a
 * late-registering provider's own in-band announcement may still be ahead
 * of us in the event stream, so judging it missing from the header alone
 * would warn about something that decodes fine moments later in the same
 * file. Never aborts -- each unresolved provider's events already fell
 * back to "[no decode blob for provider ...]" per event
 * (print_eventlog_event()) as they were printed; this is just a summary.
 */
static void
report_unresolved_providers(void)
{
	uint32_t i, missing = 0;

	for (i = 0; i < provider_map_count; i++) {
		if (!schema_id_is_zero(provider_map[i].schema_id) &&
		    ensure_blob_registered_by_schema(
		    provider_map[i].schema_id, provider_map[i].name) != NULL)
			continue;
		missing++;
	}
	if (missing > 0)
		warnx("%u provider(s) never got a decode blob (not embedded, "
		    "not announced in-band, and /dev/eventlog had none live "
		    "either); their events were shown undecoded -- if this "
		    "is unexpected, re-capture without --no-embed-decode to "
		    "always embed", missing);
}

static int
read_binary_file(const char *filename)
{
	struct elog_reader reader;
	struct elog_binary_header file_hdr;
	unsigned char *buffer = NULL;
	unsigned char *partial_buffer = NULL;
	size_t buffer_size = 64 * 1024; /* 64KB chunks */
	size_t buffer_used = 0;
	size_t buffer_capacity = buffer_size;
	size_t partial_size = 0;
	ssize_t nread;
	size_t consumed;

	elog_reader_open(&reader, filename);

	/* Read and validate file header */
	memset(&file_hdr, 0, sizeof(file_hdr));
	if (!elog_reader_read_exact(&reader, &file_hdr,
	    ELOG_BINARY_HEADER_COMMON_LEN))
		errx(1, "File is empty");

	/* Validate magic number */
	if (memcmp(file_hdr.magic, ELOG_BINARY_MAGIC, 4) != 0)
		errx(1, "Invalid binary file: bad magic number");

	/* Validate version (v1 is obsolete and no longer supported). */
	if (file_hdr.version < ELOG_BINARY_VERSION_MIN_READ ||
	    file_hdr.version > ELOG_BINARY_VERSION)
		errx(1, "Unsupported file version: %u (only versions %u-%u are "
		    "supported)", file_hdr.version, ELOG_BINARY_VERSION_MIN_READ,
		    ELOG_BINARY_VERSION);

	/* Stash for format_timestamp when printing (UTC = start_utc_us + (event_ts - capture_start)) */
	read_capture_start = file_hdr.capture_start;
	read_start_utc_us = file_hdr.start_utc_us;

	/*
	 * Header tail after event_count: v2 has a single dropped_events
	 * scalar, v3 a counted counters array. Neither is displayed on replay
	 * (capture-time-only today, like the counters always were), so just
	 * skip it. Cap the count the same way provider/blob counts are capped
	 * below, since it comes straight from the file.
	 */
	if (file_hdr.version < 3) {
		uint64_t dropped_events;

		if (!elog_reader_read_exact(&reader, &dropped_events,
		    sizeof(dropped_events)))
			err(1, "read(dropped events)");
	} else {
		if (!elog_reader_read_exact(&reader, &file_hdr.counter_count,
		    sizeof(file_hdr.counter_count)))
			err(1, "read(header counter count)");
		if (file_hdr.counter_count > ELOG_HEADER_COUNTER_SANE_MAX)
			errx(1, "Invalid header counter count %u in file",
			    file_hdr.counter_count);
		for (uint32_t k = 0; k < file_hdr.counter_count; k++) {
			uint64_t discard;

			if (!elog_reader_read_exact(&reader, &discard,
			    sizeof(discard)))
				err(1, "read(header counter)");
		}
	}

	/* Provider list for event lookup. */
	if (!elog_reader_read_exact(&reader, &provider_map_count,
	    sizeof(provider_map_count)))
		err(1, "read(provider count)");
	if (provider_map_count > ELOG_PROVIDER_MAP_SANE_MAX)
		errx(1, "Invalid provider count %u in file", provider_map_count);
	provider_map_ensure(provider_map_count);
	for (uint32_t i = 0; i < provider_map_count; i++) {
		/* Each entry carries provider_id, name, and schema_id. */
		memset(&provider_map[i], 0, sizeof(provider_map[i]));
		if (!elog_reader_read_exact(&reader, &provider_map[i],
		    sizeof(provider_map[i])))
			err(1, "read(provider)");
		provider_map[i].name[sizeof(provider_map[i].name) - 1] = '\0';
	}

	/* Optional embedded decode-blob section. */
	read_embedded_decode_blobs(&reader);

	print_provider_names();

	/* Allocate buffers for reading events */
	buffer = malloc(buffer_capacity);
	if (buffer == NULL)
		err(1, "malloc(buffer)");
	partial_buffer = malloc(buffer_capacity);
	if (partial_buffer == NULL)
		err(1, "malloc(partial_buffer)");

	/* Read events in chunks and parse them using the same code as kernel events */
	while (!elog_reader_eof(&reader)) {
		/* If we have partial data from previous read, prepend it */
		if (partial_size > 0) {
			if (partial_size > buffer_capacity) {
				/* Partial event is too large - likely corrupted */
				errx(1, "Partial event too large, file may be corrupted");
			}
			memcpy(buffer, partial_buffer, partial_size);
			buffer_used = partial_size;
			partial_size = 0;
		} else {
			buffer_used = 0;
		}

		/* Read more data into buffer */
		nread = elog_reader_read(&reader, buffer + buffer_used,
		    buffer_capacity - buffer_used);
		if (nread == 0 && elog_reader_eof(&reader)) {
			/* EOF - parse any remaining data */
			if (buffer_used > 0)
				parse_and_print_events(buffer, buffer_used);
			break;
		}

		buffer_used += nread;

		/* Parse events - returns number of bytes consumed */
		consumed = parse_and_print_events(buffer, buffer_used);

		/* Move any remaining (partial) data to partial buffer */
		if (consumed < buffer_used) {
			size_t remaining = buffer_used - consumed;
			if (remaining > buffer_capacity) {
				/* This shouldn't happen, but handle it */
				errx(1, "Unexpected: remaining data larger than buffer capacity");
			}
			memcpy(partial_buffer, buffer + consumed, remaining);
			partial_size = remaining;
		}
		buffer_used = 0;
	}

	free(buffer);
	free(partial_buffer);
	elog_reader_close(&reader);

	/*
	 * Now that every in-band announcement has had its chance to add to
	 * provider_map, report on whatever is still missing a decode blob.
	 * See report_unresolved_providers().
	 */
	report_unresolved_providers();

	return (0);
}

/*
 * Parse and print eventlog data.
 * Format (V1):
 *   Each event: eventlog_event_header (includes provider_id, session_id, event_id) + payload
 *   event_length = sizeof(header) + payload_size
 * Multiple events can be present in a single buffer read.
 * Returns the number of bytes consumed (complete events processed).
 * Requires provider_map to be populated (from GET_PROVIDERS or file header).
 */
static size_t
parse_and_print_events(const unsigned char *data, size_t len)
{
	const unsigned char *buf = data;
	const unsigned char *end = data + len;
	const unsigned char *start = data;

	while (buf < end) {
		struct eventlog_event_header hdr;
		size_t event_payload_len;
		const unsigned char *event_start = buf;

		if (buf + sizeof(struct eventlog_event_header) > end)
			break;
		memcpy(&hdr, buf, sizeof(struct eventlog_event_header));

		if (hdr.event_length < sizeof(struct eventlog_event_header)) {
			fprintf(stderr, "Error: invalid event_length %u at offset %zu\n",
			    hdr.event_length, (size_t)(buf - start));
			buf += sizeof(struct eventlog_event_header);
			return (buf - start);
		}
		if (event_start + hdr.event_length > end)
			break;

		buf += sizeof(struct eventlog_event_header);
		event_payload_len = hdr.event_length - sizeof(struct eventlog_event_header);
		if (print_eventlog_event(&hdr, buf, event_payload_len))
			events_received++;
		buf = event_start + hdr.event_length;
	}
	return (buf - start);
}

static void
source_lines_binary_note(uint8_t kind, uint32_t id, const char *pathname,
    bool open_ok, uint64_t lines, uint64_t misses, void *cookie __unused)
{
	if (open_ok && lines > 0)
		return;
	if (!open_ok)
		fprintf(stderr, "  Source-line gap: %s (%s id %u): "
		    "no DWARF found\n",
		    pathname, kind == 0 ? "kernel" : "user", id);
	else
		fprintf(stderr, "  Source-line gap: %s (%s id %u): "
		    "0 of %llu lookups resolved\n",
		    pathname, kind == 0 ? "kernel" : "user", id,
		    (unsigned long long)(lines + misses));
}

static void
print_stats(void)
{
	struct eventlog_stats stats;

	/* Prevent double-printing */
	if (stats_printed)
		return;
	stats_printed = true;

	fetch_eventlog_stats(&stats);

	/*
	 * Always surface unknown-provider events: a silent capture with
	 * unbound ids is exactly the cloud "unknown providers" failure
	 * mode. verbose_stats still gates the rest of the dump.
	 */
	if (unknown_provider_events > 0)
		warnx("%llu event%s from provider_id(s) never resolved "
		    "(no GET_PROVIDERS2 entry and no in-band announcement); "
		    "binary decode of those events will lack a schema",
		    (unsigned long long)unknown_provider_events,
		    unknown_provider_events == 1 ? "" : "s");

	if (!verbose_stats)
		return;

	fprintf(stderr, "\n[Stats]\n");
	fprintf(stderr, "  Providers: %u\n", provider_map_count);
	fprintf(stderr, "  Events received: %llu\n", (unsigned long long)events_received);
	if (unknown_provider_events > 0)
		fprintf(stderr, "  Unknown-provider events: %llu\n",
		    (unsigned long long)unknown_provider_events);
	if (stats.dropped_events > 0)
		fprintf(stderr, "  Dropped events: %llu\n",
		    (unsigned long long)stats.dropped_events);
	if (stats.user_dropped_full > 0)
		fprintf(stderr, "  User dropped (ring full): %llu\n",
		    (unsigned long long)stats.user_dropped_full);
	if (stats.user_dropped_prejoin > 0)
		fprintf(stderr, "  User dropped (prejoin): %llu\n",
		    (unsigned long long)stats.user_dropped_prejoin);
	if (stats.user_dropped_late > 0)
		fprintf(stderr, "  User dropped (late): %llu\n",
		    (unsigned long long)stats.user_dropped_late);
	if (roll_enabled && roll_time_us > 0) {
		fprintf(stderr, "  Roll dump triggers issued: %llu\n",
		    (unsigned long long)roll_dump_triggers_issued);
		fprintf(stderr, "  Roll dump completes seen: %llu\n",
		    (unsigned long long)roll_dump_completes_seen);
		if (roll_dump_trigger_lag_us > 0)
			fprintf(stderr, "  Last roll dump trigger lag: %llu us\n",
			    (unsigned long long)roll_dump_trigger_lag_us);
		if (roll_dump_trigger_issued_at != 0)
			fprintf(stderr, "  Roll dump trigger pending: yes "
			    "(no DUMP_COMPLETE observed yet)\n");
	}
	if (user_symbols_enabled) {
		fprintf(stderr, "  User-symbol files parsed: %llu\n",
		    (unsigned long long)elog_user_symbols_files_parsed());
		fprintf(stderr, "  User-symbol ranges emitted: %llu\n",
		    (unsigned long long)elog_user_symbols_ranges_emitted());
		fprintf(stderr, "  User-symbol files replayed: %llu\n",
		    (unsigned long long)elog_user_symbols_files_replayed());
		fprintf(stderr, "  User-symbol ranges replayed: %llu\n",
		    (unsigned long long)elog_user_symbols_ranges_replayed());
	}
	if (source_lines_enabled) {
		fprintf(stderr, "  Source-line binaries opened: %llu\n",
		    (unsigned long long)elog_source_lines_binaries_opened());
		fprintf(stderr, "  Source-line files emitted: %llu\n",
		    (unsigned long long)elog_source_lines_files_emitted());
		fprintf(stderr, "  Source-line mappings emitted: %llu\n",
		    (unsigned long long)elog_source_lines_lines_emitted());
		fprintf(stderr, "  Source-line misses: %llu "
		    "(no binary %llu, no debug %llu, bad addr %llu, "
		    "no line %llu)\n",
		    (unsigned long long)elog_source_lines_misses(),
		    (unsigned long long)elog_source_lines_misses_no_binary(),
		    (unsigned long long)elog_source_lines_misses_open(),
		    (unsigned long long)elog_source_lines_misses_addr(),
		    (unsigned long long)elog_source_lines_misses_line());
		fprintf(stderr, "  Source-line index rows capped: %llu\n",
		    (unsigned long long)elog_source_lines_lines_capped());
		elog_source_lines_foreach_binary(source_lines_binary_note, NULL);
	}
}

static void
sigint_handler(int sig __unused)
{
	struct session_file *sf;

	done = true;
	/* Stats will be printed by atexit handler or normal exit path */
	/* Flush output before exit */
	if (roll_enabled) {
		if (rollf.fp != NULL)
			fflush(rollf.fp);
	} else if (output_dir != NULL) {
		STAILQ_FOREACH(sf, &session_files, link) {
			if (sf->fp != NULL)
				fflush(sf->fp);
		}
	} else if (single_output.fp != NULL) {
		fflush(single_output.fp);
	} else {
		fflush(stdout);
	}
}

/* Parse a byte count with optional K/M/G suffix for --roll-size. */
static uint64_t
parse_roll_size(const char *s)
{
	unsigned long long v;
	char *end;

	v = strtoull(s, &end, 0);
	if (end == s)
		errx(1, "--roll-size: invalid size: %s", s);
	while (*end == ' ' || *end == '\t')
		end++;
	if (*end != '\0') {
		char unit = *end++;
		while (*end == ' ' || *end == '\t')
			end++;
		if (*end != '\0')
			errx(1, "--roll-size: trailing characters after unit");
		switch (unit) {
		case 'K':
		case 'k':
			v *= 1024ULL;
			break;
		case 'M':
		case 'm':
			v *= 1024ULL * 1024;
			break;
		case 'G':
		case 'g':
			v *= 1024ULL * 1024 * 1024;
			break;
		default:
			errx(1, "--roll-size: bad unit '%c' (use K/M/G)", unit);
		}
	}
	if (v == 0)
		errx(1, "--roll-size must be greater than 0");
	return ((uint64_t)v);
}

/*
 * Parse a time interval for --roll-time into microseconds.  Accepts an
 * optional s/m/h/d suffix; a bare number is seconds.
 */
static uint64_t
parse_roll_time(const char *s)
{
	unsigned long long v;
	char *end;
	uint64_t unit_us = 1000000ULL; /* default: seconds */

	v = strtoull(s, &end, 0);
	if (end == s)
		errx(1, "--roll-time: invalid interval: %s", s);
	while (*end == ' ' || *end == '\t')
		end++;
	if (*end != '\0') {
		char unit = *end++;
		while (*end == ' ' || *end == '\t')
			end++;
		if (*end != '\0')
			errx(1, "--roll-time: trailing characters after unit");
		switch (unit) {
		case 's':
		case 'S':
			unit_us = 1000000ULL;
			break;
		case 'm':
		case 'M':
			unit_us = 60ULL * 1000000;
			break;
		case 'h':
		case 'H':
			unit_us = 3600ULL * 1000000;
			break;
		case 'd':
		case 'D':
			unit_us = 86400ULL * 1000000;
			break;
		default:
			errx(1, "--roll-time: bad unit '%c' (use s/m/h/d)", unit);
		}
	}
	if (v == 0)
		errx(1, "--roll-time must be greater than 0");
	return ((uint64_t)v * unit_us);
}

static int
parse_gzip_level(const char *s)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (end == s || *end != '\0' || errno != 0 || v < 1 || v > 9)
		errx(1, "--gzip: level must be 1-9, got: %s", s);
	return ((int)v);
}

static void
add_subscription(const char *provider, enum eventlog_level level,
    uint32_t keywords, const char *pending_names)
{
	if (strlen(provider) >= EVENTLOG_PROVIDER_NAME_MAX)
		errx(1, "provider name too long");

	if (subscription_count >= subscription_capacity) {
		int new_capacity = (subscription_capacity == 0)
		    ? 16 : subscription_capacity * 2;
		struct subscription *new_subscriptions =
		    realloc(subscriptions, new_capacity *
		    sizeof(struct subscription));
		if (new_subscriptions == NULL)
			errx(1, "failed to allocate subscriptions");
		subscriptions = new_subscriptions;
		subscription_capacity = new_capacity;
	}

	memset(&subscriptions[subscription_count], 0,
	    sizeof(subscriptions[0]));
	strlcpy(subscriptions[subscription_count].provider_name, provider,
	    sizeof(subscriptions[0].provider_name));
	/* Always include SESSION for lifecycle events. */
	subscriptions[subscription_count].level = level;
	subscriptions[subscription_count].keywords =
	    keywords | EVENTLOG_KEYWORD_SESSION;
	if (pending_names != NULL && pending_names[0] != '\0')
		strlcpy(subscriptions[subscription_count].pending_names,
		    pending_names,
		    sizeof(subscriptions[0].pending_names));
	subscription_count++;
}

/*
 * Append a subscription for "-c <provider> [level] [keywords]". The provider
 * is the option-argument (optarg); the optional level and keywords are picked
 * up from the following operands, advancing optind past any we consume.
 */
static void
parse_capture_arg(int argc, char *argv[])
{
	enum eventlog_level level = EVENTLOG_LEVEL_VERBOSE;
	uint32_t keywords = 0xFFFFFFFF;
	char pending[ELOG_KEYWORD_NAMES_MAX];

	pending[0] = '\0';
	if (optind < argc && argv[optind][0] != '-' &&
	    try_parse_level(argv[optind], &level))
		optind++;

	/* Optional keywords (hex 0x prefix or pipe-delimited names). */
	if (optind < argc && argv[optind][0] != '-' &&
	    try_parse_keywords(optarg, argv[optind], &keywords, pending,
	    sizeof(pending)))
		optind++;

	add_subscription(optarg, level, keywords, pending);
}

/*
 * One "-c <provider> [level] [keywords]" of a scenario. `level` and
 * `keywords` are spelled exactly as they would be on the command line
 * and go through the same parsers; NULL takes elog's default (VERBOSE,
 * all keywords).
 */
struct elog_scenario_cap {
	const char *provider;
	const char *level;
	const char *keywords;
};

struct elog_scenario {
	const char *name;
	const struct elog_scenario_cap *caps;
	size_t ncaps;
	bool dump_state;
	bool user_symbols;
};

static const struct elog_scenario_cap elog_scenario_cpu_caps[] = {
	{ "cpu", NULL, NULL },
	{ "process", NULL, NULL },
	{ "symbols", NULL, NULL },
};

static const struct elog_scenario_cap elog_scenario_net_caps[] = {
	{ "if", NULL, NULL },
	{ "tcp", NULL, "SAMPLE|SAMPLE_HIST" },
};

static const struct elog_scenario elog_scenarios[] = {
	{ "cpu", elog_scenario_cpu_caps, nitems(elog_scenario_cpu_caps),
	    true, true },
	{ "net", elog_scenario_net_caps, nitems(elog_scenario_net_caps),
	    true, false },
	{ "network", elog_scenario_net_caps, nitems(elog_scenario_net_caps),
	    true, false },
};

static void
merge_subscription(const char *provider, enum eventlog_level level,
    uint32_t keywords, const char *pending_names)
{
	int i;

	for (i = 0; i < subscription_count; i++) {
		if (strcmp(subscriptions[i].provider_name, provider) != 0)
			continue;
		if (level > subscriptions[i].level)
			subscriptions[i].level = level;
		subscriptions[i].keywords |= keywords | EVENTLOG_KEYWORD_SESSION;
		if (pending_names != NULL && pending_names[0] != '\0') {
			if (subscriptions[i].pending_names[0] == '\0') {
				strlcpy(subscriptions[i].pending_names,
				    pending_names,
				    sizeof(subscriptions[i].pending_names));
			} else {
				strlcat(subscriptions[i].pending_names, "|",
				    sizeof(subscriptions[i].pending_names));
				strlcat(subscriptions[i].pending_names,
				    pending_names,
				    sizeof(subscriptions[i].pending_names));
				pending_keyword_filters--;
			}
		}
		return;
	}
	add_subscription(provider, level, keywords, pending_names);
}

static void
apply_scenario_cap(const struct elog_scenario_cap *cap)
{
	enum eventlog_level level = EVENTLOG_LEVEL_VERBOSE;
	uint32_t keywords = 0xFFFFFFFF;
	char pending[ELOG_KEYWORD_NAMES_MAX];

	pending[0] = '\0';
	if (cap->level != NULL && !try_parse_level(cap->level, &level))
		errx(1, "scenario: bad level '%s' for provider '%s'",
		    cap->level, cap->provider);
	if (cap->keywords != NULL &&
	    !try_parse_keywords(cap->provider, cap->keywords, &keywords,
	    pending, sizeof(pending)))
		errx(1, "scenario: bad keywords '%s' for provider '%s'",
		    cap->keywords, cap->provider);
	merge_subscription(cap->provider, level, keywords, pending);
}

static void
apply_scenario_one(const char *name)
{
	size_t i, j;

	for (i = 0; i < nitems(elog_scenarios); i++) {
		const struct elog_scenario *sc = &elog_scenarios[i];

		if (strcmp(sc->name, name) != 0)
			continue;
		for (j = 0; j < sc->ncaps; j++)
			apply_scenario_cap(&sc->caps[j]);
		if (sc->dump_state)
			dump_state = true;
		if (sc->user_symbols)
			user_symbols_enabled = true;
		return;
	}

	fprintf(stderr, "elog: unknown scenario: %s (available:", name);
	for (i = 0; i < nitems(elog_scenarios); i++)
		fprintf(stderr, " %s", elog_scenarios[i].name);
	fprintf(stderr, ")\n");
	exit(1);
}

static char *
trim_scenario_token(char *tok)
{
	char *end;

	while (*tok == ' ' || *tok == '\t')
		tok++;
	end = tok + strlen(tok);
	while (end > tok && (end[-1] == ' ' || end[-1] == '\t'))
		*--end = '\0';
	return (tok);
}

static void
apply_scenario(const char *spec)
{
	char *copy, *p, *bar, *name;

	copy = strdup(spec);
	if (copy == NULL)
		err(1, "strdup");
	p = copy;
	for (;;) {
		bar = strchr(p, '|');
		if (bar != NULL)
			*bar = '\0';
		name = trim_scenario_token(p);
		if (*name == '\0') {
			free(copy);
			errx(1, "empty scenario name in '%s'", spec);
		}
		apply_scenario_one(name);
		if (bar == NULL)
			break;
		p = bar + 1;
	}
	free(copy);
}

/*
 * Parse command line arguments and populate global state. Options that have
 * no single-letter form use synthetic values above the byte range.
 */
enum {
	OPT_DURATION = 256,
	OPT_DELTA_TIME,
	OPT_ROLL_SIZE,
	OPT_ROLL_TIME,
	OPT_ROLL_PREFIX,
	OPT_ROLL_KEEP,
	OPT_SYMBOL_MODE,
	OPT_GZIP,
	OPT_NO_METADATA,
};

static void
parse_arguments(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "capture",	   required_argument, NULL, 'c' },
		{ "scenario",	   required_argument, NULL, 'S' },
		{ "buffer-size",   required_argument, NULL, 'b' },
		{ "duration",	   required_argument, NULL, OPT_DURATION },
		{ "roll-size",	   required_argument, NULL, OPT_ROLL_SIZE },
		{ "roll-time",	   required_argument, NULL, OPT_ROLL_TIME },
		{ "roll-prefix",   required_argument, NULL, OPT_ROLL_PREFIX },
		{ "roll-keep",	   required_argument, NULL, OPT_ROLL_KEEP },
		{ "symbol-mode",   required_argument, NULL, OPT_SYMBOL_MODE },
		{ "gzip",	   optional_argument, NULL, OPT_GZIP },
		{ "no-metadata",   no_argument,	      NULL, OPT_NO_METADATA },
		{ "date",	   no_argument,	      NULL, 'd' },
		{ "event-name",	   no_argument,	      NULL, 'e' },
		{ "event-number",  no_argument,	      NULL, 'n' },
		{ "providers",	   no_argument,	      NULL, 'p' },
		{ "stats",	   no_argument,	      NULL, 's' },
		{ "format",	   required_argument, NULL, 'f' },
		{ "output",	   required_argument, NULL, 'o' },
		{ "read-binary",   required_argument, NULL, 'r' },
		{ "relative-time", no_argument,	      NULL, 't' },
		{ "delta-time",	   no_argument,	      NULL, OPT_DELTA_TIME },
		{ "dump-state",	   no_argument,	      NULL, 'D' },
		{ "no-embed-decode", no_argument,    NULL, 'N' },
		{ "user-symbols",  no_argument,	      NULL, 'U' },
		{ "embed-source-lines", no_argument,  NULL, 'L' },
		{ "help",	   no_argument,	      NULL, 'h' },
		{ NULL,		   0,		      NULL, 0 },
	};
	int ch;
	int i;

	/*
	 * Leading '+' keeps operands in order so "-c <provider> [level]
	 * [keywords]" can consume the operands that follow it; getopt_long
	 * still allows clustered flags such as "-enr file.elog". opterr is
	 * disabled so an unknown option reports "unknown argument" rather
	 * than getopt's default message.
	 */
	opterr = 0;
	while ((ch = getopt_long(argc, argv, "+S:b:c:dDef:hLnNo:pr:stU", longopts,
	    NULL)) != -1) {
		switch (ch) {
		case 'c':
			parse_capture_arg(argc, argv);
			break;
		case 'S':
			apply_scenario(optarg);
			break;
		case 'b':
			buffer_size_per_cpu = parse_size(optarg);
			buffer_size_explicit = true;
			break;
		case OPT_DURATION: {
			char *endptr;
			unsigned long val;

			val = strtoul(optarg, &endptr, 10);
			if (*optarg == '\0' || *endptr != '\0')
				errx(1, "--duration: not a number: %s", optarg);
			if (val > UINT_MAX)
				errx(1, "--duration: value too large");
			duration_sec = (unsigned int)val;
			break;
		}
		case OPT_ROLL_SIZE:
			roll_size_bytes = parse_roll_size(optarg);
			roll_enabled = true;
			break;
		case OPT_ROLL_TIME:
			roll_time_us = parse_roll_time(optarg);
			roll_enabled = true;
			break;
		case OPT_ROLL_PREFIX:
			roll_prefix = optarg;
			roll_prefix_set = true;
			break;
		case OPT_ROLL_KEEP: {
			char *end;
			unsigned long v;

			errno = 0;
			v = strtoul(optarg, &end, 10);
			if (end == optarg || *end != '\0' ||
			    errno != 0 || v == 0 || v > UINT_MAX)
				errx(1, "--roll-keep: invalid count: %s",
				    optarg);
			roll_keep = (unsigned int)v;
			roll_keep_set = true;
			break;
		}
		case OPT_SYMBOL_MODE:
			if (strcmp(optarg, "refs") == 0)
				symbol_mode_refs = true;
			else if (strcmp(optarg, "inline") != 0)
				errx(1, "--symbol-mode: expected 'inline' or 'refs'");
			break;
		case OPT_GZIP:
			if (optarg == NULL)
				output_gzip_level = ELOG_GZIP_DEFAULT_LEVEL;
			else
				output_gzip_level = parse_gzip_level(optarg);
			break;
		case OPT_NO_METADATA:
			machine_metadata_set_enabled(false);
			break;
		case 'd':
			show_date = true;
			break;
		case 'e':
			show_event_name = true;
			break;
		case 'n':
			show_event_number = true;
			break;
		case 'p':
			show_providers = true;
			break;
		case 's':
			verbose_stats = true;
			break;
		case 'o':
			if (strncmp(optarg, "dir=", 4) == 0) {
				output_dir = strdup(optarg + 4);
				if (output_dir == NULL)
					err(1, "strdup");
				if (mkdir(output_dir, 0755) != 0 &&
				    errno != EEXIST)
					err(1, "mkdir(%s)", output_dir);
			} else {
				single_output_path = strdup(optarg);
				if (single_output_path == NULL)
					err(1, "strdup");
				single_output.fp = fopen(single_output_path, "wb");
				if (single_output.fp == NULL)
					err(1, "fopen(%s)", single_output_path);
			}
			break;
		case 'r':
			binary_input_file = optarg;
			break;
		case 't':
			show_relative_time = true;
			break;
		case OPT_DELTA_TIME:
			show_delta_time = true;
			break;
		case 'D':
			dump_state = true;
			break;
		case 'N':
			embed_decode = false;
			no_embed_decode_requested = true;
			break;
		case 'U':
			user_symbols_enabled = true;
			break;
		case 'L':
			source_lines_enabled = true;
			break;
		case 'f':
			if (strcmp(optarg, "tcp") != 0)
				errx(1, "--format requires 'tcp' argument");
			format_tcp = true;
			break;
		case 'h':
			usage();
			break;
		case '?':
		default:
			errx(1, "unknown argument: %s", argv[optind - 1]);
		}
	}

	if (optind < argc)
		errx(1, "unexpected argument: %s", argv[optind]);

	if (roll_prefix_set && !roll_enabled)
		errx(1, "--roll-prefix requires --roll-size or --roll-time");
	if (roll_keep_set && !roll_enabled)
		errx(1, "--roll-keep requires --roll-size or --roll-time");

	if (!buffer_size_explicit) {
		for (i = 0; i < subscription_count; i++) {
			const char *p = subscriptions[i].provider_name;

			if (strcmp(p, "cpu") == 0 || strcmp(p, "symbols") == 0 ||
			    strcmp(p, "process") == 0) {
				buffer_size_per_cpu =
				    ELOG_AUTO_BUFFER_SIZE_FOR_DUMP_PROVIDERS;
				break;
			}
		}
	}

	if (roll_enabled) {
		if (output_dir == NULL)
			errx(1, "rolling (--roll-size/--roll-time) requires "
			    "-o dir=<path>");
		if (single_output.fp != NULL)
			errx(1, "rolling requires -o dir=<path>, not -o <file>");
		if (format_tcp)
			errx(1, "--format tcp is incompatible with rolling output");
		if (roll_prefix[0] == '\0')
			errx(1, "--roll-prefix must not be empty");
	}

	if (output_gzip_level > 0 && !binary_output_mode())
		errx(1, "--gzip requires binary output (-o <file> or -o dir=<path>)");

	if (symbol_mode_refs) {
		/*
		 * KERNEL_META|USER_META|REFS|SOURCE_META: identity + refs +
		 * lines, no ranges. The generator treats a schema KEYWORD
		 * below 16 as a 1-based bit position (1 << (n-1)), but 16
		 * and above as the literal mask value -- SOURCE_META is
		 * declared "16" and so is already the bit 0x10.
		 */
		uint32_t refs_mask =
		    ELOG_KW(1) | ELOG_KW(4) | ELOG_KW(8) | 16;
		bool have_symbols = false;

		for (i = 0; i < subscription_count; i++) {
			if (strcmp(subscriptions[i].provider_name, "symbols") != 0)
				continue;
			subscriptions[i].keywords =
			    refs_mask | EVENTLOG_KEYWORD_SESSION;
			if (subscriptions[i].pending_names[0] != '\0') {
				subscriptions[i].pending_names[0] = '\0';
				if (pending_keyword_filters > 0)
					pending_keyword_filters--;
			}
			have_symbols = true;
		}
		if (!have_symbols)
			warnx("--symbol-mode=refs: no symbols subscription to "
			    "narrow (expected -c symbols or -S cpu)");
		/* refs implies the -U walk: one SYMBOL_PACK_REF per build-id file. */
		if (binary_input_file == NULL)
			user_symbols_enabled = true;
		elog_user_symbols_set_ref_mode(true);
	}
}

/*
 * Run eventlog device mode - open device, create subscriber, and read events.
 */
static int
run_eventlog_mode(void)
{
	int fd;
	char device_path[] = "/dev/eventlog";
	char *buffer;
	ssize_t nread;
	size_t bufsize = 1024 * 1024;
	int i, error;

	/* Open device */
	fd = open(device_path, O_RDONLY);
	if (fd < 0) {
		err(1, "open(%s)", device_path);
	}

	/* Prepare CREATE request with buffer size and subscriptions */
	/* Calculate exact size needed */
	size_t base_offset = __builtin_offsetof(struct eventlog_create_req, subscriptions);
	size_t sub_size = sizeof(struct eventlog_subscription_req);
	size_t req_size = base_offset + subscription_count * sub_size;
	struct eventlog_create_req *req;
	u_long ioctl_cmd;
	size_t ioctl_size;

	req = malloc(req_size);
	if (req == NULL)
		err(1, "malloc");

	memset(req, 0, req_size);
	req->buffer_size_per_cpu = buffer_size_per_cpu;
	req->count = subscription_count;
	for (i = 0; i < subscription_count; i++) {
		strlcpy(req->subscriptions[i].provider_name,
		    subscriptions[i].provider_name,
		    sizeof(req->subscriptions[i].provider_name));
		req->subscriptions[i].level = subscriptions[i].level;
		req->subscriptions[i].keywords = subscriptions[i].keywords;
		req->subscriptions[i].flags = dump_state ?
		    EVENTLOG_SUBSCRIPTION_DUMP_STATE : 0;
	}

	/* Calculate ioctl command with exact size */
	ioctl_cmd = EVENTLOG_IOCTL_CREATE_SIZE(subscription_count);
	ioctl_size = ((ioctl_cmd >> 16) & 0x1fff); /* Extract IOCPARM_LEN */

	/* The 13-bit IOCPARM_LEN caps how many subscriptions fit. */
	if (ioctl_size != req_size)
		errx(1, "too many -c subscriptions: maximum is %zu",
		    (IOCPARM_MASK - base_offset) / sub_size);

	/* Send CREATE ioctl (creates subscriber and subscribes) */
	error = ioctl(fd, ioctl_cmd, req);
	if (error != 0) {
		err(1, "ioctl(EVENTLOG_IOCTL_CREATE)");
	}

	free(req);

	/*
	 * Get provider ids for event lookup. Not fatal: get_provider_entry()
	 * retries this on a miss, so a failure here just means decode is
	 * unavailable until then instead of killing the whole capture.
	 */
	if (!fetch_provider_map(fd))
		warn("ioctl(EVENTLOG_IOCTL_GET_PROVIDERS)");

	/*
	 * Fetch decode blobs from the live kernel when we will need them: any
	 * text output requires them to format events, and embedding (the
	 * binary-output default; see --no-embed-decode) needs them to write
	 * into the file. A plain binary capture with embedding suppressed
	 * copies raw bytes only and does not query blobs.
	 */
	if (!binary_output_mode() || embed_decode) {
		for (uint32_t pi = 0; pi < provider_map_count; pi++) {
			unsigned char *blob;
			size_t blob_size;
			const uint8_t *want_schema = NULL;

			if (!schema_id_is_zero(provider_map[pi].schema_id)) {
				if (decode_registry_find_by_schema(
				    provider_map[pi].schema_id) != NULL)
					continue;
				/*
				 * Fetch/validate by the schema_id we already
				 * have, not by name: names aren't unique, so
				 * fetching by name could pull a different
				 * provider's blob instead.
				 */
				want_schema = provider_map[pi].schema_id;
			} else if (decode_registry_find_by_name(
			    provider_map[pi].name) != NULL)
				continue;
			blob = fetch_blob_from_device(fd, provider_map[pi].name,
			    want_schema, &blob_size);
			if (blob != NULL)
				(void)decode_registry_add(want_schema,
				    provider_map[pi].name, blob, blob_size);
		}
	}

	print_provider_names();


	/* Allocate buffer */
	buffer = malloc(bufsize);
	if (buffer == NULL)
		err(1, "malloc");

	eventlog_fd = fd; /* Store for signal handler */

	/* Read and parse events */
	while (!done) {
		/*
		 * The read below times out on its own, so a provider that
		 * registers without emitting anything is still noticed.
		 */
		if (pending_keyword_filters > 0)
			resolve_pending_keywords();
		if (roll_enabled)
			roll_idle_close();

		nread = read(fd, buffer, bufsize);
		if (nread < 0) {
			if (errno == EINTR) {
				/* Check if we were interrupted by signal */
				if (done)
					break;
				continue;
			}
			if (errno == EAGAIN)
				continue;
			err(1, "read");
		}
		if (nread == 0) {
			/* EOF - wait a bit and retry */
			usleep(100000); /* 100ms */
			continue;
		}

		/* Parse events - provider name is now included in the event format */
		parse_and_print_events((const unsigned char *)buffer, nread);
	}

	/*
	 * With -L, DWARF resolution is deferred so the read loop above
	 * only records unique PCs. Resolve them now, appending
	 * SOURCE_FILE / SOURCE_LINE to the capture.
	 */
	if (source_lines_enabled)
		elog_source_lines_resolve(source_lines_emit, NULL);

	/* Print stats before cleanup */
	print_stats();

	/* Update binary header with final event/drop counts before closing */
	update_binary_header();

	/* Cleanup on exit */
	close(fd);
	eventlog_fd = -1;
	free(buffer);
	free(subscriptions);
	if (roll_enabled) {
		roll_close();
		embedded_set_reset(&rollf.embedded);
		free(output_dir);
		output_dir = NULL;
	} else if (output_dir != NULL) {
		struct session_file *sf, *sf_next;
		for (sf = STAILQ_FIRST(&session_files); sf != NULL; sf = sf_next) {
			sf_next = STAILQ_NEXT(sf, link);
			if (sf->fp != NULL) {
				fflush(sf->fp);
				fclose(sf->fp);
				sf->fp = NULL;
				rename_session_file(sf);
			}
			free(sf->filepath);
			free(sf->session_id);
			embedded_set_reset(&sf->embedded);
			free(sf);
		}
		STAILQ_INIT(&session_files);
		free(output_dir);
		output_dir = NULL;
	} else if (single_output.fp != NULL) {
		fflush(single_output.fp);
		fclose(single_output.fp);
		single_output.fp = NULL;
		embedded_set_reset(&single_output.embedded);
		if (output_gzip_level > 0 && single_output_path != NULL)
			gzip_enqueue(single_output_path);
	}

	if (output_gzip_level > 0)
		gzip_drain();
	free(single_output_path);
	single_output_path = NULL;

	return (0);
}

static void
init_machine_metadata(void)
{
	const unsigned char *blob;
	unsigned char *copy;
	size_t size;

	machine_metadata_register();
	if (!machine_metadata_enabled())
		return;
	blob = machine_metadata_decode_blob(&size);
	copy = malloc(size);
	if (copy == NULL)
		err(1, "malloc(machine decode blob)");
	memcpy(copy, blob, size);
	(void)decode_registry_add(NULL, "machine", copy, size);
}

int
main(int argc, char *argv[])
{
	struct sigaction sa;

	/* Parse command line arguments */
	parse_arguments(argc, argv);
	init_machine_metadata();

	/* Handle binary read mode - this bypasses capture */
	if (binary_input_file != NULL) {
		if (subscription_count > 0) {
			errx(1, "--read-binary cannot be used with subscribe options");
		}
		if (no_embed_decode_requested)
			errx(1, "--no-embed-decode is only valid when capturing to a binary file");
		if (user_symbols_enabled)
			errx(1, "--read-binary cannot be used with -U / --user-symbols");
		if (source_lines_enabled)
			errx(1, "--read-binary cannot be used with -L / --embed-source-lines");
		return (read_binary_file(binary_input_file));
	}

	/* Check if we have any subscriptions */
	if (subscription_count == 0)
		errx(1, "no subscriptions specified (use --capture, -c, or --scenario)");

	/*
	 * Embedding decode blobs only makes sense for binary output (a single
	 * -o file or a -o dir= tree); plain text output has nowhere to put them.
	 */
	if (no_embed_decode_requested && !binary_output_mode())
		errx(1, "--no-embed-decode requires binary output (-o <file> or -o dir=<path>)");

	/* Register atexit handler to ensure stats are always printed */
	atexit(print_stats);

	if (user_symbols_enabled)
		elog_user_symbols_init();
	if (source_lines_enabled) {
		char version[256];
		size_t version_len;

		elog_source_lines_init();
		version_len = sizeof(version);
		if (sysctlbyname("kern.version", version, &version_len,
		    NULL, 0) == 0)
			elog_source_lines_set_kernel_version(version);
	}

	/* Set up signal handlers for cleanup on interrupt */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/*
	 * --duration schedules a SIGALRM that uses the same cleanup
	 * path as SIGINT/SIGTERM (see sigint_handler). The main read
	 * loop in run_eventlog_mode() checks `done` after EINTR.
	 */
	if (duration_sec > 0) {
		sigaction(SIGALRM, &sa, NULL);
		alarm(duration_sec);
	}

	/* Run eventlog device mode */
	return (run_eventlog_mode());
}

