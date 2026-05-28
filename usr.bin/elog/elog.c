/*
 * Copyright (c) 2026 Netflix, Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/eventlog.h>
#include <sys/eventlog_subscriber.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <fcntl.h>
#include <limits.h>
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
#include <zlib.h>

/* Include consumer header for formatting events */
/* Generated headers are in the build directory */
#include "eventlog_consumer.h"

struct subscription {
	char provider_name[EVENTLOG_PROVIDER_NAME_MAX];
	enum eventlog_level level;
	uint32_t keywords;
};

static struct subscription *subscriptions = NULL;
static int subscription_count = 0;
static int subscription_capacity = 0;
static uint32_t buffer_size_per_cpu = 512 * 1024; /* Default 512K */
/* When > 0, exit cleanly via SIGALRM after this many seconds. */
static unsigned int duration_sec = 0;
static volatile bool done = false;
static int eventlog_fd = -1;		/* eventlog device fd (for stats) */
static volatile bool stats_printed = false;
static uint64_t events_received = 0;
static bool verbose_stats = false;	/* Print detailed stats on exit */
static const char *binary_input_file = NULL;
static uint64_t last_dropped_events = 0;	/* From last GET_STATS */

/* For read mode: base timestamps from file header for UTC calculation */
static uint64_t read_capture_start = 0;
static uint64_t read_start_utc_us = 0;
static bool show_date = false;		/* Full date in timestamps */
static bool show_event_number = false;	/* Print serial number per line */
static bool show_providers = false;	/* Print provider names at start */
static bool show_event_name = false;	/* Print event name after sid */
static bool show_relative_time = false;	/* Time relative to first event */
static bool show_delta_time = false;	/* Time since previous event */
static uint64_t first_event_ts = 0;
static uint64_t prev_event_ts = 0;
static bool dump_state = false;		/* Replay current state on subscribe */
static char *output_dir = NULL;		/* If set, one file per session */
/* Rename per-session files using TCP connection metadata */
static bool format_tcp = false;

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
	/* TCP connection metadata for file rename (-f tcp). */
	char log_id[64];
	char remote_ip[INET6_ADDRSTRLEN];
	uint16_t local_port;
	uint16_t remote_port;
	bool has_log_id;
	bool has_conn_info;
};
static STAILQ_HEAD(, session_file) session_files =
    STAILQ_HEAD_INITIALIZER(session_files);
/* Binary output state for single-file mode. */
static struct session_file single_output;

static inline bool
binary_output_mode(void)
{
	return (output_dir != NULL || single_output.fp != NULL);
}

/* Provider id->name map (from GET_PROVIDERS or file header) */
static struct eventlog_provider_info provider_map[EVENTLOG_MAX_PROVIDERS];
static uint32_t provider_map_count = 0;

static void
print_provider_names(void)
{
	if (!show_providers || provider_map_count == 0)
		return;
	fprintf(stderr, "[Providers] %u registered:", provider_map_count);
	for (uint32_t i = 0; i < provider_map_count; i++)
		fprintf(stderr, " %s", provider_map[i].name);
	fprintf(stderr, "\n");
}

static const char *
get_provider_name(uint16_t id)
{
	for (uint32_t i = 0; i < provider_map_count; i++) {
		if (provider_map[i].provider_id == id)
			return (provider_map[i].name);
	}
	return ("?");
}

/* Binary file format structures */
#define ELOG_BINARY_MAGIC "ELOG"
#define ELOG_BINARY_VERSION 1

struct elog_binary_header {
	char magic[4];		/* "ELOG" */
	uint32_t version;	/* File format version */
	uint64_t capture_start;	/* us since boot at capture start */
	uint64_t start_utc_us;	/* UTC us at capture start */
	uint64_t event_count;	/* Total events in file */
	uint64_t dropped_events;
} __packed;

static void
usage(void)
{
	fprintf(stderr,
"usage: elog [options]\n"
"  -c, --capture <provider> [level] [keywords]\n"
"                      Capture events from provider\n"
"                      provider: Provider name\n"
"                      level:    NONE/0, ERROR/1, WARN/2, INFO/3,\n"
"                                VERBOSE/4, TRACE/5 (default: VERBOSE)\n"
"                      keywords: Hex (0x3F) or names (CC|RX|TX)\n"
"                                (default: 0xFFFFFFFF, all flags)\n"
"  -b, --buffer-size <size>  Set per-CPU buffer size (default: 512K)\n"
"                        Size in bytes or with K/M/G suffix\n"
"                        Valid range: %uKB to %uMB per CPU\n"
"      --duration <sec>  Self-exit after <sec> seconds (SIGALRM).\n"
"                        Same cleanup as SIGINT/SIGTERM. 0 = no timeout.\n"
"  -d, --date            Show full date (YYYY-MM-DD) in timestamps\n"
"  -e, --event-name      Show event name after session ID\n"
"  -n, --event-number    Print event serial number per line\n"
"  -p, --providers       Print provider names at start of output\n"
"  -s, --stats           Print detailed statistics on exit\n"
"  -o, --output <file>   Write binary output to file (default: stdout)\n"
"  -o dir=<path>         Write one binary file per session under <path>\n"
"  -f, --format <type>   Rename per-session files using connection metadata\n"
"                        Supported types: tcp\n"
"  -r, --read-binary <file>\n"
"                        Read binary file and convert to text (.gz ok)\n"
"  -t, --relative-time   Show time relative to first event\n"
"      --delta-time      Show time since previous event\n"
"  -D, --dump-state      Request providers to replay current state\n"
"\n"
"  Multiple captures can be specified:\n"
"    elog -c provider\n"
"    elog -c provider INFO\n"
"    elog -c provider INFO 0x3F\n"
"    elog -c provider1 -c provider2 WARN\n"
"    elog -c provider -o /tmp/events.bin\n"
"    elog -r /tmp/events.bin\n",
	    EVENTLOG_BUFFER_SIZE_MIN / 1024,
	    EVENTLOG_BUFFER_SIZE_MAX / (1024 * 1024));
	exit(1);
}

static bool
try_parse_level(const char *str, enum eventlog_level *out)
{
	long num;
	char *endptr;

	static const struct {
		const char *name;
		enum eventlog_level level;
	} levels[] = {
		{ "NONE",    EVENTLOG_LEVEL_NONE },
		{ "ERROR",   EVENTLOG_LEVEL_ERROR },
		{ "WARN",    EVENTLOG_LEVEL_WARN },
		{ "INFO",    EVENTLOG_LEVEL_INFO },
		{ "VERBOSE", EVENTLOG_LEVEL_VERBOSE },
		{ "TRACE",   EVENTLOG_LEVEL_TRACE },
	};

	for (size_t i = 0; i < nitems(levels); i++) {
		if (strcasecmp(str, levels[i].name) == 0) {
			*out = levels[i].level;
			return (true);
		}
	}

	num = strtol(str, &endptr, 10);
	if (*endptr == '\0' && num >= EVENTLOG_LEVEL_NONE &&
	    num <= EVENTLOG_LEVEL_TRACE) {
		*out = (enum eventlog_level)num;
		return (true);
	}
	return (false);
}

static bool
try_parse_keywords(const char *provider, const char *str, uint32_t *out)
{
	char *copy, *token, *saveptr;
	uint32_t result, kw;

	if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
		*out = (uint32_t)strtoul(str, NULL, 0);
		return (true);
	}

	copy = strdup(str);
	if (copy == NULL)
		return (false);

	result = 0;
	token = strtok_r(copy, "|", &saveptr);
	while (token != NULL) {
		kw = eventlog_keyword_from_string(provider, token);
		if (kw == 0) {
			free(copy);
			return (false);
		}
		result |= kw;
		token = strtok_r(NULL, "|", &saveptr);
	}
	free(copy);

	if (result == 0)
		return (false);

	*out = result;
	return (true);
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
			errx(1,
			    "invalid buffer size: trailing characters after unit");

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
			errx(1, "invalid buffer size unit: %c (use K, M, or G)",
			    unit);
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
    uint64_t start_utc_time_us);
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

	for (i = 0, j = 0;
	    session_id[i] != '\0' && j < (sizeof(sanitized) - 1); i++) {
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

	sf = malloc(sizeof(*sf));
	if (sf == NULL)
		err(1, "malloc(session_file)");
	sf->session_id = strdup(session_id);
	if (sf->session_id == NULL)
		err(1, "strdup");
	if (snprintf(fullpath, sizeof(fullpath), "%s/%s.elog", output_dir,
	    sanitized) >= (int)sizeof(fullpath))
		errx(1, "path too long");
	sf->filepath = strdup(fullpath);
	if (sf->filepath == NULL)
		err(1, "strdup");
	sf->fp = fopen(fullpath, "wb");
	if (sf->fp == NULL)
		err(1, "fopen(%s)", fullpath);
	sf->header_written = false;
	sf->capture_start = 0;
	sf->event_count = 0;
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

static void
init_binary_header(struct elog_binary_header *hdr, uint64_t capture_start,
    uint64_t start_utc_us, uint64_t event_count, uint64_t dropped_events)
{
	memcpy(hdr->magic, ELOG_BINARY_MAGIC, 4);
	hdr->version = ELOG_BINARY_VERSION;
	hdr->capture_start = capture_start;
	hdr->start_utc_us = start_utc_us;
	hdr->event_count = event_count;
	hdr->dropped_events = dropped_events;
}

static void
rewrite_binary_header(FILE *fp, uint64_t capture_start,
    uint64_t start_utc_us, uint64_t event_count, uint64_t dropped_events)
{
	struct elog_binary_header hdr;
	init_binary_header(&hdr, capture_start, start_utc_us,
	    event_count, dropped_events);
	if (fseek(fp, 0, SEEK_SET) != 0)
		err(1, "fseek");
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(binary header)");
}

/*
 * Extract TCP connection metadata from CONN_SET_IP_V[46] / LOG_ID
 * events for the file-rename feature (-f tcp). Only the first log_id
 * and first connection address seen for a session are captured.
 */
static void
extract_tcp_metadata(struct session_file *sf,
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	if (sf == NULL || (sf->has_log_id && sf->has_conn_info) ||
	    strcmp(get_provider_name(hdr->provider_id), "tcp") != 0)
		return;

	switch (hdr->event_id) {
	case TCP_EVENTLOG_CONN_SET_IP_V4_ID: {
		const struct tcp_eventlog_conn_set_ip_v4 *evt;
		if (sf->has_conn_info)
			break;
		if (payload_size < sizeof(*evt))
			break;
		evt = (const struct tcp_eventlog_conn_set_ip_v4 *)payload;
		sf->local_port = ntohs(evt->src_port);
		sf->remote_port = ntohs(evt->dst_port);
		inet_ntop(AF_INET, &evt->dst_addr, sf->remote_ip,
		    sizeof(sf->remote_ip));
		sf->has_conn_info = true;
		break;
	}
	case TCP_EVENTLOG_CONN_SET_IP_V6_ID: {
		const struct tcp_eventlog_conn_set_ip_v6 *evt;
		if (sf->has_conn_info)
			break;
		if (payload_size < sizeof(*evt))
			break;
		evt = (const struct tcp_eventlog_conn_set_ip_v6 *)payload;
		sf->local_port = ntohs(evt->src_port);
		sf->remote_port = ntohs(evt->dst_port);
		inet_ntop(AF_INET6, &evt->dst_addr, sf->remote_ip,
		    sizeof(sf->remote_ip));
		sf->has_conn_info = true;
		break;
	}
	case TCP_EVENTLOG_LOG_ID_ID: {
		const struct tcp_eventlog_log_id *evt;
		if (sf->has_log_id)
			break;
		if (payload_size < sizeof(*evt))
			break;
		evt = (const struct tcp_eventlog_log_id *)payload;
		if (evt->log_id[0] != '\0') {
			strlcpy(sf->log_id, evt->log_id, sizeof(sf->log_id));
			sf->has_log_id = true;
		}
		break;
	}
	}
}

/*
 * Rename a session file based on captured TCP metadata.
 * Format: <log_id>_<local_port>_<remote_ip>_<remote_port>.elog
 * Missing fields are replaced with "unknown". If no metadata at all,
 * skip the rename.
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
			if (sf->header_written)
				rewrite_binary_header(sf->fp, sf->capture_start,
				    sf->start_utc_us, sf->event_count, 0);
			fflush(sf->fp);
			fclose(sf->fp);
			sf->fp = NULL;
			rename_session_file(sf);
			STAILQ_REMOVE(&session_files, sf, session_file, link);
			free(sf->filepath);
			free(sf->session_id);
			free(sf);
			return;
		}
	}
}

static void
write_binary_header_to_file(FILE *fp, uint64_t capture_start_time,
    uint64_t start_utc_time_us)
{
	struct elog_binary_header hdr;
	uint32_t i;

	init_binary_header(&hdr, capture_start_time, start_utc_time_us, 0, 0);
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(binary header)");
	if (fwrite(&provider_map_count, sizeof(provider_map_count), 1, fp) != 1)
		err(1, "fwrite(provider count)");
	for (i = 0; i < provider_map_count; i++) {
		if (fwrite(&provider_map[i], sizeof(provider_map[i]), 1, fp)
		    != 1)
			err(1, "fwrite(provider)");
	}
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

	snprintf(session_id_str, sizeof(session_id_str), "%lu",
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
			struct timeval tv;
			gettimeofday(&tv, NULL);
			uint64_t utc_us = (uint64_t)tv.tv_sec * 1000000 +
			    tv.tv_usec;
			write_binary_header_to_file(out_fp, hdr->timestamp,
			    utc_us);
			sf->header_written = true;
			sf->capture_start = hdr->timestamp;
			sf->start_utc_us = utc_us;
		}
		sf->event_count++;
		if (format_tcp)
			extract_tcp_metadata(sf, hdr, payload, payload_size);
	}

	event_length = sizeof(struct eventlog_event_header) + payload_size;
	if (event_length > UINT16_MAX)
		errx(1, "Event too large for binary format: %zu bytes",
		    event_length);

	struct eventlog_event_header hdr_copy = *hdr;
	hdr_copy.event_length = (uint16_t)event_length;
	if (fwrite(&hdr_copy, sizeof(struct eventlog_event_header), 1, out_fp)
	    != 1)
		err(1, "fwrite(event header)");
	if (payload_size > 0 && fwrite(payload, payload_size, 1, out_fp) != 1)
		err(1, "fwrite(payload)");

	if (output_dir != NULL) {
		if (eventlog_is_session_end(NULL, hdr->event_id))
			close_session_file(session_id_str);
	}
}

static void
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
	int formatted_len;

	if (binary_output_mode()) {
		write_binary_event(hdr, payload, payload_size);
		return;
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

	formatted_len = eventlog_format_payload(
	    provider_name, payload, payload_size,
	    hdr->event_id, formatted_buf, sizeof(formatted_buf));
	if (formatted_len <= 0)
		snprintf(formatted_buf, sizeof(formatted_buf),
		    "[UNKNOWN_EVENT_ID:%u]", hdr->event_id);

	event_num_buf[0] = '\0';
	if (show_event_number)
		snprintf(event_num_buf, sizeof(event_num_buf),
		    "%-8llu ", (unsigned long long)(events_received + 1));

	event_name_buf[0] = '\0';
	if (show_event_name) {
		const char *name = eventlog_event_id_to_name(
		    provider_name, hdr->event_id);
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

	fputs(log_line, stdout);
}

static void
update_binary_header(void)
{
	struct session_file *sf;

	if (output_dir != NULL) {
		STAILQ_FOREACH(sf, &session_files, link) {
			if (sf->header_written)
				rewrite_binary_header(sf->fp, sf->capture_start,
				    sf->start_utc_us, sf->event_count, 0);
		}
		return;
	}

	if (!single_output.header_written)
		return;
	rewrite_binary_header(single_output.fp, single_output.capture_start,
	    single_output.start_utc_us, events_received, last_dropped_events);
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
		ssize_t n;

		n = elog_reader_read(r, (char *)buf + total, len - total);
		if (n <= 0) {
			if (total == 0)
				return (false);
			errx(1,
			    "Unexpected end of file (read %zu of %zu bytes)",
			    total, len);
		}
		total += n;
	}
	return (true);
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
	if (!elog_reader_read_exact(&reader, &file_hdr, sizeof(file_hdr)))
		errx(1, "File is empty");

	/* Validate magic number */
	if (memcmp(file_hdr.magic, ELOG_BINARY_MAGIC, 4) != 0)
		errx(1, "Invalid binary file: bad magic number");

	/* Validate version */
	if (file_hdr.version != ELOG_BINARY_VERSION)
		errx(1, "Unsupported file version: %u (expected %u)",
		    file_hdr.version, ELOG_BINARY_VERSION);

	/*
	 * Stash for format_timestamp when printing
	 * (UTC = start_utc_us + (event_ts - capture_start)).
	 */
	read_capture_start = file_hdr.capture_start;
	read_start_utc_us = file_hdr.start_utc_us;

	/* V2: read provider list for event lookup */
	if (!elog_reader_read_exact(&reader, &provider_map_count,
	    sizeof(provider_map_count)))
		err(1, "read(provider count)");
	if (provider_map_count > EVENTLOG_MAX_PROVIDERS)
		errx(1, "Invalid provider count %u in file",
		    provider_map_count);
	for (uint32_t i = 0; i < provider_map_count; i++) {
		if (!elog_reader_read_exact(&reader, &provider_map[i],
		    sizeof(provider_map[i])))
			err(1, "read(provider)");
	}

	print_provider_names();

	/* Allocate buffers for reading events */
	buffer = malloc(buffer_capacity);
	if (buffer == NULL)
		err(1, "malloc(buffer)");
	partial_buffer = malloc(buffer_capacity);
	if (partial_buffer == NULL)
		err(1, "malloc(partial_buffer)");

	/*
	 * Read events in chunks and parse them using the same code as
	 * kernel events.
	 */
	while (!elog_reader_eof(&reader)) {
		/* If we have partial data from previous read, prepend it */
		if (partial_size > 0) {
			if (partial_size > buffer_capacity) {
				/* Partial event too large; likely corrupt. */
				errx(1,
				    "Partial event too large, file may be corrupted");
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
				errx(1,
				    "remaining data larger than buffer capacity");
			}
			memcpy(partial_buffer, buffer + consumed, remaining);
			partial_size = remaining;
		}
		buffer_used = 0;
	}

	free(buffer);
	free(partial_buffer);
	elog_reader_close(&reader);

	return (0);
}

/*
 * Parse and print eventlog data.
 * Format (V1):
 *   Each event: eventlog_event_header (includes provider_id, session_id,
 *   event_id) + payload.
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
			fprintf(stderr,
			    "Error: invalid event_length %u at offset %zu\n",
			    hdr.event_length, (size_t)(buf - start));
			buf += sizeof(struct eventlog_event_header);
			return (buf - start);
		}
		if (event_start + hdr.event_length > end)
			break;

		buf += sizeof(struct eventlog_event_header);
		event_payload_len = hdr.event_length -
		    sizeof(struct eventlog_event_header);
		print_eventlog_event(&hdr, buf, event_payload_len);
		events_received++;
		buf = event_start + hdr.event_length;
	}
	return (buf - start);
}

static void
print_stats(void)
{
	/* Prevent double-printing */
	if (stats_printed)
		return;
	stats_printed = true;

	/* Always query kernel stats for binary header update */
	if (eventlog_fd >= 0) {
		struct eventlog_stats stats;
		if (ioctl(eventlog_fd, EVENTLOG_IOCTL_GET_STATS, &stats) == 0)
			last_dropped_events = stats.dropped_events;
	}

	if (!verbose_stats)
		return;

	fprintf(stderr, "\n[Stats]\n");
	fprintf(stderr, "  Providers: %u\n", provider_map_count);
	fprintf(stderr, "  Events received: %llu\n",
	    (unsigned long long)events_received);
	if (last_dropped_events > 0)
		fprintf(stderr, "  Dropped events: %llu\n",
		    (unsigned long long)last_dropped_events);
}

static void
sigint_handler(int sig __unused)
{
	struct session_file *sf;

	done = true;
	/* Stats will be printed by atexit handler or normal exit path */
	/* Flush output before exit */
	if (output_dir != NULL) {
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

/*
 * Parse command line arguments and populate global state.
 */
static bool
arg_match(const char *arg, const char *long_form, const char *short_form)
{
	return (strcmp(arg, long_form) == 0 ||
	    (short_form != NULL && strcmp(arg, short_form) == 0));
}

static void
parse_arguments(int argc, char *argv[])
{
	int arg_idx;
	const char *arg;

	for (arg_idx = 1; arg_idx < argc; arg_idx++) {
		arg = argv[arg_idx];
		if (arg_match(arg, "--capture", "-c")) {
			enum eventlog_level level = EVENTLOG_LEVEL_VERBOSE;
			uint32_t keywords = 0xFFFFFFFF;
			int next_idx = arg_idx + 1;

			if (subscription_count >= subscription_capacity) {
				int new_capacity = (subscription_capacity == 0)
				    ? 16 : subscription_capacity * 2;
				struct subscription *new_subscriptions =
				    realloc(subscriptions, new_capacity *
				    sizeof(struct subscription));
				if (new_subscriptions == NULL)
					errx(1,
					    "failed to allocate subscriptions");
				subscriptions = new_subscriptions;
				subscription_capacity = new_capacity;
			}

			if (next_idx >= argc)
				errx(1,
				    "--capture requires at least provider name");

			if (strlen(argv[next_idx]) >=
			    EVENTLOG_PROVIDER_NAME_MAX)
				errx(1, "provider name too long");

			memset(&subscriptions[subscription_count], 0,
			    sizeof(subscriptions[0]));
			strlcpy(subscriptions[subscription_count].provider_name,
			    argv[next_idx],
			    sizeof(subscriptions[0].provider_name));
			next_idx++;

			if (next_idx < argc &&
			    try_parse_level(argv[next_idx], &level))
				next_idx++;

			/*
			 * Optional keywords (hex 0x prefix or pipe-delimited
			 * names).
			 */
			if (next_idx < argc &&
			    try_parse_keywords(
				subscriptions[subscription_count].provider_name,
				argv[next_idx], &keywords))
				next_idx++;

			/* Always include SESSION for lifecycle events. */
			subscriptions[subscription_count].level = level;
			subscriptions[subscription_count].keywords =
			    keywords | EVENTLOG_KEYWORD_SESSION;

			arg_idx = next_idx - 1;
			subscription_count++;
		} else if (arg_match(arg, "--buffer-size", "-b")) {
			int next_idx = arg_idx + 1;
			if (next_idx >= argc)
				errx(1, "--buffer-size requires a size value");
			buffer_size_per_cpu = parse_size(argv[next_idx]);
			arg_idx = next_idx;
		} else if (arg_match(arg, "--duration", NULL)) {
			int next_idx = arg_idx + 1;
			char *endptr;
			unsigned long val;

			if (next_idx >= argc)
				errx(1, "--duration requires a seconds value");
			val = strtoul(argv[next_idx], &endptr, 10);
			if (*argv[next_idx] == '\0' || *endptr != '\0')
				errx(1, "--duration: not a number: %s",
				    argv[next_idx]);
			if (val > UINT_MAX)
				errx(1, "--duration: value too large");
			duration_sec = (unsigned int)val;
			arg_idx = next_idx;
		} else if (arg_match(arg, "--date", "-d")) {
			show_date = true;
		} else if (arg_match(arg, "--event-name", "-e")) {
			show_event_name = true;
		} else if (arg_match(arg, "--event-number", "-n")) {
			show_event_number = true;
		} else if (arg_match(arg, "--providers", "-p")) {
			show_providers = true;
		} else if (arg_match(arg, "--stats", "-s")) {
			verbose_stats = true;
		} else if (arg_match(arg, "--output", "-o")) {
			int next_idx = arg_idx + 1;
			if (next_idx >= argc)
				errx(1,
				    "--output requires a filename or dir=path");
			if (strncmp(argv[next_idx], "dir=", 4) == 0) {
				output_dir = strdup(argv[next_idx] + 4);
				if (output_dir == NULL)
					err(1, "strdup");
				if (mkdir(output_dir, 0755) != 0 &&
				    errno != EEXIST)
					err(1, "mkdir(%s)", output_dir);
			} else {
				single_output.fp = fopen(argv[next_idx], "wb");
				if (single_output.fp == NULL)
					err(1, "fopen(%s)", argv[next_idx]);
			}
			arg_idx = next_idx;
		} else if (arg_match(arg, "--relative-time", "-t")) {
			show_relative_time = true;
		} else if (arg_match(arg, "--delta-time", NULL)) {
			show_delta_time = true;
		} else if (arg_match(arg, "--dump-state", "-D")) {
			dump_state = true;
		} else if (arg_match(arg, "--format", "-f")) {
			int next_idx = arg_idx + 1;
			if (next_idx >= argc ||
			    strcmp(argv[next_idx], "tcp") != 0)
				errx(1, "--format requires 'tcp' argument");
			format_tcp = true;
			arg_idx = next_idx;
		} else if (arg_match(arg, "--read-binary", "-r")) {
			int next_idx = arg_idx + 1;
			if (next_idx >= argc)
				errx(1, "--read-binary requires a filename");
			binary_input_file = argv[next_idx];
			arg_idx = next_idx;
		} else if (arg_match(arg, "--help", "-h")) {
			usage();
		} else {
			errx(1, "unknown argument: %s (use --capture or -c)",
			    arg);
		}
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
	size_t base_offset = __builtin_offsetof(struct eventlog_create_req,
	    subscriptions);
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

	/* Verify sizes match */
	if (ioctl_size != req_size) {
		errx(1, "ioctl size calculation error");
	}

	/* Send CREATE ioctl (creates subscriber and subscribes) */
	error = ioctl(fd, ioctl_cmd, req);
	if (error != 0) {
		err(1, "ioctl(EVENTLOG_IOCTL_CREATE)");
	}

	free(req);

	/* Get provider ids for event lookup (required for new binary format) */
	{
		struct eventlog_get_providers_resp prov_resp;
		memset(&prov_resp, 0, sizeof(prov_resp));
		error = ioctl(fd, EVENTLOG_IOCTL_GET_PROVIDERS, &prov_resp);
		if (error != 0)
			err(1, "ioctl(EVENTLOG_IOCTL_GET_PROVIDERS)");
		provider_map_count = prov_resp.count;
		memcpy(provider_map, prov_resp.providers,
		    provider_map_count * sizeof(provider_map[0]));
	}

	print_provider_names();


	/* Allocate buffer */
	buffer = malloc(bufsize);
	if (buffer == NULL)
		err(1, "malloc");

	eventlog_fd = fd; /* Store for signal handler */

	/* Read and parse events */
	while (!done) {
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

		/* Provider name is included in the event format. */
		parse_and_print_events((const unsigned char *)buffer, nread);
	}

	/* Print stats before cleanup */
	print_stats();

	/* Update binary header with final event/drop counts before closing */
	update_binary_header();

	/* Cleanup on exit */
	close(fd);
	eventlog_fd = -1;
	free(buffer);
	free(subscriptions);
	if (output_dir != NULL) {
		struct session_file *sf, *sf_next;
		for (sf = STAILQ_FIRST(&session_files); sf != NULL;
		    sf = sf_next) {
			sf_next = STAILQ_NEXT(sf, link);
			if (sf->fp != NULL) {
				fflush(sf->fp);
				fclose(sf->fp);
				sf->fp = NULL;
				rename_session_file(sf);
			}
			free(sf->filepath);
			free(sf->session_id);
			free(sf);
		}
		STAILQ_INIT(&session_files);
		free(output_dir);
		output_dir = NULL;
	} else if (single_output.fp != NULL) {
		fflush(single_output.fp);
		fclose(single_output.fp);
		single_output.fp = NULL;
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	/* Parse command line arguments */
	parse_arguments(argc, argv);

	/* Handle binary read mode - this bypasses capture */
	if (binary_input_file != NULL) {
		if (subscription_count > 0) {
			errx(1,
			    "--read-binary cannot be used with subscribe options");
		}
		return (read_binary_file(binary_input_file));
	}

	/* Check if we have any subscriptions */
	if (subscription_count == 0)
		errx(1, "no subscriptions specified (use --capture or -c)");

	/* Register atexit handler to ensure stats are always printed */
	atexit(print_stats);

	/* Set up signal handlers for cleanup on interrupt. */
	struct sigaction sa;
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);

	/*
	 * --duration schedules a SIGALRM that uses the same cleanup
	 * path as SIGINT/SIGTERM (see sigint_handler). The main read
	 * loop in run_eventlog_mode() checks `done` after EINTR.
	 */
	if (duration_sec > 0) {
		(void)sigaction(SIGALRM, &sa, NULL);
		alarm(duration_sec);
	}

	/* Run eventlog device mode */
	return (run_eventlog_mode());
}

