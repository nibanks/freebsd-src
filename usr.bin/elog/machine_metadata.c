/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#include <sys/eventlog.h>
#include <sys/eventlog_decode.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <err.h>

#include <sha256.h>

#include "machine_metadata.h"

#define	MACHINE_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/machine_eventlog.h>

static bool metadata_enabled = true;
static struct eventlog_provider_info machine_pi;
static struct machine_eventlog_machine_info collected;
static bool collected_valid;

static void
strlcpy_safe(char *dst, const char *src, size_t len)
{

	if (len == 0)
		return;
	strlcpy(dst, src != NULL ? src : "", len);
}

static void
sysctl_string(const char *name, char *buf, size_t len)
{
	size_t sz;

	if (len == 0)
		return;
	buf[0] = '\0';
	sz = len;
	if (sysctlbyname(name, buf, &sz, NULL, 0) != 0)
		return;
	buf[len - 1] = '\0';
}

static void
sysctl_u64(const char *name, uint64_t *out)
{
	uint64_t v;
	size_t sz;

	sz = sizeof(v);
	if (sysctlbyname(name, &v, &sz, NULL, 0) == 0 && sz == sizeof(v))
		*out = v;
}

static void
sysctl_u32(const char *name, uint32_t *out)
{
	uint32_t v;
	size_t sz;

	sz = sizeof(v);
	if (sysctlbyname(name, &v, &sz, NULL, 0) == 0 && sz == sizeof(v))
		*out = v;
}

static void
read_firmware_version(char *buf, size_t len)
{
	FILE *fp;
	char line[512];

	if (len == 0)
		return;
	buf[0] = '\0';
	fp = fopen("/etc/VERSION", "re");
	if (fp == NULL)
		return;
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p, *hash, *end;

		hash = strchr(line, '#');
		if (hash != NULL)
			*hash = '\0';
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		end = p + strcspn(p, "\r\n");
		*end = '\0';
		while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (*p == '\0')
			continue;
		strlcpy_safe(buf, p, len);
		break;
	}
	fclose(fp);
}

static void
read_kenv(const char *name, char *buf, size_t len)
{
	char cmd[128];
	FILE *fp;

	if (len == 0)
		return;
	buf[0] = '\0';
	if (snprintf(cmd, sizeof(cmd), "kenv -q %s 2>/dev/null", name) >=
	    (int)sizeof(cmd))
		return;
	fp = popen(cmd, "r");
	if (fp == NULL)
		return;
	if (fgets(buf, (int)len, fp) != NULL) {
		size_t n = strlen(buf);

		while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
			buf[--n] = '\0';
	}
	pclose(fp);
}

const unsigned char *
machine_metadata_decode_blob(size_t *size_out)
{

	*size_out = machine_eventlog_decode_blob_size;
	return (machine_eventlog_decode_blob);
}

void
machine_metadata_register(void)
{
	SHA256_CTX ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];

	memset(&machine_pi, 0, sizeof(machine_pi));
	machine_pi.provider_id = ELOG_MACHINE_PROVIDER_ID;
	strlcpy(machine_pi.name, "machine", sizeof(machine_pi.name));
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, machine_eventlog_decode_blob,
	    machine_eventlog_decode_blob_size);
	SHA256_Final(digest, &ctx);
	memcpy(machine_pi.schema_id, digest, EVENTLOG_DECODE_SCHEMA_ID_LEN);
}

bool
machine_metadata_enabled(void)
{

	return (metadata_enabled);
}

void
machine_metadata_set_enabled(bool enabled)
{

	metadata_enabled = enabled;
}

const struct eventlog_provider_info *
machine_metadata_provider(void)
{

	return (&machine_pi);
}

static void
machine_metadata_collect_once(void)
{
	char product[64], maker[64], machine[32];
	struct timeval boottime;
	uint32_t ncpu;
	uint64_t physmem;
	size_t sz;

	if (collected_valid)
		return;
	memset(&collected, 0, sizeof(collected));
	sysctl_string("kern.hostuuid", collected.hostuuid,
	    sizeof(collected.hostuuid));
	sysctl_string("kern.hostname", collected.hostname,
	    sizeof(collected.hostname));
	sysctl_string("kern.osrelease", collected.osrelease,
	    sizeof(collected.osrelease));
	sysctl_string("kern.version", collected.kernel_version,
	    sizeof(collected.kernel_version));
	read_firmware_version(collected.firmware_version,
	    sizeof(collected.firmware_version));
	sysctl_string("hw.model", collected.cpu_model,
	    sizeof(collected.cpu_model));
	ncpu = 0;
	physmem = 0;
	sysctl_u32("hw.ncpu", &ncpu);
	sysctl_u64("hw.physmem", &physmem);
	collected.ncpu = ncpu;
	collected.physmem = physmem;
	sz = sizeof(boottime);
	if (sysctlbyname("kern.boottime", &boottime, &sz, NULL, 0) == 0 &&
	    sz == sizeof(boottime))
		collected.boottime_sec = boottime.tv_sec;
	sysctl_string("hw.machine", machine, sizeof(machine));
	read_kenv("smbios.system.product", product, sizeof(product));
	read_kenv("smbios.system.maker", maker, sizeof(maker));
	if (product[0] != '\0' || maker[0] != '\0') {
		snprintf(collected.platform, sizeof(collected.platform),
		    "%s%s%s (%s)", maker, (maker[0] != '\0' &&
		    product[0] != '\0') ? " " : "", product, machine);
	} else
		strlcpy_safe(collected.platform, machine,
		    sizeof(collected.platform));
	collected_valid = true;
}

static void
write_synth_event(FILE *fp, uint16_t provider_id, uint32_t event_id,
    uint64_t timestamp, const void *payload, size_t payload_size,
    uint64_t *bytes, uint64_t *event_count)
{
	struct eventlog_event_header hdr;
	size_t event_length;

	event_length = sizeof(hdr) + payload_size;
	if (event_length > UINT16_MAX)
		return;
	memset(&hdr, 0, sizeof(hdr));
	hdr.event_length = (uint16_t)event_length;
	hdr.provider_id = provider_id;
	hdr.timestamp = timestamp;
	hdr.session_id = EVENTLOG_SESSION_ID_NONE;
	hdr.event_id = event_id;
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "fwrite(machine metadata header)");
	if (payload_size > 0 &&
	    fwrite(payload, payload_size, 1, fp) != 1)
		err(1, "fwrite(machine metadata payload)");
	if (bytes != NULL)
		*bytes += event_length;
	if (event_count != NULL)
		(*event_count)++;
}

static void
maybe_write_tcp_stack_kv(FILE *fp, struct embedded_set *emb __unused,
    uint64_t timestamp, uint64_t *bytes, uint64_t *event_count)
{
	struct machine_eventlog_metadata_kv kv;
	char stack[128];

	memset(&kv, 0, sizeof(kv));
	sysctl_string("net.inet.tcp.functions_default", stack, sizeof(stack));
	if (stack[0] == '\0')
		return;
	strlcpy(kv.key, "tcp.stack", sizeof(kv.key));
	strlcpy(kv.value, stack, sizeof(kv.value));
	write_synth_event(fp, ELOG_MACHINE_PROVIDER_ID,
	    MACHINE_EVENTLOG_MetadataKV_ID, timestamp, &kv, sizeof(kv),
	    bytes, event_count);
}

void
machine_metadata_write_events(FILE *fp, struct embedded_set *emb,
    uint64_t timestamp, uint64_t *bytes, uint64_t *event_count,
    void (*announce_provider)(FILE *, struct embedded_set *, uint16_t,
    uint64_t, uint64_t *))
{

	if (!metadata_enabled)
		return;
	machine_metadata_collect_once();
	if (announce_provider != NULL)
		announce_provider(fp, emb, ELOG_MACHINE_PROVIDER_ID,
		    timestamp, bytes);
	write_synth_event(fp, ELOG_MACHINE_PROVIDER_ID,
	    MACHINE_EVENTLOG_MachineInfo_ID, timestamp, &collected,
	    sizeof(collected), bytes, event_count);
	maybe_write_tcp_stack_kv(fp, emb, timestamp, bytes, event_count);
}
