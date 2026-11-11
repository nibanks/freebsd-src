/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _MACHINE_METADATA_H_
#define	_MACHINE_METADATA_H_

#include <sys/eventlog_dev.h>
#include <stdint.h>
#include <stdio.h>

/* Reserved provider_id for elog-synthesised machine metadata events. */
#define	ELOG_MACHINE_PROVIDER_ID	0xfffeu

struct embedded_set;

void machine_metadata_register(void);
const unsigned char *machine_metadata_decode_blob(size_t *size_out);
bool machine_metadata_enabled(void);
void machine_metadata_set_enabled(bool enabled);
const struct eventlog_provider_info *machine_metadata_provider(void);

/*
 * Write MACHINE_INFO (and optional METADATA_KV) events into an open
 * capture file immediately after its binary header. *bytes and
 * *event_count are updated when non-NULL.
 */
void machine_metadata_write_events(FILE *fp, struct embedded_set *emb,
    uint64_t timestamp, uint64_t *bytes, uint64_t *event_count,
    void (*announce_provider)(FILE *, struct embedded_set *, uint16_t,
    uint64_t, uint64_t *));

#endif /* !_MACHINE_METADATA_H_ */
