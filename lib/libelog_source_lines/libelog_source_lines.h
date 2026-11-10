/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _LIBELOG_SOURCE_LINES_H_
#define _LIBELOG_SOURCE_LINES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct eventlog_event_header;

/*
 * libelog_source_lines turns sampled stack PCs into synthesised
 * symbols.SOURCE_FILE / symbols.SOURCE_LINE events. observe() records
 * unique (pc, pid) frames; resolve() maps them to binaries and looks
 * up on-disk DWARF once the capture loop has seen every mapping event.
 *
 * The library is a pure consumer of the event stream: callers feed
 * every event via elog_source_lines_observe(). elog_source_lines_resolve()
 * invokes emit_fn once per synthesised SOURCE_FILE / SOURCE_LINE.
 * Counts are intentionally not embedded — EventExplorer recomputes
 * them under the active Flame filter from CPU_SAMPLE + this map.
 *
 * Kernel SOURCE_FILE rows carry the firmware commit parsed from the
 * kern.version string handed to elog_source_lines_set_kernel_version().
 *
 * Observed providers / events:
 *   symbols.LINKER_FILE  — kernel image metadata + DWARF open path
 *   symbols.USER_FILE    — user ELF metadata + DWARF open path
 *   process.PROC_MAP     — per-pid executable mappings
 *   cpu.CPU_SAMPLE       — every frame in frames[0..depth)
 */

typedef void (*elog_source_lines_emit_fn)(
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size,
    void *cookie);

void	elog_source_lines_init(void);
void	elog_source_lines_shutdown(void);

void	elog_source_lines_observe(const char *provider_name,
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size);

/*
 * Resolve every PC recorded since init() against on-disk DWARF,
 * invoking emit_fn per synthesised SOURCE_FILE / SOURCE_LINE. Call
 * once after the capture loop ends; later calls are no-ops.
 */
void	elog_source_lines_resolve(elog_source_lines_emit_fn emit_fn,
    void *cookie);

void	elog_source_lines_set_kernel_version(const char *version);

uint64_t	elog_source_lines_binaries_opened(void);
uint64_t	elog_source_lines_files_emitted(void);
uint64_t	elog_source_lines_lines_emitted(void);
uint64_t	elog_source_lines_misses(void);
uint64_t	elog_source_lines_misses_no_binary(void);
uint64_t	elog_source_lines_misses_open(void);
uint64_t	elog_source_lines_misses_addr(void);
uint64_t	elog_source_lines_misses_line(void);
uint64_t	elog_source_lines_lines_capped(void);

/* Test hook: replace the split-debug root for this process. Passing
 * NULL restores /usr/lib/debug. */
void	elog_source_lines_set_debug_path(const char *root);

/* Visits binaries whose DWARF open was attempted, including failures. */
typedef void (*elog_source_lines_binary_fn)(uint8_t kind, uint32_t id,
    const char *pathname, bool open_ok, uint64_t lines, uint64_t misses,
    void *arg);
void	elog_source_lines_foreach_binary(elog_source_lines_binary_fn fn,
    void *arg);

/* Where one binary's line index was read from: the mapped file, or its
 * split debug twin when the first index was thin. NULL when the open
 * failed or the path was never observed. */
const char *elog_source_lines_binary_debug_path(const char *pathname);

#endif /* _LIBELOG_SOURCE_LINES_H_ */
