/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _LIBELOG_USER_SYMBOLS_H_
#define _LIBELOG_USER_SYMBOLS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct eventlog_event_header;

/*
 * libelog_user_symbols turns an .elog stream's symbols.USER_FILE events
 * into a stream of synthetic symbols.USER_SYMBOL_RANGE events that
 * carry one (file_id, offset, size, name) per function in each
 * backing user-mode binary (.symtab, or .gopclntab for Go).
 *
 * The library is a pure consumer: it does not open the kernel's
 * eventlog control device, does not subscribe, does not produce
 * events on its own. Callers feed every event they receive via
 * elog_user_symbols_observe() and the library invokes the supplied
 * `emit_fn` callback once per synthesised USER_SYMBOL_RANGE event.
 *
 * Architecture vs. earlier elog -U:
 *   - The kernel "symbols" provider emits USER_FILE for each (dev,ino)
 *     interned via eventlog_symbols_intern_user_file(); the kernel
 *     "process" provider emits PROC_EXEC / PROC_EXIT / PROC_MAP for
 *     every process and executable mapping. So this library does NOT
 *     need libprocstat: every binary it must symbolise arrives in a
 *     USER_FILE event with its pathname.
 *   - The library treats `pathname` as the source of truth for the
 *     ELF to parse. Same path on disk == same parse result; (dev,ino)
 *     identity is the kernel's responsibility.
 */

/*
 * Callback used by the library to inject synthesised USER_SYMBOL_RANGE
 * events into the consumer's output stream. The header `hdr` is the
 * library's copy of the triggering USER_FILE event's header with
 * event_id rewritten; the consumer is responsible for setting
 * event_length to match `payload_size` if its file format requires it.
 */
typedef void (*elog_user_symbols_emit_fn)(
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size,
    void *cookie);

/*
 * Initialise / shut down the resolver. init() is cheap and always
 * succeeds; shutdown() releases the per-file caches. Calling
 * shutdown() without a matching init() is safe and a no-op.
 */
void	elog_user_symbols_init(void);
void	elog_user_symbols_shutdown(void);

/*
 * Reference mode: emit a SYMBOL_PACK_REF for each GNU build-id and
 * skip that file's USER_SYMBOL_RANGE walk. A Go binary still emits
 * its .gopclntab ranges beside the ref. The caller is expected to
 * have narrowed the symbols subscription to
 * KERNEL_META/USER_META/REFS so kernel-side ranges stay out of the
 * capture too. Off by default (inline mode).
 */
void	elog_user_symbols_set_ref_mode(bool ref_mode);

/*
 * Per-event hook. The consumer calls this exactly once per event it
 * receives, in stream order.
 *
 * If the event is a symbols.USER_FILE that names a real file on disk
 * the library has not parsed yet, it opens the file, enumerates its
 * functions, and invokes emit_fn once per symbol with a synthesised
 * symbols.USER_SYMBOL_RANGE event. C binaries are read from .symtab /
 * .dynsym; a Go binary (.note.go.buildid) is read from .gopclntab. The
 * library never consumes the source event -- the consumer is free to
 * forward USER_FILE through to its own output.
 *
 * Any other event is a cheap early return.
 *
 * `provider_name` is the resolved provider name for hdr->provider_id
 * (the consumer obtains it from its provider-map). Anything other
 * than "symbols" is ignored.
 */
void	elog_user_symbols_observe(const char *provider_name,
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size,
    elog_user_symbols_emit_fn emit_fn, void *cookie);

/*
 * Statistics: number of files parsed/replayed and number of
 * synthesised USER_SYMBOL_RANGE events emitted/replayed since
 * init(). A "replay" is a repeat USER_FILE sighting for an
 * already-parsed file (e.g. a second process mapping the same
 * shared object during one dump_state): its cached ranges are
 * re-emitted from memory instead of re-parsing the ELF. Useful for
 * elog -s output.
 */
uint64_t	elog_user_symbols_files_parsed(void);
uint64_t	elog_user_symbols_ranges_emitted(void);
uint64_t	elog_user_symbols_files_replayed(void);
uint64_t	elog_user_symbols_ranges_replayed(void);

#endif /* _LIBELOG_USER_SYMBOLS_H_ */
