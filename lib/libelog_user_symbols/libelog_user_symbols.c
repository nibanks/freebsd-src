/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

/*
 * libelog_user_symbols -- userspace half of the eventlog symbol
 * resolution path.
 *
 * The kernel "symbols" provider emits one USER_FILE event per
 * (st_dev, st_ino) pair on first sighting, carrying the resolved
 * pathname. This library observes those events and, for each
 * pathname it has not parsed yet, opens the on-disk ELF, and
 * synthesises one symbols.USER_SYMBOL_RANGE event per function.
 * C binaries are read from .symtab / .dynsym (STT_FUNC /
 * STT_GNU_IFUNC). A Go binary (.note.go.buildid) is read from
 * .gopclntab.
 *
 * Each emitted USER_SYMBOL_RANGE.offset is the symbol's on-disk file
 * offset, computed by translating st_value through the matching
 * executable PT_LOAD segment (st_value - p_vaddr + p_offset). This
 * shares a coordinate space with the kernel process provider's
 * PROC_MAP.offset (which carries the vm_map_entry's file offset),
 * so consumers resolve a sample with the formula
 *
 *     pc - PROC_MAP.base + PROC_MAP.offset == USER_SYMBOL_RANGE.offset
 *
 * for any PC inside any executable file-backed mapping, regardless
 * of PIE / ASLR / load_bias.
 *
 * The synthesised events are emitted via the caller-supplied
 * `emit_fn` callback. The library does not write to the .elog
 * stream itself; the caller decides when and where the events
 * land. Synthesised events copy the triggering USER_FILE event's
 * provider_id / session_id / timestamp / cpu / thread_id so they
 * sort with their parent on any per-session consumer.
 *
 * While the ELF is open the library also reads NT_GNU_BUILD_ID and
 * emits one symbols.SYMBOL_PACK_REF naming the file's symbol pack:
 * id_kind 0 (GNU build-id) when the note exists, else id_kind 1, a
 * SHA-256 of the file's bytes. In reference mode (elog
 * --symbol-mode=refs) the ref is emitted only for id_kind 0 — a
 * content hash says nothing about whether a pack exists — and
 * note-less files keep the inline walk instead. A Go binary is
 * read from .gopclntab and those ranges are emitted even when the
 * file also has a GNU build-id.
 *
 * v1 limitations (deferred follow-ups):
 *   - libelf only. A non-Go binary with an empty .symtab/.dynsym
 *     produces zero USER_SYMBOL_RANGEs.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/elf_common.h>
#include <sha256.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/eventlog.h>
#include <sys/eventlog_subscriber.h>

#include "libelog_user_symbols.h"

/*
 * Hand-declared mirrors of the "symbols" provider's USER_FILE /
 * USER_SYMBOL_RANGE event structs and IDs (see
 * include/eventlog/symbols_eventlog_schema.src / kern_symbols_eventlog.c).
 * There's no userspace-safe generated header for these anymore --
 * eventlog_gen.awk's producer header pulls in <sys/libkern.h>, and the
 * schema's runtime decode-blob is for name/format resolution, not C
 * struct layout. This is a small, stable surface (2 structs, 2 IDs), so
 * duplicating it here beats standing up a new codegen mode for one
 * consumer; keep it in sync with the schema by hand if it ever changes.
 */
#define	SYMBOLS_EVENTLOG_USER_FILE_ID		3
#define	SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID	4
#define	SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID	7

struct symbols_eventlog_user_file {
	uint32_t	user_file_id;
	char		build_id[41];
	char		pathname[128];
} __packed;

struct symbols_eventlog_user_symbol_range {
	uint32_t	user_file_id;
	uint64_t	offset;
	uint32_t	size;
	char		name[96];
} __packed;

struct symbols_eventlog_symbol_pack_ref {
	uint8_t		kind;
	uint8_t		id_kind;
	uint32_t	file_id;
	char		pack_id[65];
} __packed;

/* SYMBOL_PACK_REF kind / id_kind values (mirrors kern_symbols_eventlog.c). */
#define	SYM_ELOG_REF_KIND_LINKER_FILE	0
#define	SYM_ELOG_REF_KIND_USER_FILE	1
#define	SYM_ELOG_REF_ID_GNU_BUILD_ID	0
#define	SYM_ELOG_REF_ID_FILE_SHA256	1

#define	USER_FILE_HASH	256
#define	USER_FILE_MAX_PTLOADS	8

struct file_ptload {
	uint64_t	p_vaddr;
	uint64_t	p_offset;
	uint64_t	p_filesz;
};

struct user_file_entry {
	LIST_ENTRY(user_file_entry) link;
	uint32_t	user_file_id;
	bool		parsed;
	uint32_t	n_ptloads;
	struct file_ptload ptloads[USER_FILE_MAX_PTLOADS];
	char		pathname[128];
	/* Pack id: the GNU build-id hex when the note exists, else the
	 * SHA-256 of the file's bytes (most userland ELFs have no note). */
	char		build_id[65];
	uint8_t		id_kind;
	/* Whether this file contributes a SYMBOL_PACK_REF (refs mode:
	 * only when the id came from the file's own build-id note). */
	bool		refable;
	/* .note.go.buildid: refs mode still emits .gopclntab ranges. */
	bool		go_binary;
	/* Cached USER_SYMBOL_RANGE payloads, replayed on repeat sightings. */
	struct symbols_eventlog_user_symbol_range *cached_ranges;
	uint32_t	n_cached_ranges;
	uint32_t	cached_ranges_cap;
};

LIST_HEAD(user_file_bucket, user_file_entry);

static struct user_file_bucket	user_file_buckets[USER_FILE_HASH];
static bool			g_initialized;
static bool			g_libelf_initialized;
static bool			g_ref_mode;
static uint64_t			g_files_parsed;
static uint64_t			g_ranges_emitted;
static uint64_t			g_files_replayed;
static uint64_t			g_ranges_replayed;

static struct user_file_entry *
user_file_lookup(uint32_t user_file_id)
{
	struct user_file_entry *fe;
	struct user_file_bucket *bucket;

	bucket = &user_file_buckets[user_file_id % USER_FILE_HASH];
	LIST_FOREACH(fe, bucket, link) {
		if (fe->user_file_id == user_file_id)
			return (fe);
	}
	return (NULL);
}

static struct user_file_entry *
user_file_insert(uint32_t user_file_id, const char *pathname)
{
	struct user_file_entry *fe;
	struct user_file_bucket *bucket;

	fe = calloc(1, sizeof(*fe));
	if (fe == NULL)
		return (NULL);
	fe->user_file_id = user_file_id;
	if (pathname != NULL)
		strlcpy(fe->pathname, pathname, sizeof(fe->pathname));
	bucket = &user_file_buckets[user_file_id % USER_FILE_HASH];
	LIST_INSERT_HEAD(bucket, fe, link);
	return (fe);
}

void
elog_user_symbols_init(void)
{
	int i;

	if (g_initialized)
		return;
	for (i = 0; i < USER_FILE_HASH; i++)
		LIST_INIT(&user_file_buckets[i]);
	if (elf_version(EV_CURRENT) != EV_NONE)
		g_libelf_initialized = true;
	else
		warnx("libelog_user_symbols: libelf init failed: %s",
		    elf_errmsg(-1));
	g_initialized = true;
}

void
elog_user_symbols_shutdown(void)
{
	struct user_file_entry *fe, *tmp;
	int i;

	if (!g_initialized)
		return;
	for (i = 0; i < USER_FILE_HASH; i++) {
		LIST_FOREACH_SAFE(fe, &user_file_buckets[i], link, tmp) {
			LIST_REMOVE(fe, link);
			free(fe->cached_ranges);
			free(fe);
		}
	}
	g_initialized = false;
	g_libelf_initialized = false;
	g_files_parsed = 0;
	g_ranges_emitted = 0;
	g_files_replayed = 0;
	g_ranges_replayed = 0;
}

uint64_t
elog_user_symbols_files_parsed(void)
{
	return (g_files_parsed);
}

uint64_t
elog_user_symbols_ranges_emitted(void)
{
	return (g_ranges_emitted);
}

uint64_t
elog_user_symbols_files_replayed(void)
{
	return (g_files_replayed);
}

uint64_t
elog_user_symbols_ranges_replayed(void)
{
	return (g_ranges_replayed);
}

void
elog_user_symbols_set_ref_mode(bool ref_mode)
{
	g_ref_mode = ref_mode;
}

/*
 * Format one SYMBOL_PACK_REF for the file's build-id. Emitted as soon
 * as the id is known, in both modes: a stripped binary produces no
 * ranges at all, and its pack still names it.
 */
static void
emit_pack_ref(const struct user_file_entry *fe,
    const struct eventlog_event_header *src,
    elog_user_symbols_emit_fn emit_fn, void *cookie)
{
	struct symbols_eventlog_symbol_pack_ref payload;
	struct eventlog_event_header hdr;

	if (fe->build_id[0] == '\0')
		return;

	hdr = *src;
	hdr.event_length = 0;
	hdr.event_id = SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID;

	memset(&payload, 0, sizeof(payload));
	payload.kind = SYM_ELOG_REF_KIND_USER_FILE;
	payload.id_kind = fe->id_kind;
	payload.file_id = fe->user_file_id;
	strlcpy(payload.pack_id, fe->build_id, sizeof(payload.pack_id));
	emit_fn(&hdr, &payload, sizeof(payload), cookie);
}

/*
 * SHA-256 over the ELF's bytes, formatted as 64 lowercase hex chars.
 * The id_kind=1 fallback for files without a build-id note: cheap
 * (one streaming pass, no symbol walk), and the CI publish computes
 * the same id from the same bytes. The fd is rewound first because
 * the libelf walk above moved it.
 */
static void
read_file_sha256(struct user_file_entry *fe, int fd)
{
	SHA256_CTX ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint8_t buf[65536];
	ssize_t n;
	size_t i;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return;
	SHA256_Init(&ctx);
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		SHA256_Update(&ctx, buf, (size_t)n);
	if (n < 0)
		return;
	SHA256_Final(digest, &ctx);

	for (i = 0; i < sizeof(digest); i++)
		snprintf(&fe->build_id[i * 2], 3, "%02x", digest[i]);
	fe->build_id[sizeof(fe->build_id) - 1] = '\0';
	fe->id_kind = SYM_ELOG_REF_ID_FILE_SHA256;
}

/*
 * Walk SHT_NOTE sections for NT_GNU_BUILD_ID and format it as
 * lowercase hex (capped at 64 chars so it always fits pack_id).
 */
static void
read_build_id(struct user_file_entry *fe, Elf *e)
{
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr sh;
	size_t off, nameoff, descoff, next, i, hashlen;
	const char *notes;

	fe->build_id[0] = '\0';
	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &sh) == NULL || sh.sh_type != SHT_NOTE)
			continue;
		data = elf_getdata(scn, NULL);
		if (data == NULL || data->d_buf == NULL)
			continue;
		notes = data->d_buf;
		for (off = 0; off + 12 <= data->d_size; off = next) {
			uint32_t namesz, descsz, type;

			memcpy(&namesz, notes + off, sizeof(namesz));
			memcpy(&descsz, notes + off + 4, sizeof(descsz));
			memcpy(&type, notes + off + 8, sizeof(type));
			nameoff = off + 12;
			descoff = nameoff + roundup2(namesz, 4);
			next = descoff + roundup2(descsz, 4);
			if (next > data->d_size || next <= off)
				break;
			if (type == NT_GNU_BUILD_ID && namesz == 4 &&
			    descsz > 0 && memcmp(notes + nameoff, "GNU\0", 4) == 0) {
				hashlen = descsz;
				if (hashlen * 2 >= sizeof(fe->build_id))
					hashlen = (sizeof(fe->build_id) - 1) / 2;
				for (i = 0; i < hashlen; i++)
					snprintf(&fe->build_id[i * 2], 3, "%02x",
					    (uint8_t)notes[descoff + i]);
				return;
			}
		}
	}
}

/*
 * Translate a symbol's runtime virtual address (`st_value` in the
 * ELF) to its file offset by locating the PT_LOAD segment that
 * contains it. Returns false if no PT_LOAD covers the symbol, in
 * which case the caller skips the symbol -- the kernel's PROC_MAP
 * carries an `offset` field in file-offset coordinates, so a symbol
 * that doesn't sit in any cached PT_LOAD has no file-offset that a
 * consumer can match against.
 */
static bool
translate_st_value_to_file_offset(const struct user_file_entry *fe,
    uint64_t st_value, uint64_t *file_offset_out)
{
	const struct file_ptload *pl;
	uint32_t i;

	for (i = 0; i < fe->n_ptloads; i++) {
		pl = &fe->ptloads[i];
		if (st_value >= pl->p_vaddr &&
		    st_value < pl->p_vaddr + pl->p_filesz) {
			*file_offset_out = st_value - pl->p_vaddr +
			    pl->p_offset;
			return (true);
		}
	}
	return (false);
}

/*
 * Walk one symbol-table section, emitting USER_SYMBOL_RANGE for each
 * STT_FUNC / STT_GNU_IFUNC entry with a non-empty name and non-zero
 * value.
 *
 * `payload.offset` is emitted in file-offset coordinates: the file
 * offset of the symbol's first byte in the on-disk ELF. This shares
 * a coordinate space with `process.PROC_MAP.offset` (which carries
 * the kernel vm_map_entry's file offset), so consumers resolve a
 * sample with the formula
 *
 *     pc - PROC_MAP.base + PROC_MAP.offset == USER_SYMBOL_RANGE.offset
 *
 * for any PC inside any executable file-backed mapping, regardless
 * of PIE / load_bias / ASLR. Symbols whose `st_value` falls outside
 * every cached PT_LOAD are skipped -- the consumer formula has no
 * matching coordinate for them.
 */
static void
user_file_cache_range(struct user_file_entry *fe,
    const struct symbols_eventlog_user_symbol_range *payload)
{
	struct symbols_eventlog_user_symbol_range *grown;
	uint32_t new_cap;

	if (fe->n_cached_ranges == fe->cached_ranges_cap) {
		new_cap = fe->cached_ranges_cap == 0 ? 16 :
		    fe->cached_ranges_cap * 2;
		grown = realloc(fe->cached_ranges,
		    new_cap * sizeof(*fe->cached_ranges));
		if (grown == NULL)
			return;
		fe->cached_ranges = grown;
		fe->cached_ranges_cap = new_cap;
	}
	fe->cached_ranges[fe->n_cached_ranges++] = *payload;
}

static size_t
emit_symtab(Elf *e, Elf_Scn *scn,
    const struct eventlog_event_header *src,
    struct user_file_entry *fe,
    elog_user_symbols_emit_fn emit_fn, void *cookie)
{
	GElf_Shdr shdr;
	Elf_Data *data;
	GElf_Sym sym;
	struct symbols_eventlog_user_symbol_range payload;
	struct eventlog_event_header hdr;
	const char *name;
	uint64_t file_offset;
	size_t nsyms, i, emitted;

	if (gelf_getshdr(scn, &shdr) == NULL)
		return (0);
	if (shdr.sh_entsize == 0 || shdr.sh_type == SHT_NOBITS)
		return (0);
	data = elf_getdata(scn, NULL);
	if (data == NULL || data->d_size == 0)
		return (0);

	nsyms = shdr.sh_size / shdr.sh_entsize;
	emitted = 0;

	hdr = *src;
	hdr.event_length = 0;
	hdr.event_id = SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID;

	for (i = 0; i < nsyms; i++) {
		int st_type;

		if (gelf_getsym(data, (int)i, &sym) == NULL)
			continue;
		st_type = GELF_ST_TYPE(sym.st_info);
		if (st_type != STT_FUNC && st_type != STT_GNU_IFUNC)
			continue;
		if (sym.st_value == 0)
			continue;
		if (!translate_st_value_to_file_offset(fe,
		    (uint64_t)sym.st_value, &file_offset))
			continue;
		name = elf_strptr(e, shdr.sh_link, sym.st_name);
		if (name == NULL || name[0] == '\0')
			continue;

		memset(&payload, 0, sizeof(payload));
		payload.user_file_id = fe->user_file_id;
		payload.offset = file_offset;
		payload.size = (uint32_t)sym.st_size;
		strlcpy(payload.name, name, sizeof(payload.name));

		emit_fn(&hdr, &payload, sizeof(payload), cookie);
		user_file_cache_range(fe, &payload);
		emitted++;
	}
	return (emitted);
}

/*
 * Cache executable PT_LOAD program headers so emit_symtab() can
 * translate each symbol's st_value (a runtime virtual address) into
 * the on-disk file offset that the kernel's PROC_MAP.offset shares a
 * coordinate space with.
 */
static void
cache_ptloads(struct user_file_entry *fe, Elf *e)
{
	GElf_Phdr phdr;
	size_t nphdrs, i;

	fe->n_ptloads = 0;
	if (elf_getphdrnum(e, &nphdrs) != 0 || nphdrs == 0)
		return;

	for (i = 0; i < nphdrs; i++) {
		if (gelf_getphdr(e, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type != PT_LOAD)
			continue;
		if ((phdr.p_flags & PF_X) == 0)
			continue;
		if (fe->n_ptloads >= USER_FILE_MAX_PTLOADS)
			break;
		fe->ptloads[fe->n_ptloads].p_vaddr = (uint64_t)phdr.p_vaddr;
		fe->ptloads[fe->n_ptloads].p_offset = (uint64_t)phdr.p_offset;
		fe->ptloads[fe->n_ptloads].p_filesz = (uint64_t)phdr.p_filesz;
		fe->n_ptloads++;
	}
}

/* Go 1.18 / 1.20 pclntab magic (debug/gosym). */
#define	GO_PCLN_MAGIC_118	0xfffffff0u
#define	GO_PCLN_MAGIC_120	0xfffffff1u
#define	GO_PCLN_MAX_FUNCS	(1u << 20)

static Elf_Scn *
find_named_section(Elf *e, const char *name)
{
	size_t shstrndx;
	Elf_Scn *scn;
	GElf_Shdr sh;
	const char *sn;

	if (elf_getshdrstrndx(e, &shstrndx) != 0)
		return (NULL);
	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &sh) == NULL)
			continue;
		sn = elf_strptr(e, shstrndx, sh.sh_name);
		if (sn != NULL && strcmp(sn, name) == 0)
			return (scn);
	}
	return (NULL);
}

static const uint8_t *
section_buf(Elf_Scn *scn, size_t *len)
{
	Elf_Data *data;
	GElf_Shdr sh;

	if (scn == NULL || gelf_getshdr(scn, &sh) == NULL ||
	    sh.sh_type == SHT_NOBITS)
		return (NULL);
	data = elf_getdata(scn, NULL);
	if (data == NULL || data->d_buf == NULL || data->d_size == 0)
		return (NULL);
	if (elf_getdata(scn, data) != NULL)
		return (NULL);
	*len = (size_t)data->d_size;
	return (data->d_buf);
}

static bool
go_u32(const uint8_t *p, size_t len, size_t off, uint32_t *out)
{
	if (off > len || len - off < 4)
		return (false);
	*out = (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
	    ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
	return (true);
}

static bool
go_ptr(const uint8_t *p, size_t len, size_t off, int ptrsz, uint64_t *out)
{
	uint32_t lo, hi;

	if (ptrsz == 4) {
		if (!go_u32(p, len, off, &lo))
			return (false);
		*out = lo;
		return (true);
	}
	if (ptrsz != 8 || !go_u32(p, len, off, &lo) ||
	    !go_u32(p, len, off + 4, &hi))
		return (false);
	*out = (uint64_t)lo | ((uint64_t)hi << 32);
	return (true);
}

/*
 * Go 1.18+ .gopclntab (magic 0xfffffff0 / 0xfffffff1). Eight bytes of
 * header, then pointer-sized words: word 0 is nfunc, word 2 is
 * textStart, word 3 is the funcname table, word 7 is the functab.
 * A functab slot is two uint32s (entry offset from textStart, offset
 * of the _func) followed by one trailing end-PC uint32. The name is
 * the C string at funcname + the _func's second uint32. Size is the
 * distance to the next entry.
 */
static size_t
emit_gopclntab(Elf *e, const struct eventlog_event_header *src,
    struct user_file_entry *fe, elog_user_symbols_emit_fn emit_fn,
    void *cookie)
{
	struct symbols_eventlog_user_symbol_range payload;
	struct eventlog_event_header hdr;
	const uint8_t *p;
	const char *name;
	uint64_t nfunc_raw, text_start, funcname_off, pcln_off, va, file_offset;
	uint32_t magic, pc_off, next_off, func_off, name_off;
	size_t len, i, emitted, name_at, nlen, avail;
	int ptrsz;

	p = section_buf(find_named_section(e, ".gopclntab"), &len);
	if (p == NULL || len < 8 + 8)
		return (0);
	if (p[4] != 0 || p[5] != 0)
		return (0);
	if (p[6] != 1 && p[6] != 2 && p[6] != 4)
		return (0);
	ptrsz = p[7];
	if (ptrsz != 4 && ptrsz != 8)
		return (0);
	if (!go_u32(p, len, 0, &magic))
		return (0);
	if (magic != GO_PCLN_MAGIC_118 && magic != GO_PCLN_MAGIC_120)
		return (0);
	if (len < 8 + 8 * (size_t)ptrsz)
		return (0);
	if (!go_ptr(p, len, 8, ptrsz, &nfunc_raw) || nfunc_raw == 0 ||
	    nfunc_raw > GO_PCLN_MAX_FUNCS)
		return (0);
	if (!go_ptr(p, len, 8 + 2 * (size_t)ptrsz, ptrsz, &text_start) ||
	    !go_ptr(p, len, 8 + 3 * (size_t)ptrsz, ptrsz, &funcname_off) ||
	    !go_ptr(p, len, 8 + 7 * (size_t)ptrsz, ptrsz, &pcln_off))
		return (0);
	if (text_start == 0 && fe->n_ptloads > 0)
		text_start = fe->ptloads[0].p_vaddr;
	if (pcln_off > len ||
	    (nfunc_raw * 2 + 1) > (len - pcln_off) / 4)
		return (0);

	hdr = *src;
	hdr.event_length = 0;
	hdr.event_id = SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID;
	emitted = 0;
	for (i = 0; i < (size_t)nfunc_raw; i++) {
		uint64_t size;

		if (!go_u32(p, len, pcln_off + (2 * i) * 4, &pc_off) ||
		    !go_u32(p, len, pcln_off + (2 * i + 1) * 4, &func_off) ||
		    !go_u32(p, len, pcln_off + (2 * (i + 1)) * 4, &next_off))
			break;
		if (next_off <= pc_off)
			continue;
		size = (uint64_t)next_off - pc_off;
		if (size > UINT32_MAX)
			continue;
		va = text_start + pc_off;
		if (!translate_st_value_to_file_offset(fe, va, &file_offset))
			continue;
		if (func_off > len - pcln_off ||
		    len - (pcln_off + func_off) < 8 ||
		    !go_u32(p, len, pcln_off + func_off + 4, &name_off))
			continue;
		if (funcname_off > len || name_off > len - funcname_off)
			continue;
		name_at = (size_t)funcname_off + name_off;
		name = (const char *)(p + name_at);
		avail = len - name_at;
		nlen = strnlen(name, avail);
		if (nlen == 0 || nlen == avail)
			continue;

		memset(&payload, 0, sizeof(payload));
		payload.user_file_id = fe->user_file_id;
		payload.offset = file_offset;
		payload.size = (uint32_t)size;
		strlcpy(payload.name, name, sizeof(payload.name));
		emit_fn(&hdr, &payload, sizeof(payload), cookie);
		user_file_cache_range(fe, &payload);
		emitted++;
	}
	return (emitted);
}

static void
parse_and_emit(struct user_file_entry *fe,
    const struct eventlog_event_header *src,
    elog_user_symbols_emit_fn emit_fn, void *cookie)
{
	Elf *e;
	Elf_Scn *scn, *symtab_scn, *dynsym_scn;
	GElf_Shdr sh;
	int fd;
	size_t emitted;

	fe->parsed = true;
	if (!g_libelf_initialized || fe->pathname[0] == '\0')
		return;

	fd = open(fe->pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	e = elf_begin(fd, ELF_C_READ, NULL);
	if (e == NULL || elf_kind(e) != ELF_K_ELF) {
		if (e != NULL)
			elf_end(e);
		close(fd);
		return;
	}

	/*
	 * Count the file as parsed only after open() and the ELF
	 * magic check both succeed, so the stat reflects work the
	 * library actually did.
	 */
	g_files_parsed++;

	read_build_id(fe, e);
	/*
	 * Refs mode keys a file's ref on its own build-id note; a
	 * SHA-256 of the bytes is computable for anything, so it says
	 * nothing about whether a pack exists. Note-less files (SVM
	 * pushes, vendor blobs) fall through to the inline walk below.
	 */
	fe->refable = fe->build_id[0] != '\0';
	if (!g_ref_mode && !fe->refable) {
		read_file_sha256(fe, fd);
		fe->refable = fe->build_id[0] != '\0';
	}
	fe->go_binary = find_named_section(e, ".note.go.buildid") != NULL;
	if (fe->refable)
		emit_pack_ref(fe, src, emit_fn, cookie);

	/*
	 * A Go binary emits its .gopclntab ranges beside the pack ref.
	 * The reader uses an in-file range.
	 */
	if (g_ref_mode && fe->refable && !fe->go_binary) {
		elf_end(e);
		close(fd);
		return;
	}

	cache_ptloads(fe, e);

	/*
	 * Go keeps its functions in .gopclntab. .symtab is empty after
	 * `go build -ldflags=-s`, so a .note.go.buildid selects that
	 * table.
	 */
	emitted = 0;
	if (fe->n_ptloads > 0 && fe->go_binary)
		emitted = emit_gopclntab(e, src, fe, emit_fn, cookie);

	symtab_scn = NULL;
	dynsym_scn = NULL;
	scn = NULL;
	if (emitted == 0) {
		while ((scn = elf_nextscn(e, scn)) != NULL) {
			if (gelf_getshdr(scn, &sh) == NULL)
				continue;
			if (sh.sh_type == SHT_SYMTAB)
				symtab_scn = scn;
			else if (sh.sh_type == SHT_DYNSYM)
				dynsym_scn = scn;
		}
	}

	/*
	 * Prefer .symtab when present (it's a strict superset of
	 * .dynsym for unstripped binaries; emitting both produces
	 * duplicate USER_SYMBOL_RANGEs at identical (file_id, offset)).
	 * Fall back to .dynsym only when .symtab is absent (stripped
	 * binaries). Matches cddl/contrib/opensolaris/cmd/lockstat/sym.c.
	 */
	if (emitted == 0 && fe->n_ptloads > 0) {
		Elf_Scn *use_scn = symtab_scn != NULL ? symtab_scn : dynsym_scn;

		if (use_scn != NULL) {
			emitted = emit_symtab(e, use_scn, src, fe,
			    emit_fn, cookie);
		}
	}
	g_ranges_emitted += (uint64_t)emitted;

	elf_end(e);
	close(fd);
}

/*
 * Re-emit a file's already-parsed USER_SYMBOL_RANGE payloads from
 * cache. Called on a repeat USER_FILE sighting for a file we've
 * already parsed -- e.g. a second process mapping the same shared
 * object during one dump_state -- so the consumer's symbol table
 * isn't silently missing entries for anyone who observes this
 * subscriber's stream from partway through.
 */
static void
replay_cached_ranges(const struct user_file_entry *fe,
    const struct eventlog_event_header *src,
    elog_user_symbols_emit_fn emit_fn, void *cookie)
{
	struct eventlog_event_header hdr;
	uint32_t i;

	if (g_ref_mode && fe->refable) {
		emit_pack_ref(fe, src, emit_fn, cookie);
		/*
		 * Only a Go file replays cached ranges beside the ref.
		 */
		if (!fe->go_binary)
			return;
	}
	if (fe->n_cached_ranges == 0)
		return;

	hdr = *src;
	hdr.event_length = 0;
	hdr.event_id = SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID;

	for (i = 0; i < fe->n_cached_ranges; i++)
		emit_fn(&hdr, &fe->cached_ranges[i],
		    sizeof(fe->cached_ranges[i]), cookie);

	g_files_replayed++;
	g_ranges_replayed += fe->n_cached_ranges;
}

void
elog_user_symbols_observe(const char *provider_name,
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size,
    elog_user_symbols_emit_fn emit_fn, void *cookie)
{
	const struct symbols_eventlog_user_file *uf;
	struct user_file_entry *fe;

	if (!g_initialized || hdr == NULL || provider_name == NULL ||
	    emit_fn == NULL)
		return;
	if (strcmp(provider_name, "symbols") != 0)
		return;
	if (hdr->event_id != SYMBOLS_EVENTLOG_USER_FILE_ID)
		return;
	if (payload == NULL || payload_size < sizeof(*uf))
		return;

	uf = payload;
	if (uf->user_file_id == 0)
		return;

	fe = user_file_lookup(uf->user_file_id);
	if (fe == NULL) {
		fe = user_file_insert(uf->user_file_id, uf->pathname);
		if (fe == NULL)
			return;
	}
	if (fe->parsed) {
		replay_cached_ranges(fe, hdr, emit_fn, cookie);
		return;
	}

	parse_and_emit(fe, hdr, emit_fn, cookie);
}
