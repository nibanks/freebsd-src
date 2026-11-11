/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

/*
 * libelog_source_lines -- deferred DWARF line embedding for elog -L.
 *
 * Watches LINKER_FILE / USER_FILE / PROC_MAP / CPU_SAMPLE and records
 * each unique (pc, pid) from sampled stacks. The capture path does no
 * binary lookup or DWARF work; elog_source_lines_resolve() runs after
 * the capture loop, maps each pending PC to a binary, opens DWARF (or
 * its /usr/lib/debug twin), builds a sorted line index once per
 * binary, and emits symbols.SOURCE_FILE + symbols.SOURCE_LINE.
 *
 * Coordinate spaces match SYMBOL_RANGE / USER_SYMBOL_RANGE:
 *   kernel: file_offset = pc - LINKER_FILE.base
 *   user:   file_offset = pc - PROC_MAP.base + PROC_MAP.offset
 *
 * Counts are not emitted; EventExplorer joins this map with the live
 * CPU_SAMPLE stream under whatever Flame filter is active.
 */

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/elf_common.h>

#include <ctype.h>
#include <dwarf.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/eventlog.h>

#include "libelog_source_lines.h"

#define	SYMBOLS_EVENTLOG_LINKER_FILE_ID		1
#define	SYMBOLS_EVENTLOG_USER_FILE_ID		3
#define	SYMBOLS_EVENTLOG_SOURCE_FILE_ID		5
#define	SYMBOLS_EVENTLOG_SOURCE_LINE_ID		6

#define	CPU_EVENTLOG_CPU_SAMPLE_ID		1
#define	PROCESS_EVENTLOG_PROC_MAP_ID		4

#define	SOURCE_BINARY_KIND_KERNEL		0
#define	SOURCE_BINARY_KIND_USER			1

#define	HASH_SIZE				16384
#define	MAX_PTLOADS				8

struct symbols_eventlog_linker_file {
	uint32_t	file_id;
	uint64_t	base;
	uint64_t	size;
	uint32_t	flags;
	char		build_id[41];
	char		filename[64];
	char		pathname[128];
} __packed;

struct symbols_eventlog_user_file {
	uint32_t	user_file_id;
	char		build_id[41];
	char		pathname[128];
} __packed;

struct process_eventlog_proc_map {
	uint32_t	pid;
	uint32_t	user_file_id;
	uint64_t	base;
	uint64_t	size;
	uint64_t	offset;
} __packed;

struct cpu_eventlog_cpu_sample_head {
	uint32_t	tid;
	uint32_t	pid;
	uint8_t		type;
	uint8_t		flags;
	uint8_t		depth;
	uint16_t	freq_mhz;
} __packed;

struct symbols_eventlog_source_file {
	uint32_t	source_file_id;
	uint8_t		binary_kind;
	uint32_t	binary_id;
	char		commit_id[41];
	char		pathname[256];
} __packed;

struct symbols_eventlog_source_line {
	uint32_t	source_file_id;
	uint8_t		binary_kind;
	uint32_t	binary_id;
	uint64_t	file_offset;
	uint32_t	line;
} __packed;

struct file_ptload {
	uint64_t	p_vaddr;
	uint64_t	p_offset;
	uint64_t	p_filesz;
};

/* Sorted line row; line 0 marks an end_sequence range end. */
struct line_entry {
	uint64_t	addr;
	uint32_t	file_idx;
	uint32_t	line;
};

struct dwarf_binary {
	LIST_ENTRY(dwarf_binary) link;
	uint8_t		kind;
	uint32_t	id;
	uint64_t	runtime_base;
	uint64_t	runtime_size;
	char		pathname[PATH_MAX];
	/* Where the line index came from; empty until an open succeeds. */
	char		dwarf_path[PATH_MAX];
	/* Stale build-id from the file that stopped the open search. */
	char		open_error[128];
	char		build_id[41];
	bool		open_attempted;
	bool		open_ok;
	bool		line_index_built;
	int		fd;
	Elf		*elf;
	Dwarf_Debug	dbg;
	uint32_t	n_ptloads;
	struct file_ptload ptloads[MAX_PTLOADS];
	/*
	 * Link VA of image offset 0. linker_file.address is that point
	 * at runtime; file_offset is pc minus that address.
	 */
	uint64_t	elf_image_vaddr;
	/* Sorted-by-addr line index, built once from .debug_line. */
	struct line_entry *line_entries;
	uint64_t	n_line_entries;
	uint64_t	line_entries_cap;
	char		**line_files;
	uint32_t	n_line_files;
	uint32_t	line_files_cap;
	uint64_t	lines_emitted;
	uint64_t	lookup_misses;
	/* Split debug twin opened when the first line index was thin; the
	 * index merges both files, and the first file stays b->elf. */
	char		split_path[PATH_MAX];
	bool		split_opened;
	bool		split_checked;
	Elf		*split_elf;
	Dwarf_Debug	split_dbg;
	int		split_fd;
};

struct proc_map_entry {
	LIST_ENTRY(proc_map_entry) link;
	uint32_t	pid;
	uint32_t	user_file_id;
	uint64_t	base;
	uint64_t	size;
	uint64_t	offset;
};

struct source_file_entry {
	LIST_ENTRY(source_file_entry) link;
	uint32_t	source_file_id;
	uint8_t		binary_kind;
	uint32_t	binary_id;
	char		pathname[256];
};

struct resolved_offset {
	LIST_ENTRY(resolved_offset) link;
	uint8_t		kind;
	uint32_t	binary_id;
	uint64_t	file_offset;
};

/* Unique sampled (pc, pid) held until resolve(); pid 0 skips user maps. */
struct pending_pc {
	LIST_ENTRY(pending_pc) link;
	uint64_t	pc;
	uint32_t	pid;
};

LIST_HEAD(dwarf_bucket, dwarf_binary);
LIST_HEAD(proc_map_bucket, proc_map_entry);
LIST_HEAD(source_file_bucket, source_file_entry);
LIST_HEAD(resolved_bucket, resolved_offset);
LIST_HEAD(pending_bucket, pending_pc);

static struct dwarf_bucket	dwarf_buckets[HASH_SIZE];
static struct proc_map_bucket	proc_map_buckets[HASH_SIZE];
static struct source_file_bucket source_file_buckets[HASH_SIZE];
static struct resolved_bucket	resolved_buckets[HASH_SIZE];
static struct pending_bucket	pending_buckets[HASH_SIZE];

static bool		g_initialized;
static bool		g_libelf_ok;
static uint16_t		g_symbols_provider_id;
static bool		g_symbols_provider_known;
static uint16_t		g_process_provider_id;
static bool		g_process_provider_known;
static uint16_t		g_cpu_provider_id;
static bool		g_cpu_provider_known;
/* Kernel binaries sorted by runtime_base; rebuilt when linker files change. */
static struct dwarf_binary **g_kernel_by_base;
static size_t		g_kernel_count;
static bool		g_kernel_by_base_dirty;
static uint32_t		g_next_source_file_id = 1;
static uint64_t		g_binaries_opened;
static uint64_t		g_files_emitted;
static uint64_t		g_lines_emitted;
static uint64_t		g_misses_no_binary;
static uint64_t		g_misses_open;
static uint64_t		g_misses_addr;
static uint64_t		g_misses_line;
static uint64_t		g_lines_capped;
static char		g_split_debug_root[PATH_MAX] = "/usr/lib/debug";
/* Max observed event timestamp; stamped on synthesised SOURCE_* rows. */
static uint64_t		g_emit_timestamp;
/* Firmware commit parsed from kern.version; stamped on kernel files. */
static char		g_kernel_commit[41];
/* Set once elog_source_lines_resolve() has run; later calls are no-ops. */
static bool		g_resolved;

static uint32_t
hash32(uint32_t v)
{
	return (v % HASH_SIZE);
}

static uint32_t
hash_resolved(uint8_t kind, uint32_t id, uint64_t off)
{
	uint32_t h;

	h = (uint32_t)kind * 1315423911u;
	h ^= id * 2654435761u;
	h ^= (uint32_t)off;
	h ^= (uint32_t)(off >> 32);
	return (h % HASH_SIZE);
}

static uint32_t
hash_pending(uint64_t pc, uint32_t pid)
{
	uint32_t h;

	h = pid * 2654435761u;
	h ^= (uint32_t)pc;
	h ^= (uint32_t)(pc >> 32);
	return (h % HASH_SIZE);
}

static uint32_t
hash_path(const char *path, uint8_t kind, uint32_t binary_id)
{
	uint32_t h = binary_id * 2654435761u ^ kind;
	const unsigned char *p;

	for (p = (const unsigned char *)path; *p != '\0'; p++)
		h = h * 33u + *p;
	return (h % HASH_SIZE);
}

void
elog_source_lines_init(void)
{
	int i;

	if (g_initialized)
		return;
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_INIT(&dwarf_buckets[i]);
		LIST_INIT(&proc_map_buckets[i]);
		LIST_INIT(&source_file_buckets[i]);
		LIST_INIT(&resolved_buckets[i]);
		LIST_INIT(&pending_buckets[i]);
	}
	g_libelf_ok = (elf_version(EV_CURRENT) != EV_NONE);
	if (!g_libelf_ok)
		warnx("libelog_source_lines: libelf init failed: %s",
		    elf_errmsg(-1));
	strlcpy(g_split_debug_root, "/usr/lib/debug",
	    sizeof(g_split_debug_root));
	g_initialized = true;
}

static void
dwarf_binary_close(struct dwarf_binary *b)
{
	Dwarf_Error de;
	uint32_t i;

	free(b->line_entries);
	b->line_entries = NULL;
	b->n_line_entries = 0;
	b->line_entries_cap = 0;
	for (i = 0; i < b->n_line_files; i++)
		free(b->line_files[i]);
	free(b->line_files);
	b->line_files = NULL;
	b->n_line_files = 0;
	b->line_files_cap = 0;
	if (b->dbg != NULL) {
		dwarf_finish(b->dbg, &de);
		b->dbg = NULL;
	}
	if (b->elf != NULL) {
		elf_end(b->elf);
		b->elf = NULL;
	}
	if (b->fd >= 0) {
		close(b->fd);
		b->fd = -1;
	}
	if (b->split_dbg != NULL) {
		dwarf_finish(b->split_dbg, &de);
		b->split_dbg = NULL;
	}
	if (b->split_elf != NULL) {
		elf_end(b->split_elf);
		b->split_elf = NULL;
	}
	if (b->split_fd >= 0) {
		close(b->split_fd);
		b->split_fd = -1;
	}
}

void
elog_source_lines_shutdown(void)
{
	struct dwarf_binary *b, *btmp;
	struct proc_map_entry *pm, *pmtmp;
	struct source_file_entry *sf, *sftmp;
	struct resolved_offset *ro, *rotmp;
	struct pending_pc *pp, *pptmp;
	int i;

	if (!g_initialized)
		return;
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_FOREACH_SAFE(b, &dwarf_buckets[i], link, btmp) {
			LIST_REMOVE(b, link);
			dwarf_binary_close(b);
			free(b);
		}
		LIST_FOREACH_SAFE(pm, &proc_map_buckets[i], link, pmtmp) {
			LIST_REMOVE(pm, link);
			free(pm);
		}
		LIST_FOREACH_SAFE(sf, &source_file_buckets[i], link, sftmp) {
			LIST_REMOVE(sf, link);
			free(sf);
		}
		LIST_FOREACH_SAFE(ro, &resolved_buckets[i], link, rotmp) {
			LIST_REMOVE(ro, link);
			free(ro);
		}
		LIST_FOREACH_SAFE(pp, &pending_buckets[i], link, pptmp) {
			LIST_REMOVE(pp, link);
			free(pp);
		}
	}
	g_initialized = false;
	g_libelf_ok = false;
	g_symbols_provider_id = 0;
	g_symbols_provider_known = false;
	g_process_provider_id = 0;
	g_process_provider_known = false;
	g_cpu_provider_id = 0;
	g_cpu_provider_known = false;
	free(g_kernel_by_base);
	g_kernel_by_base = NULL;
	g_kernel_count = 0;
	g_kernel_by_base_dirty = false;
	g_next_source_file_id = 1;
	g_binaries_opened = 0;
	g_files_emitted = 0;
	g_lines_emitted = 0;
	g_misses_no_binary = 0;
	g_misses_open = 0;
	g_misses_addr = 0;
	g_misses_line = 0;
	g_lines_capped = 0;
	g_emit_timestamp = 0;
	g_kernel_commit[0] = '\0';
	g_resolved = false;
}

uint64_t
elog_source_lines_binaries_opened(void)
{
	return (g_binaries_opened);
}

uint64_t
elog_source_lines_files_emitted(void)
{
	return (g_files_emitted);
}

uint64_t
elog_source_lines_lines_emitted(void)
{
	return (g_lines_emitted);
}

uint64_t
elog_source_lines_misses(void)
{
	return (g_misses_no_binary + g_misses_open + g_misses_addr +
	    g_misses_line);
}

uint64_t
elog_source_lines_misses_no_binary(void)
{
	return (g_misses_no_binary);
}

uint64_t
elog_source_lines_misses_open(void)
{
	return (g_misses_open);
}

uint64_t
elog_source_lines_misses_addr(void)
{
	return (g_misses_addr);
}

uint64_t
elog_source_lines_misses_line(void)
{
	return (g_misses_line);
}

uint64_t
elog_source_lines_lines_capped(void)
{
	return (g_lines_capped);
}

static int
commit_hash(const char *s, size_t len)
{
	size_t i;

	if (len < 7 || len >= sizeof(g_kernel_commit))
		return (0);
	for (i = 0; i < len; i++) {
		if (!isxdigit((unsigned char)s[i]))
			return (0);
	}
	return (1);
}

void
elog_source_lines_set_kernel_version(const char *version)
{
	const char *p, *tok, *tok_end, *hash, *prev, *prev_end, *d;
	size_t len;

	g_kernel_commit[0] = '\0';
	if (version == NULL)
		return;
	/*
	 * newvers.sh ends the ident in n<count>-<hash>, then -dirty when
	 * the tree was modified. PR images use pull/<id>-n<count>-<hash>.
	 */
	p = version;
	while (*p != '\0') {
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '\0')
			break;
		tok = p;
		while (*p != '\0' && !isspace((unsigned char)*p))
			p++;
		tok_end = p;
		if (tok_end > tok && tok_end[-1] == ':')
			tok_end--;
		if ((size_t)(tok_end - tok) > 6 &&
		    strncmp(tok_end - 6, "-dirty", 6) == 0)
			tok_end -= 6;
		hash = tok_end;
		while (hash > tok && hash[-1] != '-')
			hash--;
		len = (size_t)(tok_end - hash);
		if (hash == tok || !commit_hash(hash, len))
			continue;
		prev_end = hash - 1;
		prev = prev_end;
		while (prev > tok && prev[-1] != '-')
			prev--;
		if ((size_t)(prev_end - prev) < 2 || *prev != 'n')
			continue;
		for (d = prev + 1; d < prev_end; d++) {
			if (!isdigit((unsigned char)*d))
				break;
		}
		if (d != prev_end)
			continue;
		memcpy(g_kernel_commit, hash, len);
		g_kernel_commit[len] = '\0';
		return;
	}
}

const char *
elog_source_lines_binary_debug_path(const char *pathname)
{
	struct dwarf_binary *b;
	int i;

	if (pathname == NULL)
		return (NULL);
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_FOREACH(b, &dwarf_buckets[i], link) {
			if (strcmp(b->pathname, pathname) != 0)
				continue;
			if (b->split_opened)
				return (b->split_path);
			if (b->dwarf_path[0] != '\0')
				return (b->dwarf_path);
			return (NULL);
		}
	}
	return (NULL);
}

void
elog_source_lines_foreach_binary(elog_source_lines_binary_fn fn, void *arg)
{
	struct dwarf_binary *b;
	int i;

	if (!g_initialized || fn == NULL)
		return;
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_FOREACH(b, &dwarf_buckets[i], link) {
			if (!b->open_attempted)
				continue;
			fn(b->kind, b->id, b->pathname, b->open_ok,
			    b->lines_emitted, b->lookup_misses, arg);
		}
	}
}

static struct dwarf_binary *
dwarf_binary_lookup(uint8_t kind, uint32_t id)
{
	struct dwarf_binary *b;

	LIST_FOREACH(b, &dwarf_buckets[hash32(id)], link) {
		if (b->kind == kind && b->id == id)
			return (b);
	}
	return (NULL);
}

static struct dwarf_binary *
dwarf_binary_insert(uint8_t kind, uint32_t id, const char *pathname,
    const char *build_id, uint64_t runtime_base, uint64_t runtime_size)
{
	struct dwarf_binary *b;

	b = calloc(1, sizeof(*b));
	if (b == NULL)
		return (NULL);
	b->kind = kind;
	b->id = id;
	b->runtime_base = runtime_base;
	b->runtime_size = runtime_size;
	b->fd = -1;
	b->split_fd = -1;
	if (pathname != NULL)
		strlcpy(b->pathname, pathname, sizeof(b->pathname));
	if (build_id != NULL)
		strlcpy(b->build_id, build_id, sizeof(b->build_id));
	LIST_INSERT_HEAD(&dwarf_buckets[hash32(id)], b, link);
	return (b);
}

static void
cache_ptloads_elf(struct dwarf_binary *b, Elf *e)
{
	GElf_Phdr phdr;
	size_t nphdrs, i;

	b->n_ptloads = 0;
	b->elf_image_vaddr = 0;
	if (e == NULL || elf_getphdrnum(e, &nphdrs) != 0)
		return;
	for (i = 0; i < nphdrs; i++) {
		if (gelf_getphdr(e, (int)i, &phdr) == NULL)
			continue;
		if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0)
			continue;
		if (b->n_ptloads >= MAX_PTLOADS)
			break;
		b->ptloads[b->n_ptloads].p_vaddr = (uint64_t)phdr.p_vaddr;
		b->ptloads[b->n_ptloads].p_offset = (uint64_t)phdr.p_offset;
		b->ptloads[b->n_ptloads].p_filesz = (uint64_t)phdr.p_filesz;
		if (b->n_ptloads == 0 && phdr.p_vaddr >= phdr.p_offset)
			b->elf_image_vaddr = (uint64_t)phdr.p_vaddr -
			    (uint64_t)phdr.p_offset;
		b->n_ptloads++;
	}
}

/*
 * File offsets are positions in the mapped binary. A split debug file
 * keeps the same p_vaddr with a zero p_filesz, so the ranges come from
 * the mapped file when that file can be opened.
 */
static void
cache_ptloads(struct dwarf_binary *b, const char *mapped_path)
{
	Elf *e;
	int fd;

	cache_ptloads_elf(b, b->elf);
	if (mapped_path == NULL || mapped_path[0] == '\0')
		return;
	fd = open(mapped_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (e != NULL && elf_kind(e) == ELF_K_ELF)
		cache_ptloads_elf(b, e);
	if (e != NULL)
		elf_end(e);
	close(fd);
}

static bool
elf_has_debug_line(Elf *e)
{
	GElf_Shdr sh;
	Elf_Scn *scn;
	size_t shstrndx;
	char *nm;

	if (elf_getshdrstrndx(e, &shstrndx) != 0)
		return (false);
	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &sh) == NULL)
			continue;
		nm = elf_strptr(e, shstrndx, sh.sh_name);
		if (nm != NULL && strcmp(nm, ".debug_line") == 0 &&
		    sh.sh_size > 0)
			return (true);
	}
	return (false);
}

/*
 * GNU build-id of the opened file, lowercase hex. False when the note
 * is absent. The caller compares it to b->build_id when that field is
 * set and treats a mismatch as an open failure.
 *
 * The note's three header words are little-endian in the file.
 */
static uint32_t
note_le32(const uint8_t *p)
{
	return ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static bool
elf_build_id_hex(Elf *e, char *buf, size_t buflen)
{
	Elf_Scn *scn;
	GElf_Shdr sh;
	Elf_Data *data;
	const uint8_t *p, *end;
	size_t shstrndx, namesz, descsz;
	uint32_t n_type;
	char *nm;

	if (buflen < 3)
		return (false);
	if (elf_getshdrstrndx(e, &shstrndx) != 0)
		return (false);
	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (gelf_getshdr(scn, &sh) == NULL)
			continue;
		nm = elf_strptr(e, shstrndx, sh.sh_name);
		if (nm == NULL || strcmp(nm, ".note.gnu.build-id") != 0)
			continue;
		data = elf_getdata(scn, NULL);
		if (data == NULL || data->d_buf == NULL)
			continue;
		p = data->d_buf;
		end = p + data->d_size;
		while (p + 12 <= end) {
			namesz = note_le32(p);
			descsz = note_le32(p + 4);
			n_type = note_le32(p + 8);
			p += 12;
			if (p + ((namesz + 3) & ~3u) + descsz > end)
				break;
			if (n_type == NT_GNU_BUILD_ID &&
			    descsz * 2 + 1 <= buflen) {
				const uint8_t *d = p + ((namesz + 3) & ~3u);
				size_t i;

				for (i = 0; i < descsz; i++)
					snprintf(buf + i * 2, 3, "%02x", d[i]);
				buf[descsz * 2] = '\0';
				return (true);
			}
			p += ((namesz + 3) & ~3u) + ((descsz + 3) & ~3u);
		}
	}
	return (false);
}

static void
close_open_attempt(struct dwarf_binary *b, Elf *e, int fd)
{
	Dwarf_Error de;

	if (b->dbg != NULL) {
		dwarf_finish(b->dbg, &de);
		b->dbg = NULL;
	}
	if (e != NULL)
		elf_end(e);
	if (fd >= 0)
		close(fd);
}

/*
 * Open a DWARF-bearing file for one candidate path. Fills b->dwarf_path
 * on success. -1 without a message is an unreadable or table-less file;
 * -1 with a message is a stale build-id, which stops the search in the
 * caller.
 */
static int
try_open_path(struct dwarf_binary *b, const char *path, char *err,
    size_t errlen)
{
	Dwarf_Error de;
	Elf *e;
	int fd;

	err[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (e == NULL || elf_kind(e) != ELF_K_ELF) {
		close_open_attempt(b, e, fd);
		return (-1);
	}
	if (dwarf_elf_init(e, DW_DLC_READ, NULL, NULL, &b->dbg, &de) !=
	    DW_DLV_OK) {
		close_open_attempt(b, e, fd);
		return (-1);
	}
	/*
	 * Line tables are the .debug_line section. dwarf_elf_init also
	 * succeeds for a stripped binary whose only DWARF-like section
	 * is .eh_frame; that file's lines live in the split debug file.
	 */
	if (!elf_has_debug_line(e)) {
		close_open_attempt(b, e, fd);
		return (-1);
	}
	/*
	 * A stale debug file for a different build would attribute
	 * lines from the wrong source. Refuse it like any other open
	 * failure so the miss counter reflects the mismatch.
	 */
	if (b->build_id[0] != '\0') {
		char note_id[41];

		if (!elf_build_id_hex(e, note_id, sizeof(note_id)) ||
		    strcmp(note_id, b->build_id) != 0) {
			snprintf(err, errlen,
			    "build-id mismatch for %s", path);
			close_open_attempt(b, e, fd);
			return (-1);
		}
	}
	strlcpy(b->dwarf_path, path, sizeof(b->dwarf_path));
	b->fd = fd;
	b->elf = e;
	cache_ptloads(b, b->pathname);
	return (0);
}

/*
 * Locate a DWARF-bearing file for `pathname`: the path itself, then
 * /usr/lib/debug/<path>.debug, then the .gnu_debuglink target next to
 * the binary or under /usr/lib/debug.
 */
static bool
open_or_stale(struct dwarf_binary *b, const char *path)
{
	if (try_open_path(b, path, b->open_error, sizeof(b->open_error)) != 0)
		return (false);
	b->open_ok = true;
	g_binaries_opened++;
	return (true);
}

static void
dwarf_binary_open(struct dwarf_binary *b)
{
	char debug_path[PATH_MAX];
	char link_name[PATH_MAX];
	Elf_Scn *scn;
	GElf_Shdr sh;
	Elf_Data *data;
	size_t namelen;

	b->open_attempted = true;
	if (!g_libelf_ok || b->pathname[0] == '\0')
		return;

	if (open_or_stale(b, b->pathname))
		return;
	if (b->open_error[0] != '\0')
		return;

	snprintf(debug_path, sizeof(debug_path), "/usr/lib/debug%s.debug",
	    b->pathname);
	if (open_or_stale(b, debug_path))
		return;
	if (b->open_error[0] != '\0')
		return;

	/*
	 * Peek .gnu_debuglink from the stripped binary (re-open just for
	 * the note; no DWARF expected here).
	 */
	{
		int fd;
		Elf *e;
		size_t shstrndx;
		char *nm;

		fd = open(b->pathname, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return;
		e = elf_begin(fd, ELF_C_READ, NULL);
		if (e == NULL || elf_kind(e) != ELF_K_ELF) {
			if (e != NULL)
				elf_end(e);
			close(fd);
			return;
		}
		link_name[0] = '\0';
		if (elf_getshdrstrndx(e, &shstrndx) == 0) {
			scn = NULL;
			while ((scn = elf_nextscn(e, scn)) != NULL) {
				if (gelf_getshdr(scn, &sh) == NULL)
					continue;
				nm = elf_strptr(e, shstrndx, sh.sh_name);
				if (nm == NULL ||
				    strcmp(nm, ".gnu_debuglink") != 0)
					continue;
				data = elf_getdata(scn, NULL);
				if (data == NULL || data->d_buf == NULL ||
				    data->d_size == 0)
					continue;
				namelen = strnlen(data->d_buf, data->d_size);
				if (namelen == 0 ||
				    namelen >= sizeof(link_name))
					continue;
				memcpy(link_name, data->d_buf, namelen);
				link_name[namelen] = '\0';
				break;
			}
		}
		elf_end(e);
		close(fd);

		if (link_name[0] != '\0') {
			char dir[PATH_MAX];
			char *slash;

			strlcpy(dir, b->pathname, sizeof(dir));
			slash = strrchr(dir, '/');
			if (slash != NULL)
				*slash = '\0';
			else
				strlcpy(dir, ".", sizeof(dir));
			snprintf(debug_path, sizeof(debug_path), "%s/%s",
			    dir, link_name);
			if (open_or_stale(b, debug_path))
				return;
			if (b->open_error[0] != '\0')
				return;
			snprintf(debug_path, sizeof(debug_path),
			    "/usr/lib/debug%s/%s", dir, link_name);
			(void)open_or_stale(b, debug_path);
		}
	}
}

static bool
file_offset_to_dwarf_addr(const struct dwarf_binary *b, uint64_t file_offset,
    Dwarf_Addr *addr_out)
{
	uint32_t i;
	const struct file_ptload *pl;

	if (b->kind == SOURCE_BINARY_KIND_KERNEL) {
		/*
		 * file_offset is pc - linker_file.address. That address
		 * is the image start, whose link VA is p_vaddr - p_offset
		 * of the text segment (the same value for every PT_LOAD).
		 */
		*addr_out = (Dwarf_Addr)(b->elf_image_vaddr + file_offset);
		return (true);
	}
	for (i = 0; i < b->n_ptloads; i++) {
		pl = &b->ptloads[i];
		if (file_offset >= pl->p_offset &&
		    file_offset < pl->p_offset + pl->p_filesz) {
			*addr_out = (Dwarf_Addr)(file_offset - pl->p_offset +
			    pl->p_vaddr);
			return (true);
		}
	}
	return (false);
}

/*
 * Line tables are per-CU. Build one sorted-by-address index per binary
 * so a lookup is a binary search instead of a per-address walk that
 * re-parses every CU's .debug_line from the head.
 */

static int
line_entry_cmp(const void *a, const void *b)
{
	const struct line_entry *ea = a;
	const struct line_entry *eb = b;

	if (ea->addr < eb->addr)
		return (-1);
	if (ea->addr > eb->addr)
		return (1);
	/* end_sequence (line 0) sorts first so a real row at this addr wins. */
	if (ea->line == 0 && eb->line != 0)
		return (-1);
	if (eb->line == 0 && ea->line != 0)
		return (1);
	return (0);
}

static int
line_files_intern(struct dwarf_binary *b, const char *path)
{
	uint32_t i;
	char **nf;

	for (i = 0; i < b->n_line_files; i++) {
		if (strcmp(b->line_files[i], path) == 0)
			return ((int)i);
	}
	if (b->n_line_files == b->line_files_cap) {
		uint32_t ncap = b->line_files_cap == 0 ? 16 :
		    b->line_files_cap * 2;
		nf = realloc(b->line_files, ncap * sizeof(*nf));
		if (nf == NULL)
			return (-1);
		b->line_files = nf;
		b->line_files_cap = ncap;
	}
	b->line_files[b->n_line_files] = strdup(path);
	if (b->line_files[b->n_line_files] == NULL)
		return (-1);
	return ((int)b->n_line_files++);
}

/* Per-binary cap on the line index: a pathological .debug_line table
 * cannot grow resolve-time memory (or the SOURCE_LINE rows it bounds)
 * without limit. 64k rows is far above any legitimate table. */
#define	LINE_INDEX_MAX_ENTRIES	(1 << 16)

static bool
line_entry_add(struct dwarf_binary *b, uint64_t addr, int file_idx,
    uint32_t line)
{
	struct line_entry *ne;

	if (b->n_line_entries >= LINE_INDEX_MAX_ENTRIES) {
		if (g_lines_capped++ == 0)
			warnx("libelog_source_lines: %s: line index capped "
			    "at %u rows", b->pathname, LINE_INDEX_MAX_ENTRIES);
		return (false);
	}
	if (b->n_line_entries == b->line_entries_cap) {
		uint64_t ncap = b->line_entries_cap == 0 ? 4096 :
		    b->line_entries_cap * 2;
		ne = realloc(b->line_entries, ncap * sizeof(*ne));
		if (ne == NULL)
			return (false);
		b->line_entries = ne;
		b->line_entries_cap = ncap;
	}
	b->line_entries[b->n_line_entries].addr = addr;
	b->line_entries[b->n_line_entries].file_idx = (uint32_t)file_idx;
	b->line_entries[b->n_line_entries].line = line;
	b->n_line_entries++;
	return (true);
}

/*
 * Parse every CU's .debug_line into b->line_entries. end_sequence rows
 * are kept as line=0 sentinels (range ends); other line-0 rows are
 * skipped. Remaining paths are interned once via dwarf_linesrc.
 */
static void
build_line_index_from(struct dwarf_binary *b, Dwarf_Debug dbg)
{
	Dwarf_Die die, ret_die;
	Dwarf_Error de;
	Dwarf_Half tag;
	Dwarf_Line *lbuf;
	Dwarf_Signed lcount;
	Dwarf_Unsigned lineno;
	Dwarf_Addr lineaddr;
	Dwarf_Bool endseq;
	char *file;
	int ret, i, file_idx;

	if (dbg == NULL)
		return;

	while ((ret = dwarf_next_cu_header(dbg, NULL, NULL, NULL, NULL,
	    NULL, &de)) == DW_DLV_OK) {
		die = NULL;
		ret_die = NULL;
		tag = 0;
		while (dwarf_siblingof(dbg, die, &ret_die, &de) ==
		    DW_DLV_OK) {
			if (die != NULL)
				dwarf_dealloc(dbg, die, DW_DLA_DIE);
			die = ret_die;
			if (dwarf_tag(die, &tag, &de) != DW_DLV_OK)
				continue;
			if (tag == DW_TAG_compile_unit)
				break;
		}
		if (die == NULL || tag != DW_TAG_compile_unit) {
			if (die != NULL)
				dwarf_dealloc(dbg, die, DW_DLA_DIE);
			continue;
		}
		if (dwarf_srclines(die, &lbuf, &lcount, &de) != DW_DLV_OK) {
			dwarf_dealloc(dbg, die, DW_DLA_DIE);
			die = NULL;
			continue;
		}
		for (i = 0; i < lcount; i++) {
			if (dwarf_lineaddr(lbuf[i], &lineaddr, &de) !=
			    DW_DLV_OK)
				continue;
			endseq = false;
			if (dwarf_lineendsequence(lbuf[i], &endseq, &de) ==
			    DW_DLV_OK && endseq) {
				if (!line_entry_add(b, (uint64_t)lineaddr,
				    0, 0))
					break;
				continue;
			}
			if (dwarf_lineno(lbuf[i], &lineno, &de) != DW_DLV_OK)
				continue;
			if (lineno == 0)
				continue;
			file = NULL;
			if (dwarf_linesrc(lbuf[i], &file, &de) != DW_DLV_OK ||
			    file == NULL)
				continue;
			file_idx = line_files_intern(b, file);
			dwarf_dealloc(dbg, file, DW_DLA_STRING);
			if (file_idx < 0)
				continue;
			if (!line_entry_add(b, (uint64_t)lineaddr, file_idx,
			    (uint32_t)lineno))
				break;
		}
		dwarf_srclines_dealloc(dbg, lbuf, lcount);
		lbuf = NULL;
		dwarf_dealloc(dbg, die, DW_DLA_DIE);
		die = NULL;
	}
}

static void
sort_line_index(struct dwarf_binary *b)
{
	if (b->n_line_entries > 1)
		qsort(b->line_entries, b->n_line_entries,
		    sizeof(*b->line_entries), line_entry_cmp);
}

static void
build_line_index(struct dwarf_binary *b)
{
	if (b->line_index_built)
		return;
	b->line_index_built = true;
	build_line_index_from(b, b->dbg);
	if (b->split_dbg != NULL)
		build_line_index_from(b, b->split_dbg);
	sort_line_index(b);
}

/* Below this many rows the main file is thin enough to try the split
 * debug twin. Kernel images sit above it; a stripped user binary does not. */
#define LINE_COVERAGE_THRESHOLD	256

void
elog_source_lines_set_debug_path(const char *root)
{
	if (root == NULL)
		strlcpy(g_split_debug_root, "/usr/lib/debug",
		    sizeof(g_split_debug_root));
	else
		strlcpy(g_split_debug_root, root,
		    sizeof(g_split_debug_root));
}

static void
open_split_debug(struct dwarf_binary *b)
{
	char debug_path[PATH_MAX];
	char err[sizeof(b->open_error)];
	Dwarf_Error de;
	Dwarf_Debug dbg = NULL;
	Elf *e;
	int fd;

	snprintf(debug_path, sizeof(debug_path), "%s%s.debug",
	    g_split_debug_root, b->pathname);
	if (strcmp(b->dwarf_path, debug_path) == 0)
		return;
	fd = open(debug_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (e == NULL || elf_kind(e) != ELF_K_ELF) {
		if (e != NULL)
			elf_end(e);
		close(fd);
		return;
	}
	if (dwarf_elf_init(e, DW_DLC_READ, NULL, NULL, &dbg, &de) !=
	    DW_DLV_OK || !elf_has_debug_line(e)) {
		if (dbg != NULL)
			dwarf_finish(dbg, &de);
		elf_end(e);
		close(fd);
		return;
	}
	if (b->build_id[0] != '\0') {
		char note_id[41];

		if (!elf_build_id_hex(e, note_id, sizeof(note_id)) ||
		    strcmp(note_id, b->build_id) != 0) {
			dwarf_finish(dbg, &de);
			elf_end(e);
			close(fd);
			snprintf(err, sizeof(err),
			    "split build-id mismatch for %s", debug_path);
			strlcpy(b->open_error, err, sizeof(b->open_error));
			return;
		}
	}
	strlcpy(b->split_path, debug_path, sizeof(b->split_path));
	b->split_dbg = dbg;
	b->split_elf = e;
	b->split_fd = fd;
	b->split_opened = true;
}

/*
 * A first index with almost no rows means the binary kept only a
 * fragment of .debug_line. Read the build-id twin into the same index.
 */
static void
maybe_open_split_debug(struct dwarf_binary *b)
{
	build_line_index(b);
	if (b->split_checked)
		return;
	b->split_checked = true;
	if (b->n_line_entries >= LINE_COVERAGE_THRESHOLD)
		return;
	open_split_debug(b);
	if (b->split_dbg != NULL) {
		build_line_index_from(b, b->split_dbg);
		sort_line_index(b);
	}
}

/*
 * Resolve addr against the binary's line index. Returns true and fills
 * path/line on hit: the last entry at or before addr, unless that
 * entry is an end_sequence sentinel (line 0) — then the address sits
 * past the preceding range and is a miss (same rule as addr2line(1)).
 */
static bool
dwarf_lookup_line(struct dwarf_binary *b, Dwarf_Addr addr, char *path_out,
    size_t path_len, uint32_t *line_out)
{
	const struct line_entry *e;
	size_t lo, hi, mid;

	*line_out = 0;
	path_out[0] = '\0';
	build_line_index(b);
	if (b->n_line_entries == 0)
		return (false);

	lo = 0;
	hi = b->n_line_entries;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (b->line_entries[mid].addr <= addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return (false);
	e = &b->line_entries[lo - 1];
	if (e->line == 0)
		return (false);
	strlcpy(path_out, b->line_files[e->file_idx], path_len);
	*line_out = e->line;
	return (true);
}

static bool
resolved_seen(uint8_t kind, uint32_t binary_id, uint64_t file_offset)
{
	struct resolved_offset *ro;

	LIST_FOREACH(ro, &resolved_buckets[hash_resolved(kind, binary_id,
	    file_offset)], link) {
		if (ro->kind == kind && ro->binary_id == binary_id &&
		    ro->file_offset == file_offset)
			return (true);
	}
	return (false);
}

static void
resolved_mark(uint8_t kind, uint32_t binary_id, uint64_t file_offset)
{
	struct resolved_offset *ro;

	ro = calloc(1, sizeof(*ro));
	if (ro == NULL)
		return;
	ro->kind = kind;
	ro->binary_id = binary_id;
	ro->file_offset = file_offset;
	LIST_INSERT_HEAD(&resolved_buckets[hash_resolved(kind, binary_id,
	    file_offset)], ro, link);
}

static uint32_t
source_file_intern(uint8_t kind, uint32_t binary_id, const char *pathname,
    elog_source_lines_emit_fn emit_fn, void *cookie)
{
	struct source_file_entry *sf;
	struct symbols_eventlog_source_file payload;
	struct eventlog_event_header hdr;
	uint32_t h;

	h = hash_path(pathname, kind, binary_id);
	LIST_FOREACH(sf, &source_file_buckets[h], link) {
		if (sf->binary_kind == kind && sf->binary_id == binary_id &&
		    strcmp(sf->pathname, pathname) == 0)
			return (sf->source_file_id);
	}
	sf = calloc(1, sizeof(*sf));
	if (sf == NULL)
		return (0);
	sf->source_file_id = g_next_source_file_id++;
	sf->binary_kind = kind;
	sf->binary_id = binary_id;
	strlcpy(sf->pathname, pathname, sizeof(sf->pathname));
	LIST_INSERT_HEAD(&source_file_buckets[h], sf, link);

	memset(&payload, 0, sizeof(payload));
	payload.source_file_id = sf->source_file_id;
	payload.binary_kind = kind;
	payload.binary_id = binary_id;
	if (kind == SOURCE_BINARY_KIND_KERNEL)
		strlcpy(payload.commit_id, g_kernel_commit,
		    sizeof(payload.commit_id));
	strlcpy(payload.pathname, pathname, sizeof(payload.pathname));

	memset(&hdr, 0, sizeof(hdr));
	hdr.timestamp = g_emit_timestamp;
	hdr.event_id = SYMBOLS_EVENTLOG_SOURCE_FILE_ID;
	if (g_symbols_provider_known)
		hdr.provider_id = g_symbols_provider_id;
	emit_fn(&hdr, &payload, sizeof(payload), cookie);
	g_files_emitted++;
	return (sf->source_file_id);
}

/*
 * DWARF names the file from the objdir, so the string walks back to
 * the tree with "." and "..". Collapse those before the row is stored.
 */
static void
collapse_dotdot(char *path)
{
	char out[PATH_MAX];
	const char *p, *s;
	size_t n, len;
	bool abs;

	abs = path[0] == '/';
	n = 0;
	p = path;
	while (*p != '\0') {
		while (*p == '/')
			p++;
		if (*p == '\0')
			break;
		s = p;
		while (*p != '\0' && *p != '/')
			p++;
		len = (size_t)(p - s);
		if (len == 1 && s[0] == '.')
			continue;
		if (len == 2 && s[0] == '.' && s[1] == '.') {
			while (n > 0 && out[n - 1] != '/')
				n--;
			if (n > 1 || (n == 1 && out[0] != '/'))
				n--;
			continue;
		}
		if (n == 0) {
			if (abs)
				out[n++] = '/';
		} else if (!(n == 1 && out[0] == '/')) {
			if (n + 1 >= sizeof(out))
				return;
			out[n++] = '/';
		}
		if (n + len >= sizeof(out))
			return;
		memcpy(out + n, s, len);
		n += len;
	}
	if (n == 0)
		out[n++] = abs ? '/' : '.';
	out[n] = '\0';
	memcpy(path, out, n + 1);
}

static void
resolve_and_emit(struct dwarf_binary *b, uint64_t file_offset,
    elog_source_lines_emit_fn emit_fn, void *cookie)
{
	struct symbols_eventlog_source_line payload;
	struct eventlog_event_header hdr;
	Dwarf_Addr dwarf_addr;
	char path[PATH_MAX];
	uint32_t line, source_file_id;

	if (!b->open_attempted)
		dwarf_binary_open(b);
	if (!b->open_ok) {
		g_misses_open++;
		b->lookup_misses++;
		return;
	}
	maybe_open_split_debug(b);
	if (!file_offset_to_dwarf_addr(b, file_offset, &dwarf_addr)) {
		g_misses_addr++;
		b->lookup_misses++;
		return;
	}
	if (!dwarf_lookup_line(b, dwarf_addr, path, sizeof(path),
	    &line)) {
		g_misses_line++;
		b->lookup_misses++;
		return;
	}
	collapse_dotdot(path);
	source_file_id = source_file_intern(b->kind, b->id, path,
	    emit_fn, cookie);
	if (source_file_id == 0) {
		g_misses_line++;
		b->lookup_misses++;
		return;
	}

	memset(&payload, 0, sizeof(payload));
	payload.source_file_id = source_file_id;
	payload.binary_kind = b->kind;
	payload.binary_id = b->id;
	payload.file_offset = file_offset;
	payload.line = line;

	memset(&hdr, 0, sizeof(hdr));
	hdr.timestamp = g_emit_timestamp;
	hdr.event_id = SYMBOLS_EVENTLOG_SOURCE_LINE_ID;
	if (g_symbols_provider_known)
		hdr.provider_id = g_symbols_provider_id;
	emit_fn(&hdr, &payload, sizeof(payload), cookie);
	g_lines_emitted++;
	b->lines_emitted++;
}

static void
observe_linker_file(const void *payload, size_t payload_size)
{
	const struct symbols_eventlog_linker_file *lf;
	struct dwarf_binary *b;

	if (payload_size < sizeof(*lf))
		return;
	lf = payload;
	if (lf->file_id == 0)
		return;
	b = dwarf_binary_lookup(SOURCE_BINARY_KIND_KERNEL, lf->file_id);
	if (b != NULL) {
		if (b->runtime_base == lf->base && b->runtime_size == lf->size)
			return;
		b->runtime_base = lf->base;
		b->runtime_size = lf->size;
	} else if (dwarf_binary_insert(SOURCE_BINARY_KIND_KERNEL, lf->file_id,
	    lf->pathname, lf->build_id, lf->base, lf->size) == NULL) {
		return;
	}
	g_kernel_by_base_dirty = true;
}

static void
observe_user_file(const void *payload, size_t payload_size)
{
	const struct symbols_eventlog_user_file *uf;

	if (payload_size < sizeof(*uf))
		return;
	uf = payload;
	if (uf->user_file_id == 0)
		return;
	if (dwarf_binary_lookup(SOURCE_BINARY_KIND_USER, uf->user_file_id) !=
	    NULL)
		return;
	(void)dwarf_binary_insert(SOURCE_BINARY_KIND_USER, uf->user_file_id,
	    uf->pathname, uf->build_id, 0, 0);
}

static void
observe_proc_map(const void *payload, size_t payload_size)
{
	const struct process_eventlog_proc_map *pm;
	struct proc_map_entry *e;

	if (payload_size < sizeof(*pm))
		return;
	pm = payload;
	if (pm->pid == 0 || pm->user_file_id == 0 || pm->size == 0)
		return;
	LIST_FOREACH(e, &proc_map_buckets[hash32(pm->pid)], link) {
		if (e->pid == pm->pid && e->base == pm->base &&
		    e->size == pm->size && e->offset == pm->offset &&
		    e->user_file_id == pm->user_file_id)
			return;
	}
	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return;
	e->pid = pm->pid;
	e->user_file_id = pm->user_file_id;
	e->base = pm->base;
	e->size = pm->size;
	e->offset = pm->offset;
	LIST_INSERT_HEAD(&proc_map_buckets[hash32(pm->pid)], e, link);
}

static int
kernel_base_cmp(const void *a, const void *b)
{
	const struct dwarf_binary *ba = *(struct dwarf_binary *const *)a;
	const struct dwarf_binary *bb = *(struct dwarf_binary *const *)b;

	if (ba->runtime_base < bb->runtime_base)
		return (-1);
	if (ba->runtime_base > bb->runtime_base)
		return (1);
	return (0);
}

static void
kernel_by_base_rebuild(void)
{
	struct dwarf_binary *b;
	size_t n;
	int i;

	free(g_kernel_by_base);
	g_kernel_by_base = NULL;
	g_kernel_count = 0;
	n = 0;
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_FOREACH(b, &dwarf_buckets[i], link) {
			if (b->kind == SOURCE_BINARY_KIND_KERNEL)
				n++;
		}
	}
	if (n == 0) {
		g_kernel_by_base_dirty = false;
		return;
	}
	g_kernel_by_base = malloc(n * sizeof(*g_kernel_by_base));
	if (g_kernel_by_base == NULL)
		return;	/* dirty stays set; retried on the next lookup */
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_FOREACH(b, &dwarf_buckets[i], link) {
			if (b->kind == SOURCE_BINARY_KIND_KERNEL)
				g_kernel_by_base[g_kernel_count++] = b;
		}
	}
	qsort(g_kernel_by_base, g_kernel_count, sizeof(*g_kernel_by_base),
	    kernel_base_cmp);
	g_kernel_by_base_dirty = false;
}

static struct dwarf_binary *
find_kernel_binary(uint64_t pc, uint64_t *file_offset_out)
{
	struct dwarf_binary *b;
	size_t lo, hi, mid;

	if (g_kernel_by_base_dirty)
		kernel_by_base_rebuild();
	/* Last entry with runtime_base <= pc is the only possible match. */
	lo = 0;
	hi = g_kernel_count;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (g_kernel_by_base[mid]->runtime_base <= pc)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return (NULL);
	b = g_kernel_by_base[lo - 1];
	if (b->runtime_size == 0 || pc >= b->runtime_base + b->runtime_size)
		return (NULL);
	*file_offset_out = pc - b->runtime_base;
	return (b);
}

static struct dwarf_binary *
find_user_binary(uint32_t pid, uint64_t pc, uint64_t *file_offset_out)
{
	struct proc_map_entry *pm;
	struct dwarf_binary *b;

	LIST_FOREACH(pm, &proc_map_buckets[hash32(pid)], link) {
		if (pm->pid != pid)
			continue;
		if (pc < pm->base || pc >= pm->base + pm->size)
			continue;
		b = dwarf_binary_lookup(SOURCE_BINARY_KIND_USER,
		    pm->user_file_id);
		if (b == NULL)
			return (NULL);
		*file_offset_out = pc - pm->base + pm->offset;
		return (b);
	}
	return (NULL);
}

static bool
pending_seen(uint64_t pc, uint32_t pid)
{
	struct pending_pc *pp;

	LIST_FOREACH(pp, &pending_buckets[hash_pending(pc, pid)], link) {
		if (pp->pc == pc && pp->pid == pid)
			return (true);
	}
	return (false);
}

static void
pending_mark(uint64_t pc, uint32_t pid)
{
	struct pending_pc *pp;

	pp = calloc(1, sizeof(*pp));
	if (pp == NULL)
		return;
	pp->pc = pc;
	pp->pid = pid;
	LIST_INSERT_HEAD(&pending_buckets[hash_pending(pc, pid)], pp, link);
}

static void
observe_cpu_sample(const void *payload, size_t payload_size)
{
	const struct cpu_eventlog_cpu_sample_head *head;
	uint64_t pc;
	size_t head_size, nframes, i;

	head_size = sizeof(*head); /* packed: 13 bytes; frames follow immediately */
	if (payload_size < head_size + sizeof(uint64_t))
		return;
	head = payload;
	if (head->depth == 0)
		return;
	nframes = (payload_size - head_size) / sizeof(uint64_t);
	if (nframes > head->depth)
		nframes = head->depth;
	/*
	 * frames[] may be misaligned on the wire; copy each PC. Record
	 * unique (pc, pid) only; binary lookup and DWARF happen in
	 * elog_source_lines_resolve() after every mapping event has
	 * been seen.
	 */
	for (i = 0; i < nframes; i++) {
		memcpy(&pc, (const uint8_t *)payload + head_size +
		    i * sizeof(uint64_t), sizeof(pc));
		if (pc == 0)
			continue;
		if (!pending_seen(pc, head->pid))
			pending_mark(pc, head->pid);
	}
}

void
elog_source_lines_resolve(elog_source_lines_emit_fn emit_fn, void *cookie)
{
	struct pending_pc *pp;
	struct dwarf_binary *b;
	uint64_t file_offset;
	int i;

	if (!g_initialized || g_resolved || emit_fn == NULL)
		return;
	g_resolved = true;
	for (i = 0; i < HASH_SIZE; i++) {
		LIST_FOREACH(pp, &pending_buckets[i], link) {
			b = find_kernel_binary(pp->pc, &file_offset);
			if (b == NULL && pp->pid != 0)
				b = find_user_binary(pp->pid, pp->pc,
				    &file_offset);
			if (b == NULL) {
				g_misses_no_binary++;
				continue;
			}
			if (resolved_seen(b->kind, b->id, file_offset))
				continue;
			resolved_mark(b->kind, b->id, file_offset);
			resolve_and_emit(b, file_offset, emit_fn, cookie);
		}
	}
}

void
elog_source_lines_observe(const char *provider_name,
    const struct eventlog_event_header *hdr,
    const void *payload, size_t payload_size)
{
	if (!g_initialized || hdr == NULL || provider_name == NULL)
		return;

	if (hdr->timestamp > g_emit_timestamp)
		g_emit_timestamp = hdr->timestamp;

	/* Provider ids stick for the capture; strcmp only on first sighting. */
	if (g_cpu_provider_known && hdr->provider_id == g_cpu_provider_id) {
		if (hdr->event_id == CPU_EVENTLOG_CPU_SAMPLE_ID)
			observe_cpu_sample(payload, payload_size);
		return;
	}
	if (g_symbols_provider_known &&
	    hdr->provider_id == g_symbols_provider_id) {
		if (hdr->event_id == SYMBOLS_EVENTLOG_LINKER_FILE_ID)
			observe_linker_file(payload, payload_size);
		else if (hdr->event_id == SYMBOLS_EVENTLOG_USER_FILE_ID)
			observe_user_file(payload, payload_size);
		return;
	}
	if (g_process_provider_known &&
	    hdr->provider_id == g_process_provider_id) {
		if (hdr->event_id == PROCESS_EVENTLOG_PROC_MAP_ID)
			observe_proc_map(payload, payload_size);
		return;
	}

	if (strcmp(provider_name, "cpu") == 0) {
		g_cpu_provider_id = hdr->provider_id;
		g_cpu_provider_known = true;
		if (hdr->event_id == CPU_EVENTLOG_CPU_SAMPLE_ID)
			observe_cpu_sample(payload, payload_size);
		return;
	}
	if (strcmp(provider_name, "symbols") == 0) {
		g_symbols_provider_id = hdr->provider_id;
		g_symbols_provider_known = true;
		if (hdr->event_id == SYMBOLS_EVENTLOG_LINKER_FILE_ID)
			observe_linker_file(payload, payload_size);
		else if (hdr->event_id == SYMBOLS_EVENTLOG_USER_FILE_ID)
			observe_user_file(payload, payload_size);
		return;
	}
	if (strcmp(provider_name, "process") == 0) {
		g_process_provider_id = hdr->provider_id;
		g_process_provider_known = true;
		if (hdr->event_id == PROCESS_EVENTLOG_PROC_MAP_ID)
			observe_proc_map(payload, payload_size);
		return;
	}
}
