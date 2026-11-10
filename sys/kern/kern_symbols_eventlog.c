/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

/*
 * Kernel-side producer for the "symbols" eventlog provider.
 *
 * Responsibilities:
 *   - One global eventlog_session that carries all symbol metadata.
 *   - On session create, emit KERNEL_INFO (text base/size, build_id,
 *     ident) so consumers can pin a capture to a specific kernel
 *     image.
 *   - On dump_state, walk the linker file list and emit one
 *     LINKER_FILE per loaded file plus one SYMBOL_RANGE per
 *     STT_FUNC symbol.
 *   - Cross-provider intern KPI: eventlog_symbols_intern_user_file()
 *     allocates a stable user_file_id keyed on (dev, ino) and emits
 *     a single USER_FILE event the first time a given backing file
 *     is observed. The process provider (and any future caller that
 *     attributes events to user-mode binaries) calls this so every
 *     consumer gets USER_FILE for free regardless of which provider
 *     surfaced the binary first.
 *
 * The user-mode half (libelog_user_symbols + elog -U) emits
 * USER_SYMBOL_RANGE events on the .elog stream after the fact;
 * those do not flow through this file.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/smp.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/eventlog.h>
#include <sys/eventlog_symbols.h>
#include <sys/vnode.h>
#include <machine/cpu.h>
#include <machine/elf.h>

/*
 * Compile the symbols decode blob into this TU (the "symbols" provider's
 * one registration site) -- see <eventlog/tcp_eventlog.h>'s definition site
 * in tcp_subr.c for the pattern this mirrors.
 */
#define	SYMBOLS_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/symbols_eventlog.h>

static MALLOC_DEFINE(M_SYM_ELOG, "sym_elog", "symbols eventlog provider");

static struct eventlog_provider	*sym_elog_provider;
static struct eventlog_session	*sym_elog_session;

/* Formatted once at boot by symbols_eventlog_init(); immutable after. */
static char sym_elog_kernel_build_id[41];

/*
 * USER_FILE intern table.
 *
 * Keyed on (st_dev, st_ino). Entries live for the rest of kernel
 * uptime; ids are stable so other providers (process, future memory)
 * can cache a user_file_id alongside their own per-process state and
 * not have to revisit it.
 *
 * v1 design notes:
 *   - Linear list under an rwlock: lookups (the common, post-warmup
 *     path, hit from every exec()/mmap()) take the read lock so they
 *     don't serialize against each other across CPUs; only
 *     first-sighting inserts take the write lock. Expected population
 *     is the executable + its libraries (~50 entries on an OCA), so
 *     even O(N) per intern is comfortably under the cost of the
 *     vnode lookup that preceded the call.
 *   - build_id is left empty for v1. NT_GNU_BUILD_ID parsing is a
 *     follow-up; consumers fall back to matching by pathname.
 *   - id allocation is monotonic; id 0 is reserved for "no file".
 */
struct sym_elog_user_file {
	LIST_ENTRY(sym_elog_user_file)	link;
	uint64_t	dev;
	uint64_t	ino;
	uint32_t	user_file_id;
	char		pathname[128];
};

static LIST_HEAD(, sym_elog_user_file) sym_elog_user_files =
    LIST_HEAD_INITIALIZER(sym_elog_user_files);
static struct rwlock	 sym_elog_user_files_lock;
static uint32_t		 sym_elog_next_user_file_id = 1;

static void	sym_elog_emit_kernel_info(struct eventlog_session *session);
static void	sym_elog_emit_linker_files(struct eventlog_session *session);
static void	sym_elog_emit_all_symbols(struct eventlog_session *session);
static void	sym_elog_emit_user_files(struct eventlog_session *session);
static void	sym_elog_dump_state(struct eventlog_provider *, void *);
static void	sym_elog_format_kernel_build_id(char *buf, size_t bufsize);
static void	sym_elog_read_module_build_id(const char *pathname, char *buf,
		    size_t bufsize);

/* SYMBOL_PACK_REF kind / id_kind values (no schema enum; keep in sync). */
#define	SYM_ELOG_REF_KIND_LINKER_FILE	0
#define	SYM_ELOG_REF_KIND_USER_FILE	1
#define	SYM_ELOG_REF_ID_GNU_BUILD_ID	0
#define	SYM_ELOG_REF_ID_FILE_SHA256	1

/*
 * Extract the kernel's .note.gnu.build-id and format as the 40-char
 * lowercase hex string. Mirrors sysctl_build_id() in kern_mib.c.
 *
 * The note section layout (per ELF spec) is a 16-byte prologue
 * (namesz=4, descsz, type=NT_GNU_BUILD_ID, name="GNU\0") followed
 * by descsz bytes of build-id. Leaves buf empty when the kernel
 * was not linked with --build-id (or the note is malformed).
 */
static void
sym_elog_format_kernel_build_id(char *buf, size_t bufsize)
{
	size_t sectionlen, hashlen, i;

	if (bufsize == 0)
		return;
	buf[0] = '\0';

	sectionlen = (size_t)((uintptr_t)__build_id_end -
	    (uintptr_t)__build_id_start);
	if (sectionlen <= 16 || sectionlen > 16 + 20)
		return;
	hashlen = sectionlen - 16;
	if (bufsize < hashlen * 2 + 1)
		return;
	for (i = 0; i < hashlen; i++) {
		snprintf(&buf[i * 2], 3, "%02x",
		    (uint8_t)__build_id_start[i + 16]);
	}
}

static void
sym_elog_emit_kernel_info(struct eventlog_session *session)
{
	/*
	 * linker_kernel_file->address, not btext: btext is only provided
	 * by the amd64/i386 ldscripts (it's their ENTRY()), arm64 has no
	 * such symbol. linker_kernel_file->address is portable and is
	 * already the base LINKER_FILE/SYMBOL_RANGE use below, so this
	 * keeps text_base consistent with those.
	 */
	uint64_t base = (uint64_t)(uintptr_t)linker_kernel_file->address;
	uint64_t size = (uint64_t)((uintptr_t)etext - (uintptr_t)base);

	SYMBOLS_EVENTLOG_KERNEL_INFO_LOG_ALWAYS(session,
	    base, size, sym_elog_kernel_build_id, ostype);
}

/* Parse a note segment for NT_GNU_BUILD_ID and hex-format it into buf. */
static void
sym_elog_parse_note(char *buf, size_t bufsize, const char *notes,
    size_t notesz)
{
	uint32_t namesz, descsz, type;
	size_t off, nameoff, descoff, next, i;

	for (off = 0; off + 12 <= notesz; off = next) {
		memcpy(&namesz, notes + off, sizeof(namesz));
		memcpy(&descsz, notes + off + 4, sizeof(descsz));
		memcpy(&type, notes + off + 8, sizeof(type));
		nameoff = off + 12;
		descoff = nameoff + roundup2(namesz, 4);
		next = descoff + roundup2(descsz, 4);
		if (next > notesz || next <= off)
			break;
		if (type == NT_GNU_BUILD_ID && namesz == 4 &&
		    descsz > 0 && bufsize >= descsz * 2 + 1 &&
		    memcmp(notes + nameoff, "GNU\0", 4) == 0) {
			for (i = 0; i < descsz; i++)
				snprintf(&buf[i * 2], 3, "%02x",
				    (uint8_t)notes[descoff + i]);
			break;
		}
	}
}

/*
 * Read one module's .note.gnu.build-id from its image file and format
 * it as lowercase hex. Reading the file (rather than the loaded image)
 * avoids depending on how much of the ELF header link_elf keeps
 * mapped, and dump_state runs on the eventlog dump taskqueue, where
 * sleeping on vnode I/O is allowed. Re-read on every dump: modules
 * are few and the walk is hourly, so caching by lf->id is not worth
 * the invalidation question.
 *
 * ET_EXEC/ET_DYN files carry the note in a PT_NOTE segment; ET_REL
 * files (in-image kmods load via link_elf_obj) have no program
 * headers, so those go through the SHT_NOTE section table instead.
 */
static void
sym_elog_read_module_build_id(const char *pathname, char *buf,
    size_t bufsize)
{
	struct nameidata nd;
	struct thread *td = curthread;
	Elf_Ehdr *ehdr;
	Elf_Phdr *phdr, *phlimit;
	Elf_Shdr *shdr;
	char *firstpage, *notes;
	size_t notesz, tabsz;
	off_t noteoff;
	ssize_t resid;
	int error, flags, i;

	if (bufsize == 0)
		return;
	buf[0] = '\0';

	firstpage = malloc(PAGE_SIZE, M_SYM_ELOG, M_WAITOK);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, pathname);
	flags = FREAD;
	error = vn_open(&nd, &flags, 0, NULL);
	if (error != 0)
		goto out;
	NDFREE_PNBUF(&nd);
	if (nd.ni_vp->v_type != VREG)
		goto out_vn;
	error = vn_rdwr(UIO_READ, nd.ni_vp, firstpage, PAGE_SIZE, 0,
	    UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, &resid, td);
	if (error != 0 || resid > PAGE_SIZE - sizeof(*ehdr))
		goto out_vn;

	ehdr = (Elf_Ehdr *)firstpage;
	if (!IS_ELF(*ehdr) ||
	    ehdr->e_ident[EI_CLASS] != ELF_TARG_CLASS ||
	    ehdr->e_ident[EI_DATA] != ELF_TARG_DATA ||
	    ehdr->e_version != EV_CURRENT ||
	    ehdr->e_machine != ELF_TARG_MACH)
		goto out_vn;

	if (ehdr->e_type == ET_REL) {
		/*
		 * Section-header walk for relocatable modules. The table
		 * is small in practice (tens of sections); cap it anyway.
		 */
		if (ehdr->e_shentsize != sizeof(Elf_Shdr) ||
		    ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
		    ehdr->e_shnum > 4096)
			goto out_vn;
		tabsz = (size_t)ehdr->e_shnum * sizeof(Elf_Shdr);
		shdr = malloc(tabsz, M_SYM_ELOG, M_WAITOK);
		error = vn_rdwr(UIO_READ, nd.ni_vp, shdr, tabsz,
		    ehdr->e_shoff, UIO_SYSSPACE, IO_NODELOCKED,
		    td->td_ucred, NOCRED, &resid, td);
		if (error != 0 || resid != 0) {
			free(shdr, M_SYM_ELOG);
			goto out_vn;
		}
		for (i = 0; i < ehdr->e_shnum && buf[0] == '\0'; i++) {
			if (shdr[i].sh_type != SHT_NOTE ||
			    shdr[i].sh_size < 16 ||
			    shdr[i].sh_size > PAGE_SIZE)
				continue;
			notes = malloc(shdr[i].sh_size, M_SYM_ELOG, M_WAITOK);
			error = vn_rdwr(UIO_READ, nd.ni_vp, notes,
			    shdr[i].sh_size, shdr[i].sh_offset,
			    UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred,
			    NOCRED, &resid, td);
			if (error == 0 && resid == 0)
				sym_elog_parse_note(buf, bufsize, notes,
				    shdr[i].sh_size);
			free(notes, M_SYM_ELOG);
		}
		free(shdr, M_SYM_ELOG);
		goto out_vn;
	}

	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		goto out_vn;
	/* Program headers sit in the first page, as link_elf assumes. */
	if (ehdr->e_phentsize != sizeof(Elf_Phdr) ||
	    ehdr->e_phoff > (uint64_t)(PAGE_SIZE - resid) ||
	    ehdr->e_phnum * sizeof(Elf_Phdr) >
	    (uint64_t)(PAGE_SIZE - resid) - ehdr->e_phoff)
		goto out_vn;

	phdr = (Elf_Phdr *)(firstpage + ehdr->e_phoff);
	phlimit = phdr + ehdr->e_phnum;
	for (; phdr < phlimit && buf[0] == '\0'; phdr++) {
		if (phdr->p_type != PT_NOTE)
			continue;
		noteoff = phdr->p_offset;
		notesz = phdr->p_filesz;
		/* A build-id note is tens of bytes; cap the read. */
		if (notesz < 16 || notesz > PAGE_SIZE)
			continue;
		notes = malloc(notesz, M_SYM_ELOG, M_WAITOK);
		error = vn_rdwr(UIO_READ, nd.ni_vp, notes, notesz, noteoff,
		    UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED,
		    &resid, td);
		if (error == 0 && resid == 0)
			sym_elog_parse_note(buf, bufsize, notes, notesz);
		free(notes, M_SYM_ELOG);
	}

out_vn:
	VOP_UNLOCK(nd.ni_vp);
	vn_close(nd.ni_vp, flags, td->td_ucred, td);
out:
	free(firstpage, M_SYM_ELOG);
}

/*
 * Snapshot of one non-kernel linker file taken under kld_sx. The note
 * read happens after the lock is dropped (vnode I/O must not run under
 * kld_sx: kldload orders vnode->linker, so reading here would invert
 * it), which is why LINKER_FILE emission needs a second pass.
 */
struct sym_elog_lf_snap {
	LIST_ENTRY(sym_elog_lf_snap) link;
	uint32_t	file_id;
	char		pathname[128];
	char		build_id[41];
};

LIST_HEAD(sym_elog_lf_snap_head, sym_elog_lf_snap);

struct sym_elog_emit_lf_ctx {
	struct eventlog_session		*session;
	struct sym_elog_lf_snap_head	*snaps;
};

static int
sym_elog_snapshot_lf_cb(linker_file_t lf, void *context)
{
	struct sym_elog_lf_snap_head *snaps = context;
	struct sym_elog_lf_snap *snap;

	if (lf == linker_kernel_file || lf->pathname == NULL ||
	    lf->pathname[0] == '\0')
		return (0);
	snap = malloc(sizeof(*snap), M_SYM_ELOG, M_WAITOK);
	snap->file_id = (uint32_t)lf->id;
	strlcpy(snap->pathname, lf->pathname, sizeof(snap->pathname));
	snap->build_id[0] = '\0';
	LIST_INSERT_HEAD(snaps, snap, link);
	return (0);
}

/*
 * linker_file_foreach() callback that emits one LINKER_FILE event and,
 * when the file's GNU build-id is known, one SYMBOL_PACK_REF naming
 * the pack that carries this file's ranges.
 *
 * The kernel's build_id comes from __build_id_start; a module's was
 * read from its image file before this pass. A file with no readable
 * note just gets no ref: consumers fall back to matching by pathname.
 *
 * filename / pathname are copied into fixed-width schema fields and
 * truncated with NAME_TRUNCATED set if either source string didn't
 * fit. Module names are short in practice; the flag exists so a
 * pathological case is self-describing rather than silently broken.
 */
static int
sym_elog_emit_linker_file_cb(linker_file_t lf, void *context)
{
	struct sym_elog_emit_lf_ctx *ctx = context;
	struct eventlog_session *session = ctx->session;
	struct sym_elog_lf_snap *snap;
	const char *filename, *pathname;
	char build_id[41];
	uint32_t flags;

	build_id[0] = '\0';
	flags = (lf->flags & LINKER_FILE_LINKED) ? SYMBOLS_EVENTLOG_FLAG_LINKED : 0;
	if (lf == linker_kernel_file) {
		strlcpy(build_id, sym_elog_kernel_build_id, sizeof(build_id));
		flags |= SYMBOLS_EVENTLOG_FLAG_KERNEL;
	} else {
		LIST_FOREACH(snap, ctx->snaps, link) {
			if (snap->file_id == (uint32_t)lf->id) {
				strlcpy(build_id, snap->build_id,
				    sizeof(build_id));
				break;
			}
		}
	}

	filename = lf->filename != NULL ? lf->filename : "";
	pathname = lf->pathname != NULL ? lf->pathname : "";
	if (strlen(filename) >=
	    sizeof(((struct symbols_eventlog_linker_file *)0)->filename) ||
	    strlen(pathname) >=
	    sizeof(((struct symbols_eventlog_linker_file *)0)->pathname))
		flags |= SYMBOLS_EVENTLOG_FLAG_NAME_TRUNCATED;

	SYMBOLS_EVENTLOG_LINKER_FILE_LOG_ALWAYS(session,
	    (uint32_t)lf->id,
	    (uint64_t)(uintptr_t)lf->address,
	    (uint64_t)lf->size,
	    flags,
	    build_id,
	    filename,
	    pathname);
	if (build_id[0] != '\0')
		SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_LOG_ALWAYS(session,
		    SYM_ELOG_REF_KIND_LINKER_FILE, SYM_ELOG_REF_ID_GNU_BUILD_ID,
		    (uint32_t)lf->id, build_id);
	return (0);
}

static void
sym_elog_emit_linker_files(struct eventlog_session *session)
{
	struct sym_elog_lf_snap_head snaps;
	struct sym_elog_emit_lf_ctx ctx;
	struct sym_elog_lf_snap *snap, *tmp;

	/*
	 * Snapshot pathnames under kld_sx, read the notes with the lock
	 * dropped, then a second pass emits LINKER_FILE / SYMBOL_PACK_REF
	 * with the results. A file unloaded between passes is just absent
	 * from the second walk; an id recycled by a reload names the new
	 * file, whose note was read for the old one and simply won't
	 * match (different bytes, empty ref) -- neither is worth locking
	 * the whole dump against.
	 */
	LIST_INIT(&snaps);
	(void)linker_file_foreach(sym_elog_snapshot_lf_cb, &snaps);
	LIST_FOREACH(snap, &snaps, link)
		sym_elog_read_module_build_id(snap->pathname, snap->build_id,
		    sizeof(snap->build_id));
	ctx.session = session;
	ctx.snaps = &snaps;
	(void)linker_file_foreach(sym_elog_emit_linker_file_cb, &ctx);
	LIST_FOREACH_SAFE(snap, &snaps, link, tmp) {
		LIST_REMOVE(snap, link);
		free(snap, M_SYM_ELOG);
	}
}

/*
 * linker_file_function_listall() callback. Emits one SYMBOL_RANGE
 * event per STT_FUNC symbol visible in lf, as
 * (file_id, offset, size, name).
 *
 * symval->value is the runtime virtual address the in-kernel linker
 * relocated this symbol to, which is exactly what we want for mapping
 * a captured PC back to a symbol. For loaded modules the kernel
 * already did the per-section relocation; userspace would otherwise
 * have to reconstruct it.
 *
 * Some symbols point just past the end of the enclosing linker file
 * (e.g. __stop_set_* set terminators). Drop those to keep consumer
 * heuristics simple.
 */
static int
sym_elog_emit_symbol_cb(linker_file_t lf, int symidx __unused,
    linker_symval_t *symval, void *context)
{
	struct eventlog_session *session = context;
	uint64_t runtime_va;
	uint64_t base;
	uint64_t offset;

	if (symval->name == NULL || symval->name[0] == '\0')
		return (0);
	if (symval->value == NULL)
		return (0);

	runtime_va = (uint64_t)(uintptr_t)symval->value;
	base = (uint64_t)(uintptr_t)lf->address;
	if (runtime_va < base)
		return (0);
	offset = runtime_va - base;
	if (lf->size > 0 && offset >= (uint64_t)lf->size)
		return (0);

	/*
	 * LOG_ALWAYS rather than keyword-gated LOG: dump_state runs even
	 * if the session is in its default-disabled state (a subscriber
	 * may attach before anyone writes kern.eventlog.symbols.default
	 * to enable). The framework's per-subscriber filter drops these
	 * for subscribers that masked SYMBOL_META off, so the wire cost
	 * is only paid for subscribers that actually want symbols.
	 */
	SYMBOLS_EVENTLOG_SYMBOL_RANGE_LOG_ALWAYS(session,
	    (uint32_t)lf->id, offset, (uint32_t)symval->size, symval->name);
	return (0);
}

static int
sym_elog_emit_symbols_lf_cb(linker_file_t lf, void *context)
{
	(void)linker_file_function_listall(lf, sym_elog_emit_symbol_cb,
	    context);
	return (0);
}

static void
sym_elog_emit_all_symbols(struct eventlog_session *session)
{
	(void)linker_file_foreach(sym_elog_emit_symbols_lf_cb, session);
}

/*
 * Re-emit every interned USER_FILE entry to the dumping subscriber.
 * _LOG_ALWAYS is a bounded, lock-free ring write (no sleeping, no
 * allocation), so emitting directly under the read lock is cheap
 * even for a large table.
 */
static void
sym_elog_emit_user_files(struct eventlog_session *session)
{
	struct sym_elog_user_file *uf;
	char build_id[41];

	build_id[0] = '\0';

	rw_rlock(&sym_elog_user_files_lock);
	LIST_FOREACH(uf, &sym_elog_user_files, link) {
		SYMBOLS_EVENTLOG_USER_FILE_LOG_ALWAYS(session,
		    uf->user_file_id, build_id, uf->pathname);
	}
	rw_runlock(&sym_elog_user_files_lock);
}

static void
sym_elog_dump_state(struct eventlog_provider *provider __unused,
    void *arg __unused)
{

	if (sym_elog_session == NULL)
		return;
	sym_elog_emit_kernel_info(sym_elog_session);
	sym_elog_emit_linker_files(sym_elog_session);
	sym_elog_emit_all_symbols(sym_elog_session);
	sym_elog_emit_user_files(sym_elog_session);
}

/*
 * Public KPI -- look up or allocate a user_file_id for the backing
 * file of `vp`. Emits a single USER_FILE event on first sighting.
 *
 * The intern table is keyed on (st_dev, st_ino). If multiple paths
 * resolve to the same inode (hard links, bind-mounts) they share an
 * id; if a file is replaced under the same path but gets a new
 * inode, we allocate a new id (no GC of the old one, but that's
 * fine -- ids are uptime-scoped).
 *
 * Returns 0 on success and stores the allocated/looked-up id in
 * *user_file_id_out. Returns EINVAL for vp == NULL or vnodes that
 * VOP_GETATTR refuses.
 */
int
eventlog_symbols_intern_user_file(struct vnode *vp, const char *pathname,
    uint32_t *user_file_id_out)
{
	struct sym_elog_user_file *uf, *new_uf;
	struct vattr va;
	uint64_t dev, ino;
	uint32_t id;
	int error;
	bool found;

	if (user_file_id_out == NULL)
		return (EINVAL);
	*user_file_id_out = 0;
	if (vp == NULL)
		return (EINVAL);

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(vp, &va, curthread->td_ucred);
	VOP_UNLOCK(vp);
	if (error != 0)
		return (error);

	dev = (uint64_t)va.va_fsid;
	ino = (uint64_t)va.va_fileid;
	if (dev == 0 && ino == 0)
		return (EINVAL);

	/* Lookup. */
	rw_rlock(&sym_elog_user_files_lock);
	LIST_FOREACH(uf, &sym_elog_user_files, link) {
		if (uf->dev == dev && uf->ino == ino) {
			id = uf->user_file_id;
			rw_runlock(&sym_elog_user_files_lock);
			*user_file_id_out = id;
			return (0);
		}
	}
	rw_runlock(&sym_elog_user_files_lock);

	/* Insert. */
	new_uf = malloc(sizeof(*new_uf), M_SYM_ELOG, M_WAITOK | M_ZERO);
	new_uf->dev = dev;
	new_uf->ino = ino;
	if (pathname != NULL)
		strlcpy(new_uf->pathname, pathname, sizeof(new_uf->pathname));

	found = false;
	rw_wlock(&sym_elog_user_files_lock);
	LIST_FOREACH(uf, &sym_elog_user_files, link) {
		if (uf->dev == dev && uf->ino == ino) {
			id = uf->user_file_id;
			found = true;
			break;
		}
	}
	if (!found) {
		new_uf->user_file_id = sym_elog_next_user_file_id++;
		id = new_uf->user_file_id;
		LIST_INSERT_HEAD(&sym_elog_user_files, new_uf, link);
	}
	rw_wunlock(&sym_elog_user_files_lock);

	if (!found) {
		char build_id[41];

		build_id[0] = '\0';
		SYMBOLS_EVENTLOG_USER_FILE_LOG(sym_elog_session,
		    id, build_id, new_uf->pathname);
	}
	if (found)
		free(new_uf, M_SYM_ELOG);

	*user_file_id_out = id;
	return (0);
}

/*
 * Provider lifecycle. Runs once at boot; the provider and session
 * live for the rest of the kernel's uptime, same as kern_eventlog.c's
 * own state (see if_eventlog_init() for the pattern this mirrors).
 */
static void
symbols_eventlog_init(void *unused __unused)
{
	struct eventlog_provider_config cfg = {
		.dump_callback = sym_elog_dump_state,
		.default_enabled = 1,
		.decode_blob = symbols_eventlog_decode_blob,
		.decode_blob_size = symbols_eventlog_decode_blob_size,
	};

	rw_init(&sym_elog_user_files_lock, "sym_elog user_files");
	sym_elog_format_kernel_build_id(sym_elog_kernel_build_id,
	    sizeof(sym_elog_kernel_build_id));

	sym_elog_provider = eventlog_provider_create("symbols", &cfg);
	sym_elog_session = eventlog_session_create(
	    sym_elog_provider, 0, true, NULL, 0);
	sym_elog_emit_kernel_info(sym_elog_session);
	/*
	 * LINKER_FILE / SYMBOL_RANGE are emitted lazily via dump_state
	 * rather than here, to keep this SYSINIT itself cheap.
	 */
}
SYSINIT(symbols_eventlog_init, SI_SUB_LAST, SI_ORDER_ANY,
    symbols_eventlog_init, NULL);
