/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

/*
 * Kernel-side producer for the "process" eventlog provider.
 *
 * One global eventlog_session that carries process / thread
 * lifecycle metadata so consumers can resolve a tid observed in a
 * sample back to a process and a (process, address) pair back to a
 * user-mode binary.
 *
 * dump_state walks allproc and synthesizes PROC_EXEC + PROC_MAP +
 * PROC_TITLE for every existing process plus THREAD_CREATE for every
 * thread, so a subscriber attaching mid-flight observes the same
 * metadata as one that attached before any of these processes started.
 *
 * fork() without exec inherits the parent's address space (nginx
 * reload). Live emission is a PROC_FORK(pid, ppid) edge; consumers
 * copy the parent's PROC_MAP set onto the child. dump_state already
 * walks the child's vmspace, so a late subscriber does not need the
 * edge.
 *
 * Cross-provider contract: PROC_MAP.user_file_id is allocated by
 * eventlog_symbols_intern_user_file() (KPI in
 * <sys/eventlog_symbols.h>); the matching USER_FILE event is emitted
 * on the symbols provider's session.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/eventlog.h>
#define	PROCESS_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/process_eventlog.h>
#include <sys/eventlog_process.h>
#include <sys/eventlog_symbols.h>
#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>

static struct eventlog_provider	*proc_elog_provider;
struct eventlog_session			*proc_elog_session;

static void	proc_elog_dump_state(struct eventlog_provider *, void *);
static void	proc_elog_process_fork(void *, struct proc *, struct proc *,
		    int);

static void
proc_elog_process_fork(void *arg __unused, struct proc *p1, struct proc *p2,
    int flags __unused)
{

	if ((p2->p_flag & P_KPROC) != 0)
		return;
	PROCESS_EVENTLOG_PROC_FORK_LOG(proc_elog_session,
	    (uint32_t)p2->p_pid, (uint32_t)p1->p_pid);
}

/*
 * Walk every executable file-backed mapping in p's vmspace and emit
 * one PROC_MAP per mapping. Used both from the exec hook (p just
 * completed execve, single-threaded) and from dump_state (p is held
 * but may be running concurrently on other threads).
 *
 * Mirrors kern_proc_vmmap_out().
 */
void
proc_elog_walk_vmmap(struct eventlog_session *session, struct proc *p)
{
	struct vmspace *vm;
	vm_map_t map;
	vm_map_entry_t entry, tmp_entry;
	vm_object_t obj, tobj, lobj, nobj;
	struct vnode *vp;
	char *fullpath, *freepath;
	vm_offset_t addr;
	unsigned int last_timestamp;
	uint32_t pid;

	if (!PROCESS_EVENTLOG_PROC_MAP_ENABLED(session))
		return;
	pid = (uint32_t)p->p_pid;

	vm = vmspace_acquire_ref(p);
	if (vm == NULL)
		return;
	map = &vm->vm_map;

	vm_map_lock_read(map);
	VM_MAP_ENTRY_FOREACH(entry, map) {
		uint64_t base, size, offset;
		uint32_t user_file_id;

		if ((entry->protection & VM_PROT_EXECUTE) == 0)
			continue;
		if ((entry->eflags & MAP_ENTRY_IS_SUB_MAP) != 0)
			continue;
		obj = entry->object.vm_object;
		if (obj == NULL)
			continue;

		/* Lock the whole shadow chain, then find its leaf's vnode. */
		lobj = NULL;
		for (tobj = obj; tobj != NULL; tobj = tobj->backing_object) {
			VM_OBJECT_RLOCK(tobj);
			lobj = tobj;
		}
		vp = NULL;
		if (lobj != NULL) {
			(void)vm_object_kvme_type(lobj, &vp);
			if (vp != NULL)
				vref(vp);
		}
		/* Unlock the chain, saving each backing_object before unlock. */
		for (tobj = obj; tobj != NULL; tobj = nobj) {
			nobj = tobj->backing_object;
			VM_OBJECT_RUNLOCK(tobj);
		}

		base = entry->start;
		size = entry->end - entry->start;
		offset = entry->offset;
		addr = entry->end;
		last_timestamp = map->timestamp;

		vm_map_unlock_read(map);

		fullpath = "";
		freepath = NULL;
		if (vp != NULL &&
		    vn_fullpath(vp, &fullpath, &freepath) != 0) {
			fullpath = "";
			freepath = NULL;
		}
		user_file_id = 0;
		(void)eventlog_symbols_intern_user_file(vp, fullpath,
		    &user_file_id);
		if (vp != NULL)
			vrele(vp);

		PROCESS_EVENTLOG_PROC_MAP_LOG_ALWAYS(session, pid, user_file_id,
		    base, size, offset);

		free(freepath, M_TEMP);

		vm_map_lock_read(map);
		if (last_timestamp != map->timestamp) {
			/*
			 * The map mutated while unlocked. `entry' may
			 * be on a freelist now -- re-position to the
			 * entry containing the last address we saw and
			 * let VM_MAP_ENTRY_FOREACH advance from there.
			 */
			vm_map_lookup_entry(map, addr - 1, &tmp_entry);
			entry = tmp_entry;
		}
	}
	vm_map_unlock_read(map);
	vmspace_free(vm);
}

static void
proc_elog_dump_state(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	struct proc *p, **snap;
	struct thread *td;
	u_int count, i, n;

	/*
	 * PROC_MAP emission does real vnode I/O per mapping
	 * (vn_lock/VOP_GETATTR/vn_fullpath in proc_elog_walk_vmmap()),
	 * which can block on a contended vnode for an unbounded time.
	 * Snapshot PHOLD'd procs under allproc_lock, then drop the lock
	 * before touching any of them, so a slow vnode only stalls this
	 * dump instead of also blocking every fork()/exit()/wait4() in
	 * the system behind a shared allproc_lock hold.
	 */
	count = nprocs + 16;
	snap = malloc(count * sizeof(*snap), M_TEMP, M_WAITOK);
	n = 0;
	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		if (n >= count)
			break;	/* grew past the estimate; catch it next dump */
		PROC_LOCK(p);
		if (p->p_state == PRS_NEW || (p->p_flag & P_WEXIT) != 0) {
			PROC_UNLOCK(p);
			continue;
		}
		_PHOLD(p);
		PROC_UNLOCK(p);
		snap[n++] = p;
	}
	sx_sunlock(&allproc_lock);

	for (i = 0; i < n; i++) {
		struct pargs *pa;
		char title[sizeof(((struct process_eventlog_proc_title *)0)->title)];
		u_int ntitle;

		p = snap[i];
		PROCESS_EVENTLOG_PROC_EXEC_LOG(proc_elog_session,
		    (uint32_t)p->p_pid,
		    (p->p_pptr != NULL) ? (uint32_t)p->p_pptr->p_pid : 0,
		    (p->p_stats != NULL) ?
		    (uint64_t)p->p_stats->p_start.tv_sec : 0, p->p_comm);
		proc_elog_walk_vmmap(proc_elog_session, p);

		title[0] = '\0';
		PROC_LOCK(p);
		pa = p->p_args;
		if (pa != NULL && pa->ar_length > 0) {
			ntitle = pa->ar_length;
			if (ntitle >= sizeof(title))
				ntitle = sizeof(title) - 1;
			memcpy(title, pa->ar_args, ntitle);
			title[ntitle] = '\0';
		}
		_PRELE(p);
		PROC_UNLOCK(p);
		if (title[0] != '\0')
			PROCESS_EVENTLOG_PROC_TITLE_LOG(proc_elog_session,
			    (uint32_t)p->p_pid, title);
	}
	free(snap, M_TEMP);

	/* THREAD_CREATE has no vnode I/O, so this pass keeps the plain
	 * lock-held walk. */
	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		PROC_LOCK(p);
		if (p->p_state == PRS_NEW || (p->p_flag & P_WEXIT) != 0) {
			PROC_UNLOCK(p);
			continue;
		}
		FOREACH_THREAD_IN_PROC(p, td) {
			PROCESS_EVENTLOG_THREAD_CREATE_LOG(proc_elog_session,
			    (uint32_t)td->td_tid, (uint32_t)p->p_pid,
			    p->p_comm, td->td_name);
		}
		PROC_UNLOCK(p);
	}
	sx_sunlock(&allproc_lock);
}

/*
 * Provider lifecycle. Runs once at boot; the provider and session
 * live for the rest of the kernel's uptime, same as kern_eventlog.c's
 * own state (see if_eventlog_init() for the pattern this mirrors).
 */
static void
process_eventlog_init(void *unused __unused)
{
	struct eventlog_provider_config cfg = {
		.dump_callback = proc_elog_dump_state,
		.default_enabled = 1,
		.decode_blob = process_eventlog_decode_blob,
		.decode_blob_size = process_eventlog_decode_blob_size,
	};

	proc_elog_provider = eventlog_provider_create("process", &cfg);
	proc_elog_session = eventlog_session_create(proc_elog_provider,
	    0, true, NULL, 0);

	EVENTHANDLER_REGISTER(process_fork, proc_elog_process_fork, NULL,
	    EVENTHANDLER_PRI_ANY);
}
SYSINIT(process_eventlog_init, SI_SUB_LAST, SI_ORDER_ANY,
    process_eventlog_init, NULL);
