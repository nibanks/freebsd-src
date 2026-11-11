/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

/*
 * In-kernel PMU sample consumer support (see sys/pmc_sample.h).  Reuses
 * the normal hwpmc sample path with a synthetic PMC_PO_KERNEL_SAMPLER
 * owner whose samples are diverted to pmc_sampler_deliver().
 * Supported on amd64/i386/arm64 via pmc_md_resolve_sample_event().
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/domainset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/cpu.h>
#include <sys/pmc.h>
#include <sys/pmckern.h>
#include <sys/pmc_sample.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/smp.h>
#include <sys/sx.h>

#include <machine/pmc_mdep.h>
#if defined(__amd64__) || defined(__i386__)
#include <machine/clock.h>	/* tsc_freq */
#endif

/* Per-session state. Guarded by pmc_sx for start/stop, none for delivery. */
static struct pmc_owner	*pmc_sampler_po;	/* synthetic kernel owner */
static struct pmc	**pmc_sampler_pmcs;	/* indexed by cpu id */
static int		  pmc_sampler_ncpus;	/* size of pmc_sampler_pmcs */
static pmc_sample_cb_t	  pmc_sampler_cb;
static void		 *pmc_sampler_cb_arg;

static int	pmc_sampler_alloc_pmc_on_cpu(int cpu, enum pmc_sample_event ev,
		    uint64_t reload);
static void	pmc_sampler_release_pmc(int cpu);

/*
 * Synthesise the pmc_op_pmcallocate that pcd_allocate_pmc() expects,
 * mirroring libpmc(3) but with a fixed event set.  The class and
 * pm_md config come from the per-vendor pmc_md_resolve_sample_event().
 */
static int
pmc_sampler_build_pa(struct pmc_op_pmcallocate *pa, enum pmc_sample_event ev,
    uint64_t reload, int cpu)
{
	int error;

	bzero(pa, sizeof(*pa));
	error = pmc_md_resolve_sample_event(ev, pa);
	if (error != 0)
		return (error);
	pa->pm_mode = PMC_MODE_SS;
	pa->pm_cpu = cpu;
	pa->pm_count = reload;
	pa->pm_caps = PMC_CAP_INTERRUPT | PMC_CAP_SYSTEM | PMC_CAP_USER;
	pa->pm_flags = PMC_F_CALLCHAIN | PMC_F_USERCALLCHAIN | PMC_F_EV_PMU;
	return (0);
}

/*
 * Allocate, configure, and start one system-mode sampling PMC on the
 * given CPU.  pmc_sx must be held exclusive.
 */
static int
pmc_sampler_alloc_pmc_on_cpu(int cpu, enum pmc_sample_event ev,
    uint64_t reload)
{
	struct pmc *pmc;
	struct pmc_op_pmcallocate pa;
	struct pmc_classdep *pcd;
	struct pmc_binding pb;
	struct pmc_hw *phw;
	int adjri, error, n;

	sx_assert(&pmc_sx, SX_XLOCKED);

	error = pmc_sampler_build_pa(&pa, ev, reload, cpu);
	if (error != 0)
		return (error);

	if (!pmc_cpu_is_active(cpu))
		return (ENXIO);

	pcd = pmc_class_to_classdep(pa.pm_class);
	if (pcd == NULL)
		return (ENXIO);

	pmc = pmc_allocate_pmc_descriptor();
	pmc->pm_id = PMC_ID_MAKE_ID(cpu, PMC_MODE_SS, pa.pm_class,
	    PMC_ID_INVALID);
	pmc->pm_event = 0;	/* filled in by the allocator for IAF/IAP */
	pmc->pm_state = PMC_STATE_FREE;
	pmc->pm_caps = PMC_CAP_INTERRUPT | PMC_CAP_SYSTEM | PMC_CAP_USER;
	pmc->pm_flags = PMC_F_CALLCHAIN | PMC_F_USERCALLCHAIN | PMC_F_EV_PMU;
	pmc->pm_sc.pm_reloadcount = MAX(MAX(1, pmc_mincount), reload);

	/* Find a free row within the requested class. */
	pmc_save_cpu_binding(&pb);
	pmc_select_cpu(cpu);
	for (n = pcd->pcd_ri; n < md->pmd_npmc; n++) {
		struct pmc_classdep *pcd_n;

		pcd_n = pmc_ri_to_classdep(md, n, &adjri);
		if (pcd_n != pcd)
			continue;
		if (!pmc_can_allocate_row(n, PMC_MODE_SS))
			continue;
		if (pmc_pcpu[cpu]->pc_hwpmcs[n]->phw_pmc != NULL)
			continue;	/* already in use */

		if (pcd_n->pcd_allocate_pmc(cpu, adjri, pmc, &pa) == 0)
			break;
	}
	if (n == md->pmd_npmc) {
		pmc_restore_cpu_binding(&pb);
		pmc_destroy_pmc_descriptor(pmc);
		return (ENOMEM);
	}

	pmc->pm_id = PMC_ID_MAKE_ID(cpu, PMC_MODE_SS, pa.pm_class, n);

	/* Configure the PMC into the hardware row. */
	phw = pmc_pcpu[cpu]->pc_hwpmcs[n];
	if ((phw->phw_state & PMC_PHW_FLAG_IS_ENABLED) == 0) {
		error = ENXIO;
		goto release;
	}
	pcd = pmc_ri_to_classdep(md, n, &adjri);
	error = pcd->pcd_config_pmc(cpu, adjri, pmc);
	if (error != 0)
		goto release;

	pmc->pm_state = PMC_STATE_ALLOCATED;
	pmc->pm_class = pa.pm_class;
	pmc_mark_row_standalone(n);

	/* Link into synthetic owner. */
	KASSERT(pmc_sampler_po != NULL,
	    ("[pmc,%d] kernel sampler owner not set", __LINE__));
	pmc->pm_owner = pmc_sampler_po;
	LIST_INSERT_HEAD(&pmc_sampler_po->po_pmcs, pmc, pm_next);

	/*
	 * pmc_start() does the write+arm+start dance and the po_sscount
	 * bookkeeping; it manages its own CPU binding, so restore ours first.
	 */
	pmc_restore_cpu_binding(&pb);
	error = pmc_start(pmc);
	if (error != 0) {
		/* pmc_start() doesn't roll back po_sscount on failure. */
		pmc_sampler_po->po_sscount--;
		if (pmc_sampler_po->po_sscount == 0) {
			atomic_subtract_rel_int(&pmc_ss_count, 1);
			pmc_ss_owner_unlink(pmc_sampler_po);
			epoch_wait_preempt(global_epoch_preempt);
		}
		pmc->pm_state = PMC_STATE_STOPPED;
		goto release;
	}

	pmc_sampler_pmcs[cpu] = pmc;
	return (0);

release:
	pmc_restore_cpu_binding(&pb);
	if (pmc->pm_owner != NULL) {
		LIST_REMOVE(pmc, pm_next);
		pmc->pm_owner = NULL;
	}
	(void)pcd->pcd_release_pmc(cpu, adjri, pmc);
	if (pmc->pm_state == PMC_STATE_ALLOCATED ||
	    pmc->pm_state == PMC_STATE_STOPPED)
		pmc_unmark_row_standalone(n);
	pmc->pm_state = PMC_STATE_DELETED;
	pmc_destroy_pmc_descriptor(pmc);
	return (error);
}

/*
 * Stop and release the per-CPU PMC previously allocated by
 * pmc_sampler_alloc_pmc_on_cpu().  pmc_sx must be held exclusive.
 */
static void
pmc_sampler_release_pmc(int cpu)
{
	struct pmc *pmc;
	struct pmc_classdep *pcd;
	struct pmc_binding pb;
	int adjri, ri;

	sx_assert(&pmc_sx, SX_XLOCKED);

	pmc = pmc_sampler_pmcs[cpu];
	if (pmc == NULL)
		return;
	pmc_sampler_pmcs[cpu] = NULL;

	ri = PMC_TO_ROWINDEX(pmc);
	pcd = pmc_ri_to_classdep(md, ri, &adjri);

	/*
	 * pmc_sampler_pmcs[cpu] is only set after a successful pmc_start(),
	 * so this PMC is always running.  pmc_stop() stops the hardware,
	 * drops the po_sscount refcount, and manages its own CPU binding.
	 */
	(void)pmc_stop(pmc);

	/* Deconfigure the row. */
	pmc_save_cpu_binding(&pb);
	pmc_select_cpu(cpu);
	critical_enter();
	(void)pcd->pcd_config_pmc(cpu, adjri, NULL);
	critical_exit();
	pmc->pm_state = PMC_STATE_DELETED;
	pmc_restore_cpu_binding(&pb);

	/* Drain any in-flight samples that still reference this PMC. */
	pmc_wait_for_pmc_idle(pmc);

	/* Release hardware and free descriptor. */
	(void)pcd->pcd_release_pmc(cpu, adjri, pmc);
	pmc_unmark_row_standalone(ri);
	if (pmc->pm_owner != NULL) {
		LIST_REMOVE(pmc, pm_next);
		pmc->pm_owner = NULL;
	}
	pmc_destroy_pmc_descriptor(pmc);
}

/*
 * Deliver one sample to the registered callback.  Called from
 * pmc_process_samples() in hardclock context.
 */
void
pmc_sampler_deliver(struct pmc *pm, struct pmc_sample *ps)
{
	struct pmc_sample_info s;

	if (__predict_false(pmc_sampler_cb == NULL))
		return;	/* raced with stop */

	bzero(&s, sizeof(s));
	s.hs_pid = ps->ps_pid;
	s.hs_tid = ps->ps_tid;
	s.hs_cpu = (uint16_t)ps->ps_cpu;
	s.hs_nframes = (uint16_t)MIN(ps->ps_nsamples, UINT16_MAX);
	if ((ps->ps_flags & PMC_CC_F_USERSPACE) != 0)
		s.hs_flags |= PMC_SAMPLE_F_USERMODE;
	s.hs_tsc = ps->ps_tsc;
	s.hs_pmc_id = pm->pm_id;
	s.hs_freq_mhz = ps->ps_freq_mhz;
	if (ps->ps_freq_valid)
		s.hs_flags |= PMC_SAMPLE_F_FREQ_VALID;
	s.hs_pc = (const uintptr_t *)ps->ps_pc;
	pmc_sampler_cb(&s, pmc_sampler_cb_arg);
}

/* Cycles-PMC overflow count for rate_hz on this CPU. */
static int
pmc_sampler_cycles_reload(int cpu, uint64_t rate_hz, uint64_t *reload)
{

#if defined(__amd64__) || defined(__i386__)
	(void)cpu;
	if (tsc_freq == 0)
		return (ENXIO);
	*reload = tsc_freq / rate_hz;
#elif defined(__aarch64__)
	uint64_t freq;
	int error;

	error = cpu_est_clockrate(cpu, &freq);
	if (error != 0 || freq == 0) {
		error = pmc_md_estimate_cycle_freq(cpu, &freq);
		if (error != 0)
			return (error);
	}
	*reload = freq / rate_hz;
#else
	(void)cpu;
	(void)rate_hz;
	(void)reload;
	return (ENOTSUP);
#endif
	if (*reload == 0)
		return (EINVAL);
	return (0);
}

/* Start a system-wide kernel PMU sampling session. */
int
pmc_sample_start(enum pmc_sample_event ev, uint64_t rate_hz,
    pmc_sample_cb_t cb, void *arg)
{
	struct pmc_owner *po;
	uint64_t reload;
	int cpu, error;

	if (cb == NULL || rate_hz == 0)
		return (EINVAL);

	sx_xlock(&pmc_sx);
	if (pmc_sampler_po != NULL) {
		sx_xunlock(&pmc_sx);
		return (EBUSY);
	}

	/* Synthesise a kernel owner. */
	po = malloc(sizeof(*po), M_PMC, M_WAITOK | M_ZERO);
	po->po_owner = &proc0;
	/*
	 * No logfile, so pre-mark the process/kernel-mapping logging that
	 * pmc_start() would otherwise do as already done; skips walking
	 * every process to log into a pmclog buffer nothing ever drains.
	 */
	po->po_flags = PMC_PO_KERNEL_SAMPLER | PMC_PO_INITIAL_MAPPINGS_DONE;
	po->po_logprocmaps = 1;
	LIST_INIT(&po->po_pmcs);
	TAILQ_INIT(&po->po_logbuffers);
	mtx_init(&po->po_mtx, "pmc-owner-mtx", "pmc-sampler", MTX_SPIN);
	pmc_sampler_po = po;

	pmc_sampler_ncpus = mp_maxid + 1;
	pmc_sampler_pmcs = malloc(sizeof(*pmc_sampler_pmcs) *
	    pmc_sampler_ncpus, M_PMC, M_WAITOK | M_ZERO);

	/* Publish the callback before any PMC starts running. */
	pmc_sampler_cb = cb;
	pmc_sampler_cb_arg = arg;

	/* Allocate and start a PMC on every online CPU. */
	error = 0;
	CPU_FOREACH(cpu) {
		if (cpu >= pmc_sampler_ncpus)
			continue;
		error = pmc_sampler_cycles_reload(cpu, rate_hz, &reload);
		if (error != 0)
			break;
		error = pmc_sampler_alloc_pmc_on_cpu(cpu, ev, reload);
		if (error != 0)
			break;
	}

	if (error != 0) {
		/* Roll back: release everything we started. */
		CPU_FOREACH(cpu) {
			if (cpu < pmc_sampler_ncpus)
				pmc_sampler_release_pmc(cpu);
		}
		pmc_sampler_cb = NULL;
		pmc_sampler_cb_arg = NULL;
		free(pmc_sampler_pmcs, M_PMC);
		pmc_sampler_pmcs = NULL;
		pmc_sampler_ncpus = 0;
		mtx_destroy(&pmc_sampler_po->po_mtx);
		free(pmc_sampler_po, M_PMC);
		pmc_sampler_po = NULL;
		sx_xunlock(&pmc_sx);
		return (error);
	}

	sx_xunlock(&pmc_sx);
	return (0);
}

/*
 * Stop the active session, drain in-flight samples, release per-CPU PMCs.
 */
void
pmc_sample_stop(void)
{
	int cpu;

	sx_xlock(&pmc_sx);
	if (pmc_sampler_po == NULL) {
		sx_xunlock(&pmc_sx);
		return;
	}

	/* Stop and release each per-CPU PMC. */
	CPU_FOREACH(cpu) {
		if (cpu < pmc_sampler_ncpus)
			pmc_sampler_release_pmc(cpu);
	}

	/* Clear cb only after PMCs are stopped and samples drained. */
	pmc_sampler_cb = NULL;
	pmc_sampler_cb_arg = NULL;

	free(pmc_sampler_pmcs, M_PMC);
	pmc_sampler_pmcs = NULL;
	pmc_sampler_ncpus = 0;
	mtx_destroy(&pmc_sampler_po->po_mtx);
	free(pmc_sampler_po, M_PMC);
	pmc_sampler_po = NULL;

	sx_xunlock(&pmc_sx);
}
