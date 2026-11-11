/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _SYS_PMC_SAMPLE_H_
#define _SYS_PMC_SAMPLE_H_

/*
 * In-kernel PMU sample consumer KPI for hwpmc(4): arm a system-wide
 * sampling PMC and receive callchains via callback, bypassing
 * pmcstat(8)/pmclog.  One session at a time.  The callback runs from
 * hardclock (PMC_FN_DO_SAMPLES) and must not sleep or re-enter hwpmc.
 */

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/cdefs.h>

/* Logical sampling events; hwpmc maps each to the per-arch counter. */
enum pmc_sample_event {
	PMC_SAMPLE_EV_CPU_CYCLES,	/* unhalted CPU cycles */
};

struct pmc_sample_info {
	uint32_t	hs_pid;		/* process id at sample time */
	uint32_t	hs_tid;		/* thread id at sample time */
	uint16_t	hs_cpu;		/* CPU the sample fired on */
	uint16_t	hs_nframes;	/* valid entries in hs_pc[] */
	uint32_t	hs_flags;	/* PMC_SAMPLE_F_* below */
	uint64_t	hs_tsc;		/* TSC at overflow */
	uint32_t	hs_pmc_id;	/* hwpmc PMC ID (pm->pm_id) */
	uint16_t	hs_freq_mhz;	/* eff. freq; valid iff F_FREQ_VALID */
	uint16_t	hs_reserved;	/* must be zero */
	const uintptr_t	*hs_pc;		/* valid during callback only */
};

/* hs_flags */
#define	PMC_SAMPLE_F_USERMODE	0x00000001	/* interrupted user mode */
#define	PMC_SAMPLE_F_FREQ_VALID	0x00000002	/* hs_freq_mhz is meaningful */

typedef void (*pmc_sample_cb_t)(
    const struct pmc_sample_info *sample, void *arg);

/*
 * Start a session.  For CPU_CYCLES, rate_hz is the desired samples
 * per second per CPU; hwpmc programs each CPU's overflow reload from
 * that CPU's cycle-counter frequency.  Returns EBUSY if a session is
 * running, ENOTSUP if the event/arch is unsupported, or other errno.
 */
int	pmc_sample_start(enum pmc_sample_event ev, uint64_t rate_hz,
	    pmc_sample_cb_t cb, void *arg);

/* Stop the session, drain in-flight samples, release PMCs.  No-op if idle. */
void	pmc_sample_stop(void);

#endif /* _KERNEL */

#endif /* !_SYS_PMC_SAMPLE_H_ */
