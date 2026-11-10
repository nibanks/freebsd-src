/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

/*
 * Kernel-side producer for the "cpu" eventlog provider.
 *
 * Per-CPU eventlog_session emitting CPU_SAMPLE events from hwpmc
 * CPU_CYCLES overflows (kern.eventlog.cpu.pmchz Hz/CPU), plus CPU_INFO
 * (ncpus / hz / pmchz / freq_max_mhz) and ARM_FAILED if the sampler
 * cannot start. Sampling is armed only while a subscriber is attached.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/eventlog.h>
#include <sys/pmc_sample.h>
#include "cpufreq_if.h"

/*
 * Compile the cpu decode blob into this TU (the "cpu" provider's one
 * registration site) -- see <eventlog/tcp_eventlog.h>'s definition site in
 * tcp_subr.c for the pattern this mirrors.
 */
#define	CPU_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/cpu_eventlog.h>

static MALLOC_DEFINE(M_CPU_ELOG, "cpu_elog", "cpu eventlog provider");

struct cpu_elog_cpu_session {
	struct eventlog_session	*session;
	int			 cpu_id;
};

static struct eventlog_provider	*cpu_elog_provider;
static struct cpu_elog_cpu_session *cpu_elog_sessions;	/* indexed by cpu_id */
static int			 cpu_elog_ncpus;

/*
 * hwpmc CPU_CYCLES sampling at cpu_elog_pmchz Hz/CPU. 0 disables.
 * Armed only while a subscriber is attached and the provider default
 * is on. Default 10 Hz/CPU; bump via sysctl for targeted profiling.
 */
#define	CPU_ELOG_DEFAULT_PMCHZ	10
#define	CPU_ELOG_CF_MAX_LEVELS	64

static int		 cpu_elog_pmchz = CPU_ELOG_DEFAULT_PMCHZ;
static bool		 cpu_elog_pmc_active;
static int		 cpu_elog_arm_error;	/* last pmc_sample_start errno */
static bool		 cpu_elog_has_subscribers;
static struct mtx	 cpu_elog_arming_mtx;

static void	cpu_elog_hwpmc_sample(
		    const struct pmc_sample_info *s, void *arg);
static void	cpu_elog_dump_state(struct eventlog_provider *, void *);
static void	cpu_elog_default_changed(struct eventlog_provider *, int,
		    void *);
static void	cpu_elog_subscribers_changed(struct eventlog_provider *,
		    bool, void *);
static void	cpu_elog_emit_cpu_info(struct cpu_elog_cpu_session *pcs,
		    struct cf_level *levels);
static void	cpu_elog_emit_all_cpu_info(void);
static void	cpu_elog_emit_arm_failed(int error);
static int	cpu_elog_pmchz_sysctl(SYSCTL_HANDLER_ARGS);
static int	cpu_elog_sampler_refresh_locked(void);
static void	cpu_elog_sampler_arm(void);
static void	cpu_elog_sampler_disarm(void);

static uint16_t
cpu_elog_freq_max_mhz(int cpu, struct cf_level *levels)
{
	device_t cf_dev;
	devclass_t dc;
	int count, error, freq, i, max_mhz;

	dc = devclass_find("cpufreq");
	if (dc == NULL)
		return (0);
	cf_dev = devclass_get_device(dc, cpu);
	if (cf_dev == NULL && cpu != 0)
		cf_dev = devclass_get_device(dc, 0);
	if (cf_dev == NULL)
		return (0);
	count = CPU_ELOG_CF_MAX_LEVELS;
	error = CPUFREQ_LEVELS(cf_dev, levels, &count);
	if (error != 0 || count <= 0)
		return (0);
	max_mhz = 0;
	for (i = 0; i < count; i++) {
		freq = levels[i].total_set.freq;
		if (freq > max_mhz)
			max_mhz = freq;
	}
	if (max_mhz > 0xffff)
		max_mhz = 0xffff;
	return ((uint16_t)max_mhz);
}

static void
cpu_elog_emit_cpu_info(struct cpu_elog_cpu_session *pcs,
    struct cf_level *levels)
{

	CPU_EVENTLOG_CPU_INFO_LOG(pcs->session,
	    (uint32_t)mp_ncpus, (uint32_t)hz, (uint32_t)cpu_elog_pmchz,
	    cpu_elog_freq_max_mhz(pcs->cpu_id, levels));
}

static void
cpu_elog_emit_all_cpu_info(void)
{
	struct cf_level *levels;
	int cpu;

	levels = malloc(CPU_ELOG_CF_MAX_LEVELS * sizeof(*levels), M_TEMP,
	    M_WAITOK);
	for (cpu = 0; cpu < cpu_elog_ncpus; cpu++) {
		if (cpu_elog_sessions[cpu].session == NULL)
			continue;
		cpu_elog_emit_cpu_info(&cpu_elog_sessions[cpu], levels);
	}
	free(levels, M_TEMP);
}

static void
cpu_elog_emit_arm_failed(int error)
{
	int cpu;

	for (cpu = 0; cpu < cpu_elog_ncpus; cpu++)
		CPU_EVENTLOG_ARM_FAILED_LOG(cpu_elog_sessions[cpu].session,
		    (int32_t)error, (uint32_t)cpu_elog_pmchz);
}

/*
 * hwpmc sample callback. Runs from hardclock (PMC_FN_DO_SAMPLES);
 * must not sleep.
 */
static void
cpu_elog_hwpmc_sample(const struct pmc_sample_info *s,
    void *arg __unused)
{
	struct cpu_elog_cpu_session *pcs;
	struct pcpu *pc;
	struct thread *idle;
	uint64_t frames[CPU_EVENTLOG_CPU_SAMPLE_FRAMES_MAX];
	uint8_t flags, depth;
	uint16_t i;
	int cpu;

	cpu = (int)s->hs_cpu;
	KASSERT(cpu_elog_sessions != NULL,
	    ("cpu eventlog sample with no sessions"));
	KASSERT(cpu >= 0 && cpu < cpu_elog_ncpus,
	    ("cpu eventlog sample cpu %d ncpus %d", cpu, cpu_elog_ncpus));
	pcs = &cpu_elog_sessions[cpu];
	if (!CPU_EVENTLOG_CPU_SAMPLE_ENABLED(pcs->session))
		return;

	flags = 0;
	if ((s->hs_flags & PMC_SAMPLE_F_USERMODE) != 0)
		flags |= CPU_EVENTLOG_FLAG_USER_MODE;
	if ((s->hs_flags & PMC_SAMPLE_F_FREQ_VALID) != 0)
		flags |= CPU_EVENTLOG_FLAG_FREQ_VALID;
	if (s->hs_nframes > CPU_EVENTLOG_CPU_SAMPLE_FRAMES_MAX)
		flags |= CPU_EVENTLOG_FLAG_TRUNC;
	pc = pcpu_find((u_int)cpu);
	idle = (pc != NULL) ? pc->pc_idlethread : NULL;
	if (idle != NULL && (uint32_t)idle->td_tid == s->hs_tid)
		flags |= CPU_EVENTLOG_FLAG_IDLE;

	depth = 0;
	for (i = 0; i < s->hs_nframes &&
	    depth < CPU_EVENTLOG_CPU_SAMPLE_FRAMES_MAX; i++) {
		frames[depth++] = (uint64_t)s->hs_pc[i];
	}

	CPU_EVENTLOG_CPU_SAMPLE_LOG_ALWAYS(pcs->session, s->hs_tid,
	    s->hs_pid, CPU_EVENTLOG_SAMPLE_TYPE_HWPMC, flags, depth,
	    s->hs_freq_mhz, frames);
}

static int
cpu_elog_start_pmc_sampling(int rate_hz)
{

#if defined(__amd64__) || defined(__i386__) || defined(__aarch64__)
	return (pmc_sample_start(PMC_SAMPLE_EV_CPU_CYCLES, (uint64_t)rate_hz,
	    cpu_elog_hwpmc_sample, NULL));
#else
	(void)rate_hz;
	return (ENOTSUP);
#endif
}

static void
cpu_elog_stop_pmc_sampling(void)
{

	pmc_sample_stop();
}

static void
cpu_elog_sampler_arm(void)
{
	int error, rate_hz;

	mtx_assert(&cpu_elog_arming_mtx, MA_OWNED);

	if (cpu_elog_pmc_active)
		return;
	if (cpu_elog_pmchz <= 0)
		return;

	rate_hz = cpu_elog_pmchz;
	/*
	 * pmc_sample_start may sleep (M_WAITOK, pmc_sx, and on arm64 the
	 * cycle-freq calibration binds to each CPU). Drop the arming
	 * mutex for the duration.
	 */
	mtx_unlock(&cpu_elog_arming_mtx);
	error = cpu_elog_start_pmc_sampling(rate_hz);
	mtx_lock(&cpu_elog_arming_mtx);

	if (error != 0) {
		/*
		 * A concurrent arm may have succeeded while we were
		 * unlocked; only record the error if we are still idle.
		 */
		if (!cpu_elog_pmc_active)
			cpu_elog_arm_error = error;
		return;
	}
	/*
	 * pmc_sample_start returns EBUSY if a session is already live, so
	 * a successful return means we own the only session.
	 */
	KASSERT(!cpu_elog_pmc_active,
	    ("cpu elog PMC active after successful pmc_sample_start"));
	cpu_elog_pmc_active = true;
	cpu_elog_arm_error = 0;
	if (!cpu_elog_has_subscribers || cpu_elog_pmchz <= 0 ||
	    eventlog_provider_get_default(cpu_elog_provider) == 0) {
		cpu_elog_pmc_active = false;
		mtx_unlock(&cpu_elog_arming_mtx);
		cpu_elog_stop_pmc_sampling();
		mtx_lock(&cpu_elog_arming_mtx);
	}
}

static void
cpu_elog_sampler_disarm(void)
{

	mtx_assert(&cpu_elog_arming_mtx, MA_OWNED);

	if (!cpu_elog_pmc_active)
		return;
	cpu_elog_pmc_active = false;
	mtx_unlock(&cpu_elog_arming_mtx);
	cpu_elog_stop_pmc_sampling();
	mtx_lock(&cpu_elog_arming_mtx);
}

static int
cpu_elog_sampler_refresh_locked(void)
{
	bool want_armed;

	mtx_assert(&cpu_elog_arming_mtx, MA_OWNED);

	want_armed = cpu_elog_has_subscribers &&
	    cpu_elog_pmchz > 0 &&
	    eventlog_provider_get_default(cpu_elog_provider) != 0;

	if (want_armed && !cpu_elog_pmc_active) {
		cpu_elog_sampler_arm();
		if (!cpu_elog_pmc_active)
			return (cpu_elog_arm_error);
	} else if (!want_armed && cpu_elog_pmc_active)
		cpu_elog_sampler_disarm();
	return (0);
}

static void
cpu_elog_subscribers_changed(struct eventlog_provider *provider __unused,
    bool has_subscribers, void *arg __unused)
{
	int error;

	mtx_lock(&cpu_elog_arming_mtx);
	cpu_elog_has_subscribers = has_subscribers;
	error = cpu_elog_sampler_refresh_locked();
	mtx_unlock(&cpu_elog_arming_mtx);
	if (error != 0)
		cpu_elog_emit_arm_failed(error);
}

static int
cpu_elog_pmchz_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, new_hz;

	new_hz = cpu_elog_pmchz;
	error = sysctl_handle_int(oidp, &new_hz, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (new_hz < 0 || new_hz > 16000)
		return (EINVAL);
	if (new_hz == cpu_elog_pmchz)
		return (0);

	mtx_lock(&cpu_elog_arming_mtx);
	cpu_elog_pmchz = new_hz;
	if (cpu_elog_pmc_active)
		cpu_elog_sampler_disarm();
	error = cpu_elog_sampler_refresh_locked();
	mtx_unlock(&cpu_elog_arming_mtx);
	if (error != 0)
		cpu_elog_emit_arm_failed(error);
	return (0);
}

/* Re-evaluate PMC arming when kern.eventlog.cpu.default changes. */
static void
cpu_elog_default_changed(struct eventlog_provider *provider __unused,
    int val __unused, void *arg __unused)
{
	int error;

	mtx_lock(&cpu_elog_arming_mtx);
	error = cpu_elog_sampler_refresh_locked();
	mtx_unlock(&cpu_elog_arming_mtx);
	if (error != 0)
		cpu_elog_emit_arm_failed(error);
}

static void
cpu_elog_dump_state(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	int arm_error;

	cpu_elog_emit_all_cpu_info();

	mtx_lock(&cpu_elog_arming_mtx);
	arm_error = cpu_elog_arm_error;
	mtx_unlock(&cpu_elog_arming_mtx);
	if (arm_error != 0)
		cpu_elog_emit_arm_failed(arm_error);
}

static int
cpu_eventlog_modevent(module_t mod __unused, int what, void *arg __unused)
{
	int cpu;

	switch (what) {
	case MOD_LOAD: {
		struct eventlog_provider_config cfg = {
			.dump_callback = cpu_elog_dump_state,
			.default_changed = cpu_elog_default_changed,
			.subscribers_changed = cpu_elog_subscribers_changed,
			.default_enabled = 1,
			.decode_blob = cpu_eventlog_decode_blob,
			.decode_blob_size = cpu_eventlog_decode_blob_size,
		};

		mtx_init(&cpu_elog_arming_mtx, "cpu_elog arming",
		    NULL, MTX_DEF);

		cpu_elog_provider = eventlog_provider_create("cpu", &cfg);
		if (cpu_elog_provider == NULL) {
			mtx_destroy(&cpu_elog_arming_mtx);
			return (ENOMEM);
		}

		cpu_elog_ncpus = mp_maxid + 1;
		cpu_elog_sessions = malloc(
		    sizeof(*cpu_elog_sessions) * cpu_elog_ncpus, M_CPU_ELOG,
		    M_WAITOK | M_ZERO);
		CPU_FOREACH(cpu) {
			cpu_elog_sessions[cpu].cpu_id = cpu;
			cpu_elog_sessions[cpu].session =
			    eventlog_session_create(cpu_elog_provider,
			        (uint64_t)cpu, true, NULL, 0);
		}
		cpu_elog_emit_all_cpu_info();

		SYSCTL_ADD_PROC(
		    eventlog_provider_get_sysctl_ctx(cpu_elog_provider),
		    SYSCTL_CHILDREN(
			eventlog_provider_get_sysctl_node(cpu_elog_provider)),
		    OID_AUTO, "pmchz",
		    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
		    NULL, 0, cpu_elog_pmchz_sysctl, "I",
		    "hwpmc sampling rate (Hz/CPU); 0 disables sampling, "
		    "1..16000 arms hwpmc CPU_CYCLES at that rate");
		return (0);
	}

	case MOD_UNLOAD:
		mtx_lock(&cpu_elog_arming_mtx);
		cpu_elog_sampler_disarm();
		mtx_unlock(&cpu_elog_arming_mtx);

		for (cpu = 0; cpu < cpu_elog_ncpus; cpu++)
			eventlog_session_destroy(cpu_elog_sessions[cpu].session);
		free(cpu_elog_sessions, M_CPU_ELOG);
		cpu_elog_sessions = NULL;
		cpu_elog_ncpus = 0;

		eventlog_provider_destroy(cpu_elog_provider);
		cpu_elog_provider = NULL;
		mtx_destroy(&cpu_elog_arming_mtx);
		return (0);
	}
	return (EOPNOTSUPP);
}

static moduledata_t cpu_eventlog_mod = {
	"cpu_eventlog",
	cpu_eventlog_modevent,
	NULL
};

DECLARE_MODULE(cpu_eventlog, cpu_eventlog_mod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_VERSION(cpu_eventlog, 1);
