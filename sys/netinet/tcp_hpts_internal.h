/*-
 * Copyright (c) 2025 Netflix, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __tcp_hpts_internal_h__
#define __tcp_hpts_internal_h__

/*
 * TCP High Precision Timer System (HPTS) - Internal Definitions
 *
 * This header contains internal structures, constants, and interfaces that are
 * implemented in tcp_hpts.c but exposed to enable comprehensive unit testing of
 * the HPTS subsystem.
 */

#if defined(_KERNEL)

/*
 * The HPTS slot duration and wheel size are computed at module load time.
 * The slot duration defaults to 64 microseconds per slot, and the total
 * wheel time defaults to 1.048576 seconds (1048576 microseconds). Both values
 * can be tuned at runtime via loader tunables (which requires a reboot to take
 * effect). The values are restricted to powers of two to avoid multiplication
 * and division operations.
 *
 * If the connection requests a timeout longer than the wheel can accommodate,
 * a remainder is stored and the HPTS will re-insert the inpcb with the
 * remaining time when the wheel completes its current cycle.
 */

/* Defaults and limits */
#define HPTS_DEFAULT_TOTAL_SLOT_TIME 0x100000U /* 1,048,576 microseconds */
#define HPTS_MAX_TOTAL_SLOT_TIME 0x4000000U    /* 67,108,864 microseconds */
#define HPTS_MIN_TOTAL_SLOTS 2U
#define HPTS_DEFAULT_USECS_PER_SLOT 64U
#define HPTS_MAX_USECS_PER_SLOT 0x10000U       /* 65,536 microseconds */

/* Total time covered by all HPTS slots in microseconds (power of two) */
extern uint32_t hpts_total_slot_time;
/* Effective microseconds per slot (power-of-two) */
extern uint32_t hpts_usecs_per_slot;
/* log2(hpts_usecs_per_slot) for fast division */
extern uint32_t hpts_usecs_per_slot_shift;
/* Total slots on the wheel (power-of-two) */
extern uint32_t hpts_num_slots;
/* hpts_num_slots - 1, used for fast modulo */
extern uint32_t hpts_wheel_mask;

/* Convert microseconds to HPTS slots */
static inline uint32_t hpts_usec_to_slots(uint32_t usec)
{
	return ((usec + (hpts_usecs_per_slot - 1)) >> hpts_usecs_per_slot_shift);
}

/* Convert HPTS slots to microseconds */
static inline uint32_t hpts_slots_to_usec(uint32_t slots)
{
	return (slots << hpts_usecs_per_slot_shift);
}

/* Map absolute microseconds to the wheel position */
static inline uint32_t hpts_usecs_to_wheel(uint32_t usec)
{
	return ((usec >> hpts_usecs_per_slot_shift) & hpts_wheel_mask);
}

/* Add slots to a wheel position (wrap via mask) */
static inline uint32_t hpts_wheel_add(uint32_t wheel_slot, uint32_t plus)
{
	return ((wheel_slot + plus) & hpts_wheel_mask);
}

/* Check if two timestamps are in different slots */
static inline bool hpts_different_slots(uint32_t a, uint32_t b)
{
	return ((a >> hpts_usecs_per_slot_shift) != (b >> hpts_usecs_per_slot_shift));
}

/* The number of connections after which the dynamic sleep logic kicks in. */
#define DEFAULT_CONNECTION_THRESHOLD 100

extern int tcp_bind_threads; 		/* Thread binding configuration
					 * (0=none, 1=cpu, 2=numa) */

/*
 * Abstraction layer controlling time, interrupts and callouts.
 */
struct tcp_hptsi_funcs {
	void (*binuptime)(struct bintime *bt);
	int (*swi_add)(struct intr_event **eventp, const char *name,
		driver_intr_t handler, void *arg, int pri, enum intr_type flags,
		void **cookiep);
	int (*swi_remove)(void *cookie);
	void (*swi_sched)(void *cookie, int flags);
	int (*intr_event_bind)(struct intr_event *ie, int cpu);
	int (*intr_event_bind_ithread_cpuset)(struct intr_event *ie,
		struct _cpuset *mask);
	void (*callout_init)(struct callout *c, int mpsafe);
	int (*callout_reset_sbt_on)(struct callout *c, sbintime_t sbt,
		sbintime_t precision, void (*func)(void *), void *arg, int cpu,
		int flags);
	int (*_callout_stop_safe)(struct callout *c, int flags);
};

/* Default function table for system operation */
extern const struct tcp_hptsi_funcs tcp_hptsi_default_funcs;

#define HPTS_HISTOGRAM_BUCKETS 16

/* Histogram for tracking various metrics */
struct hpts_histogram {
	uint64_t buckets[HPTS_HISTOGRAM_BUCKETS];
};

/* Increment the 'log2 of the value' bucket by one */
static inline void hpts_hist_exp_inc(struct hpts_histogram *hist,
	uint64_t value) {
	uint32_t bucket = flsll(value);
	if (__predict_false(bucket >= HPTS_HISTOGRAM_BUCKETS))
		bucket = HPTS_HISTOGRAM_BUCKETS - 1;
	hist->buckets[bucket]++;
}
/* Increment the linear bucket by one */
static inline void hpts_hist_linear_inc(struct hpts_histogram *hist,
	uint64_t value) {
	if (__predict_false(value >= HPTS_HISTOGRAM_BUCKETS))
		value = HPTS_HISTOGRAM_BUCKETS - 1;
	hist->buckets[value]++;
}

/* Each hpts has its own p_mtx which is used for locking */
#define	HPTS_MTX_ASSERT(hpts)	mtx_assert(&(hpts)->p_mtx, MA_OWNED)
#define	HPTS_LOCK(hpts)		mtx_lock(&(hpts)->p_mtx)
#define	HPTS_TRYLOCK(hpts)	mtx_trylock(&(hpts)->p_mtx)
#define	HPTS_UNLOCK(hpts)	mtx_unlock(&(hpts)->p_mtx)

struct tcp_hpts_entry {
	/* Cache line 0x00 */
	struct mtx p_mtx;		/* Mutex for hpts */
	uint32_t p_mysleep_usec;	/* Our min sleep time in microseconds */
	uint64_t syscall_cnt;
	uint64_t sleeping;		/* What the actual sleep was (if sleeping) */
	uint16_t p_hpts_active; 	/* Flag that says hpts is awake  */
	uint8_t p_wheel_complete; 	/* have we completed the wheel arc walk? */
	uint32_t p_runningslot; 	/* Current slot we are at if we are running */
	uint32_t p_prev_slot;		/* Previous slot we were on */
	uint32_t p_cur_slot;		/* Current slot in wheel hpts is draining */
	uint32_t p_nxt_slot;		/* The next slot outside the current range
					 * of slots that the hpts is running on. */
	uint32_t p_tp_cur_count;	/* Current number of TCP connections queued */
	uint32_t p_tp_max_count;	/* Maximum number of TCP connections ever queued simultaneously */
	uint64_t p_tp_insert_count;	/* Total number of TCP connections ever inserted */
	uint64_t p_tp_remove_count;	/* Total number of TCP connections ever removed */
	uint64_t p_tp_move_count;	/* Total number of TCP connections ever moved */
	uint64_t p_num_process_callout;	/* Number of times processed via callout path */
	uint64_t p_num_process_oppor;	/* Number of times processed via opportunistic path */
	uint64_t p_num_process_oppor_noop;/* Number of times opportunistic processing did nothing */
	uint64_t p_long_timers_count;	/* Number of timers > 1 second inserted */
	uint8_t p_direct_wake :1, 	/* boolean */
		p_on_min_sleep:1, 	/* boolean */
		p_hpts_wake_scheduled:1,/* boolean */
		hit_callout_thresh:1,
		p_avail:4;
	uint8_t p_fill[3];		/* Fill to 32 bits */
	/* Cache line 0x40 */
	struct hptsh {
		TAILQ_HEAD(, tcpcb)	head;
		uint32_t		count;
		uint32_t		gencnt;
	} *p_hptss;			/* Hptsi wheel */
	uint32_t p_hpts_sleep_time;	/* Current sleep interval in microseconds */
	uint32_t overidden_sleep;	/* what was overrided by min-sleep for logging */
	uint32_t saved_curslot;		/* for logging */
	uint32_t saved_prev_slot;	/* for logging */
	uint32_t p_delayed_by;		/* How much were we delayed by */
	/* Cache line 0x80 */
	struct sysctl_ctx_list hpts_ctx;
	struct sysctl_oid *hpts_root;
	struct hpts_histogram hist_lateness;		/* process_time - expiry_time */
	struct hpts_histogram hist_lateness_usec;	/* lateness in microseconds */
	struct hpts_histogram hist_tp_batch_size;	/* number of connections processed per loop */
	struct hpts_histogram hist_slot_batch_size;	/* number of slots processed per call */
	struct hpts_histogram hist_run_time_callout;	/* runtime for callout-triggered processing */
	struct hpts_histogram hist_run_time_oppor;	/* runtime for opportunistic processing */
	struct hpts_histogram hist_insert_slots;	/* slots requested for timer insertions */
	struct hpts_histogram hist_per_tp_time;		/* average processing time per connection */
	struct hpts_histogram hist_processing_loops;	/* number of processing loops per tcp_hptsi call */
	struct intr_event *ie;
	void *ie_cookie;
	uint16_t p_cpu;			/* The hpts CPU */
	struct tcp_hptsi *p_hptsi;	/* Back pointer to parent hptsi structure */
	/* There is extra space in here */
	/* Cache line 0x100 */
	struct callout co __aligned(CACHE_LINE_SIZE);
}               __aligned(CACHE_LINE_SIZE);

struct tcp_hptsi {
	struct cpu_group **grps;
	struct tcp_hpts_entry **rp_ent;	/* Array of hptss */
	uint32_t *cts_last_ran;
	uint32_t grp_cnt;
	uint32_t rp_num_hptss;		/* Number of hpts threads */
	struct hpts_domain_info {
		int count;
		int cpu[MAXCPU];
	} domains[MAXMEMDOM];		/* Per-NUMA domain CPU assignments */
	const struct tcp_hptsi_funcs *funcs;	/* Function table for testability */
};

/*
 * Core tcp_hptsi structure manipulation functions.
 */
struct tcp_hptsi* tcp_hptsi_create(const struct tcp_hptsi_funcs *funcs,
	bool enable_sysctl);
void tcp_hptsi_destroy(struct tcp_hptsi *pace);
void tcp_hptsi_start(struct tcp_hptsi *pace);
void tcp_hptsi_stop(struct tcp_hptsi *pace);
uint16_t tcp_hptsi_random_cpu(struct tcp_hptsi *pace);
uint32_t tcp_hptsi(struct tcp_hpts_entry *hpts, bool from_callout);

void tcp_hpts_wake(struct tcp_hpts_entry *hpts);

/*
 * LRO HPTS initialization and uninitialization, only for internal use by the
 * HPTS code.
 */
void tcp_lro_hpts_init(void);
void tcp_lro_hpts_uninit(void);

#endif /* defined(_KERNEL) */
#endif /* __tcp_hpts_internal_h__ */
