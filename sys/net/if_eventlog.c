/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Kernel-side producer for the "if" eventlog provider.
 *
 * Lifecycle, link-state, configuration, and address events are
 * emitted from the existing ifnet code paths the moment they
 * happen.  Most are hooked via the existing eventhandler(9)
 * declarations in <net/if_var.h>; the configuration changes
 * (FLAGS / MTU / CAPABILITIES) lack a kernel eventhandler today
 * and are reached via direct entry points that ifhwioctl() calls.
 *
 * One eventlog session per VNET; the per-VNET session owns every
 * event for ifnets in that VNET so subscribers see a coherent
 * per-VNET view.
 *
 * The provider is gated by the framework's _ENABLED() macro: when
 * no subscriber matches the event's keyword, emission is a single
 * load-and-branch and never touches the malloc/copy path.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/ck.h>
#include <sys/epoch.h>
#include <sys/eventhandler.h>
#include <sys/eventlog.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_eventlog.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/vnet.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif
#ifdef INET6
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#endif

/*
 * Compile the if decode blob into this TU (the "if" provider's one
 * registration site) -- see <eventlog/tcp_eventlog.h>'s definition site in
 * tcp_subr.c for the pattern this mirrors.
 */
#define	IF_EVENTLOG_DEFINE_DECODE_BLOB
#include <eventlog/if_eventlog.h>

/*
 * Provider is global; sessions are per-VNET.  Provider exists for
 * the life of the kernel; sessions come and go with VNETs.
 */
static struct eventlog_provider	*if_eventlog_provider;

VNET_DEFINE_STATIC(struct eventlog_session *, if_eventlog_session);
#define	V_if_eventlog_session		VNET(if_eventlog_session)

/* Eventhandler tags so we can deregister in the (unlikely) module-unload path. */
static eventhandler_tag	if_eventlog_attached_tag;
static eventhandler_tag	if_eventlog_lladdr_tag;
static eventhandler_tag	if_eventlog_departure_tag;
static eventhandler_tag	if_eventlog_rename_tag;
static eventhandler_tag	if_eventlog_link_tag;
static eventhandler_tag	if_eventlog_addr_tag;

/*
 * Periodic sampler.  One global callout walks every VNET; each
 * VNET has its own session and emits IF_SAMPLE_BYTES/IF_SAMPLE_PACKETS
 * for the ifnets it owns.  Armed only when the provider has at least
 * one subscriber (subscribers_changed callback) so the sampler costs
 * nothing when no consumer is listening.
 */
static struct callout		if_eventlog_sample_callout;
static struct mtx		if_eventlog_sample_mtx;
static bool			if_eventlog_sampler_armed;
static uint32_t			if_eventlog_sample_period_us = 500000;	/* 2 Hz */

#define	IF_EVENTLOG_SAMPLE_PERIOD_US_MIN	1000		/* 1 ms */
#define	IF_EVENTLOG_SAMPLE_PERIOD_US_MAX	1800000000U	/* 30 min (uint32 wrap safety) */

/*
 * Resolve a sockaddr to the wire bytes for the IF_ADDR varlen
 * tail.  IPv4 produces 4 bytes, IPv6 produces 16; the caller
 * passes a 16-byte buffer.  Returns the address family on success
 * (writing the address bytes and the byte count), or 0 if the
 * sockaddr's family is unsupported.
 */
static uint16_t
if_eventlog_extract_addr(const struct sockaddr *sa, uint8_t addr[16],
    uint8_t *addr_len)
{
	*addr_len = 0;

	if (sa == NULL)
		return (0);

	switch (sa->sa_family) {
#ifdef INET
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		memcpy(addr, &sin->sin_addr, sizeof(sin->sin_addr));
		*addr_len = sizeof(sin->sin_addr);
		return (AF_INET);
	}
#endif
#ifdef INET6
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 =
		    (const struct sockaddr_in6 *)sa;
		memcpy(addr, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
		*addr_len = sizeof(sin6->sin6_addr);
		return (AF_INET6);
	}
#endif
	default:
		return (0);
	}
}

/*
 * Convert a netmask sockaddr to a prefix length in bits.  Walks the
 * mask bytes looking for the first zero bit.  Returns 0 if the mask
 * is NULL or its family is unsupported.
 */
static uint8_t
if_eventlog_masklen(const struct sockaddr *mask)
{
	const uint8_t *m;
	size_t mlen, off;
	uint8_t prefixlen = 0;

	if (mask == NULL)
		return (0);

	switch (mask->sa_family) {
#ifdef INET
	case AF_INET:
		m = (const uint8_t *)&((const struct sockaddr_in *)mask)->sin_addr;
		mlen = sizeof(struct in_addr);
		off = 0;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		m = (const uint8_t *)&((const struct sockaddr_in6 *)mask)->sin6_addr;
		mlen = sizeof(struct in6_addr);
		off = 0;
		break;
#endif
	default:
		return (0);
	}

	for (; off < mlen; off++) {
		uint8_t b = m[off];
		if (b == 0xff) {
			prefixlen += 8;
			continue;
		}
		while (b & 0x80) {
			prefixlen++;
			b <<= 1;
		}
		break;
	}
	return (prefixlen);
}

/*
 * Look up the link-layer address from an ifnet's primary AF_LINK
 * ifaddr.  Returns the length and copies up to maxlen bytes into
 * out; if the interface has no link-layer address (e.g. lo0), the
 * length is 0 and out is not touched.
 */
static uint8_t
if_eventlog_hwaddr(struct ifnet *ifp, uint8_t *out, size_t maxlen)
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	uint8_t len;

	ifa = ifp->if_addr;
	if (ifa == NULL || ifa->ifa_addr == NULL ||
	    ifa->ifa_addr->sa_family != AF_LINK)
		return (0);
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	len = sdl->sdl_alen;
	if (len > maxlen)
		len = maxlen;
	if (len > 0)
		memcpy(out, LLADDR(sdl), len);
	return (len);
}

/*
 * Driver name (e.g. "em", "ix") from the ifnet's dname.  Falls back
 * to the empty string if not available.
 */
static const char *
if_eventlog_driver(struct ifnet *ifp)
{

	if (ifp->if_dname != NULL)
		return (ifp->if_dname);
	return ("");
}

/*
 * Eventhandler callbacks.
 *
 * These run in the curvnet of the firing event (the framework
 * preserves curvnet across the EVENTHANDLER_INVOKE call site), so
 * V_if_eventlog_session resolves to the right per-VNET session.
 */

static void
if_eventlog_attached(void *arg __unused, if_t ifp)
{
	uint8_t hwaddr[32];
	uint8_t hwaddr_len;

	if (!IF_EVENTLOG_IF_ATTACH_ENABLED(V_if_eventlog_session))
		return;

	hwaddr_len = if_eventlog_hwaddr(ifp, hwaddr, sizeof(hwaddr));
	IF_EVENTLOG_IF_ATTACH_LOG_ALWAYS(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    ifp->if_xname,
	    (uint8_t)ifp->if_type,
	    if_eventlog_driver(ifp),
	    (uint32_t)ifp->if_mtu,
	    (uint64_t)ifp->if_baudrate,
	    hwaddr_len,
	    hwaddr);
}

/*
 * Link-layer address changed via if_setlladdr() -- an operator MAC
 * override, or a lagg/bridge reprogramming a member.  The ifnet_attached
 * hook fires from inside if_attach(), before ether_ifattach() writes the
 * initial address, so that record can carry an empty hwaddr; the initial
 * write does not fire iflladdr_event, so this hook does not rewrite it.
 * It re-emits IF_ATTACH to keep the consumer's ifindex->hwaddr binding
 * current when the address changes after attach.
 */
static void
if_eventlog_lladdr_changed(void *arg __unused, if_t ifp)
{
	uint8_t hwaddr[32];
	uint8_t hwaddr_len;

	if (!IF_EVENTLOG_IF_ATTACH_ENABLED(V_if_eventlog_session))
		return;

	hwaddr_len = if_eventlog_hwaddr(ifp, hwaddr, sizeof(hwaddr));
	IF_EVENTLOG_IF_ATTACH_LOG_ALWAYS(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    ifp->if_xname,
	    (uint8_t)ifp->if_type,
	    if_eventlog_driver(ifp),
	    (uint32_t)ifp->if_mtu,
	    (uint64_t)ifp->if_baudrate,
	    hwaddr_len,
	    hwaddr);
}

static void
if_eventlog_departed(void *arg __unused, if_t ifp)
{

	IF_EVENTLOG_IF_DETACH_LOG(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    ifp->if_xname);
}

static void
if_eventlog_renamed(void *arg __unused, if_t ifp, const char *old_name)
{

	IF_EVENTLOG_IF_RENAME_LOG(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    old_name,
	    ifp->if_xname);
}

static void
if_eventlog_link_changed(void *arg __unused, if_t ifp, int link_state)
{

	IF_EVENTLOG_IF_LINK_STATE_LOG(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    (uint8_t)link_state,
	    (uint64_t)ifp->if_baudrate);
}

static void
if_eventlog_addr_changed(void *arg __unused, if_t ifp, struct ifaddr *ifa,
    int addr_event)
{
	uint8_t addr[16];
	uint8_t addr_len, prefixlen;
	uint16_t family;

	if (ifa == NULL || ifa->ifa_addr == NULL)
		return;

	family = if_eventlog_extract_addr(ifa->ifa_addr, addr, &addr_len);
	if (family == 0)
		return;
	prefixlen = if_eventlog_masklen(ifa->ifa_netmask);

	if (addr_event == IFADDR_EVENT_ADD) {
		IF_EVENTLOG_IF_ADDR_ADD_LOG(V_if_eventlog_session,
		    (uint16_t)ifp->if_index,
		    family,
		    prefixlen,
		    addr_len,
		    addr);
	} else {
		IF_EVENTLOG_IF_ADDR_REMOVE_LOG(V_if_eventlog_session,
		    (uint16_t)ifp->if_index,
		    family,
		    prefixlen,
		    addr_len,
		    addr);
	}
}

/*
 * Direct entry points called from ifhwioctl() in if.c when admin
 * flags / MTU / capabilities change.  These are needed because the
 * existing eventhandler(9) declarations in <net/if_var.h> do not
 * cover these transitions; introducing new eventhandlers just for
 * eventlog would impose runtime cost on consumers (eventhandler
 * dispatch) that nobody has asked for.  The direct entry points
 * are thin wrappers that the producer macro short-circuits to a
 * load-and-branch when no subscriber is attached.
 */

void
if_eventlog_log_flags_change(if_t ifp, uint32_t old_flags, uint32_t new_flags)
{

	if (old_flags == new_flags)
		return;
	IF_EVENTLOG_IF_FLAGS_CHANGE_LOG(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    old_flags,
	    new_flags);
}

void
if_eventlog_log_mtu_change(if_t ifp, uint32_t old_mtu, uint32_t new_mtu)
{

	if (old_mtu == new_mtu)
		return;
	IF_EVENTLOG_IF_MTU_CHANGE_LOG(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    old_mtu,
	    new_mtu);
}

void
if_eventlog_log_caps_change(if_t ifp, uint32_t old_caps, uint32_t new_caps)
{

	if (old_caps == new_caps)
		return;
	IF_EVENTLOG_IF_CAPABILITIES_CHANGE_LOG(V_if_eventlog_session,
	    (uint16_t)ifp->if_index,
	    old_caps,
	    new_caps);
}

/*
 * Count the ifnets in the current VNET.  Caller holds IFNET_RLOCK.
 */
static uint16_t
if_eventlog_count_ifnets(void)
{
	struct ifnet *ifp;
	uint16_t n = 0;

	IFNET_RLOCK_ASSERT();
	CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link)
		n++;
	return (n);
}

/*
 * Emit an IF_INFO record on the per-VNET session.  Caller holds
 * IFNET_RLOCK so the ifnet count is consistent with the session
 * state at emission.
 */
static void
if_eventlog_log_info(void)
{
	uint32_t period_us;

	IFNET_RLOCK_ASSERT();

	period_us = if_eventlog_sampler_armed ? if_eventlog_sample_period_us : 0;

	IF_EVENTLOG_IF_INFO_LOG(V_if_eventlog_session,
	    period_us,
	    (uint64_t)(uintptr_t)curvnet,
	    if_eventlog_count_ifnets());
}

/*
 * Sampler callback.  Walks every VNET and emits one IF_SAMPLE_BYTES
 * and one IF_SAMPLE_PACKETS per ifnet on that VNET's session, then
 * re-arms itself for the next tick.
 *
 * Coupled to if_eventlog_sample_mtx via callout_init_mtx so the
 * mutex is held on entry; the framework provides atomic stop+drain
 * semantics via that coupling.  All work inside this callback is
 * non-sleeping: ifnet list iteration runs under NET_EPOCH and
 * VNET iteration uses the rwlock-based VNET_LIST_RLOCK_NOSLEEP.
 */
static void
if_eventlog_sample_tick(void *arg __unused)
{
	VNET_ITERATOR_DECL(vnet_iter);
	struct ifnet *ifp;
	struct epoch_tracker et;
	bool bytes_enabled, packets_enabled;

	mtx_assert(&if_eventlog_sample_mtx, MA_OWNED);

	NET_EPOCH_ENTER(et);
	VNET_LIST_RLOCK_NOSLEEP();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		bytes_enabled =
		    IF_EVENTLOG_IF_SAMPLE_BYTES_ENABLED(V_if_eventlog_session);
		packets_enabled =
		    IF_EVENTLOG_IF_SAMPLE_PACKETS_ENABLED(V_if_eventlog_session);
		if (!bytes_enabled && !packets_enabled) {
			CURVNET_RESTORE();
			continue;
		}
		CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link) {
			if (bytes_enabled) {
				IF_EVENTLOG_IF_SAMPLE_BYTES_LOG_ALWAYS(
				    V_if_eventlog_session, (uint16_t)ifp->if_index,
				    if_getcounter(ifp, IFCOUNTER_IBYTES),
				    if_getcounter(ifp, IFCOUNTER_OBYTES),
				    if_getcounter(ifp, IFCOUNTER_TCP_IBYTES),
				    if_getcounter(ifp, IFCOUNTER_TCP_OBYTES),
				    if_getcounter(ifp, IFCOUNTER_UDP_IBYTES),
				    if_getcounter(ifp, IFCOUNTER_UDP_OBYTES),
				    if_getcounter(ifp, IFCOUNTER_OTHER_IBYTES),
				    if_getcounter(ifp, IFCOUNTER_OTHER_OBYTES));
			}
			if (packets_enabled) {
				IF_EVENTLOG_IF_SAMPLE_PACKETS_LOG_ALWAYS(
				    V_if_eventlog_session, (uint16_t)ifp->if_index,
				    if_getcounter(ifp, IFCOUNTER_IPACKETS),
				    if_getcounter(ifp, IFCOUNTER_OPACKETS),
				    if_getcounter(ifp, IFCOUNTER_TCP_IPACKETS),
				    if_getcounter(ifp, IFCOUNTER_TCP_OPACKETS),
				    if_getcounter(ifp, IFCOUNTER_UDP_IPACKETS),
				    if_getcounter(ifp, IFCOUNTER_UDP_OPACKETS),
				    if_getcounter(ifp, IFCOUNTER_IERRORS),
				    if_getcounter(ifp, IFCOUNTER_OERRORS),
				    if_getcounter(ifp, IFCOUNTER_IQDROPS),
				    if_getcounter(ifp, IFCOUNTER_OQDROPS),
				    if_getcounter(ifp, IFCOUNTER_IMCASTS),
				    if_getcounter(ifp, IFCOUNTER_OMCASTS),
				    if_getcounter(ifp, IFCOUNTER_NOPROTO),
				    if_getcounter(ifp, IFCOUNTER_OTHER_IPACKETS),
				    if_getcounter(ifp, IFCOUNTER_OTHER_OPACKETS));
			}
		}
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK_NOSLEEP();
	NET_EPOCH_EXIT(et);

	if (if_eventlog_sampler_armed)
		callout_reset_sbt(&if_eventlog_sample_callout,
		    ustosbt(if_eventlog_sample_period_us), 0,
		    if_eventlog_sample_tick, NULL, C_PREL(2));
}

/*
 * Subscribers-changed callback.  Arms the sampler when at least
 * one subscriber attaches to the provider, disarms it when the
 * last subscriber detaches.  May sleep (callout_drain).
 */
static void
if_eventlog_subscribers_changed(struct eventlog_provider *provider __unused,
    bool has_subscribers, void *arg __unused)
{
	if (has_subscribers) {
		mtx_lock(&if_eventlog_sample_mtx);
		if (if_eventlog_sampler_armed) {
			mtx_unlock(&if_eventlog_sample_mtx);
			return;
		}
		if_eventlog_sampler_armed = true;
		callout_reset_sbt(&if_eventlog_sample_callout,
		    ustosbt(if_eventlog_sample_period_us), 0,
		    if_eventlog_sample_tick, NULL, C_PREL(2));
		mtx_unlock(&if_eventlog_sample_mtx);
	} else {
		mtx_lock(&if_eventlog_sample_mtx);
		if (!if_eventlog_sampler_armed) {
			mtx_unlock(&if_eventlog_sample_mtx);
			return;
		}
		if_eventlog_sampler_armed = false;
		mtx_unlock(&if_eventlog_sample_mtx);
		callout_drain(&if_eventlog_sample_callout);
		/*
		 * subscribers_changed is not serialized by the framework: a
		 * concurrent arm can re-set the flag and reschedule the callout
		 * in the window between the unlock and the drain, which drain
		 * then cancels.  Re-arm if the flag is set again so the sampler
		 * matches the latched state.
		 */
		mtx_lock(&if_eventlog_sample_mtx);
		if (if_eventlog_sampler_armed)
			callout_reset_sbt(&if_eventlog_sample_callout,
			    ustosbt(if_eventlog_sample_period_us), 0,
			    if_eventlog_sample_tick, NULL, C_PREL(2));
		mtx_unlock(&if_eventlog_sample_mtx);
	}
}

/*
 * sysctl handler for kern.eventlog.if.sample_period_us.  Range is
 * [IF_EVENTLOG_SAMPLE_PERIOD_US_MIN, IF_EVENTLOG_SAMPLE_PERIOD_US_MAX].
 */
static int
if_eventlog_sample_period_us_sysctl(SYSCTL_HANDLER_ARGS)
{
	uint32_t new_us;
	int error;

	new_us = if_eventlog_sample_period_us;
	error = sysctl_handle_int(oidp, &new_us, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (new_us < IF_EVENTLOG_SAMPLE_PERIOD_US_MIN ||
	    new_us > IF_EVENTLOG_SAMPLE_PERIOD_US_MAX)
		return (EINVAL);

	/* Plain store: the u32 write is atomic and the callout re-reads on re-arm. */
	if_eventlog_sample_period_us = new_us;
	return (0);
}

/*
 * dump_state: replay current state to a newly-attached subscriber.
 *
 * Walks every VNET and, within each, every ifnet.  Emits IF_INFO
 * once per VNET, then a synthetic IF_ATTACH for each interface
 * (rebuilding the (ifindex -> name) binding the consumer's table
 * needs), one IF_LINK_STATE for the interface's current link
 * state, and one IF_ADDR_ADD per attached address.  IF_SAMPLE_BYTES/
 * IF_SAMPLE_PACKETS are deliberately not replayed: the next sampler
 * tick provides a complete sample for every ifnet, and replaying a
 * stale snapshot here would just be noise.
 *
 * Runs on the eventlog dump taskqueue (sleepable).  IFNET_RLOCK is
 * an sx lock and is safe here.
 */
static void
if_eventlog_dump_state(struct eventlog_provider *provider __unused,
    void *arg __unused)
{
	VNET_ITERATOR_DECL(vnet_iter);
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct epoch_tracker et;
	uint8_t hwaddr[32];
	uint8_t hwaddr_len;
	uint8_t addr[16];
	uint8_t addr_len, prefixlen;
	uint16_t family;

	VNET_LIST_RLOCK();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		if (V_if_eventlog_session == NULL) {
			CURVNET_RESTORE();
			continue;
		}
		IFNET_RLOCK();
		if_eventlog_log_info();
		CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link) {
			hwaddr_len = if_eventlog_hwaddr(ifp, hwaddr,
			    sizeof(hwaddr));
			IF_EVENTLOG_IF_ATTACH_LOG(V_if_eventlog_session,
			    (uint16_t)ifp->if_index,
			    ifp->if_xname,
			    (uint8_t)ifp->if_type,
			    if_eventlog_driver(ifp),
			    (uint32_t)ifp->if_mtu,
			    (uint64_t)ifp->if_baudrate,
			    hwaddr_len,
			    hwaddr);
			IF_EVENTLOG_IF_LINK_STATE_LOG(V_if_eventlog_session,
			    (uint16_t)ifp->if_index,
			    (uint8_t)ifp->if_link_state,
			    (uint64_t)ifp->if_baudrate);
			NET_EPOCH_ENTER(et);
			CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				if (ifa->ifa_addr == NULL)
					continue;
				family = if_eventlog_extract_addr(ifa->ifa_addr,
				    addr, &addr_len);
				if (family == 0)
					continue;
				prefixlen = if_eventlog_masklen(
				    ifa->ifa_netmask);
				IF_EVENTLOG_IF_ADDR_ADD_LOG(
				    V_if_eventlog_session,
				    (uint16_t)ifp->if_index,
				    family,
				    prefixlen,
				    addr_len,
				    addr);
			}
			NET_EPOCH_EXIT(et);
		}
		IFNET_RUNLOCK();
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK();
}

/*
 * Per-VNET session lifecycle.
 */
static void
if_eventlog_vnet_init(const void *unused __unused)
{

	V_if_eventlog_session = eventlog_session_create(if_eventlog_provider,
	    (uint64_t)(uintptr_t)curvnet, true, NULL, 0);
	IFNET_RLOCK();
	if_eventlog_log_info();
	IFNET_RUNLOCK();
}
VNET_SYSINIT(if_eventlog_session_init, SI_SUB_PROTO_IF, SI_ORDER_ANY,
    if_eventlog_vnet_init, NULL);

static void
if_eventlog_vnet_uninit(const void *unused __unused)
{

	eventlog_session_destroy(V_if_eventlog_session);
	V_if_eventlog_session = NULL;
}
VNET_SYSUNINIT(if_eventlog_session_uninit, SI_SUB_PROTO_IF, SI_ORDER_ANY,
    if_eventlog_vnet_uninit, NULL);

/*
 * Provider lifecycle.  Runs once at boot, before VNET sysinits at
 * the same SI_SUB level fire (global SYSINITs precede per-VNET ones
 * at the same subsystem/order).
 */
static void
if_eventlog_init(void *unused __unused)
{
	struct eventlog_provider_config cfg = {
		.default_enabled = 1,
		.dump_callback = if_eventlog_dump_state,
		.subscribers_changed = if_eventlog_subscribers_changed,
		.decode_blob = if_eventlog_decode_blob,
		.decode_blob_size = if_eventlog_decode_blob_size,
	};
	struct sysctl_oid *node;
	struct sysctl_ctx_list *ctx;

	mtx_init(&if_eventlog_sample_mtx, "if_eventlog_sample", NULL, MTX_DEF);
	callout_init_mtx(&if_eventlog_sample_callout,
	    &if_eventlog_sample_mtx, 0);

	if_eventlog_provider = eventlog_provider_create("if", &cfg);
	if (if_eventlog_provider == NULL) {
		printf("if_eventlog: failed to create provider\n");
		return;
	}

	/*
	 * Hang the sampler tunable under the provider's auto-generated
	 * kern.eventlog.if node so operators find it next to the
	 * provider's own knobs (kern.eventlog.if.default, etc.).
	 */
	node = eventlog_provider_get_sysctl_node(if_eventlog_provider);
	ctx = eventlog_provider_get_sysctl_ctx(if_eventlog_provider);
	if (node != NULL && ctx != NULL) {
		SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(node),
		    OID_AUTO, "sample_period_us",
		    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
		    NULL, 0, if_eventlog_sample_period_us_sysctl, "IU",
		    "Interface sample emission period in us (1000-1800000000)");
	}

	if_eventlog_attached_tag = EVENTHANDLER_REGISTER(ifnet_attached_event,
	    if_eventlog_attached, NULL, EVENTHANDLER_PRI_ANY);
	if_eventlog_lladdr_tag = EVENTHANDLER_REGISTER(iflladdr_event,
	    if_eventlog_lladdr_changed, NULL, EVENTHANDLER_PRI_ANY);
	if_eventlog_departure_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    if_eventlog_departed, NULL, EVENTHANDLER_PRI_ANY);
	if_eventlog_rename_tag = EVENTHANDLER_REGISTER(ifnet_rename_event,
	    if_eventlog_renamed, NULL, EVENTHANDLER_PRI_ANY);
	if_eventlog_link_tag = EVENTHANDLER_REGISTER(ifnet_link_event,
	    if_eventlog_link_changed, NULL, EVENTHANDLER_PRI_ANY);
	if_eventlog_addr_tag = EVENTHANDLER_REGISTER(ifaddr_event_ext,
	    if_eventlog_addr_changed, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(if_eventlog_init, SI_SUB_PROTO_IF, SI_ORDER_FIRST,
    if_eventlog_init, NULL);
