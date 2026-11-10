/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _NET_IF_PROTO_H_
#define	_NET_IF_PROTO_H_

#ifdef _KERNEL

#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>

/*
 * Bump IFCOUNTER_{TCP,UDP,OTHER}_* where ifp and the upper-layer
 * protocol are both known.
 */
static __inline void
if_proto_inc_counter(if_t ifp, uint8_t proto, bool rx, int64_t len)
{
	ift_counter bytes_cnt, pkts_cnt;

	if (ifp == NULL)
		return;

	switch (proto) {
	case IPPROTO_TCP:
		bytes_cnt = rx ? IFCOUNTER_TCP_IBYTES : IFCOUNTER_TCP_OBYTES;
		pkts_cnt = rx ? IFCOUNTER_TCP_IPACKETS : IFCOUNTER_TCP_OPACKETS;
		break;
	case IPPROTO_UDP:
		bytes_cnt = rx ? IFCOUNTER_UDP_IBYTES : IFCOUNTER_UDP_OBYTES;
		pkts_cnt = rx ? IFCOUNTER_UDP_IPACKETS : IFCOUNTER_UDP_OPACKETS;
		break;
	default:
		bytes_cnt = rx ? IFCOUNTER_OTHER_IBYTES : IFCOUNTER_OTHER_OBYTES;
		pkts_cnt = rx ? IFCOUNTER_OTHER_IPACKETS : IFCOUNTER_OTHER_OPACKETS;
		break;
	}
	if_inc_counter(ifp, bytes_cnt, len);
	if_inc_counter(ifp, pkts_cnt, 1);
}

/*
 * IPv6 input walks extension headers before the upper-layer proto; skip
 * those so each packet is counted once (see ip6_input()).
 */
static __inline void
if_proto_inc_counter_ip6(if_t ifp, uint8_t proto, bool rx, int64_t len)
{
	switch (proto) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_DSTOPTS:
		return;
	default:
		if_proto_inc_counter(ifp, proto, rx, len);
	}
}

#endif /* _KERNEL */

#endif /* !_NET_IF_PROTO_H_ */
