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

#ifndef _NET_IF_EVENTLOG_H_
#define _NET_IF_EVENTLOG_H_

/*
 * Direct hook entry points for the "if" eventlog provider.
 *
 * These cover the SIOCSIF{FLAGS,MTU,CAP*} transitions that lack a
 * kernel eventhandler today.  Lifecycle, link-state, rename, and
 * address events are hooked via the existing eventhandler(9)
 * declarations in <net/if_var.h> and need no in-tree changes here.
 *
 * Each entry point is a thin wrapper over the schema-generated
 * producer macro and does the standard _ENABLED short-circuit when
 * no subscriber matches the CONFIG keyword.  Calling these from
 * any context is safe.
 */

#ifdef _KERNEL

struct ifnet;

void	if_eventlog_log_flags_change(struct ifnet *ifp, uint32_t old_flags,
	    uint32_t new_flags);
void	if_eventlog_log_mtu_change(struct ifnet *ifp, uint32_t old_mtu,
	    uint32_t new_mtu);
void	if_eventlog_log_caps_change(struct ifnet *ifp, uint32_t old_caps,
	    uint32_t new_caps);

#endif /* _KERNEL */

#endif /* !_NET_IF_EVENTLOG_H_ */
