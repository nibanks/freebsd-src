/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _SYS_EVENTLOG_PROCESS_H_
#define _SYS_EVENTLOG_PROCESS_H_

/*
 * The "process" eventlog provider's single global session. Callers
 * use it directly with the PROCESS_EVENTLOG_*_LOG() macros; those
 * macros already no-op on a NULL/disabled session, so there's
 * nothing to check here.
 */

#ifdef _KERNEL

#include <eventlog/process_eventlog.h>

struct proc;

extern struct eventlog_session *proc_elog_session;

void proc_elog_walk_vmmap(struct eventlog_session *session, struct proc *p);

#endif /* _KERNEL */

#endif /* _SYS_EVENTLOG_PROCESS_H_ */
