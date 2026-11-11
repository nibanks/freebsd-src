/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#ifndef _SYS_EVENTLOG_SYMBOLS_H_
#define _SYS_EVENTLOG_SYMBOLS_H_

#ifdef _KERNEL

#include <sys/types.h>

struct vnode;

/*
 * Cross-provider KPI: look up or allocate a stable user_file_id for
 * the backing file of `vp`, keyed on (dev, ino). The first call for
 * a given file emits a USER_FILE event on the symbols provider's
 * session with `pathname`; later calls return the same id without
 * re-emitting. Sleeps (VOP_GETATTR, and I/O on first sighting), so
 * callers must hold no spin locks.
 *
 * Returns 0 and stores the id in *user_file_id_out, or a non-zero
 * errno and 0 on failure (vp NULL or no useful vnode identity).
 * Callers with no backing file (anonymous mappings) should skip this
 * call entirely and use user_file_id 0 directly.
 */
int eventlog_symbols_intern_user_file(struct vnode *vp,
    const char *pathname, uint32_t *user_file_id_out);

#endif /* _KERNEL */

#endif /* _SYS_EVENTLOG_SYMBOLS_H_ */
