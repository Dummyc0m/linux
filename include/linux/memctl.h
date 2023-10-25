/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel interface for /dev/memctl - memctl Guest Memory Service Module
 *
 * Copyright (c) 2021, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _MEMCTL_H
#define _MEMCTL_H

#include <uapi/linux/memctl.h>
#include <linux/errno.h>

#ifdef CONFIG_MEMCTL
/* buf must be kzalloc'd */
long memctl_vmm_call(__u64 func_code, __u64 addr, __u64 length, __u64 arg,
		     struct memctl_buf *buf);
#else
static inline long memctl_vmm_call(__u64 func_code, __u64 addr, __u64 length,
				   __u64 arg, struct memctl_buf *buf)
{
	return -ENODEV;
}
#endif /* CONFIG_MEMCTL */

#endif /* _MEMCTL_H */
