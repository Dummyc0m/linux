/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interface for /dev/memctl - memctl Guest Memory Service Module
 *
 * Copyright (c) 2021, Google LLC.
 * Yuanchu Xie <yuanchu@google.com>
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _UAPI_MEMCTL_H
#define _UAPI_MEMCTL_H

#include <linux/wait.h>
#include <linux/types.h>
#include <asm/param.h>

/* Contains the function code and arguments for specific function */
struct memctl_vmm_call {
	__u64 func_code;	/* memctl set function code */
	__u64 addr;		/* hyper. page size aligned guest phys. addr */
	__u64 length;		/* hyper. page size aligned length */
	__u64 arg;		/* function code specific argument */
};

/* Is filled on return to guest from VMM from most function calls */
struct memctl_vmm_ret {
	__u32 ret_errno;	/* on error, value of errno */
	__u32 ret_code;		/* memctl internal error code, on success 0 */
	__u64 ret_value;	/* return value from the function call */
	__u64 arg0;		/* currently unused */
	__u64 arg1;		/* currently unused */
};

/* Is filled on return to guest from VMM from MEMCTL_INFO function call */
struct memctl_vmm_info {
	__u32 ret_errno;	/* on error, value of errno */
	__u32 ret_code;		/* memctl internal error code, on success 0 */
	__u64 big_endian;	/* non-zero when hypervisor is big endian */
	__u32 major_version;	/* VMM memctl backend major version */
	__u32 minor_version;	/* VMM memctl backend minor version */
	__u64 page_size;	/* hypervisor page size */
};

struct memctl_buf {
	union {
		struct memctl_vmm_call call;
		struct memctl_vmm_ret ret;
		struct memctl_vmm_info info;
	};
};

/* The ioctl type, documented in ioctl-number.rst */
#define MEMCTL_IOCTL_TYPE		0xDA

#define MEMCTL_IOCTL_VMM _IOWR(MEMCTL_IOCTL_TYPE, 0x00, struct memctl_buf)

/* Get memctl_vmm_info, addr, length, and arg are ignored */
#define MEMCTL_INFO		0

/* Memctl calls, memctl_vmm_return is returned */
#define MEMCTL_DONTNEED		1 /* madvise(addr, len, MADV_DONTNEED); */
#define MEMCTL_REMOVE		2 /* madvise(addr, len, MADV_MADV_REMOVE); */
#define MEMCTL_FREE		3 /* madvise(addr, len, MADV_FREE); */
#define MEMCTL_PAGEOUT		4 /* madvise(addr, len, MADV_PAGEOUT); */

#define MEMCTL_UNMERGEABLE	5 /* madvise(addr, len, MADV_UNMERGEABLE); */
#define MEMCTL_DONTDUMP		6 /* madvise(addr, len, MADV_DONTDUMP); */

#define MEMCTL_MLOCK		7 /* mlock2(addr, len, 0) */
#define MEMCTL_MUNLOCK		8 /* munlock(addr, len) */

#define MEMCTL_MPROTECT_NONE	9 /* mprotect(addr, len, PROT_NONE) */
#define MEMCTL_MPROTECT_R	10 /* mprotect(addr, len, PROT_READ) */
#define MEMCTL_MPROTECT_W	11 /* mprotect(addr, len, PROT_WRITE) */
/* mprotect(addr, len, PROT_READ | PROT_WRITE) */
#define MEMCTL_MPROTECT_RW	12

/* prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, arg) */
#define MEMCTL_SET_VMA_ANON_NAME 13

#endif /* _UAPI_MEMCTL_H */
