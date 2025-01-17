/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2021 Authors of Cilium */

#ifndef __LIB_TIME_CACHE_H_
#define __LIB_TIME_CACHE_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "time.h"

/* Per-CPU ktime cache for faster clock access. */
struct bpf_map_def SEC("maps") cilium_ktime_cache = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32), 
    .value_size = sizeof(__u64), 
    .max_entries = 1,
};

/* Currently supported clock types:
 *
 * - bpf_ktime_cache_set(ns)      -> CLOCK_MONOTONIC
 * - bpf_ktime_cache_set(boot_ns) -> CLOCK_BOOTTIME
 */
#define bpf_ktime_cache_set(clock)					     \
	({								     \
		__u32 __z = 0;						     \
		__u64 *__cache = map_lookup_elem(&cilium_ktime_cache, &__z); \
		__u64 __ktime = ktime_get_##clock();			     \
		if (always_succeeds(__cache))				     \
			*__cache = __ktime;				     \
		__ktime;						     \
	})

#define bpf_ktime_cache_get()						     \
	({								     \
		__u32 __z = 0;						     \
		__u64 *__cache = map_lookup_elem(&cilium_ktime_cache, &__z); \
		__u64 __ktime = 0;					     \
		if (always_succeeds(__cache))				     \
			__ktime = *__cache;				     \
		__ktime;						     \
	})

#endif /* __LIB_TIME_CACHE_H_ */
