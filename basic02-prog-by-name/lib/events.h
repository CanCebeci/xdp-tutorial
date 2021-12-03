/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2021 Authors of Cilium */

#ifndef __LIB_EVENTS_H_
#define __LIB_EVENTS_H_

#include <bpf/api.h>

#define EVENTS_MAP_MAX_CPUS 128

struct bpf_map_def SEC("maps") EVENTS_MAP = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = EVENTS_MAP_MAX_CPUS,
	.map_flags = CONDITIONAL_PREALLOC,
};

#endif /* __LIB_EVENTS_H_ */
