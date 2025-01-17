/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2021 Authors of Cilium */

#ifndef __LIB_MAPS_H_
#define __LIB_MAPS_H_

#include "common.h"
#include "ipv6.h"
#include "ids.h"

#include "bpf/compiler.h"

struct bpf_map_def SEC("maps") ENDPOINTS_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct endpoint_key),
    .value_size = sizeof(struct endpoint_info),
    .max_entries = ENDPOINTS_MAP_SIZE,
		.map_flags = CONDITIONAL_PREALLOC,
};

struct bpf_map_def SEC("maps") METRICS_MAP = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct metrics_key),
    .value_size = sizeof(struct metrics_value),
    .max_entries = METRICS_MAP_SIZE,
		.map_flags = CONDITIONAL_PREALLOC,
};
//#define SKIP_POLICY_MAP
#ifndef SKIP_POLICY_MAP
/* Global map to jump into policy enforcement of receiving endpoint */
struct bpf_map_def SEC("maps") POLICY_CALL_MAP = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	// .id		= CILIUM_MAP_POLICY,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= POLICY_PROG_MAP_SIZE,
};
#endif /* SKIP_POLICY_MAP */

#ifdef ENABLE_BANDWIDTH_MANAGER
struct bpf_map_def SEC("maps") THROTTLE_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct edt_id),
    .value_size = sizeof(struct edt_info),
    .max_entries = THROTTLE_MAP_SIZE,
		.map_flags = BPF_F_NO_PREALLOC,
};
#endif /* ENABLE_BANDWIDTH_MANAGER */

/* Map to link endpoint id to per endpoint cilium_policy map */
#ifdef SOCKMAP
struct bpf_map_def SEC("maps") EP_POLICY_MAP = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(struct endpoint_key),
    .value_size = sizeof(int),
    .max_entries = ENDPOINTS_MAP_SIZE,
};
#endif

#ifdef POLICY_MAP
/* Per-endpoint policy enforcement map */
struct bpf_map_def SEC("maps") POLICY_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct policy_key),
    .value_size = sizeof(struct policy_entry),
    .max_entries = POLICY_MAP_SIZE,
		.map_flags = CONDITIONAL_PREALLOC,
};
#endif

//#define SKIP_CALLS_MAP
#ifndef SKIP_CALLS_MAP
/* Private per EP map for internal tail calls */
struct bpf_map_def SEC("maps") CALLS_MAP = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
		// .id		= CILIUM_MAP_CALLS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = CILIUM_CALL_SIZE,
};
#endif /* SKIP_CALLS_MAP */

#ifdef ENCAP_IFINDEX
struct bpf_map_def SEC("maps") TUNNEL_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct endpoint_key),
    .value_size = sizeof(struct endpoint_key),
    .max_entries = TUNNEL_ENDPOINT_MAP_SIZE,
		.map_flags = CONDITIONAL_PREALLOC,
};
#endif

#undef ENABLE_CUSTOM_CALLS
#if defined(ENABLE_CUSTOM_CALLS) && defined(CUSTOM_CALLS_MAP)
asfhsfhfha
/* Private per-EP map for tail calls to user-defined programs.
 * CUSTOM_CALLS_MAP is a per-EP map name, only defined for programs that need
 * to use the map, so we do not want to compile this definition if
 * CUSTOM_CALLS_MAP has not been #define-d.
 */
struct bpf_map_def SEC("maps") CUSTOM_CALLS_MAP = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
		// .id		= CILIUM_MAP_CUSTOM_CALLS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 4, /* ingress and egress, IPv4 and IPv6 */
};

#define CUSTOM_CALLS_IDX_IPV4_INGRESS	0
#define CUSTOM_CALLS_IDX_IPV4_EGRESS	1
#define CUSTOM_CALLS_IDX_IPV6_INGRESS	2
#define CUSTOM_CALLS_IDX_IPV6_EGRESS	3
#endif /* ENABLE_CUSTOM_CALLS && CUSTOM_CALLS_MAP */

#ifdef HAVE_LPM_TRIE_MAP_TYPE
#define LPM_MAP_TYPE BPF_MAP_TYPE_LPM_TRIE
#else
#define LPM_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifndef HAVE_LPM_TRIE_MAP_TYPE
/* Define a function with the following NAME which iterates through PREFIXES
 * (a list of integers ordered from high to low representing prefix length),
 * performing a lookup in MAP using LOOKUP_FN to find a provided IP of type
 * IPTYPE.
 */
#define LPM_LOOKUP_FN(NAME, IPTYPE, PREFIXES, MAP, LOOKUP_FN)		\
static __always_inline int __##NAME(IPTYPE addr)			\
{									\
	int prefixes[] = { PREFIXES };					\
	const int size = ARRAY_SIZE(prefixes);				\
	int i;								\
									\
_Pragma("unroll")							\
	for (i = 0; i < size; i++)					\
		if (LOOKUP_FN(&MAP, addr, prefixes[i]))			\
			return 1;					\
									\
	return 0;							\
}
#endif /* HAVE_LPM_TRIE_MAP_TYPE */

#ifndef SKIP_UNDEF_LPM_LOOKUP_FN
#undef LPM_LOOKUP_FN
#endif

struct ipcache_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16 pad1;
	__u8 pad2;
	__u8 family;
	union {
		struct {
			__u32		ip4;
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
		union v6addr	ip6;
	};
} __packed;

/* Global IP -> Identity map for applying egress label-based policy */
struct bpf_map_def SEC("maps") IPCACHE_MAP = {
    .type = LPM_MAP_TYPE,
    .key_size = sizeof(struct ipcache_key),
    .value_size = sizeof(struct remote_endpoint_info),
    .max_entries = IPCACHE_MAP_SIZE,
		.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ENCRYPT_MAP = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct encrypt_config),
    .max_entries = 1,
};

#ifdef ENABLE_EGRESS_GATEWAY
struct bpf_map_def SEC("maps") EGRESS_POLICY_MAP = {
    .type = LPM_MAP_TYPE,
    .key_size = sizeof(struct egress_gw_policy_key),
    .value_size = sizeof(struct egress_gw_policy_entry),
    .max_entries = EGRESS_POLICY_MAP_SIZE,
		.map_flags = BPF_F_NO_PREALLOC,
};
#endif /* ENABLE_EGRESS_GATEWAY */

#ifndef SKIP_CALLS_MAP
static __always_inline void ep_tail_call(struct __ctx_buff *ctx __maybe_unused,
					 const __u32 index __maybe_unused)
{
	tail_call_static(ctx, &CALLS_MAP, index);
}
#endif /* SKIP_CALLS_MAP */
#endif
