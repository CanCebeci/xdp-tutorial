/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2021 Authors of Cilium */

#ifndef __LIB_CONNTRACK_MAP_H_
#define __LIB_CONNTRACK_MAP_H_

#include "common.h"
#include "config.h"

#if defined(CT_MAP_TCP4) && defined(CT_MAP_TCP6)
#ifdef HAVE_LRU_HASH_MAP_TYPE
#define CT_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#else
#define CT_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifdef ENABLE_IPV6

struct bpf_map_def SEC("maps") CT_MAP_TCP6 = {
	.type = CT_MAP_TYPE,
	.key_size = sizeof(struct ipv6_ct_tuple),
	.value_size = sizeof(struct ct_entry),
	.max_entries = CT_MAP_SIZE_TCP,
#ifndef HAVE_LRU_HASH_MAP_TYPE
	.map_flags = CONDITIONAL_PREALLOC,
#endif
};

struct bpf_map_def SEC("maps") CT_MAP_ANY6 = {
	.type = CT_MAP_TYPE,
	.key_size = sizeof(struct ipv6_ct_tuple),
	.value_size = sizeof(struct ct_entry),
	.max_entries = CT_MAP_SIZE_ANY,
#ifndef HAVE_LRU_HASH_MAP_TYPE
	.map_flags = CONDITIONAL_PREALLOC,
#endif
};

static __always_inline void *
get_ct_map6(const struct ipv6_ct_tuple *tuple)
{
	if (tuple->nexthdr == IPPROTO_TCP)
		return &CT_MAP_TCP6;

	return &CT_MAP_ANY6;
}
#endif

#ifdef ENABLE_IPV4

struct bpf_map_def SEC("maps") CT_MAP_TCP4 = {
	.type = CT_MAP_TYPE,
	.key_size = sizeof(struct ipv4_ct_tuple),
	.value_size = sizeof(struct ct_entry),
	.max_entries = CT_MAP_SIZE_TCP,
#ifndef HAVE_LRU_HASH_MAP_TYPE
	.map_flags = CONDITIONAL_PREALLOC,
#endif
};

struct bpf_map_def SEC("maps") CT_MAP_ANY4 = {
	.type = CT_MAP_TYPE,
	.key_size = sizeof(struct ipv4_ct_tuple),
	.value_size = sizeof(struct ct_entry),
	.max_entries = CT_MAP_SIZE_ANY,
#ifndef HAVE_LRU_HASH_MAP_TYPE
	.map_flags = CONDITIONAL_PREALLOC,
#endif
};

static __always_inline void *
get_ct_map4(const struct ipv4_ct_tuple *tuple)
{
	if (tuple->nexthdr == IPPROTO_TCP)
		return &CT_MAP_TCP4;

	return &CT_MAP_ANY4;
}
#endif
#endif
#endif /* __LIB_CONNTRACK_MAP_H_ */