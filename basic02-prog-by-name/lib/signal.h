/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2021 Authors of Cilium */

#ifndef __LIB_SIGNAL_H_
#define __LIB_SIGNAL_H_

#include <bpf/api.h>

struct bpf_map_def SEC("maps") SIGNAL_MAP = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32), 
    .value_size = sizeof(__u32), 
    .max_entries = 128,
};

enum {
	SIGNAL_NAT_FILL_UP = 0,
	SIGNAL_CT_FILL_UP,
};

enum {
	SIGNAL_PROTO_V4 = 0,
	SIGNAL_PROTO_V6,
};

struct signal_msg {
	__u32 signal_nr;
	union {
		struct {
			__u32 proto;
		};
	};
};

static __always_inline void send_signal(struct __ctx_buff *ctx,
					struct signal_msg *msg)
{
	ctx_event_output(ctx, &SIGNAL_MAP, BPF_F_CURRENT_CPU,
			 msg, sizeof(*msg));
}

static __always_inline void send_signal_nat_fill_up(struct __ctx_buff *ctx,
						    __u32 proto)
{
	struct signal_msg msg = {
		.signal_nr	= SIGNAL_NAT_FILL_UP,
		.proto		= proto,
	};

	send_signal(ctx, &msg);
}

static __always_inline void send_signal_ct_fill_up(struct __ctx_buff *ctx,
						   __u32 proto)
{
	struct signal_msg msg = {
		.signal_nr	= SIGNAL_CT_FILL_UP,
		.proto		= proto,
	};

	send_signal(ctx, &msg);
}

#endif /* __LIB_SIGNAL_H_ */
