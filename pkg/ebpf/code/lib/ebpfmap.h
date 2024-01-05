/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2022 Hiroki Shirokura.
 * Copyright 2022 Wide Project.
 */

#ifndef _EBPFMAP_H_
#define _EBPFMAP_H_

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct addr_port {
  __u32 addr;
  __u16 port;
  __u8 proto;
}  __attribute__ ((packed));

struct addr_port_stats {
  __u32 addr;
  __u16 port;
  __u8 proto;
  __u64 pkts;
  __u64 bytes;
  __u64 created_at;
  __u64 update_at;
  __u64 flags;
}  __attribute__ ((packed));

enum tcp_state_t {
  TCP_STATE_CLOSING   = (1<<0),
  TCP_STATE_ESTABLISH = (1<<1),
};

struct trie4_key {
  __u32 prefixlen;
  __u32 addr;
}  __attribute__ ((packed));

#define TRIE4_VAL_ACTION_END_MFNN    0
#define TRIE4_VAL_ACTION_L2_XCONNECT 1
#define TRIE4_VAL_ACTION_L3_XCONNECT 2
#define TRIE6_VAL_ACTION_UNSPEC      0
#define TRIE6_VAL_ACTION_L3_XCONNECT 1
#define TRIE6_VAL_ACTION_END_MFNL    123
#define TRIE6_VAL_ACTION_END_MFNN    456

struct trie4_val_nexthop {
  __u16 nh_family;
  __u32 nh_addr4;
  struct in6_addr nh_addr6;
}  __attribute__ ((packed));

struct trie4_val {
  __u16 action;
  __u16 backend_block_index;
  __u16 nat_port_hash_bit;

  // L3 Cross-Connect
  __u16 l3_xconn_nh_count;
  struct trie4_val_nexthop l3_xconn_nh[16];
}  __attribute__ ((packed));

struct trie6_key {
  __u32 prefixlen;
  __u8 addr[16];
}  __attribute__ ((packed));

struct snat_source {
  __u32 prefixlen;
  __u32 addr;
}  __attribute__ ((packed));

struct trie6_val {
  __u16 action;
  __u16 backend_block_index;
  __u32 vip;
  __u16 nat_port_hash_bit;
  __u16 usid_block_length;
  __u16 usid_function_length;
  __u64 stats_total_bytes;
  __u64 stats_total_pkts;
  __u64 stats_redir_bytes;
  __u64 stats_redir_pkts;
  __u8 nat_mapping;
  __u8 nat_filterring;
  struct snat_source sources[256];

  // L3 Cross-Connect
  __u16 l3_xconn_nh_count;
  struct trie4_val_nexthop l3_xconn_nh[16];
} __attribute__ ((packed));

struct overlay_fib4_key {
  __u32 vrf_id;
  __u32 addr;
} __attribute__ ((packed));

struct overlay_fib4_val {
  __u32 flags;
  struct in6_addr segs[6];
} __attribute__ ((packed));

enum nat_mapping_t {
  NAT_MAPPING_EI = 0,
  NAT_MAPPING_AD = 1,
  NAT_MAPPING_APD = 2,
};

enum nat_filtering_t {
  NAT_FILTERING_EI = 0,
  NAT_FILTERING_AD = 1,
  NAT_FILTERING_APD = 2,
};

struct vip_key {
  __u32 vip;
} __attribute__ ((packed));

struct vip_val {
  __u16 backend_block_index;
  __u16 nat_port_hash_bit;
} __attribute__ ((packed));

struct flow_processor {
  struct in6_addr addr;
  __u64 stats_total_bytes;
  __u64 stats_total_pkts;
} __attribute__ ((packed));

struct mf_redir_rate_stat_key {
  struct in6_addr next_sid;
  __u32 addr;
  __u16 port;
  __u8 proto;
  __u8 is_out;
}  __attribute__ ((packed));

struct mf_redir_rate_stat_val {
  __u64 last_reset;
  __u64 pkts;
  __u64 bytes;
}  __attribute__ ((packed));

struct neigh_key {
  __u32 family;
  __u32 addr4;
  struct in6_addr addr6;
}  __attribute__ ((packed));

struct neigh_val {
  __u32 flags;
  __u8 mac[6];
}  __attribute__ ((packed));

struct counter_val {
  __u64 xdp_action_tx_pkts;
  __u64 xdp_action_tx_bytes;
  __u64 xdp_action_drop_pkts;
  __u64 xdp_action_drop_bytes;
  __u64 xdp_action_abort_pkts;
  __u64 xdp_action_abort_bytes;
  __u64 xdp_action_pass_pkts;
  __u64 xdp_action_pass_bytes;

  // TODO(slankdev):
  // fib4_miss
  // fib6_miss
  // neigh_miss
  // nat_out_miss
  // nat_ret_miss
}  __attribute__ ((packed));

#endif /* _EBPFMAP_H_ */
