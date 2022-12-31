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
}  __attribute__ ((packed));

struct addr_port_stats {
  __u32 addr;
  __u16 port;
  __u64 pkts;
}  __attribute__ ((packed));

struct trie4_key {
  __u32 prefixlen;
  __u32 addr;
}  __attribute__ ((packed));

struct trie4_val {
  __u16 action;
  struct in6_addr segs[6];
}  __attribute__ ((packed));

struct trie6_key {
  __u32 prefixlen;
  __u8 addr[16];
}  __attribute__ ((packed));

struct trie6_val {
  __u16 action;
  __u16 backend_block_index;
  __u32 vip;
  __u16 nat_port_hash_bit;
  __u16 usid_block_length;
  __u16 usid_function_length;
} __attribute__ ((packed));

struct vip_key {
  __u32 vip;
} __attribute__ ((packed));

struct vip_val {
  __u16 backend_block_index;
  __u16 nat_port_hash_bit;
} __attribute__ ((packed));

struct flow_processor {
  struct in6_addr addr;
  // TODO(slankdev): support loadbalancing stats
  // __u64 pkts;
  // __u64 bytes;
} __attribute__ ((packed));

#endif /* _EBPFMAP_H_ */
