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

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65535);
  __type(key, struct addr_port);
  __type(value, struct addr_port_stats);
} GLUE(NAME, nat_out_table) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65535);
  __type(key, struct addr_port);
  __type(value, struct addr_port_stats);
} GLUE(NAME, nat_ret_table) SEC(".maps");

#endif /* _EBPFMAP_H_ */
