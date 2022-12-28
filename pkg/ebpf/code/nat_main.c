/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2022 Hiroki Shirokura.
 * Copyright 2022 Wide Project.
 */

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "lib/lib.h"

struct nat_ret_table_key {
  __u32 addr;
  __u16 port;
}  __attribute__ ((packed));

struct nat_ret_table_val {
  __u32 addr;
  __u16 port;
}  __attribute__ ((packed));

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 160);
  __type(key, struct nat_ret_table_key);
  __type(value, struct nat_ret_table_val);
} GLUE(NAME, nat_ret_table) SEC(".maps");

struct outer_header {
  struct ipv6hdr ip6;
  struct ipv6_rt_hdr srh;
  __u8 padding[4];
  struct in6_addr seg;
} __attribute__ ((packed));

struct trie_key {
  __u32 prefixlen;
  __u8 addr[16];
};

struct trie_val {
  __u16 action;
  __u16 backend_block_index;
  __u32 vip;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie_key));
  __uint(value_size, sizeof(struct trie_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} GLUE(NAME, fib6) SEC(".maps");

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct outer_header) + \
  sizeof(struct iphdr) + offsetof(struct tcphdr, check))

__u8 srv6_local_sid[16] = {
  // TODO(slankdev): set from map
  // fc00:11:1:::
  0xfc, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, 1);
} GLUE(NAME, encap_source) SEC(".maps");

__u8 srv6_vm_remote_sid[16] = {
  // TODO(slankdev): set from map
  // fc00:201:1:::
  0xfc, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static inline int
process_nat_return(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);
  if (oh->ip6.nexthdr != IPPROTO_ROUTING ||
      oh->srh.type != 4 ||
      oh->srh.hdrlen != 2 ||
      same_ipv6(&oh->ip6.daddr, srv6_local_sid, 6) != 0) {
    return ignore_packet(ctx);
  }
  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);
  __u8 in_ih_len = in_ih->ihl * 4;
  struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_th, data_end);

  // lookup
  struct nat_ret_table_val *val = NULL;
  struct nat_ret_table_key key = {
    .addr = in_ih->daddr,
    .port = in_th->dest,
  };
  val = bpf_map_lookup_elem(&(GLUE(NAME, nat_ret_table)), &key);
  if (!val) {
    bpf_printk(STR(NAME)"lookup fail");
    return XDP_DROP;
  }

#ifdef DEBUG
    char tmp[128] = {0};
    BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u -> %pi4:%u/%pi4:%u",
                in_ih->protocol,
                &in_ih->saddr, bpf_ntohs(in_th->source),
                &in_ih->daddr, bpf_ntohs(in_th->dest),
                &val->addr, bpf_ntohs(val->port));
    bpf_printk(STR(NAME)"nat-ret %s", tmp);
#endif

  // reverse nat
  __u32 olddest = in_ih->daddr;
  __u16 olddestport = in_th->dest;
  in_ih->daddr = val->addr;
  in_th->dest = val->port;

  // update ip checksum
  __u32 check;
  check = in_ih->check;
  check = ~check;
  check -= olddest & 0xffff;
  check -= olddest >> 16;
  check += in_ih->daddr & 0xffff;
  check += in_ih->daddr >> 16;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  in_ih->check = check;

  // update tcp checksum
  check = in_th->check;
  check = ~check;
  check -= olddest & 0xffff;
  check -= olddest >> 16;
  check -= olddestport;
  check += in_ih->daddr & 0xffff;
  check += in_ih->daddr >> 16;
  check += in_th->dest;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  in_th->check = check;

  // mac addr swap
  __u8 tmpmac[6] = {0};
  memcpy(tmpmac, eh->h_dest, 6);
  memcpy(eh->h_dest, eh->h_source, 6);
  memcpy(eh->h_source, tmpmac, 6);

  // Resolve tunsrc
  __u32 z = 0;
  struct in6_addr *tunsrc = bpf_map_lookup_elem(&GLUE(NAME, encap_source), &z);
  if (!tunsrc) {
    bpf_printk(STR(NAME)"no tunsrc is set");
    return ignore_packet(ctx);
  }

  // Craft new ipv6 header
  memcpy(&oh->ip6.saddr, tunsrc, sizeof(struct in6_addr));
  memcpy(&oh->ip6.daddr, srv6_vm_remote_sid, sizeof(struct in6_addr));
  memcpy(&oh->seg, srv6_vm_remote_sid, sizeof(struct in6_addr));

  return XDP_TX;
}

static inline int
process_nat_out(struct xdp_md *ctx, struct trie_val *val)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  // Prepare Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);
  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);
  __u8 in_ih_len = in_ih->ihl * 4;
  struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_th, data_end);

  // NAT out
  __u32 hash = 0;
  hash = jhash_2words(in_ih->daddr, in_ih->saddr, 0xdeadbeaf);
  hash = jhash_2words(in_th->dest, in_th->source, hash);
  hash = jhash_2words(in_ih->protocol, 0, hash);
  __u32 sourceport = hash & 0xffff;

  struct nat_ret_table_key key = {
    .addr = val->vip,
    .port = sourceport,
  };
  struct nat_ret_table_val nval = {
    .addr = in_ih->saddr,
    .port = in_th->source,
  };
  bpf_map_update_elem(&GLUE(NAME, nat_ret_table), &key, &nval, BPF_ANY);

#ifdef DEBUG
  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u/%pi4:%u -> %pi4:%u",
              in_ih->protocol,
              &in_ih->saddr, bpf_ntohs(in_th->source),
              &val->vip, bpf_ntohs(sourceport),
              &in_ih->daddr, bpf_ntohs(in_th->dest));
  bpf_printk(STR(NAME)"nat-out %s", tmp);
#endif

  __u32 oldsource = in_ih->saddr;
  __u16 oldsourceport = in_th->source;
  in_ih->saddr = val->vip;
  in_th->source = sourceport;

  // Special thanks: kametan0730/curo
  // https://github.com/kametan0730/curo/blob/master/nat.cpp

  // update ip checksum
  __u32 check;
  check = in_ih->check;
  check = ~check;
  check -= oldsource & 0xffff;
  check -= oldsource >> 16;
  check += in_ih->saddr & 0xffff;
  check += in_ih->saddr >> 16;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  in_ih->check = check;

  // update tcp checksum
  check = in_th->check;
  check = ~check;
  check -= oldsource & 0xffff;
  check -= oldsource >> 16;
  check -= oldsourceport;
  check += in_ih->saddr & 0xffff;
  check += in_ih->saddr >> 16;
  check += in_th->source;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  in_th->check = check;

  // mac addr swap
  struct ethhdr *old_eh = (struct ethhdr *)data;
  struct ethhdr *new_eh = (struct ethhdr *)(data + sizeof(struct outer_header));
  assert_len(new_eh, data_end);
  assert_len(old_eh, data_end);
  new_eh->h_proto = bpf_htons(ETH_P_IP);
  memcpy(new_eh->h_source, old_eh->h_dest, 6);
  memcpy(new_eh->h_dest, old_eh->h_source, 6);

  // decap and TX
  if (bpf_xdp_adjust_head(ctx, 0 + (int)sizeof(struct outer_header))) {
    return error_packet(ctx);
  }
  return XDP_TX;
}

static inline int
process_ipv6(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  // Check Outer Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);
  if (oh->ip6.nexthdr != IPPROTO_ROUTING ||
      oh->srh.type != 4 ||
      oh->srh.hdrlen != 2 ||
      same_ipv6(&oh->ip6.daddr, srv6_local_sid, 6) != 0) { // TODO(slankdev)
    return ignore_packet(ctx);
  }

  // Lookup SRv6 SID
  struct trie_key key = {0};
  key.prefixlen = 128;
  memcpy(&key.addr, &oh->ip6.daddr, sizeof(struct in6_addr));
  struct trie_val *val = bpf_map_lookup_elem(&GLUE(NAME, fib6), &key);
  if (!val) {
    return ignore_packet(ctx);
  }

  // Parse Inner Headers
  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);
  __u8 in_ih_len = in_ih->ihl * 4;
  struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_th, data_end);

  // NAT check
  return in_ih->daddr == val->vip ?
    process_nat_return(ctx) :
    process_nat_out(ctx, val);
}

static inline int
process_ethernet(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = 0;

  struct ethhdr *eth_hdr = (struct ethhdr *)data;
  assert_len(eth_hdr, data_end);
  pkt_len = data_end - data;

  switch (bpf_htons(eth_hdr->h_proto)) {
  case 0x86dd:
    return process_ipv6(ctx);
  default:
    return ignore_packet(ctx);
  }
}

SEC("xdp-ingress") int
xdp_ingress(struct xdp_md *ctx)
{
  int act = process_ethernet(ctx);
  return act;
}

char __license[] SEC("license") = "GPL";
