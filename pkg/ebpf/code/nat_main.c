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

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie4_key));
  __uint(value_size, sizeof(struct trie4_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} GLUE(NAME, fib4) SEC(".maps");

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

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, 1);
} GLUE(NAME, encap_source) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie6_key));
  __uint(value_size, sizeof(struct trie6_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} GLUE(NAME, fib6) SEC(".maps");

static inline void shift8(int oct_offset, struct in6_addr *a)
{
  __u8 *addr = a->in6_u.u6_addr8;
  for (__u8 i = 0; i < sizeof(struct in6_addr); i++) {
    if (i >= oct_offset) {
      if (i < sizeof(struct in6_addr) - 1)
        addr[i] = addr[i+1];
      else
        addr[i] = 0;
    }
  }
}

static inline int finished(struct in6_addr *addr, int oct_offset, int n_shifts)
{
  for (int i = 0; i < oct_offset + n_shifts & i < sizeof(struct in6_addr); i++)
    if (i >= oct_offset)
      if (addr->in6_u.u6_addr8[i] != 0)
        return 0;
  return 1;
}

static inline int
process_mf_redirect(struct xdp_md *ctx, struct trie6_val *val)
{
  bpf_printk(STR(NAME)"try mf_redirect");

  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  // Prepare Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);

  if (!val) {
    bpf_printk(STR(NAME)"failed");
    return XDP_DROP;
  }

  int oct_offset = val->usid_block_length / 8;
  int n_shifts = val->usid_function_length / 8;
  if (finished(&oh->ip6.daddr, oct_offset, n_shifts)) {
    bpf_printk(STR(NAME)"mf_redirect finished");
    return XDP_DROP;
  }

  // bit shitt
  for (int j = 0; j < n_shifts & j < 4; j++) {
    shift8(oct_offset, &oh->ip6.daddr);
  }

  // mac addr swap
  __u8 tmpmac[6] = {0};
  memcpy(tmpmac, eh->h_dest, 6);
  memcpy(eh->h_dest, eh->h_source, 6);
  memcpy(eh->h_source, tmpmac, 6);

  val->stats_redir_bytes += data_end - data;
  val->stats_redir_pkts++;
  return XDP_TX;
}

static inline int
process_nat_ret(struct xdp_md *ctx, struct trie6_val *val)
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
  const __u8 in_ih_len = in_ih->ihl * 4;
  struct udphdr *in_th = (struct udphdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_th, data_end);

  // XXX(slankdev): If we delete following if block, memcpy doesn't work...
  __u8 *dummy_ptr = (__u8 *)&oh->ip6.daddr;

  // lookup
  struct addr_port *nval = NULL;
  struct addr_port key = {
    .addr = in_ih->daddr,
    .port = in_th->dest,
  };
  nval = bpf_map_lookup_elem(&(GLUE(NAME, nat_ret_table)), &key);
  if (!nval) {
    return process_mf_redirect(ctx, val);
  }

#ifdef DEBUG
    char tmp[128] = {0};
    BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u -> %pi4:%u/%pi4:%u",
                in_ih->protocol,
                &in_ih->saddr, bpf_ntohs(in_th->source),
                &in_ih->daddr, bpf_ntohs(in_th->dest),
                &nval->addr, bpf_ntohs(nval->port));
    bpf_printk(STR(NAME)"nat-ret %s", tmp);
#endif

  // reverse nat
  __u32 olddest = in_ih->daddr;
  __u16 olddestport = in_th->dest;
  in_ih->daddr = nval->addr;
  in_th->dest = nval->port;

  // update checksum
  in_ih->check = checksum_recalc_addr(olddest, in_ih->daddr, in_ih->check);
  if (in_ih->protocol == IPPROTO_TCP) {
    struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_th, data_end);
    in_th->check = checksum_recalc_addrport(olddest, in_ih->daddr,
      olddestport, in_th->dest, in_th->check);
  }

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

  // Resolve next hypervisor
  struct trie4_key key4 = {0};
  key4.addr = in_ih->daddr;
  key4.prefixlen = 32;
  struct trie4_val *val4 = bpf_map_lookup_elem(&GLUE(NAME, fib4), &key4);
  if (!val4) {
    bpf_printk(STR(NAME)"fib4 lookup failed");
    return ignore_packet(ctx);
  }

  // Craft new ipv6 header
  memcpy(&oh->ip6.saddr, tunsrc, sizeof(struct in6_addr));
  memcpy(&oh->ip6.daddr, &val4->segs[0], sizeof(struct in6_addr));
  memcpy(&oh->seg, &val4->segs[0], sizeof(struct in6_addr));

  return XDP_TX;
}

static inline int
process_nat_out(struct xdp_md *ctx, struct trie6_val *val)
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
  const __u8 in_ih_len = in_ih->ihl * 4;

  __u8 syn = 0;
  if (in_ih->protocol == IPPROTO_TCP) {
    struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_th, data_end);
    syn = in_th->syn;
  }

  __u16 sport = 0, dport = 0;
  switch (in_ih->protocol) {
  case IPPROTO_TCP:
  case IPPROTO_UDP:
  {
    struct udphdr *in_uh = (struct udphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_uh, data_end);
    sport = in_uh->source;
    dport = in_uh->dest;
    break;
  }
  default:
    bpf_printk(STR(NAME)"nat unsupport l4 proto %d", in_ih->protocol);
    return ignore_packet(ctx);
  }

  struct addr_port key = {0};
  key.addr = in_ih->saddr;
  key.port = sport;

  __u32 sourceport = 0;
  struct addr_port_stats *asval = bpf_map_lookup_elem(&(GLUE(NAME, nat_out_table)), &key);
  if (!asval) {
    if (in_ih->protocol == IPPROTO_TCP && syn == 0)
      return process_mf_redirect(ctx, val);

    __u32 hash = 0;
    switch (in_ih->protocol) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
      // TODO(slankdev): Support Endpoint Independent Mapping
      hash = jhash_2words(in_ih->daddr, in_ih->saddr, 0xdeadbeaf);
      hash = jhash_2words(dport, sport, hash);
      hash = jhash_2words(in_ih->protocol, 0, hash);
      bpf_printk(STR(NAME)"hash 0x%08x", hash);
      break;
    case IPPROTO_ICMP:
    default:
      bpf_printk(STR(NAME)"nat unsupport l4 proto %d", in_ih->protocol);
      return ignore_packet(ctx);
    }
    hash = hash & 0xffff;
    hash = hash & val->nat_port_hash_bit;
    bpf_printk(STR(NAME)"hash 0x%08x (short)", hash);

    // TODO(slankdev): we should search un-used slot instead of rand-val.
    __u32 rand = bpf_get_prandom_u32();
    rand = rand & 0xffff;
    rand = rand & ~val->nat_port_hash_bit;
    sourceport = hash | rand;

    struct addr_port_stats natval = {
      .addr = val->vip,
      .port = sourceport,
      .pkts = 1,
    };
    struct addr_port_stats orgval = {
      .addr = in_ih->saddr,
      .port = sport,
      .pkts = 1,
    };
    bpf_map_update_elem(&GLUE(NAME, nat_ret_table), &natval, &orgval, BPF_ANY);
    bpf_map_update_elem(&GLUE(NAME, nat_out_table), &orgval, &natval, BPF_ANY);

  } else {
    asval->pkts++;
    sourceport = asval->port;
  }

#ifdef DEBUG
  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u/%pi4:%u -> %pi4:%u",
              in_ih->protocol,
              &in_ih->saddr, bpf_ntohs(sport),
              &val->vip, bpf_ntohs(sourceport),
              &in_ih->daddr, bpf_ntohs(dport));
  bpf_printk(STR(NAME)"nat-out %s", tmp);
#endif

  __u32 oldsource = in_ih->saddr;
  __u16 oldsourceport = sport;
  in_ih->saddr = val->vip;

  switch (in_ih->protocol) {
  case IPPROTO_TCP:
    {
      struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
      assert_len(in_th, data_end);
      in_th->source = sourceport;
      in_th->check = checksum_recalc_addrport(oldsource, in_ih->saddr,
        oldsourceport, in_th->source, in_th->check);
      break;
    }
  case IPPROTO_UDP:
    {
      struct udphdr *in_uh = (struct udphdr *)((__u8 *)in_ih + in_ih_len);
      assert_len(in_uh, data_end);
      in_uh->source = sourceport;
      break;
    }
  }

  // update checksum
  in_ih->check = checksum_recalc_addr(oldsource, in_ih->saddr, in_ih->check);

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
      oh->srh.hdrlen != 2) {
    return ignore_packet(ctx);
  }

  // Lookup SRv6 SID
  struct trie6_key key = {0};
  key.prefixlen = 128;
  memcpy(&key.addr, &oh->ip6.daddr, sizeof(struct in6_addr));
  struct trie6_val *val = bpf_map_lookup_elem(&GLUE(NAME, fib6), &key);
  if (!val) {
    return ignore_packet(ctx);
  }
  val->stats_total_bytes += data_end - data;
  val->stats_total_pkts++;

  // NAT check
  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);
  return in_ih->daddr == val->vip ?
    process_nat_ret(ctx, val) :
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
