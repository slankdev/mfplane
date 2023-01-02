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

#define MAX_RULES 2
#ifndef MAX_RULES
#error "please define MAX_RULES"
#endif

#define RING_SIZE 7
#ifndef RING_SIZE
#error "please define RING_SIZE"
#endif

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct flow_processor);
  __uint(max_entries, RING_SIZE * MAX_RULES);
} GLUE(NAME, procs) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie6_key));
  __uint(value_size, sizeof(struct trie6_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} GLUE(NAME, fib6) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct vip_key);
  __type(value, struct vip_val);
  __uint(max_entries, MAX_RULES);
} GLUE(NAME, vip_table) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, 1);
} GLUE(NAME, encap_source) SEC(".maps");

static inline int
process_nat_return(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = data_end - data;

  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct iphdr *ih = (struct iphdr *)(eh + 1);
  assert_len(ih, data_end);
  if (ih->protocol != IPPROTO_TCP)
    return ignore_packet(ctx);
  struct tcphdr *th = (struct tcphdr *)((char *)ih + ih->ihl * 4);
  assert_len(th, data_end);

  struct vip_key vk = {0};
  vk.vip = ih->daddr;
  struct vip_val *vv = bpf_map_lookup_elem(&GLUE(NAME, vip_table), &vk);
  if (!vv) {
    bpf_printk(STR(NAME)"nono");
    return ignore_packet(ctx);
  }

  __u16 hash = th->dest;
  hash = hash & vv->nat_port_hash_bit;
  __u32 idx = hash % RING_SIZE;
  idx = RING_SIZE * vv->backend_block_index + idx;
  struct flow_processor *p = bpf_map_lookup_elem(&GLUE(NAME, procs), &idx);
  if (!p) {
    bpf_printk(STR(NAME)"no entry fatal");
    return ignore_packet(ctx);
  }

#ifdef DEBUG
  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp),
               "dn-flow=[%pi4:%u %pi4:%u %u] hash=0x%08x/%u idx=%u hb=0x%x",
               &ih->saddr, bpf_ntohs(th->source),
               &ih->daddr, bpf_ntohs(th->dest),
               ih->protocol, hash, hash, idx, vv->nat_port_hash_bit);
  bpf_printk(STR(NAME)"%s", tmp);
#endif

  // Adjust packet buffer head pointer
  if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct outer_header)))) {
    return error_packet(ctx);
  }
  data = ctx->data;
  data_end = ctx->data_end;

  // Resolve tunsrc
  __u32 z = 0;
  struct in6_addr *tunsrc = bpf_map_lookup_elem(&GLUE(NAME, encap_source), &z);
  if (!tunsrc) {
    bpf_printk(STR(NAME)"no tunsrc is set");
    return ignore_packet(ctx);
  }

  // Craft new ether header
  struct ethhdr *new_eh = (struct ethhdr *)data;
  struct ethhdr *old_eh = (struct ethhdr *)(data + sizeof(struct outer_header));
  assert_len(new_eh, data_end);
  assert_len(old_eh, data_end);
  memcpy(new_eh->h_dest, old_eh->h_source, 6);
  memcpy(new_eh->h_source, old_eh->h_dest, 6);
  new_eh->h_proto = bpf_htons(ETH_P_IPV6);

  // Craft outer IP6 SRv6 header
  struct outer_header *oh = (struct outer_header *)(new_eh + 1);
  assert_len(oh, data_end);
  oh->ip6.version = 6;
  oh->ip6.priority = 0;
  oh->ip6.payload_len = bpf_ntohs(pkt_len - sizeof(struct ethhdr) +
    sizeof(struct ipv6_rt_hdr) + 4 + sizeof(struct in6_addr));
  oh->ip6.nexthdr = 43; // SR header
  oh->ip6.hop_limit = 64;
  memcpy(&oh->ip6.saddr, tunsrc, sizeof(struct in6_addr));
  memcpy(&oh->ip6.daddr, &p->addr, sizeof(struct in6_addr));
  oh->srh.hdrlen = 2;
  oh->srh.nexthdr = 4;
  oh->srh.segments_left = 0;
  oh->srh.type = 4;
  memcpy(&oh->seg, &p->addr, sizeof(struct in6_addr));

  return XDP_TX;
}

static inline int
process_ipv4_tcp(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = data_end - data;

  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct iphdr *ih = (struct iphdr *)(eh + 1);
  assert_len(ih, data_end);

  struct vip_key vk = {0};
  vk.vip = ih->daddr;
  struct vip_val *vv = bpf_map_lookup_elem(&GLUE(NAME, vip_table), &vk);
  if (vv) {
    return process_nat_return(ctx);
  }

#if 0 // This is End.MFL.R mode
  __u32 vip = bpf_ntohl(0x0afe000a); // 10.254.0.10
  if (ih->daddr != vip) {
    return ignore_packet(ctx);
  }

  __u8 hdr_len = ih->ihl * 4;
  struct tcphdr *th = (struct tcphdr *)((char *)ih + hdr_len);
  assert_len(th, data_end);

  __u32 hash = 0;
  hash = jhash_2words(ih->saddr, ih->daddr, 0xdeadbeaf);
  hash = jhash_2words(th->source, th->dest, hash);
  hash = jhash_2words(ih->protocol, 0, hash);
  hash = hash & 0xffff;

  __u32 idx = hash % RING_SIZE;
  struct flow_processor *p = bpf_map_lookup_elem(&GLUE(NAME, procs), &idx);
  if (!p) {
#ifdef DEBUG
    bpf_printk(STR(NAME)"no entry fatal");
#endif
    return ignore_packet(ctx);
  }

  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp), "%pi4:%u %pi4:%u %u -> %pi6",
               &ih->saddr, bpf_ntohs(th->source),
               &ih->daddr, bpf_ntohs(th->dest),
               ih->protocol, &p->addr);
#ifdef DEBUG
  bpf_printk(STR(NAME)"dn-flow=[%s] hash=0x%08x idx=%u", tmp, hash, idx);
#endif

  // Adjust packet buffer head pointer
  if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct outer_header)))) {
    return error_packet(ctx);
  }
  data = ctx->data;
  data_end = ctx->data_end;

  // Craft new ether header
  struct ethhdr *new_eh = (struct ethhdr *)data;
  struct ethhdr *old_eh = (struct ethhdr *)(data + sizeof(struct outer_header));
  assert_len(new_eh, data_end);
  assert_len(old_eh, data_end);
  memcpy(new_eh->h_dest, old_eh->h_source, 6);
  memcpy(new_eh->h_source, old_eh->h_dest, 6);
  new_eh->h_proto = bpf_htons(ETH_P_IPV6);

  // Resolve tunsrc
  __u32 z = 0;
  struct in6_addr *tunsrc = bpf_map_lookup_elem(&GLUE(NAME, encap_source), &z);
  if (!tunsrc) {
    bpf_printk("no tunsrc is set");
    return ignore_packet(ctx);
  }

  // Craft outer IP6 SRv6 header
  struct outer_header *oh = (struct outer_header *)(new_eh + 1);
  assert_len(oh, data_end);
  oh->ip6.version = 6;
  oh->ip6.priority = 0;
  oh->ip6.payload_len = bpf_ntohs(pkt_len - sizeof(struct ethhdr) +
    sizeof(struct ipv6_rt_hdr) + 4 + sizeof(struct in6_addr));
  oh->ip6.nexthdr = 43; // SR header
  oh->ip6.hop_limit = 64;
  memcpy(&oh->ip6.saddr, tunsrc, sizeof(struct in6_addr));
  memcpy(&oh->ip6.daddr, &p->addr, sizeof(struct in6_addr));
  oh->srh.hdrlen = 2;
  oh->srh.nexthdr = 4;
  oh->srh.segments_left = 0;
  oh->srh.type = 4;
  memcpy(&oh->seg, &p->addr, sizeof(struct in6_addr));

  ///////////////////////////////////////////////////
  // TODO(slankdev): set the NEXT_SID from p->addr //
  ///////////////////////////////////////////////////

  return XDP_TX;
#endif

  return ignore_packet(ctx);
}

static inline int
process_ipv6(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);

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

  if (oh->ip6.nexthdr != IPPROTO_ROUTING ||
      oh->srh.type != 4 || oh->srh.hdrlen != 2) {
    return ignore_packet(ctx);
  }

  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);
  const __u8 in_ih_len = in_ih->ihl * 4;

  __u32 hash = 0;
  __u16 sport = 0, dport = 0;
  switch (in_ih->protocol) {
  case IPPROTO_TCP:
  {
    struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_th, data_end);
    sport = in_th->source;
    dport = in_th->dest;
    hash = jhash_2words(in_ih->daddr, in_ih->saddr, 0xdeadbeaf);
    hash = jhash_2words(sport, dport, hash);
    hash = jhash_2words(in_ih->protocol, 0, hash);
    break;
  }
  case IPPROTO_UDP:
  {
    struct udphdr *in_uh = (struct udphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_uh, data_end);
    sport = in_uh->source;
    dport = in_uh->dest;
    hash = jhash_2words(in_ih->daddr, in_ih->saddr, 0xdeadbeaf);
    hash = jhash_2words(sport, dport, hash);
    hash = jhash_2words(in_ih->protocol, 0, hash);
    break;
  }
  case IPPROTO_ICMP:
  default:
    bpf_printk(STR(NAME)"nat unsupport l4 proto %d", in_ih->protocol);
    return ignore_packet(ctx);
  }
  hash = hash & 0xffff;
  hash = hash & val->nat_port_hash_bit;

  __u32 idx = 0;
  idx = hash % RING_SIZE;
  idx = RING_SIZE * val->backend_block_index + idx;
  struct flow_processor *p = bpf_map_lookup_elem(&GLUE(NAME, procs), &idx);
  if (!p) {
    bpf_printk(STR(NAME)"no entry fatal");
    return ignore_packet(ctx);
  }

#ifdef DEBUG
  char tmpstr[128] = {0};
  BPF_SNPRINTF(tmpstr, sizeof(tmpstr),
               "up-flow=[%pi4:%u %pi4:%u %u] hash=0x%08x/%u idx=%u hb=0x%x",
               &in_ih->saddr, bpf_ntohs(sport),
               &in_ih->daddr, bpf_ntohs(dport),
               in_ih->protocol, hash, hash, idx, val->nat_port_hash_bit);
  bpf_printk(STR(NAME)"%s", tmpstr);
#endif

  ///////////////////////////////////////////////////
  // TODO(slankdev): set the NEXT_SID from p->addr //
  ///////////////////////////////////////////////////

  // Craft new ether header
  __u8 tmp[6] = {0};
  memcpy(tmp, eh->h_dest, 6);
  memcpy(eh->h_dest, eh->h_source, 6);
  memcpy(eh->h_source, tmp, 6);

  // Resolve tunsrc
  __u32 z = 0;
  struct in6_addr *tunsrc = bpf_map_lookup_elem(&GLUE(NAME, encap_source), &z);
  if (!tunsrc) {
    bpf_printk("no tunsrc is set");
    return ignore_packet(ctx);
  }

  // Craft new ipv6 header
  memcpy(&oh->ip6.saddr, tunsrc, sizeof(*tunsrc));
  memcpy(&oh->ip6.daddr, &p->addr, sizeof(struct in6_addr));
  memcpy(&oh->seg, &p->addr, sizeof(struct in6_addr));

  return XDP_TX;
}

static inline int
process_ipv4(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  struct iphdr *ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(ih, data_end);
  __u64 pkt_len = data_end - data;

  if (ih->ihl < 5)
    return XDP_PASS;

  switch (ih->protocol) {
  case IPPROTO_TCP:
    return process_ipv4_tcp(ctx);
  default:
    return ignore_packet(ctx);
  }
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
  case 0x0800:
    return process_ipv4(ctx);
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
