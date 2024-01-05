/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2023 Hiroki Shirokura.
 * Copyright 2023 Kyoto University.
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

#ifndef MAX_RULES
#define MAX_RULES 2
#endif
#ifndef RING_SIZE
#define RING_SIZE 7
#endif
#ifndef NAT_CACHE_MAX_RULES
#define NAT_CACHE_MAX_RULES 65535
#endif

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie4_key));
  __uint(value_size, sizeof(struct trie4_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, fib4) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(key_size, sizeof(struct trie6_key));
  __uint(value_size, sizeof(struct trie6_val));
  __uint(max_entries, 50);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, fib6) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(key_size, sizeof(struct overlay_fib4_key));
  __uint(value_size, sizeof(struct overlay_fib4_val));
  __uint(max_entries, 100);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, overlay_fib4) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct flow_processor);
  __uint(max_entries, RING_SIZE * MAX_RULES);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, lb_backend) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct in6_addr);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, encap_source) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NAT_CACHE_MAX_RULES);
  __type(key, struct addr_port);
  __type(value, struct addr_port_stats);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, nat_out) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NAT_CACHE_MAX_RULES);
  __type(key, struct addr_port);
  __type(value, struct addr_port_stats);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, nat_ret) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65535);
  __type(key, struct mf_redir_rate_stat_key);
  __type(value, struct mf_redir_rate_stat_val);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, rate_stats) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));   // TODO: nos sure it is needed or not
  __uint(value_size, sizeof(__u32)); // TODO: nos sure it is needed or not
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, events) SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(key_size, sizeof(struct neigh_key));
  __uint(value_size, sizeof(struct neigh_val));
  __uint(max_entries, 100);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} GLUE(NAME, neigh) SEC(".maps");

// NOTE(slankdev); It's possible verifier will be failed when the semantic
// sorting is adopted. In this case, we sorted by size and its alignment
// perspective.
struct metadata {
  __u8 ether_dst[6];               // 6
  __u16 ether_type;                // 8
  __u16 l3_offset;                 // 10
  __u8 l3_proto;                   // 11
  __u8 nh_family;                  // 12
  __u32 l3_saddr;                  // 16
  __u32 l3_daddr;                  // 20
  __u16 l4_sport;                  // 22
  __u16 l4_dport;                  // 24
  __u16 l4_icmp_id;                // 26
  __u16 num_segs;                  // 28
  __u32 nh_addr4;                  // 32
  struct in6_addr outer_ip6_saddr; // 48
  struct in6_addr outer_ip6_daddr; // 64
  struct in6_addr nh_addr6;        // 72
};

static inline int
tx_packet_neigh(struct xdp_md *ctx, int line,
                struct metadata *md)
{
  debug_function_call(ctx, __func__, line);

  struct trie4_key key = {0};
  struct trie4_val *val = NULL;
  struct trie6_key t6_key = {0};
  struct trie6_val *t6_val = NULL;
  struct neigh_key nk = {0};
  struct neigh_val *nv = NULL;
  __u8 *mac = NULL;

  // L3 Lookup
  switch (md->nh_family) {
  case AF_INET:
    key.addr = md->nh_addr4;
    key.prefixlen = 32;
    val = bpf_map_lookup_elem(&GLUE(NAME, fib4), &key);
    if (!val) {
      return error_packet(ctx, __LINE__);
    }
    switch (val->action) {
    case TRIE4_VAL_ACTION_L3_XCONNECT:
      if (val->l3_xconn_nh_count > 1) {
        return error_packet(ctx, __LINE__);
      }
      nk.family = val->l3_xconn_nh[0].nh_family;
      nk.addr4 = val->l3_xconn_nh[0].nh_addr4;
      memcpy(&nk.addr6, &val->l3_xconn_nh[0].nh_addr6, 16);
      nv = bpf_map_lookup_elem(&GLUE(NAME, neigh), &nk);
      if (!nv) {
        return error_packet(ctx, __LINE__);
      }
      mac = nv->mac;
      break;
    default:
      return error_packet(ctx, __LINE__);
    }
    break;
  case AF_INET6:
    memcpy(&t6_key.addr, &md->nh_addr6, sizeof(struct in6_addr));
    t6_key.prefixlen = 128;
    t6_val = bpf_map_lookup_elem(&GLUE(NAME, fib6), &t6_key);
    if (!t6_val) {
      return error_packet(ctx, __LINE__);
    }
    switch (t6_val->action) {
    case TRIE6_VAL_ACTION_L3_XCONNECT:
      if (t6_val->l3_xconn_nh_count > 1) {
        return error_packet(ctx, __LINE__);
      }
      nk.family = t6_val->l3_xconn_nh[0].nh_family;
      nk.addr4 = t6_val->l3_xconn_nh[0].nh_addr4;
      memcpy(&nk.addr6, &t6_val->l3_xconn_nh[0].nh_addr6, 16);
      nv = bpf_map_lookup_elem(&GLUE(NAME, neigh), &nk);
      if (!nv) {
        return error_packet(ctx, __LINE__);
      }
      mac = nv->mac;
      break;
    default:
      return error_packet(ctx, __LINE__);
    }
    break;
  default:
    return error_packet(ctx, __LINE__);
  }

  // Parse header
  if (!mac) {
    return error_packet(ctx, __LINE__);
  }

  // Write-back Ether header
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  memcpy(eh->h_dest, mac, 6);

  // Increment Counter Vals
  __u32 idx = 0;
  struct counter_val *cv = bpf_map_lookup_elem(&GLUE(NAME, counter), &idx);
  if (cv) {
    cv->xdp_action_tx_pkts ++;
    // cv->xdp_action_tx_bytes += ??;
  }

  return XDP_TX;
}

#define E_UNKNOWN_ETH_PROTO          -10
#define E_UNKNOWN_IPV4_PROTO         -20
#define E_UNKNOWN_IPV6_NEXTHDR_PROTO -30
#define E_UNKNOWN_RTH_TYPE           -40
#define E_UNKNOWN_SRH_NEXTHDR_PROTO  -50

static inline int
parse_metadata(struct xdp_md *ctx, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 size_srh = 0;
  __u8 ihl = 0;

  struct ethhdr *eh = NULL;
  struct iphdr *i4h = NULL;
  struct ipv6hdr *i6h = NULL;
  struct l4hdr *l4h = NULL;
  struct srh *srh = NULL;
  struct iphdr *inner_i4h = NULL;
  struct l4hdr *inner_l4h = NULL;

  // Prepare Headers
  eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  memcpy(md->ether_dst, eh->h_dest, 6);
  md->ether_type = bpf_htons(eh->h_proto);

  switch (md->ether_type) {
  case ETH_P_IP:
    i4h = (struct iphdr *)(eh + 1);
    assert_len(i4h, data_end);
    ihl = i4h->ihl * 4;
    l4h = (struct l4hdr *)((__u8 *)i4h + ihl);
    assert_len(l4h, data_end);
    md->l3_offset = (__u8 *)i4h - (__u8 *)data;
    md->l3_proto = i4h->protocol;
    md->l3_saddr = i4h->saddr;
    md->l3_daddr = i4h->daddr;
    switch (md->l3_proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
      md->l4_sport = l4h->source;
      md->l4_dport = l4h->dest;
      break;
    case IPPROTO_ICMP:
      md->l4_icmp_id = l4h->icmp_id;
      break;
    default:
      return E_UNKNOWN_IPV4_PROTO;
    }
    break;
  case ETH_P_IPV6:
    i6h = (struct ipv6hdr *)(eh + 1);
    assert_len(i6h, data_end);
    memcpy(&md->outer_ip6_daddr, &i6h->daddr, sizeof(struct in6_addr));
    memcpy(&md->outer_ip6_saddr, &i6h->saddr, sizeof(struct in6_addr));
    switch (i6h->nexthdr) {
    case IPPROTO_IPIP:
      inner_i4h = (struct iphdr *)(i6h + 1);
      assert_len(inner_i4h, data_end);
      ihl = inner_i4h->ihl * 4;
      inner_l4h = (struct l4hdr *)((__u8 *)inner_i4h + ihl);
      assert_len(inner_l4h, data_end);
      md->l3_offset = (__u8 *)inner_i4h - (__u8 *)data;
      md->l3_proto = inner_i4h->protocol;
      md->l3_saddr = inner_i4h->saddr;
      md->l3_daddr = inner_i4h->daddr;
      switch (md->l3_proto) {
      case IPPROTO_TCP:
      case IPPROTO_UDP:
        md->l4_sport = inner_l4h->source;
        md->l4_dport = inner_l4h->dest;
        break;
      case IPPROTO_ICMP:
        md->l4_icmp_id = inner_l4h->icmp_id;
        break;
      default:
        return E_UNKNOWN_IPV4_PROTO;
      }
      break;
    case IPPROTO_ROUTING:
      srh = (struct srh *)(i6h + 1);
      assert_len(srh, data_end);
      switch (srh->routing_type) {
      case IPV6_SRCRT_TYPE_4:
        md->num_segs = srh->hdr_ext_len / 2;
        switch (srh->next_header) {
        case IPPROTO_IPIP:
          size_srh = 8 + sizeof(struct in6_addr) * md->num_segs;
          inner_i4h = (struct iphdr *)((__u8 *)(srh) + size_srh);
          assert_len(inner_i4h, data_end);
          ihl = inner_i4h->ihl * 4;
          inner_l4h = (struct l4hdr *)((__u8 *)inner_i4h + ihl);
          assert_len(inner_l4h, data_end);
          md->l3_offset = (__u8 *)inner_i4h - (__u8 *)data;
          md->l3_proto = inner_i4h->protocol;
          md->l3_saddr = inner_i4h->saddr;
          md->l3_daddr = inner_i4h->daddr;
          switch (md->l3_proto) {
          case IPPROTO_TCP:
          case IPPROTO_UDP:
            md->l4_sport = inner_l4h->source;
            md->l4_dport = inner_l4h->dest;
            break;
          case IPPROTO_ICMP:
            md->l4_icmp_id = inner_l4h->icmp_id;
            break;
          default:
            return E_UNKNOWN_IPV4_PROTO;
          }
          break;
        default:
          return E_UNKNOWN_SRH_NEXTHDR_PROTO;
        }
        break;
      default:
        return E_UNKNOWN_RTH_TYPE;
      }
      break;
    default:
      return E_UNKNOWN_IPV6_NEXTHDR_PROTO;
      break;
    }
    break;
  default:
    return E_UNKNOWN_ETH_PROTO;
  }

  return 0;
}

static inline int
process_nat_return(struct xdp_md *ctx, struct trie4_key *key,
                   struct trie4_val *val, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = data_end - data;

  // Prepare Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct iphdr *ih = (struct iphdr *)(eh + 1);
  assert_len(ih, data_end);
  struct l4hdr *l4h = (struct l4hdr *)((char *)ih + ih->ihl * 4);
  assert_len(l4h, data_end);

  // Calculate Hash
  __u16 hash = 0;
  if (ih->protocol == IPPROTO_TCP || ih->protocol == IPPROTO_UDP) {
    hash = l4h->dest;
  } else if (ih->protocol == IPPROTO_ICMP) {
    hash = l4h->icmp_id;
  } else {
    return ignore_packet(ctx, __LINE__);
  }
  hash = hash & val->nat_port_hash_bit;

  // Resolve Backend node
  __u32 idx = hash % RING_SIZE;
  idx = RING_SIZE * val->backend_block_index + idx;
  struct flow_processor *p = bpf_map_lookup_elem(&GLUE(NAME, lb_backend), &idx);
  if (!p) {
    return ignore_packet(ctx, __LINE__);
  }

#ifdef DEBUG
  char tmp[128] = {0};
  char transport_debug_msg[128] = {0};
  if (ih->protocol == IPPROTO_TCP || ih->protocol == IPPROTO_UDP) {
    BPF_SNPRINTF(transport_debug_msg, sizeof(transport_debug_msg),
                 "0x%02x %pi4:%u %pi4:%u]", ih->protocol,
                 &ih->saddr, bpf_ntohs(l4h->source),
                 &ih->daddr, bpf_ntohs(l4h->dest));
  } else if (ih->protocol == IPPROTO_ICMP) {
    BPF_SNPRINTF(transport_debug_msg, sizeof(transport_debug_msg),
                 "0x%02x %pi4:%u %pi4]", ih->protocol,
                 &ih->saddr, bpf_ntohs(l4h->icmp_id),
                 &ih->daddr);
  }
  BPF_SNPRINTF(tmp, sizeof(tmp),
               "dn-flow=[%s] hash=0x%08x/%u idx=%u hb=0x%x",
               transport_debug_msg, hash, hash, idx, val->nat_port_hash_bit);
  // bpf_printk(STR(NAME)"%s", tmp);
#endif

  // Adjust packet buffer head pointer
  if (bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct outer_header)))) {
    return error_packet(ctx, __LINE__);
  }
  data = ctx->data;
  data_end = ctx->data_end;

  // Resolve tunsrc
  __u32 z = 0;
  struct in6_addr *tunsrc = bpf_map_lookup_elem(&GLUE(NAME, encap_source), &z);
  if (!tunsrc) {
    return ignore_packet(ctx, __LINE__);
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

  md->nh_family = AF_INET6;
  memcpy(&md->nh_addr6, &p->addr, sizeof(struct in6_addr));
  return tx_packet_neigh(ctx, __LINE__, md);
}

static inline int
process_ipv4(struct xdp_md *ctx, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = data_end - data;

  // Prepare Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct iphdr *ih = (struct iphdr *)(eh + 1);
  assert_len(ih, data_end);

  if (ih->ihl < 5)
    return XDP_PASS;

  struct trie4_key key = {0};
  key.addr = ih->daddr;
  key.prefixlen = 32;
  struct trie4_val *val = bpf_map_lookup_elem(&GLUE(NAME, fib4), &key);
  if (val) {
    return process_nat_return(ctx, &key, val, md);
  }

  // normal c-plane packets
  return ignore_packet(ctx, __LINE__);
}

static inline int
snat_match(struct trie6_val *val, __u32 saddr)
{
  for (int i = 0; i < 256; i++) {
    __u32 plen = val->sources[i].prefixlen;
    __u32 addr = val->sources[i].addr;
    if (plen == 0 && addr == 0)
      return 0;

    __u32 mask = 0;
    for (int j = 0; j < 32 && j < plen; j++)
      mask = mask | (0x80000000 >> j);
    mask = bpf_ntohl(mask);

    if (addr == (saddr & mask))
      return 1;
  }
  return 0;
}

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
process_mf_redirect(struct xdp_md *ctx, struct trie6_val *val,
                    struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  // Prepare Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);

#ifdef DEBUG_MF_REDIRECT
    const __u8 *da = oh->ip6.daddr.s6_addr;
    bpf_printk(STR(NAME)"%p before-shift addr begin ---", ctx);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[0], da[1]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[2], da[3]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[4], da[5]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[6], da[7]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[8], da[9]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[10], da[11]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[12], da[13]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[14], da[15]);
    bpf_printk(STR(NAME)"%p before-shift addr end   ---", ctx);
#endif

  // Execute bit shitt
  int oct_offset = val->usid_block_length / 8;
  int n_shifts = val->usid_function_length / 8;
  for (int j = 0; j < n_shifts & j < 4; j++)
    shift8(oct_offset, &oh->ip6.daddr);

  // Check MF-redirect is finished, then drop
  if (finished(&oh->ip6.daddr, oct_offset, n_shifts))
    return error_packet(ctx, __LINE__);

#ifdef DEBUG_MF_REDIRECT
    da = oh->ip6.daddr.s6_addr;
    bpf_printk(STR(NAME)"%p after-shift addr begin ---", ctx);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[0], da[1]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[2], da[3]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[4], da[5]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[6], da[7]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[8], da[9]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[10], da[11]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[12], da[13]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[14], da[15]);
    bpf_printk(STR(NAME)"%p after-shift addr end   ---", ctx);
#endif

#if 0
  // STAT Get
  struct mf_redir_rate_stat_key skey = {0};
  skey.addr = apkey->addr;
  skey.port = apkey->port;
  skey.proto = apkey->proto;
  skey.is_out = is_out;
  memcpy(&skey.next_sid, &oh->ip6.daddr, sizeof(struct in6_addr));

  struct mf_redir_rate_stat_val isval = {0};
  struct mf_redir_rate_stat_val *sval = bpf_map_lookup_elem(
    &(GLUE(NAME, rate_stats)), &skey);
  __u64 now = bpf_ktime_get_ns();

  if (!sval) {
    isval.bytes = data_end - data;
    isval.pkts = 1;
    isval.last_reset = now;
    bpf_map_update_elem(&GLUE(NAME, rate_stats), &skey, &isval, BPF_ANY);
    sval = &isval;
  } else {
    if (now - sval->last_reset > 5000000000) {
      if (sval->pkts > (5 * 10)) {
        // bpf_printk("perf");
        bpf_perf_event_output(ctx, &GLUE(NAME, events), BPF_F_CURRENT_CPU,
          &skey, sizeof(skey));
      }
      sval->bytes = data_end - data;
      sval->pkts = 1;
      sval->last_reset = now;
    } else {
      sval->bytes += data_end - data;
      sval->pkts += 1;
    }
  }
#endif

  // Set src mac addrs
  memcpy(eh->h_source, eh->h_dest, 6);
  val->stats_redir_bytes += data_end - data;
  val->stats_redir_pkts++;

  // TX packets
  md->nh_family = AF_INET6;
  memcpy(&md->nh_addr6, &oh->ip6.daddr, 16);
  return tx_packet_neigh(ctx, __LINE__, md);
}

static inline int
process_nat_ret(struct xdp_md *ctx, struct trie6_key *key_,
                struct trie6_val *val, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
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
  struct l4hdr *in_l4h = (struct l4hdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_l4h, data_end);

  // XXX(slankdev):
  // If we delete following if block, memcpy doesn't work...
  __u8 *dummy_ptr = (__u8 *)&oh->ip6.daddr;

  __u8 tcp_closing = 0;
  if (in_ih->protocol == IPPROTO_TCP) {
    struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_th, data_end);
    tcp_closing = in_th->rst || in_th->fin;
  }

  // Craft lookup key
  struct addr_port key = {0};
  key.addr = in_ih->daddr;
  key.proto = in_ih->protocol;
  switch (in_ih->protocol) {
  case IPPROTO_TCP:
  case IPPROTO_UDP:
    key.port = in_l4h->dest;
    break;
  case IPPROTO_ICMP:
    key.port = in_l4h->icmp_id;
    break;
  }

  // Lookup session cache
  struct addr_port_stats *nval = NULL;
  nval = bpf_map_lookup_elem(&(GLUE(NAME, nat_ret)), &key);
  if (!nval) {
    return process_mf_redirect(ctx, val, md);
  }
  nval->pkts++;
  nval->bytes += data_end - data;
  nval->update_at = bpf_ktime_get_sec();
  if ((nval->flags & TCP_STATE_ESTABLISH) == 0) {
    nval->flags |= TCP_STATE_ESTABLISH;
    struct addr_port_stats *nat_out_val = bpf_map_lookup_elem(
      &(GLUE(NAME, nat_out)), nval);
    if (nat_out_val)
      nat_out_val->flags |= TCP_STATE_ESTABLISH;
  }

  if (tcp_closing != 0) {
    nval->flags |= TCP_STATE_CLOSING;
    struct addr_port_stats *nat_out_val = bpf_map_lookup_elem(
      &(GLUE(NAME, nat_out)), nval);
    if (nat_out_val)
      nat_out_val->flags |= TCP_STATE_CLOSING;
  }

#ifdef DEBUG
    // char tmp[128] = {0};
    // BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u -> %pi4:%u/%pi4:%u",
    //             in_ih->protocol,
    //             &in_ih->saddr, bpf_ntohs(in_l4h->source),
    //             &in_ih->daddr, bpf_ntohs(in_l4h->dest),
    //             &nval->addr, bpf_ntohs(nval->port));
    // bpf_printk(STR(NAME)"nat-ret %s", tmp);
#endif

  // Reverse nat
  __u32 olddest = in_ih->daddr;
  __u16 olddestport = in_l4h->dest;
  in_ih->daddr = nval->addr;
  if (in_ih->protocol != IPPROTO_ICMP)
    in_l4h->dest = nval->port;

  // Update checksum
  // TODO(slankdev): switch
  in_ih->check = checksum_recalc_addr(olddest, in_ih->daddr, in_ih->check);
  if (in_ih->protocol == IPPROTO_TCP) {
    struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_th, data_end);
    in_th->check = checksum_recalc_addrport(olddest, in_ih->daddr,
      olddestport, in_th->dest, in_th->check);
  } else if (in_ih->protocol == IPPROTO_UDP) {
    struct udp_hdr *in_uh = (struct udp_hdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_uh, data_end);
    in_uh->check = checksum_recalc_addrport(olddest, in_ih->daddr,
      olddestport, in_uh->dport, in_uh->check);
  } else if (in_ih->protocol == IPPROTO_ICMP) {
    __u16 old_id = in_l4h->icmp_id;
    in_l4h->icmp_id = nval->port;
    struct icmphdr *in_ich = (struct icmphdr *)(in_l4h);
    in_ich->checksum = checksum_recalc_icmp(old_id, in_l4h->icmp_id,
                                            in_ich->checksum);
  }

  // Set src mac addrs
  memcpy(eh->h_source, eh->h_dest, 6);

  // Resolve next hypervisor
  struct overlay_fib4_key overlay_key = {0};
  overlay_key.vrf_id = 1;
  overlay_key.addr = in_ih->daddr;
#ifndef OVERLAY_FIB4_PREFIX_MASK
#define OVERLAY_FIB4_PREFIX_MASK 0xffffffff
#endif
  overlay_key.addr &= bpf_htonl(OVERLAY_FIB4_PREFIX_MASK);
  struct overlay_fib4_val *overlay_val = bpf_map_lookup_elem(
    &GLUE(NAME, overlay_fib4), &overlay_key);
  if (!overlay_val) {
    return ignore_packet(ctx, __LINE__);
  }

  // Craft new ipv6 header
  memcpy(&oh->ip6.daddr, &overlay_val->segs[0], sizeof(struct in6_addr));
  memcpy(&oh->seg, &overlay_val->segs[0], sizeof(struct in6_addr));

  md->nh_family = AF_INET6;
  memcpy(&md->nh_addr6, &oh->ip6.daddr, sizeof(struct in6_addr));
  return tx_packet_neigh(ctx, __LINE__, md);
}

static inline int
process_nat_out(struct xdp_md *ctx, struct trie6_key *key,
                struct trie6_val *val, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
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
  struct l4hdr *in_l4h = (struct l4hdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_l4h, data_end);

  // Save nexthop
  __u32 nh_addr4 = in_ih->daddr;

  // Unsupport L4 Header
  // NOTE(slankdev): check is it really needed?
  if (in_ih->protocol != IPPROTO_TCP &&
      in_ih->protocol != IPPROTO_UDP &&
      in_ih->protocol != IPPROTO_ICMP) {
    bpf_printk(STR(NAME)"nat unsupport l4 proto %d", in_ih->protocol);
    return ignore_packet(ctx, __LINE__);
  }

  // Check whether Syn packet
  __u8 tcp_syn = 0;
  __u8 tcp_closing = 0;
  if (in_ih->protocol == IPPROTO_TCP) {
    struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
    assert_len(in_th, data_end);
    tcp_syn = in_th->syn;
    tcp_closing = in_th->rst || in_th->fin;
  }

  // Save pre-translate values
  const __u16 org_sport = in_l4h->source;
  const __u16 org_dport = in_l4h->dest;
  const __u16 org_icmp_id = in_l4h->icmp_id;

  // Craft NAT Calculation Key
  struct addr_port apkey = {0};
  apkey.addr = in_ih->saddr;
  apkey.proto = in_ih->protocol;
  switch (in_ih->protocol) {
  case IPPROTO_TCP:
  case IPPROTO_UDP:
    apkey.port = in_l4h->source;
    break;
  case IPPROTO_ICMP:
    apkey.port = in_l4h->icmp_id;
    break;
  }

  // Lookup session cache
  __u32 sourceport = 0;
  __u64 now = bpf_ktime_get_sec();
  struct addr_port_stats *asval = bpf_map_lookup_elem(
    &(GLUE(NAME, nat_out)), &apkey);

  // Check lookup result
  if (!asval) {
    // Un-Hit sesson cache
    __u32 hash = 0;
    switch (in_ih->protocol) {
    case IPPROTO_TCP:
      if (tcp_syn == 0)
        return process_mf_redirect(ctx, val, md);
      hash = jhash_2words(in_ih->daddr, in_ih->saddr, 0xdeadbeaf);
      hash = jhash_2words(in_l4h->dest, in_l4h->source, hash);
      hash = jhash_2words(in_ih->protocol, 0, hash);
      //bpf_printk(STR(NAME)"hash 0x%08x", hash);
      break;
    case IPPROTO_UDP:
      if (key->addr[4] != 0x00 || key->addr[5] != 0x00)
        return process_mf_redirect(ctx, val, md);
      hash = jhash_2words(in_ih->saddr, in_l4h->source, 0xdeadbeaf);
      hash = jhash_2words(in_ih->protocol, 0, hash);
      break;
    case IPPROTO_ICMP:
      hash = jhash_2words(in_ih->daddr, in_ih->saddr, 0xdeadbeaf);
      hash = jhash_2words(in_ih->protocol, in_l4h->icmp_id, hash);
      break;
    default:
      return ignore_packet(ctx, __LINE__);
    }
    hash = hash & 0xffff;
    hash = hash & val->nat_port_hash_bit;
    // bpf_printk(STR(NAME)"hash 0x%08x (short)", hash);

    // TODO(slankdev): we should search un-used slot instead of rand-val.
    __u32 rand = bpf_get_prandom_u32();
    rand = rand & 0xffff;
    rand = rand & ~val->nat_port_hash_bit;
    sourceport = hash | rand;

    struct addr_port_stats natval = {
      .addr = val->vip,
      .port = sourceport,
      .proto = in_ih->protocol,
      .pkts = 1,
      .bytes = data_end - data,
      .created_at = now,
      .update_at = now,
    };
    struct addr_port_stats orgval = {
      .addr = in_ih->saddr,
      .port = org_sport,
      .proto = in_ih->protocol,
      .pkts = 1,
      .bytes = data_end - data,
      .created_at = now,
      .update_at = now,
    };
    if (in_ih->protocol == IPPROTO_ICMP)
      orgval.port = org_icmp_id;
    bpf_map_update_elem(&GLUE(NAME, nat_ret), &natval, &orgval, BPF_ANY);
    bpf_map_update_elem(&GLUE(NAME, nat_out), &orgval, &natval, BPF_ANY);
  } else {
    // Existing connection
    asval->pkts++;
    asval->bytes += data_end - data;
    sourceport = asval->port;
    asval->update_at = now;

    if (tcp_closing != 0) {
      asval->flags |= TCP_STATE_CLOSING;
      struct addr_port_stats *nat_ret_val = bpf_map_lookup_elem(
        &(GLUE(NAME, nat_out)), asval);
      if (nat_ret_val)
        nat_ret_val->flags |= TCP_STATE_CLOSING;
    }
  }

#ifdef DEBUG
  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u/%pi4:%u -> %pi4:%u",
              in_ih->protocol,
              &in_ih->saddr, bpf_ntohs(org_sport),
              &val->vip, bpf_ntohs(sourceport),
              &in_ih->daddr, bpf_ntohs(org_dport));
  // bpf_printk(STR(NAME)"nat-out %s", tmp);
#endif

  // Update header
  __u32 oldsource = in_ih->saddr;
  in_ih->saddr = val->vip;

  // Update L4 Checksum
  switch (in_ih->protocol) {
  case IPPROTO_TCP:
    {
      struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
      assert_len(in_th, data_end);
      in_th->source = sourceport;
      in_th->check = checksum_recalc_addrport(oldsource, in_ih->saddr,
        org_sport, in_th->source, in_th->check);
      break;
    }
  case IPPROTO_UDP:
    {
      struct udp_hdr *in_uh = (struct udp_hdr *)((__u8 *)in_ih + in_ih_len);
      assert_len(in_uh, data_end);
      in_uh->sport = sourceport;
      in_uh->check = checksum_recalc_addrport(oldsource, in_ih->saddr,
        org_sport, in_uh->sport, in_uh->check);
      break;
    }
  case IPPROTO_ICMP:
    {
      __u16 old_id = in_l4h->icmp_id;
      in_l4h->icmp_id = sourceport;
      struct icmphdr *in_ich = (struct icmphdr *)(in_l4h);
      in_ich->checksum = checksum_recalc_icmp(old_id, sourceport,
                                              in_ich->checksum);
      break;
    }
  }

  // Update L3 Checksum
  in_ih->check = checksum_recalc_addr(oldsource, in_ih->saddr, in_ih->check);

  // NOTE(slankdev):
  // If there is a local cache for hairpin communication, the communication
  // can be directly returned here. However, as for the forwarding mechanism,
  // forwarding the packets once to mfplane reduces the size of the software
  // implementation. If there are many nodes, packets are forwarded to mfplane
  // in most cases, but it is possible to reduce the latency and the bandwidth
  // of mfplane here.

  // Swaping mac addrs
  struct ethhdr *old_eh = (struct ethhdr *)data;
  struct ethhdr *new_eh = (struct ethhdr *)(data + sizeof(struct outer_header));
  assert_len(new_eh, data_end);
  assert_len(old_eh, data_end);
  new_eh->h_proto = bpf_htons(ETH_P_IP);
  memcpy(new_eh->h_source, old_eh->h_dest, 6);
  memcpy(new_eh->h_dest, old_eh->h_source, 6);

  // decap and TX
  if (bpf_xdp_adjust_head(ctx, 0 + (int)sizeof(struct outer_header))) {
    return error_packet(ctx, __LINE__);
  }
  md->nh_family = AF_INET;
  md->nh_addr4 = nh_addr4;
  return tx_packet_neigh(ctx, __LINE__, md);
}

static inline int
process_srv6_end_mfn_nat(struct xdp_md *ctx, struct trie6_key *key,
                         struct trie6_val *val, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = data_end - data;

  // Parse Headers
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);
  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);

  // NAT check
  return snat_match(val, in_ih->saddr) ?
    process_nat_out(ctx, key, val, md) :
    process_nat_ret(ctx, key, val, md);
}

static inline int
process_srv6_end_mfl_nat(struct xdp_md *ctx, struct trie6_val *val,
                         struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = data_end - data;

  // Calculate Hash
  __u32 hash = 0;
  switch (md->l3_proto) {
  case IPPROTO_TCP:
    hash = jhash_2words(md->l3_daddr, md->l3_saddr, 0xdeadbeaf);
    hash = jhash_2words(md->l4_dport, md->l4_sport, hash);
    hash = jhash_2words(md->l3_proto, 0, hash);
    break;
  case IPPROTO_UDP:
    hash = jhash_2words(md->l3_saddr, md->l4_sport, 0xdeadbeaf);
    hash = jhash_2words(md->l3_proto, 0, hash);
    break;
  case IPPROTO_ICMP:
    hash = jhash_2words(md->l3_daddr, md->l3_saddr, 0xdeadbeaf);
    hash = jhash_2words(md->l3_proto, md->l4_icmp_id, hash);
    break;
  default:
    // bpf_printk(STR(NAME)"nat unsupport l4 proto %d", md->l3_proto);
    return ignore_packet(ctx, __LINE__);
  }
  hash = hash & 0xffff;
  hash = hash & val->nat_port_hash_bit;

  // Resolve Backend node
  __u32 idx = hash % RING_SIZE;
  idx = RING_SIZE * val->backend_block_index + idx;
  struct flow_processor *p = bpf_map_lookup_elem(&GLUE(NAME, lb_backend), &idx);
  if (!p) {
    // bpf_printk(STR(NAME)"no entry fatal");
    return ignore_packet(ctx, __LINE__);
  }

  // Save current values
  struct ipv6hdr *i6h = ((__u8*)data + sizeof(struct ethhdr));
  assert_len(i6h, data_end);
  //assert_len(d->i6h, data_end);
  __u8 flow_lbl0 = i6h->flow_lbl[0];
  __u8 flow_lbl1 = i6h->flow_lbl[1];
  __u8 flow_lbl2 = i6h->flow_lbl[2];
  __u8 hop_limit = i6h->hop_limit;

  // Header Adjustment
  __u16 updated_ip6_payload_len = ctx->data_end
    - ctx->data - md->l3_offset
    + sizeof(struct srh)
    + sizeof(struct in6_addr);
  int adjust_len = md->l3_offset
    - sizeof(struct outer_header)
    - sizeof(struct ethhdr);
  if (bpf_xdp_adjust_head(ctx, adjust_len))
    return error_packet(ctx, __LINE__);

  // Craft Header
  data = ctx->data;
  data_end = ctx->data_end;
  struct ethhdr *eh = (struct ethhdr *)data;
  assert_len(eh, data_end);
  struct outer_header *oh = (struct outer_header *)(eh + 1);
  assert_len(oh, data_end);

  // Craft New header
  memcpy(eh->h_source, md->ether_dst, 6);
  eh->h_proto = bpf_ntohs(md->ether_type);
  oh->ip6.version = 6;
  oh->ip6.priority = 0;
  oh->ip6.flow_lbl[0] = flow_lbl0;
  oh->ip6.flow_lbl[1] = flow_lbl1;
  oh->ip6.flow_lbl[2] = flow_lbl2;
  oh->ip6.payload_len = bpf_htons(updated_ip6_payload_len);
  oh->ip6.nexthdr = IPPROTO_ROUTING;
  oh->ip6.hop_limit = hop_limit;
  memcpy(&oh->ip6.saddr, &md->outer_ip6_saddr, sizeof(struct in6_addr));
  memcpy(&oh->ip6.daddr, &p->addr, sizeof(struct in6_addr));
  memcpy(&oh->seg, &p->addr, sizeof(struct in6_addr));
  oh->srh.nexthdr = IPPROTO_IPIP;
  oh->srh.hdrlen = 2;
  oh->srh.type = 4;
  oh->srh.segments_left = 1;
  oh->padding[0] = 0;
  oh->padding[1] = 0;
  oh->padding[2] = 0;
  oh->padding[3] = 0;

#ifdef DEBUG
  char tmpstr[128] = {0};
  char transport_debug_msg[128] = {0};
  if (in_ih->protocol == IPPROTO_TCP || in_ih->protocol == IPPROTO_UDP) {
    BPF_SNPRINTF(transport_debug_msg, sizeof(transport_debug_msg),
                 "0x%02x %pi4:%u %pi4:%u]", in_ih->protocol,
                 &in_ih->saddr, bpf_ntohs(in_l4h->source),
                 &in_ih->daddr, bpf_ntohs(in_l4h->dest));
  } else if (in_ih->protocol == IPPROTO_ICMP) {
    BPF_SNPRINTF(transport_debug_msg, sizeof(transport_debug_msg),
                 "0x%02x %pi4:%u %pi4]", in_ih->protocol,
                 &in_ih->saddr, bpf_ntohs(in_l4h->icmp_id),
                 &in_ih->daddr);
  }
  BPF_SNPRINTF(tmpstr, sizeof(tmpstr),
               "up-flow=[%s] hash=0x%08x/%u idx=%u hb=0x%x",
               transport_debug_msg, hash, hash, idx, val->nat_port_hash_bit);
  // bpf_printk(STR(NAME)"%s", tmpstr);
#endif

  md->nh_family = AF_INET6;
  memcpy(&md->nh_addr6, &p->addr, sizeof(struct in6_addr));
  return tx_packet_neigh(ctx, __LINE__, md);
}

static inline int
process_ipv6(struct xdp_md *ctx, struct metadata *md)
{
  debug_function_call(ctx, __func__, __LINE__);
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  // Lookup SRv6 SID
  struct trie6_key key = {0};
  key.prefixlen = 128;
  memcpy(&key.addr, &md->outer_ip6_daddr, sizeof(struct in6_addr));
  struct trie6_val *val = bpf_map_lookup_elem(&GLUE(NAME, fib6), &key);
  if (!val) {
    return ignore_packet(ctx, __LINE__);
  }
  val->stats_total_bytes += data_end - data;
  val->stats_total_pkts++;

#ifdef DEBUG_IPV6
    const __u8 *da = md->i6h->daddr.s6_addr;
    bpf_printk(STR(NAME)"%p ipv6-lookup addr begin ---", ctx);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[0], da[1]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[2], da[3]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[4], da[5]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[6], da[7]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[8], da[9]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[10], da[11]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[12], da[13]);
    bpf_printk(STR(NAME)"%p   %02x%02x", ctx, da[14], da[15]);
    bpf_printk(STR(NAME)"%p ipv6-lookup addr end   ---", ctx);
#endif

  // Switch localSID types
  switch (val->action) {
  case 123: // TODO(slankdev) to be const
    return process_srv6_end_mfl_nat(ctx, val, md);
  case 456: // TODO(slankdev) to be const
    return process_srv6_end_mfn_nat(ctx, &key, val, md);
  default:
    return ignore_packet(ctx, __LINE__);
  }
}

static inline int
process_ethernet(struct xdp_md *ctx)
{
  debug_function_call(ctx, __func__, __LINE__);

  struct metadata md = {0};
  int ret = parse_metadata(ctx, &md);
#ifdef DEBUG_PARSE_METADATA
  bpf_printk(STR(NAME)"%p:parse_metadata result=%d", ctx, ret);
#endif
  if (ret < 0) {
    return ignore_packet(ctx, __LINE__);
  }

  switch (md.ether_type) {
  case ETH_P_IP:
    return process_ipv4(ctx, &md);
  case ETH_P_IPV6:
    return process_ipv6(ctx, &md);
  default:
    return ignore_packet(ctx, __LINE__);
  }
}

SEC("xdp-ingress") int
xdp_ingress(struct xdp_md *ctx)
{
  return process_ethernet(ctx);
}

char __license[] SEC("license") = "GPL";
