/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Wide Project.
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
#include "jhash.h"

#ifndef RING_SIZE
#define RING_SIZE 17
//#define RING_SIZE 65537
#endif
#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF
#ifndef INTERFACE_MAX_FLOW_LIMIT
#define INTERFACE_MAX_FLOW_LIMIT 8
#endif
#define MAX_INTERFACES 512

#define assert_len(interest, end)            \
  ({                                         \
    if ((unsigned long)(interest + 1) > end) \
      return XDP_ABORTED;                    \
  })

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

static inline int same_ipv6(void *a, void *b)
{
  __u8 *a8 = (__u8 *)a;
  __u8 *b8 = (__u8 *)b;
  for (int i = 0; i < 16; i++)
    if (a8[i] != b8[i])
      return a8[i] - b8[i];
  return 0;
}

// TODO(slankdev); no support multiple sids in sid-list
struct outer_header {
  struct ipv6hdr ip6;
  struct ipv6_rt_hdr srh;
  __u8 padding[4];
  struct in6_addr seg;
} __attribute__ ((packed));

struct flow_key {
	__u32 src4;
	__u32 src6;
	__u8 proto;
	__u16 sport;
	__u16 dport;
} __attribute__ ((packed));

struct flow_processor {
  __u32 addr;
} __attribute__ ((packed));

__u8 srv6_tunsrc[16] = {
  0xfc, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

__u8 srv6_tundst[16] = {
  0xfc, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

__u8 srv6_local_sid[16] = {
  0xfc, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

struct {
	//__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct flow_processor);
	__uint(max_entries, RING_SIZE);
} procs SEC(".maps");

#ifdef DEBUG
static inline void
debug_skb(struct xdp_md *ctx, const char *name)
{
  bpf_printk("%s(%u:%u)", name, ctx->ingress_ifindex, ctx->ifindex);
  bpf_printk(" tstamp:%u mark:%u l4_hash:%u", ctx->tstamp, ctx->mark, ctx->hash);
  bpf_printk(" cb[0]: %u", ctx->cb[0]);
  bpf_printk(" cb[1]: %u", ctx->cb[1]);
  bpf_printk(" cb[2]: %u", ctx->cb[2]);
  bpf_printk(" cb[3]: %u", ctx->cb[3]); bpf_printk(" cb[4]: %u", ctx->cb[4]);
  bpf_printk(" data_meta: %u", ctx->data_meta);
  bpf_printk(" data:      %u", ctx->data);
  bpf_printk(" data_end:  %u", ctx->data_end);
}
#endif /* DEBUG */

static inline int
ignore_packet(struct xdp_md *ctx)
{
  bpf_printk("ignore packet");
  return XDP_PASS;
}

static inline int
error_packet(struct xdp_md *ctx)
{
  bpf_printk("error packet");
  return XDP_DROP;
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

  __u32 idx = hash % RING_SIZE;
  struct flow_processor *p = bpf_map_lookup_elem(&procs, &idx);
  if (!p) {
    bpf_printk("no entry fatal");
    return ignore_packet(ctx);
  }

  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp), "%pi4:%u %pi4:%u %u -> %pi4",
               &ih->saddr, bpf_ntohs(th->source),
               &ih->daddr, bpf_ntohs(th->dest),
               ih->protocol, &p->addr);
  bpf_printk("flow=[%s] hash=0x%08x idx=%u", tmp, hash, idx);

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

  // Craft outer IP6 SRv6 header
  struct outer_header *oh = (struct outer_header *)(new_eh + 1);
  assert_len(oh, data_end);
  oh->ip6.version = 6;
  oh->ip6.priority = 0;
  oh->ip6.payload_len = bpf_ntohs(pkt_len - sizeof(struct ethhdr) +
    sizeof(struct ipv6_rt_hdr) + 4 + sizeof(struct in6_addr));
  oh->ip6.nexthdr = 43; // SR header
  oh->ip6.hop_limit = 64;
  memcpy(&oh->ip6.saddr, srv6_tunsrc, sizeof(struct in6_addr));
  memcpy(&oh->ip6.daddr, srv6_tundst, sizeof(struct in6_addr));
  oh->srh.hdrlen = 2;
  oh->srh.nexthdr = 4;
  oh->srh.segments_left = 0;
  oh->srh.type = 4;
  memcpy(&oh->seg, srv6_tundst, sizeof(struct in6_addr));

  return XDP_TX;
}

static inline int
process_ipv6(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;

  struct outer_header *oh = (struct outer_header *)(data + sizeof(struct ethhdr));
  assert_len(oh, data_end);
  if (oh->ip6.nexthdr != IPPROTO_ROUTING ||
      oh->srh.type != 4 ||
      oh->srh.hdrlen != 2) {
    bpf_printk("DEBUG!!!");
    return ignore_packet(ctx);
  }
  if (same_ipv6(&oh->ip6.daddr, srv6_local_sid) != 0) {
    return ignore_packet(ctx);
  }

  bpf_printk("HOGE");
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
