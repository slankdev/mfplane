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
      return TC_ACT_SHOT;                    \
  })

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
process_ipv4_tcp(struct xdp_md *ctx)
{
  __u64 data = ctx->data;
  __u64 data_end = ctx->data_end;
  __u64 pkt_len = 0;

  struct iphdr *ih = (struct iphdr *)(data + sizeof(struct ethhdr));
  assert_len(ih, data_end);
  pkt_len = data_end - data;

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
    return XDP_PASS;
  }

  char tmp[128] = {0};
  BPF_SNPRINTF(tmp, sizeof(tmp), "%pi4:%u %pi4:%u %u -> %pi4", &ih->saddr,
               th->source, &ih->daddr, th->dest, ih->protocol, &p->addr);
  bpf_printk("flow=[%s] hash=0x%08x idx=%u", tmp, hash, idx);
  return XDP_PASS;
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
  // case IPPROTO_UDP:
  //   return process_ipv4_udp(ctx);
  // case IPPROTO_ICMP:
  //   return process_ipv4_icmp(ctx);
  default:
    return XDP_PASS;
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
  default:
    return XDP_PASS;
  }
}

SEC("xdp-ingress") int
xdp_ingress(struct xdp_md *ctx)
{
  return process_ethernet(ctx);
}

char __license[] SEC("license") = "GPL";
