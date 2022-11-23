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

struct outer_header {
  struct ipv6hdr ip6;
  struct ipv6_rt_hdr srh;
  __u8 padding[4];
  struct in6_addr seg;
} __attribute__ ((packed));

__u8 srv6_tunsrc[16] = {
  0xfc, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

__u8 srv6_local_sid[16] = {
  0xfc, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
};

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
process_ipv6(struct xdp_md *ctx)
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
      same_ipv6(&oh->ip6.daddr, srv6_local_sid) != 0) {
    return ignore_packet(ctx);
  }

  // TODO(slankdev)
  // struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  // assert_len(in_ih, data_end);
  // __u8 in_ih_len = in_ih->ihl * 4;
  // struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
  // assert_len(in_th, data_end);

  struct in6_addr next_sid = {0};
  memcpy(&next_sid, &oh->ip6.daddr, sizeof(struct in6_addr));
  next_sid.in6_u.u6_addr16[1] = next_sid.in6_u.u6_addr16[7];
  next_sid.in6_u.u6_addr16[7] = bpf_htons(0x0001);

  char tmpstr[128] = {0};
  BPF_SNPRINTF(tmpstr, sizeof(tmpstr), "%pi6 -> %pi6",
               &oh->ip6.daddr, &next_sid);
  bpf_printk("MLB [%s]", tmpstr);


  // Craft new ether header
  __u8 tmp[6] = {0};
  memcpy(tmp, eh->h_dest, 6);
  memcpy(eh->h_dest, eh->h_source, 6);
  memcpy(eh->h_source, tmp, 6);
  memcpy(&oh->ip6.saddr, &srv6_tunsrc, 16);
  memcpy(&oh->ip6.daddr, &next_sid, 16);
  memcpy(&oh->seg, &next_sid, 16);

  return XDP_TX;
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
