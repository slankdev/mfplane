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

#define LP "NAT " // log prefix
#define DEBUG

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

struct conntrack_key {
  __u32 addr1;
  __u32 addr2;
  __u16 port1;
  __u16 port2;
  __u8 proto;
}  __attribute__ ((packed));

struct conntrack_val {
  __u32 pkts;
  __u32 bytes;
  __u64 created_at;
  __u64 established_at;
  __u64 finished_at;
}  __attribute__ ((packed));

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16);
  __type(key, struct conntrack_key);
  __type(value, struct conntrack_val);
} conntrack SEC(".maps");

static inline int same_ipv6(void *a, void *b, int prefix_bytes)
{
  __u8 *a8 = (__u8 *)a;
  __u8 *b8 = (__u8 *)b;
  for (int i = 0; (i < prefix_bytes && i < 16); i++)
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

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct outer_header) + \
  sizeof(struct iphdr) + offsetof(struct tcphdr, check))

__u8 srv6_tunsrc[16] = {
  0xfc, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, //TODO(slankdev): set from map
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

__u8 srv6_local_sid[16] = {
  // fc00:11:1:::
  0xfc, 0x00, 0x00, 0x11, 0x00, 0x01, 0x00, 0x00, //TODO(slankdev): set from map
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static inline int
ignore_packet(struct xdp_md *ctx)
{
#ifdef DEBUG
  bpf_printk(LP"ignore packet");
#endif
  return XDP_PASS;
}

static inline int
error_packet(struct xdp_md *ctx)
{
#ifdef DEBUG
  bpf_printk(LP"error packet");
#endif
  return XDP_DROP;
}

static inline int
process_nat_return(struct xdp_md *ctx)
{
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
      same_ipv6(&oh->ip6.daddr, srv6_local_sid, 6) != 0) {
    return ignore_packet(ctx);
  }
  struct iphdr *in_ih = (struct iphdr *)(oh + 1);
  assert_len(in_ih, data_end);
  __u8 in_ih_len = in_ih->ihl * 4;
  struct tcphdr *in_th = (struct tcphdr *)((__u8 *)in_ih + in_ih_len);
  assert_len(in_th, data_end);

  // to-nat check
  __u32 saddrmatch = bpf_ntohl(0x0afe000a); // 10.254.0.10
  __u32 saddrupdate = bpf_ntohl(0x8e000001); // 142.0.0.1
  bpf_printk("nat %08x %08x", in_ih->saddr, saddrmatch);
  if (in_ih->saddr == saddrmatch) {
    bpf_printk("nat match");
    __u32 hash = 0;
    hash = jhash_2words(in_ih->saddr, in_ih->daddr, 0xdeadbeaf);
    hash = jhash_2words(in_th->source, in_th->dest, hash);
    hash = jhash_2words(in_ih->protocol, 0, hash);
    __u32 sourceport = hash % 0xffff;
#ifdef DEBUG
    char tmp[128] = {0};
    BPF_SNPRINTF(tmp, sizeof(tmp), "%u %pi4:%u/%pi4:%u -> %pi4:%u",
                in_ih->protocol,
                &in_ih->saddr, bpf_ntohs(in_th->source),
                &saddrupdate, bpf_ntohs(sourceport),
                &in_ih->daddr, bpf_ntohs(in_th->dest));
    bpf_printk(LP"nat! %s", tmp);
#endif
    __u32 oldsource = in_ih->saddr;
    __u16 oldsourceport = in_th->source;
    in_ih->saddr = saddrupdate;
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
  } else {
    bpf_printk("nat no match");
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
