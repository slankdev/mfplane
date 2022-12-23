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

static inline __u16 csum_fold_helper(__u32 csum)
{
  __u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static inline void ipv4_csum(void *data_start, int data_size,  __u32 *csum)
{
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

struct pseudo_hdr {
  __u32 source;
  __u32 dest;
  __u8 zero;
  __u8 proto;
  __u16 tcp_len;
  __u16 sport;
  __u16 dport;
};

static inline __u16 tcpipv4_csum(struct pseudo_hdr *hdr)
{
  return 0;
}

static inline __u16 checksum(void *buf, int bufsz, __u32 sum)
{
    __u16 *buf16 = (__u16 *)buf;
    while (bufsz > 1) {
        sum += *buf16;
        buf16++;
        bufsz -= 2;
    }

    if (bufsz == 1)
        sum += *(__u16 *)buf16;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

// static inline __u16 checksum2(void *buf, __u64 end, __u32 sum)
// {
//     __u16 *buf16 = (__u16 *)buf;
//     while (end - buf16 > 0) {
//         sum += *buf16;
//         buf16++;
//         bufsz -= 2;
//     }

//     if (bufsz == 1)
//         sum += *(__u16 *)buf16;
//     sum = (sum & 0xffff) + (sum >> 16);
//     sum = (sum & 0xffff) + (sum >> 16);
//     return ~sum;
// }


static inline __u16 l4_checksum(void *l3buf, int l3bufsz,
                                void *l4buf, int l4bufsz)
{
  __u32 sum = 0;
  __u16 *l3buf16 = (__u16 *)l3buf;
  while (l3bufsz > 1) {
      sum += *l3buf16;
      l3buf16++;
      l3bufsz -= 2;
  }
  __u16 *l4buf16 = (__u16 *)l4buf;
  while (l4bufsz > 1) {
      sum += *l4buf16;
      l4buf16++;
      l4bufsz -= 2;
  }
  if (l4bufsz == 1)
      sum += *(__u16 *)l4buf16;

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}

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

    in_ih->check = 0;
    __u32 check = 0;
    ipv4_csum(in_ih, sizeof(*in_ih), &check);
    in_ih->check = check;

    //tcp checksum
    // check = bpf_ntohs(in_th->check);
    // // check = in_th->check;

    // __u32 dec_sum = 0;
    // dec_sum += bpf_ntohs(oldsourceport);
    // dec_sum += (bpf_ntohl(oldsource) >> 16) & 0xffff;
    // dec_sum += (bpf_ntohl(oldsource) >> 0) & 0xffff;

    // __u32 inc_sum = 0;
    // inc_sum += bpf_ntohs(in_th->source);
    // inc_sum += (bpf_ntohl(in_ih->saddr) >> 16) & 0xffff;
    // inc_sum += (bpf_ntohl(in_ih->saddr) >> 0) & 0xffff;

#if 0
    check = bpf_htons(in_th->check);
    //check = ~check & 0xffff;

    //

    check -= bpf_ntohs(oldsourceport);
    //check = check & 0xffff;
    check += bpf_ntohs(in_th->source);
    //check = (check & 0xffff) + (check >> 16);

    check -= (bpf_ntohl(oldsource) >> 16) & 0xffff;
    //check = check & 0xffff;
    check += (bpf_ntohl(in_ih->saddr) >> 16) & 0xffff;
    //check = (check & 0xffff) + (check >> 16);

    check -= (bpf_ntohl(oldsource) >> 0) & 0xffff;
    //check = check & 0xffff;
    check += (bpf_ntohl(in_ih->saddr) >> 0) & 0xffff;
    //check = (check & 0xffff) + (check >> 16);

    char tmp0[256] = {0};
    BPF_SNPRINTF(tmp0, sizeof(tmp0), "inc %u dec %u check %u -> %u",
                 dec_sum, inc_sum, bpf_htons(in_th->check), check);
    bpf_printk("%s", tmp0);

    // if (dec_sum > inc_sum) {
    //   bpf_printk("my incremenet");
    //   check += 1;
    // }

    //check += 1;
    //   check += 1;
    //bpf_printk("check 0x%04x", check);
    // if (check < 0)
    //   check += 1;
    check = (~check) & 0xffff;
    // if (dec_sum > inc_sum)
    //   check = (~check) & 0xffff;
    // else
    //   check = (~check - 1) & 0xffff;

    in_th->check = bpf_htons(check);

    bpf_printk("check 0x%04x", check);
#else
    check = in_th->check;
    check = ~check;

    check -= (oldsource >> 0) & 0xffff;
    check -= (oldsource >> 16);
    check -= oldsourceport;

    check += (in_ih->saddr >> 0) & 0xffff;
    check += (in_ih->saddr >> 16);
    check += in_th->source;

    check = ~check;
    if (check > 0xffff)
      check = (check & 0xffff) + (check >> 16);

    in_th->check = check;
#endif
    bpf_printk("check 0x%04x", bpf_htons(in_th->check));
    // //check = ~( ~checksum_old + ~data1_old + ~data2_old + data1_new + data2_new);


    // check ~= ((oldsource >> 16) & 0xffff);
    // check ~= ((oldsource >>  0) & 0xffff);
    // check |= (saddrupdate >> 16) & 0xffff;
    // check |= (saddrupdate >>  0) & 0xffff;
    // check ~= (oldsourceport);
    // check |= sourceport;
    // check = csum_fold_helper(check);
    // // check = 0x08e3;
    // // check = bpf_htons(0x08e3);
    // // check = bpf_htons(0xbd9b);
    // //in_th->check = bpf_htons(check);
    // in_th->check = check;

#if 1
    // const __u32 csum_off = ETH_HLEN + sizeof(struct outer_header) +
    //   sizeof(struct iphdr) + offsetof(struct tcphdr, check);
    // __u32 sum = bpf_csum_diff(&oldsource, 4, &saddrupdate, 4, 0);
    // bpf_printk("sum %d", sum);
    // check = bpf_ntohs(in_th->check);
    // check += sum;
    // in_th->check = bpf_ntohs(check);
    // if (bpf_l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
    //   return error_packet(ctx);

    // __u16 tcp_len = bpf_ntohs(in_ih->tot_len);
    // tcp_len -= sizeof(struct iphdr);
    // __u64 p = (__u64)in_th;
    // if (p + tcp_len + 1> data_end) {
    //   return XDP_ABORTED;
    // }

    // struct pseudo_hdr ph0 = {0};
    // ph0.source = oldsource;
    // ph0.dest = in_ih->daddr;
    // ph0.proto = in_ih->protocol;
    // ph0.tcp_len = bpf_htons(tcp_len);
    // ph0.sport = oldsourceport;
    // ph0.dport = in_th->dest;
    // check = checksum(&ph0, sizeof(ph0), 0);
    // bpf_printk("old check 0x%04x", check);

    // struct pseudo_hdr ph = {0};
    // ph.source = in_ih->saddr;
    // // ph.source = 0x0200 008e;
    // // ph.source = bpf_ntohl(0x8e000002);
    // ph.source = oldsource;
    // ph.dest = in_ih->daddr;
    // ph.proto = in_ih->protocol;
    // ph.tcp_len = bpf_htons(tcp_len);
    // ph.sport = in_th->source;
    // ph.dport = in_th->dest;
    // check = checksum(&ph, sizeof(ph), 0);
    // bpf_printk("new check 0x%04x", check);

    // in_th->check = 0;

    // const int offset = ETH_HLEN + sizeof(struct outer_header) + sizeof(struct iphdr);
    // __u64 data0 = ctx->data + offset;
    // __u64 data0_end = ctx->data_end;
    // assert_len(in_th, data0_end);
    // check = checksum2(in_th, data0_end);

    //check = l4_checksum(&ph, sizeof(ph), in_th, tcp_len);
    //check = l4_checksum(&ph, sizeof(ph), in_th, 0);


    // check = 0;
    // check = bpf_csum_diff(0, 0, (void *)&ph, sizeof(ph), check);
    // check = checksum((void*)in_th, tcp_len, check);
    // //check = bpf_csum_diff(0, 0, (void *)in_th, tcp_len, check);
    // //check = bpf_csum_diff(0, 0, (void *)in_th, tcp_len, check);
    // //check = bpf_csum_diff(0, 0, (void *)in_th, sizeof(struct pseudo_hdr), check);
    //   // in_ih->tot_len - sizeof(struct iphdr) + sizeof(struct pseudo_hdr), check);
    // check = csum_fold_helper(check);
    // in_th->check = check;
#endif

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
