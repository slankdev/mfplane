/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2022 Hiroki Shirokura.
 * Copyright 2022 Wide Project.
 */

#ifndef _LIB_H_
#define _LIB_H_

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "jhash.h"
#include "memory.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x) " "
#define GLUE_HELPER(x, y) x##_##y
#define GLUE(x, y) GLUE_HELPER(x, y)
#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

#ifndef NAME
#error "please define NAME"
#endif

#include "ebpfmap.h"

#define NSEC_PER_SEC  (1000ULL * 1000ULL * 1000UL)
#define NSEC_PER_MSEC (1000ULL * 1000ULL)
#define NSEC_PER_USEC (1000UL)
#define bpf_ktime_get_sec() \
  ({ __u64 __x = bpf_ktime_get_ns() / NSEC_PER_SEC; __x; })
#define bpf_ktime_get_msec()  \
  ({ __u64 __x = bpf_ktime_get_ns() / NSEC_PER_MSEC; __x; })
#define bpf_ktime_get_usec()  \
  ({ __u64 __x = bpf_ktime_get_ns() / NSEC_PER_USEC; __x; })
#define bpf_ktime_get_nsec()  \
  ({ __u64 __x = bpf_ktime_get_ns(); __x; })

// TODO(slankdev): i'm not sure how to write like follow...
// #if STR_HELPER(NAME) == ""
// #error "PLEASE DEFINE \"NAME\""
// #endif

#ifdef DEBUG
#define assert_len(interest, end)              \
  ({                                           \
    if ((unsigned long)(interest + 1) > end) { \
      bpf_printk(STR(NAME)"assert_len abort"); \
      return XDP_ABORTED;                      \
    }                                          \
  })
#else
#define assert_len(interest, end)            \
  ({                                         \
    if ((unsigned long)(interest + 1) > end) \
      return XDP_ABORTED;                    \
  })
#endif

// TODO(slankdev); no support multiple sids in sid-list
struct outer_header {
  struct ipv6hdr ip6;
  struct ipv6_rt_hdr srh;
  __u8 padding[4];
  struct in6_addr seg;
} __attribute__ ((packed));

struct l4hdr {
  __u16 source;
  __u16 dest;
  __u16 icmp_id;
} __attribute__ ((packed));

static inline int
ignore_packet(struct xdp_md *ctx)
{
#ifdef DEBUG_IGNORE_PACKET
  bpf_printk(STR(NAME)"ignore packet");
#endif
  return XDP_PASS;
}

static inline int
error_packet(struct xdp_md *ctx)
{
#ifdef DEBUG_ERROR_PACKET
  bpf_printk(STR(NAME)"error packet");
#endif
  return XDP_DROP;
}

struct icmphdr
{
  __u8 type;                /* message type */
  __u8 code;                /* type sub-code */
  __u16 checksum;
  __u16 id;
};

struct udp_hdr {
  __u16 sport;
  __u16 dport;
  __u16 len;
  __u16 check;
};

// Special thanks: kametan0730/curo
// https://github.com/kametan0730/curo/blob/master/nat.cpp
static inline __u32
checksum_recalc_addr(__u32 old_addr, __u32 new_addr,
                     __u32 old_checksum)
{
  __u32 check = old_checksum;
  check = ~check;
  check -= old_addr & 0xffff;
  check -= old_addr >> 16;
  check += new_addr & 0xffff;
  check += new_addr >> 16;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  return check;
}

// Special thanks: kametan0730/curo
// https://github.com/kametan0730/curo/blob/master/nat.cpp
static inline __u32
checksum_recalc_addrport(__u32 old_addr, __u32 new_addr,
                         __u16 old_port, __u16 new_port,
                         __u32 old_checksum)
{
  __u32 check = old_checksum;
  check = ~check;
  check -= old_addr & 0xffff;
  check -= old_addr >> 16;
  check -= old_port;
  check += new_addr & 0xffff;
  check += new_addr >> 16;
  check += new_port;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  return check;
}

// Special thanks: kametan0730/curo
// https://github.com/kametan0730/curo/blob/master/nat.cpp
static inline __u32
checksum_recalc_icmp(__u16 old_id, __u16 new_id,
                     __u32 old_checksum)
{
  __u32 check = old_checksum;
  check = ~check;
  check -= old_id;
  check += new_id;
  check = ~check;
  if (check > 0xffff)
    check = (check & 0xffff) + (check >> 16);
  return check;
}

#endif /* _LIB_H_ */
