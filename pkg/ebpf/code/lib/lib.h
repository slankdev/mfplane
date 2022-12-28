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

#ifndef NAME
#error "please define NAME"
#endif

// TODO(slankdev): i'm not sure how to write like follow...
// #if STR_HELPER(NAME) == ""
// #error "PLEASE DEFINE \"NAME\""
// #endif

#define assert_len(interest, end)            \
  ({                                         \
    if ((unsigned long)(interest + 1) > end) \
      return XDP_ABORTED;                    \
  })

// TODO(slankdev); no support multiple sids in sid-list
struct outer_header {
  struct ipv6hdr ip6;
  struct ipv6_rt_hdr srh;
  __u8 padding[4];
  struct in6_addr seg;
} __attribute__ ((packed));

static inline int
ignore_packet(struct xdp_md *ctx)
{
#ifdef DEBUG
  bpf_printk(STR(NAME)"ignore packet");
#endif
  return XDP_PASS;
}

static inline int
error_packet(struct xdp_md *ctx)
{
#ifdef DEBUG
  bpf_printk(STR(NAME)"error packet");
#endif
  return XDP_DROP;
}

#endif /* _LIB_H_ */
