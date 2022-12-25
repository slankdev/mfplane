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

#ifndef NAME
#define NAME updateme999
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x) " "
#define GLUE_HELPER(x, y) x##_##y
#define GLUE(x, y) GLUE_HELPER(x, y)

#define assert_len(interest, end)            \
  ({                                         \
    if ((unsigned long)(interest + 1) > end) \
      return XDP_ABORTED;                    \
  })

static inline int same_ipv6(void *a, void *b, int prefix_bytes)
{
  __u8 *a8 = (__u8 *)a;
  __u8 *b8 = (__u8 *)b;
  for (int i = 0; (i < prefix_bytes && i < 16); i++)
    if (a8[i] != b8[i])
      return a8[i] - b8[i];
  return 0;
}

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
