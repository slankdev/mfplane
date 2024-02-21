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

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#include "map_struct.h"
#include "map_definition.h"

/* Types of event_header.type */
enum {
  EVENT_TYPE_UNSPEC = 0,
  EVENT_TYPE_DEBUG,
  EVENT_TYPE_NAT_SESSION_CREATE,
  EVENT_TYPE_NAT_SESSION_DELETE_BY_RST,
  EVENT_TYPE_FUNCTION_CALL,
  EVENT_TYPE_NAT_CONFLICT,
  EVENT_TYPE_IPV6_LOOKUP,
  EVENT_TYPE_PARSE_METADATA,
  EVENT_TYPE_JHASH_RESULT,
  EVENT_TYPE_MF_REDIRECT,
  EVENT_TYPE_PACKET_RECORD,
};

#define NOTIFY_COMMON_HDR \
  __u16  type;   \
  __u16  length;

struct event_body_nat_session {
  NOTIFY_COMMON_HDR
  __u32 org_src;
  __u16 ort_port;
  __u32 nat_src;
  __u16 nat_port;
  __u8 proto;
  __u8 flags;
}  __attribute__ ((packed));

struct event_body_function_call {
  NOTIFY_COMMON_HDR
  __u16 func_name_idx;
  __u16 func_call_line;
}  __attribute__ ((packed));

struct event_body_nat_conflict {
  NOTIFY_COMMON_HDR
  __u32 org_src;
  __u16 ort_port;
  __u8 proto;
}  __attribute__ ((packed));

struct event_body_ipv6_lookup {
  NOTIFY_COMMON_HDR
  __u8 addr[16];
}  __attribute__ ((packed));

struct event_body_parse_metadata {
  NOTIFY_COMMON_HDR
  __s32 result;
}  __attribute__ ((packed));

struct event_body_jhash_result {
  NOTIFY_COMMON_HDR
  __u32 hash;
}  __attribute__ ((packed));

struct event_body_redirect_result {
  NOTIFY_COMMON_HDR
  __u8 updated_addr[16];
}  __attribute__ ((packed));

struct event_body_packet_record {
  NOTIFY_COMMON_HDR
  __u32 src_addr;
  __u32 dst_addr;
  __u16 src_port;
  __u16 dst_port;
  __u8 proto;
  __u8 metadata1;
  __u8 metadata2;
  __u8 metadata3;
}  __attribute__ ((packed));

static inline void
mfplane_dbg(struct xdp_md *ctx, void *obj, int size) {
  long ret = bpf_perf_event_output(ctx, &GLUE(NAME, events),
    BPF_F_CURRENT_CPU, obj, size);
  if (ret < 0) {
    __u32 idx = 0;
    struct counter_val *counter;
    counter = bpf_map_lookup_elem(&GLUE(NAME, counter), &idx);
    if (counter)
      counter->perf_event_failed++;
    }
}

enum {
	BPF_F_TIMER_ABS = (1ULL << 0),
	BPF_F_TIMER_CPU_PIN = (1ULL << 1),
};

#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7
#define CLOCK_REALTIME_ALARM     8
#define CLOCK_BOOTTIME_ALARM     9

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
    if (!interest || (unsigned long)(interest + 1) > end) { \
      bpf_printk(STR(NAME)"assert_len abort"); \
      return XDP_ABORTED;                      \
    }                                          \
  })
#else
#define assert_len(interest, end)            \
  ({                                         \
    if (!interest || (unsigned long)(interest + 1) > end) \
      return XDP_ABORTED;                    \
  })
#endif

struct srh {
  __u8 next_header;
  __u8 hdr_ext_len;
  __u8 routing_type;
  __u8 segment_left;
  __u8 last_entry;
  __u8 flags;
  __u16 tag;
} __attribute__ ((packed));

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

enum {
  FUNCTION_NAME_unspec = 0,
  FUNCTION_NAME_ignore_packet,
  FUNCTION_NAME_error_packet,
  FUNCTION_NAME_tx_packet,
  FUNCTION_NAME_tx_packet_neigh,
  FUNCTION_NAME_parse_metadata,
  FUNCTION_NAME_process_nat_return,
  FUNCTION_NAME_process_ipv4,
  FUNCTION_NAME_process_mf_redirect,
  FUNCTION_NAME_process_nat_ret,
  FUNCTION_NAME_process_nat_out,
  FUNCTION_NAME_process_srv6_end_mfn_nat,
  FUNCTION_NAME_process_srv6_end_mfl_nat,
  FUNCTION_NAME_process_ipv6,
  FUNCTION_NAME_process_ethernet,
};

#ifdef DEBUG_FUNCTION_CALL
#define debug_function_call(ctx, name, line) \
  do { \
    struct event_body_function_call ev = { \
      .type = EVENT_TYPE_FUNCTION_CALL, \
      .func_name_idx = FUNCTION_NAME_##name, \
      .func_call_line = line, \
    }; \
    mfplane_dbg(ctx, &ev, sizeof(ev)); \
  } while(0)
#else
#define debug_function_call(ctx, name, line) ;;
#endif

static inline int
ignore_packet(struct xdp_md *ctx, int line)
{
#ifdef DEBUG_IGNORE_PACKET
  debug_function_call(ctx, ignore_packet, line);
#endif

  // Increment Counter Vals
  __u32 idx = 0;
  struct counter_val *cv = bpf_map_lookup_elem(&GLUE(NAME, counter), &idx);
  if (cv) {
    cv->xdp_action_pass_pkts ++;
    // cv->xdp_action_pass_bytes += ??;
  }

  return XDP_PASS;
}

static inline int
error_packet(struct xdp_md *ctx, int line)
{
#ifdef DEBUG_ERROR_PACKET
  debug_function_call(ctx, error_packet, line);
#endif

  // Increment Counter Vals
  __u32 idx = 0;
  struct counter_val *cv = bpf_map_lookup_elem(&GLUE(NAME, counter), &idx);
  if (cv) {
    cv->xdp_action_drop_pkts ++;
    // cv->xdp_action_drop_bytes += ??;
  }

  return XDP_DROP;
}

static inline int
tx_packet(struct xdp_md *ctx, int line)
{
#ifdef DEBUG_TX_PACKET
  debug_function_call(ctx, tx_packet, line);
#endif

  // Increment Counter Vals
  __u32 idx = 0;
  struct counter_val *cv = bpf_map_lookup_elem(&GLUE(NAME, counter), &idx);
  if (cv) {
    cv->xdp_action_tx_pkts ++;
    // cv->xdp_action_tx_bytes += ??;
  }

  return XDP_TX;
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
