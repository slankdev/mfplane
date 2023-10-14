/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2023 Hiroki Shirokura.
 * Copyright 2023 Kyoto University.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(max_entries, 256);
} drop00000000000000000000000 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(max_entries, 256);
} drop00000000000000000000001 SEC(".maps");

SEC("xdp-ingress") int
xdp_ingress(struct xdp_md *ctx)
{
  __u64 key = 0;
  __u64 *val = NULL;

  val = bpf_map_lookup_elem(&drop00000000000000000000000, &key);
  if (val) {
    return XDP_DROP;
  }

  val = bpf_map_lookup_elem(&drop00000000000000000000001, &key);
  if (val) {
    return XDP_DROP;
  }

  return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
