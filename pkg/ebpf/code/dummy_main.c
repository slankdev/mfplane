/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright 2023 Hiroki Shirokura.
 * Copyright 2023 Kyoto University.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp-ingress") int
xdp_ingress(struct xdp_md *ctx)
{
  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
