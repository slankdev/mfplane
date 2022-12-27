#!/bin/sh
set -xe
mikanectl hash bpftoolcli -t 17 -b fc00:11:1::1 -n l1 | sudo sh -xe

# fc00:1:1::/128 -> 0x80
sudo bpftool map update name l1_fib6 \
	key hex \
	80 00 00 00 \
	fc 00 00 01 00 01 00 00 \
	00 00 00 00 00 00 00 00 \
	value hex \
	80

# fc00:1:1::/32 -> 0x20
sudo bpftool map update name l1_fib6 \
	key hex \
	20 00 00 00 \
	fc 00 00 01 00 01 00 00 \
	00 00 00 00 00 00 00 00 \
	value hex \
	20
