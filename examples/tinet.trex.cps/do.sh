#!/bin/sh
set -xe
sudo mkdir -p /sys/fs/bpf/xdp/globals
sudo mfpctl bpf xdp attach common \
  --netns L1 --interface net0 --name l1 -v -f
sudo mfpctl bpf xdp attach common \
  --netns N1 --interface net0 --name n1 -v -f \
  --define OVERLAY_FIB4_PREFIX_MASK=0xffff0000 \
  --define NAT_CACHE_MAX_RULES=65535 \
  --define DEBUG_ERROR_PACKET_ \
  --define DEBUG_NAT_CONFLICT \
  --define ENABLE_NAT_TCP_RST_CACHE_CLEAR \
  --define DEBUG_FUNCTION_CALL_ \
  --define DEBUG_MF_REDIRECT_PACKET_RECORD \
  #END
sudo mfpctl bpf map set-auto -f map.yaml
