#!/bin/sh
set -xe
sudo mkdir -p /sys/fs/bpf/xdp/globals
sudo mfpctl bpf xdp attach common --netns L1 --interface net0 --name l1 -v -f
sudo mfpctl bpf xdp attach common --netns N1 --interface net0 --name n1 -v -f --define DEBUG_FUNCTION_CALL
sudo mfpctl bpf map set-auto -f map.yaml
