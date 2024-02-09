#!/bin/sh
set -xe
sudo mkdir -p /sys/fs/bpf/xdp/globals
sudo mfpctl bpf xdp detach --netns L1 --interface net0
sudo mfpctl bpf xdp detach --netns N1 --interface net0
sudo mfpctl bpf map unlink
sudo mfpctl bpf map list
