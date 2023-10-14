#!/bin/sh
set -xe

## Clear maps
sudo mfpctl bpf xdp detach -N l1 -i net0
sudo mfpctl bpf xdp detach -N n1 -i net0
sudo mfpctl bpf xdp detach -N n2 -i net0
sudo mfpctl bpf map unlink

## setup l1
sudo mfpctl bpf xdp attach common -N l1 -i net0 -n l1 -f
sudo mfpctl bpf xdp attach common -N n1 -i net0 -n n1 -f --define DEBUG_FUNCTION_CALL
sudo mfpctl bpf xdp attach common -N n2 -i net0 -n n2 -f
sudo mfpctl bpf map set-auto -f map.yaml
