set -xe
sudo mfpctl bpf map flush nat_out -n n1 -b
sudo mfpctl bpf map flush nat_ret -n n1 -b
sudo mfpctl bpf map flush nat_out -n n2 -b
sudo mfpctl bpf map flush nat_ret -n n2 -b
sudo mfpctl bpf map set-auto -f ops_n1.yaml
sudo mfpctl bpf map set-auto -f counter_zero.json
