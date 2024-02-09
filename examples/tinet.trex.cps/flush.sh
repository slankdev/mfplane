set -xe
sudo mfpctl bpf map flush nat_out -n n1 -b 
sudo mfpctl bpf map flush nat_ret -n n1 -b 
