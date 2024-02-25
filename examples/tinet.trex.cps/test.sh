sudo mfpctl bpf map set-auto -f ops_n1.yaml
sudo mfpctl bpf map set-auto -f counter_zero.json
docker exec T1 mkdir -p /opt/trex/automation/trex_control_plane/interactive/trex/examples/astf
docker cp ../../cmd/trex/new_connection_test.py T1:/opt/trex/automation/trex_control_plane/interactive/trex/examples/astf
docker exec -it -w /opt/trex/automation/trex_control_plane/interactive/trex/examples/astf T1 python3 new_connection_test.py --test connect $@
