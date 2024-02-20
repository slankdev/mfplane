# TRex

```
tinet upconf | sudo sh -xe
./do.sh
docker exec -it -w /opt/trex/automation/trex_control_plane/interactive/trex/examples/astf T1 python3 new_connection_test.py
```

```
docker run --rm -it --net container:HV1 nicolaka/netshoot tcpdump -qtnni any
```

```
docker exec -it T1 ip netns exec ns1 nc -nvl 9999
docker exec -it T1 ip netns exec ns0 nc -vs 20.0.0.1 30.0.0.1 9999
```
