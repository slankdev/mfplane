#!/bin/sh
set -xe
rm -f /tmp/in.pcap
docker exec CLOS rm -f /tmp/in.pcap
docker exec CLOS tcpdump -nni l1 -Qin -w /tmp/in.pcap -vvv -c10
docker cp CLOS:/tmp/in.pcap /tmp/in.pcap
