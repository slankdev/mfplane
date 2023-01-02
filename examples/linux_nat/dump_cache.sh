#!/bin/sh
docker exec R1 conntrack -L -p udp 2>/dev/null
echo ----
docker exec R2 conntrack -L -p udp 2>/dev/null
