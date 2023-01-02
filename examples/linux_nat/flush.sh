#!/bin/sh
set xe
docker exec R1 conntrack -F
docker exec R2 conntrack -F
