#!/bin/sh
set -xe
docker exec VM1 sh -c "echo hoge | nc -w1 -u -p 10001 20.0.0.1 1111"
docker exec VM1 sh -c "echo hoge | nc -w1 -u -p 10002 20.0.0.1 1111"
docker exec VM2 sh -c "echo hoge | nc -w1 -u -p 10001 20.0.0.1 1111"
docker exec VM2 sh -c "echo hoge | nc -w1 -u -p 10002 20.0.0.1 1111"
docker exec VM3 sh -c "echo hoge | nc -w1 -u -p 10001 20.0.0.1 1111"
docker exec VM3 sh -c "echo hoge | nc -w1 -u -p 10002 20.0.0.1 1111"
