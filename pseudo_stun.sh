#!/bin/sh
set -xe
docker exec VM1 sh -c "echo hoge | nc -w1 -u -p 8888 20.0.0.1 1111"
docker exec VM1 sh -c "echo hoge | nc -w1 -u -p 9999 20.0.0.1 1111"
