#!/bin/sh
set -xe
docker rm -f tmp || true
docker run -it --name tmp --privileged tmp bash
