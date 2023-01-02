#!/bin/sh
set -xe
make nat-attach-n1
make clb-attach-l1
sudo mikanectl map-load -f l1.config.yaml
sudo mikanectl map-load -f n1.config.yaml
