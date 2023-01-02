#!/bin/sh
set -xe
make clb-attach-l1
make nat-attach-n1
make nat-attach-n2
sudo mikanectl map-load -f l1.config.yaml
sudo mikanectl map-load -f n1.config.yaml
sudo mikanectl map-load -f n2.config.yaml
