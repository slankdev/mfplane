#!/bin/sh
set -xe
make clb-attach-l1
make nat-attach-n1
make nat-attach-n2
make nat-attach-n3
make nat-attach-n4
make nat-attach-n5
make nat-attach-n6
sudo mikanectl map-load -f l1.config.yaml
sudo mikanectl map-load -f n1.config.yaml
sudo mikanectl map-load -f n2.config.yaml
sudo mikanectl map-load -f n3.config.yaml
sudo mikanectl map-load -f n4.config.yaml
sudo mikanectl map-load -f n5.config.yaml
sudo mikanectl map-load -f n6.config.yaml
