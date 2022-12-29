#!/bin/sh
set -xe
sudo mikanectl map-load -f l1.config.yaml
sudo mikanectl map-load -f l2.config.yaml
sudo mikanectl map-load -f l3.config.yaml
sudo mikanectl map-load -f n1.config.yaml
sudo mikanectl map-load -f n2.config.yaml
sudo mikanectl map-load -f n3.config.yaml
