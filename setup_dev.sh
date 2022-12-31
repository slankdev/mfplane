#!/bin/sh
set -xe
sudo mikanectl map-load -f l1.config.yaml
sudo mikanectl map-load -f n1.config.yaml
sudo mikanectl map-load -f n2.config.yaml
