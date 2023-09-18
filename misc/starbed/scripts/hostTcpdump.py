#!/usr/bin/env python3
import sys
import yaml
import argparse
import subprocess


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("node", help="specify network-node name")
parser.add_argument("-i", "--inventory", default="hosts.large.yaml")
parser.add_argument("-I", "--interface", default="any")
args = parser.parse_args()

# Load inventory file
host = None
with open(args.inventory, "r") as f:
  obj = yaml.safe_load(f)
  for c in obj["all"]["vars"]["containers"]:
    if c["name"] == args.node:
        host = c["host"]
        break
if host is None:
  sys.exit("Error")

# Execute remote login command
cmd = f"docker -H ssh://{host} run --rm --privileged "
cmd += f"--net host "
cmd += f"nicolaka/netshoot "
cmd += f"tcpdump -qt -nni {args.interface} -l "
cmd += " not tcp port 22 and not arp and not tcp port 6443 and "
cmd += "not tcp port 179 and not icmp6[0] == 135 and not icmp6[0] == 134"
try:
    subprocess.run(cmd, shell=True)
except KeyboardInterrupt:
    print(f"QUIT: {cmd}")
    #raise
