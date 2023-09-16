#!/usr/bin/env python3
import sys
import yaml
import argparse
import subprocess


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("node", help="specify network-node name")
parser.add_argument("-c", "--command", default="bash",
                    help="specify command to execute")
parser.add_argument("-i", "--inventory", default="hosts.small.yaml",
                    help="specify inventory file")
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
cmd = f"docker -H ssh://{host} run --rm "
cmd += f"--net container:{args.node} -it -e PS1='{args.node}> ' "
cmd += f"nicolaka/netshoot {args.command}"
subprocess.run(cmd, shell=True)

