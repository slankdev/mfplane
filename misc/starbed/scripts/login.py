#!/usr/bin/env python3
import sys
import yaml
import argparse
import subprocess


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("node", help="specify network-node name")
parser.add_argument("-c", "--command", default="bash")
parser.add_argument("-i", "--inventory", default="hosts.small.yaml")
parser.add_argument("-H", "--host", action='store_true')
parser.add_argument("-S", "--ssh", action='store_true')
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
if args.ssh:
  cmd = f"ssh -t {host} {args.command}"
  subprocess.run(cmd, shell=True)
  sys.exit(0)
if args.host:
  cmd = f"docker -H ssh://{host} run --rm --privileged "
  cmd += f"--net host -it -e PS1='{args.node}-{host}> ' "
  cmd += f"nicolaka/netshoot {args.command}"
  subprocess.run(cmd, shell=True)
  sys.exit(0)
cmd = f"docker -H ssh://{host} run --rm --privileged "
cmd += f"--net container:{args.node} -it -e PS1='{args.node}> ' "
cmd += f"nicolaka/netshoot {args.command}"
subprocess.run(cmd, shell=True)
