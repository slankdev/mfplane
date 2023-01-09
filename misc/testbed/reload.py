#!/usr/bin/env python3
import argparse
import socket
import sys


parser = argparse.ArgumentParser()
parser.add_argument('-d', '--dry-run', action='store_true')
args = parser.parse_args()

local_ip = socket.gethostbyname(socket.gethostname())
actual_ip = socket.gethostbyname("vpn.slank.dev")
if local_ip != actual_ip:
    print("this script must be executed in vpn.slank.dev")
    print("this machine looks like non vpn.slank.dev")
    print(" vpn.slank.dev: {}".format(actual_ip))
    print(" local_ip:      {}".format(local_ip))
    sys.exit(1)

print(local_ip)
print(actual_ip)
