#!/usr/bin/env python3
import argparse
import socket
import sys
import yaml
import pprint
import ipaddress
import subprocess
import os


parser = argparse.ArgumentParser()
parser.add_argument('-d', '--dry-run', action='store_true')
parser.add_argument('-c', '--config', default='/home/slankdev/mfplane/misc/testbed/config.yaml')
args = parser.parse_args()

local_ip = socket.gethostbyname(socket.gethostname())
actual_ip = socket.gethostbyname("vpn.slank.dev")
if local_ip != actual_ip:
    print("this script must be executed in vpn.slank.dev")
    print("this machine looks like non vpn.slank.dev")
    print(" vpn.slank.dev: {}".format(actual_ip))
    print(" local_ip:      {}".format(local_ip))
    sys.exit(1)
# print(local_ip)
# print(actual_ip)

config = {}
with open(args.config) as f:
    config = yaml.safe_load(f)
# pprint.pprint(config)

hosts = []
first = True
server_addr = ""
for host in ipaddress.ip_network(config["cidr"]).hosts():
    if first:
        server_addr = str(host)
        first = False
        continue
    hosts.append({"addr":str(host),"reserved":False})
# for addr in hosts:
#     print(addr)
# print("\n\n")

SERVER_KEY_PATH = "/etc/wireguard/cache/server_key"
os.makedirs("/etc/wireguard/cache", exist_ok=True)
if not os.path.isfile("/etc/wireguard/cache/server_key"):
    tmp = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout
    open("/etc/wireguard/cache/server_key", 'w').write(tmp)
server_key = open(SERVER_KEY_PATH).read()

print("[Interface]")
print("Address = {}/32".format(server_addr))
print("MTU = {}".format(config["mtu"]))
print("ListenPort = {}".format(config["listenPort"]))
print("PrivateKey = {}".format(server_key))

for user in config["users"]:
    allocated_addr = ""
    for addr in hosts:
        if not addr["reserved"]:
            allocated_addr = addr["addr"]
            addr["reserved"] = True
            break
    if allocated_addr == "":
        print("address exeeded")
        sys.exit(1)

    client_key = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout

    print("")
    print("# USERNAME:    {}".format(user["name"]))
    print("# DESCRIPTION: {}".format(user["description"]))
    print("[Peer]")
    print("PublicKey = ")
    print("AllowedIPs = {}/32".format(allocated_addr))

# generate tmp file

