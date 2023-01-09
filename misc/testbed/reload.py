#!/usr/bin/env python3
import argparse
import socket
import sys
import yaml
import pprint
import ipaddress
import subprocess
import os


def run(cmd, stdin=None):
    return subprocess.run(cmd,
        capture_output=True,
        text=True, stdin=stdin).stdout


parser = argparse.ArgumentParser()
parser.add_argument('-d', '--dry-run', action='store_true')
parser.add_argument('-c', '--config', default='/home/slankdev/mfplane/misc/testbed/config.yaml')
args = parser.parse_args()
config = yaml.safe_load(open(args.config))

local_ip = socket.gethostbyname(socket.gethostname())
actual_ip = socket.gethostbyname(config["server"])
if local_ip != actual_ip:
    print("this script must be executed in {}".format(actual_ip))
    print("this machine looks like non {}".format(actual_ip))
    print(" vpn.slank.dev: {}".format(actual_ip))
    print(" local_ip:      {}".format(local_ip))
    sys.exit(1)
# print(local_ip)
# print(actual_ip)
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

os.makedirs("/etc/wireguard/cache", exist_ok=True)
SERVER_KEY_PATH = "/etc/wireguard/cache/server_key"
SERVER_PUBKEY_PATH = "/etc/wireguard/cache/server_pub"
if not os.path.isfile(SERVER_KEY_PATH):
    tmp = run(['wg', 'genkey'])
    open(SERVER_KEY_PATH, 'w').write(tmp)
server_key = open(SERVER_KEY_PATH).read().replace("\n", "")
if not os.path.isfile(SERVER_PUBKEY_PATH):
    tmp = run(['wg', 'pubkey'], stdin=open(SERVER_KEY_PATH))
    open(SERVER_KEY_PATH, 'w').write(tmp)
server_pubkey = open(SERVER_KEY_PATH).read().replace("\n", "")

serverF = open("/etc/wireguard/cache/server.conf", "w")
serverF.write("[Interface]\n")
serverF.write("Address = {}/32\n".format(server_addr))
serverF.write("MTU = {}\n".format(config["mtu"]))
serverF.write("ListenPort = {}\n".format(config["listenPort"]))
serverF.write("PrivateKey = {}\n".format(server_key))

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

    CLIENT_KEY_PATH = "/etc/wireguard/cache/client_{}_key".format(user["id"])
    CLIENT_PUBKEY_PATH = "/etc/wireguard/cache/client_{}_pub".format(user["id"])
    if not os.path.isfile(CLIENT_KEY_PATH):
        client_key = run(['wg', 'genkey'])
        open(CLIENT_KEY_PATH, 'w').write(client_key)
    client_key = open(CLIENT_KEY_PATH).read().replace("\n", "")
    if not os.path.isfile(CLIENT_PUBKEY_PATH):
        client_pubkey = run(['wg', 'pubkey'], stdin=open(CLIENT_KEY_PATH))
        open(CLIENT_PUBKEY_PATH, 'w').write(client_pubkey)
    client_pubkey = open(CLIENT_PUBKEY_PATH).read().replace("\n", "")

    CLIENT_CONFIG_PATH = "/etc/wireguard/cache/client_{}.conf".format(user["id"])
    with open(CLIENT_CONFIG_PATH, "w") as f:
        f.write("# ID: {}\n".format(user["id"]))
        f.write("# USERNAME: {}\n".format(user["name"]))
        f.write("# DESCRIPTION: {}\n".format(user["description"]))
        f.write("[Interface]\n")
        f.write("PrivateKey = {}\n".format(client_key))
        f.write("Address = {}/32\n".format(allocated_addr))
        f.write("DNS = {}\n".format(",".join(config["nameservers"])))
        f.write("[Peer]\n")
        f.write("PublicKey = {}\n".format(server_pubkey))
        f.write("AllowedIPs = 0.0.0.0/0\n")
        f.write("Endpoint = vpn.slank.dev:{}\n".format(config["listenPort"]))

    serverF.write("\n")
    serverF.write("# ID: {}\n".format(user["id"]))
    serverF.write("# USERNAME: {}\n".format(user["name"]))
    serverF.write("# DESCRIPTION: {}\n".format(user["description"]))
    serverF.write("[Peer]\n")
    serverF.write("PublicKey = {}\n".format(client_pubkey))
    serverF.write("AllowedIPs = {}/32\n".format(allocated_addr))

serverF.close()
# generate tmp file

print("wg-quick down /etc/wireguard/cache/server.conf")
print("wg-quick up /etc/wireguard/cache/server.conf")
