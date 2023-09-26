#!/usr/bin/env python3
import sys
import yaml
import json
import pprint
import socket
import hashlib
import argparse
import subprocess
import ipaddress


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", default="seed.large.yaml")
parser.add_argument("-I", "--input-ansible", default="/tmp/ansible_result.json")
args = parser.parse_args()

# Open file
inputObj = {}
with open(args.input, "r") as f:
    inputObj = yaml.safe_load(f)
infraData = {}
index = 0
for im in inputObj["infraManifests"]:
    with open(im["name"], "r") as f:
        imData = yaml.safe_load(f)
        for node in imData["nodes"]:
            infraData[node["name"]] = {
                "node": node,
                "index": index,
            }
            index = index + 1

# Open ansible log
ansibeResult = {}
with open(args.input_ansible, "r") as f:
    ansibeResult = json.load(f)
hosts = []
for item in ansibeResult["results"][0]["items"]:
    if item["type"] != "ok":
        hosts.append(item["host_name"])
for host in hosts:
    nn = infraData[host]["node"]["nodeName"]
    print(f"starbedctl resource power off -n {nn}")
for host in hosts:
    nn = infraData[host]["node"]["nodeName"]
    print(f"starbedctl resource power on -n {nn}")
