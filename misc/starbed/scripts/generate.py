#!/usr/bin/env python3
import sys
import yaml
import pprint
import argparse
import subprocess
import ipaddress


inputObj = {}
output = {}
infraData = {}


def readInfraFiles(infraManifests):
    data = {}
    index = 0
    for im in infraManifests:
        with open(im["name"], "r") as f:
            imData = yaml.safe_load(f)
            for node in imData["nodes"]:
                data[node["name"]] = {
                    "node": node,
                    "index": index,
                }
                index = index + 1
    return data


def getRouterId(name):
    addrStr = inputObj["parameter"]["minRouterId"]
    addr = ipaddress.ip_address(addrStr)
    routerId = addr + infraData[name]["index"] + 1
    return str(routerId)


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
args = parser.parse_args()

# Open file
inputObj = {}
with open(args.input, "r") as f:
    inputObj = yaml.safe_load(f)
infraData = readInfraFiles(inputObj["infraManifests"])

# Craft Data (0): Common
output = {}
output = inputObj["base"]
output["starbedNode"] = {
    "children": {
        "routeServer": {},
        "dplaneNode": {},
    },
}

# Craft Data (1): Route Server
output["routeServer"] = {"hosts": {}}
for node in inputObj["hosts"]["routeServer"]["nodes"]:
    name = node["name"]
    nodeIdx = infraData[name]["index"] + 1
    vrfs = []
    vrfIdx = 0
    for interface in inputObj["hosts"]["routeServer"]["interfaces"]:
        vrfIdx = vrfIdx + 1
        dataplaneInterfaces = []
        vrf = {}
        vrf["name"] = interface["vrf"]
        vrf["dataplaneInterfaces"] = [{
            "name": interface["name"],
            "addrs": [
                {"addr": "2001:ff00:{}::{}".format(vrfIdx, nodeIdx), "plen": 64},
                {"addr": "10.255.{}.{}".format(vrfIdx, nodeIdx), "plen": 24},
            ]
        }]
        vrfs.append(vrf)
    output["routeServer"]["hosts"][name] = {
        "kernelVersion": inputObj["parameter"]["kernelVersion"],
        "asNumber": inputObj["parameter"]["asNumber"],
        "routerId": getRouterId(name),
        "ansible_host": infraData[name]["node"]["nodeName"],
        "vrfs": vrfs,
    }

# Craft Data (2): Dplane node
output["dplaneNode"] = {"hosts": {}}
for node in inputObj["hosts"]["dplaneNode"]["nodes"]:
    name = node["name"]
    nodeIdx = infraData[name]["index"] + 1
    vrfIdx = 0
    dataplaneInterfaces = []
    for interface in inputObj["hosts"]["dplaneNode"]["interfaces"]:
        vrfIdx = vrfIdx + 1
        dataplaneInterface = {
            "name": interface["name"],
            "vrf": interface["vrf"],
            "addrs": [
                {"addr": "2001:ff00:{}::{}".format(vrfIdx, nodeIdx), "plen": 64},
                {"addr": "10.255.{}.{}".format(vrfIdx, nodeIdx), "plen": 24},
            ],
        }
        dataplaneInterfaces.append(dataplaneInterface)
    output["dplaneNode"]["hosts"][name] = {
        "kernelVersion": inputObj["parameter"]["kernelVersion"],
        "asNumber": inputObj["parameter"]["asNumber"],
        "routerId": getRouterId(name),
        "ansible_host": infraData[name]["node"]["nodeName"],
        "dataplaneInterfaces": dataplaneInterfaces,
        "srv6_locators": [{
            "prefix": "2001:a:{}::/48".format(nodeIdx),
            "token": "2001:a:{}".format(nodeIdx),
        }],
    }

# Craft Data (3): Containers
containers = []
dplaneNodeIdx = 0
for i in range(inputObj["container"]["numClientServer"]):
    nodeName = inputObj["hosts"]["dplaneNode"]["nodes"][dplaneNodeIdx]["name"]
    dplaneNodeIdx = dplaneNodeIdx + 1
    containers.append({
        "name": "c{}".format(i+1),
        "host": nodeName,
        "ports": [{
            "network": "net1",
            "type": "overlay",
            "addrs": [{"addr": "10.1.0.{}".format(i+1)}],
        }],
        "benchmark": {
            "role": "client",
            "dst": "142.1.0.{}".format(i+1),
        },
    })
    containers.append({
        "name": "s{}".format(i+1),
        "host": nodeName,
        "ports": [{
            "type": "underlay",
            "addrs": [{"addr": "142.1.0.{}".format(i+1)}],
        }],
        "httpApp": True,
        "benchmark": {
            "role": "server",
        },
    })
for i in range(inputObj["container"]["numLnodes"]):
    nodeName = inputObj["hosts"]["dplaneNode"]["nodes"][dplaneNodeIdx]["name"]
    dplaneNodeIdx = dplaneNodeIdx + 1
    containers.append({
        "name": "l{}".format(i+1),
        "host": nodeName,
        "ports": [{"type": "underlay", "addrs": [], "bgp": {}}],
    })
for i in range(inputObj["container"]["numNnodes"]):
    nodeName = inputObj["hosts"]["dplaneNode"]["nodes"][dplaneNodeIdx]["name"]
    dplaneNodeIdx = dplaneNodeIdx + 1
    containers.append({
        "name": "n{}".format(i+1),
        "host": nodeName,
        "ports": [{"type": "underlay", "addrs": [], "bgp": {}}],
    })
output["all"]["vars"]["containers"] = containers
output["all"]["vars"]["routes"] = []

# Write back to output file
with open(args.output, "w") as f:
    yaml.dump(output, f)
