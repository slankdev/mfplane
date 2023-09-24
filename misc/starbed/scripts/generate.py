#!/usr/bin/env python3
import sys
import yaml
import pprint
import hashlib
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
parser.add_argument("-O", "--output-manifest", required=True)
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
    for k in inputObj["hosts"]["dplaneNode"]["vars"]:
        output["dplaneNode"]["hosts"][name][k] = inputObj["hosts"]["dplaneNode"]["vars"][k]

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
    })
    containers.append({
        "name": "s{}".format(i+1),
        "host": nodeName,
        "ports": [{
            "type": "underlay",
            "addrs": [{"addr": "142.1.0.{}".format(i+1)}],
        }],
    })
mfpNodeIdx = 0
for i in range(inputObj["container"]["numLnodes"]):
    nodeName = inputObj["hosts"]["dplaneNode"]["nodes"][dplaneNodeIdx]["name"]
    dplaneNodeIdx = dplaneNodeIdx + 1
    mfpNodeIdx = mfpNodeIdx + 1
    containers.append({
        "name": "l{}".format(i+1),
        "host": nodeName,
        "ports": [{"type": "underlay", "addrs": [], "bgp": {}}],
        "role": "lnode",
        "nodeIdx": i+1,
        "mfpNodeIdx": mfpNodeIdx,
    })
for i in range(inputObj["container"]["numNnodes"]):
    nodeName = inputObj["hosts"]["dplaneNode"]["nodes"][dplaneNodeIdx]["name"]
    dplaneNodeIdx = dplaneNodeIdx + 1
    mfpNodeIdx = mfpNodeIdx + 1
    containers.append({
        "name": "n{}".format(i+1),
        "host": nodeName,
        "ports": [{"type": "underlay", "addrs": [], "bgp": {}}],
        "role": "nnode",
        "nodeIdx": i+1,
        "mfpNodeIdx": mfpNodeIdx,
    })
for i, c in enumerate(containers):
    for p in inputObj["benchmarkPair"]:
        dst = ""
        for c0 in containers:
            if c0["name"] == p["server"]:
                dst = c0["ports"][0]["addrs"][0]["addr"]
        if dst == "":
            print("ERROR dst resolve")
            sys.exit(0)
        if p["client"] == c["name"]:
            containers[i]["benchmark"] = {
                "role": "client",
                "dst": dst,
            }
        elif p["server"] == c["name"]:
            containers[i]["benchmark"] = {"role": "server"}
output["all"]["vars"]["containers"] = containers

# Write back to output file
with open(args.output, "w") as f:
    yaml.dump(output, f)

# Craft Data (10)): Common
items = []
for container in output["all"]["vars"]["containers"]:
    if "role" in container and container["role"] == "lnode":
        v = format(container["mfpNodeIdx"], "02x")
        item = {
            "apiVersion": "mfplane.mfplane.io/v1alpha1",
            "kind": "Node",
            "metadata": {
                "name": container["host"],
                "namespace": "default",
            },
            "spec": {
                "hostname":container["host"],
                "functions": [{
                    "name": container["name"],
                    "netns": container["name"],
                    "device": "eth0",
                    "type": "clb",
                    "mode": "xdpgeneric",
                    "labels": {
                      "lbGroup": "lbGroup1",
                      "lbMaxRules": "2",
                      "lbMaxBackends": "7",
                    },
                    "segmentRoutingSrv6": {
                        "encapSource": "fc00:{}00::0".format(v),
                        "locators": [
                            {
                                "name": "default",
                                "prefix": "fc00:{}00::/24".format(v),
                                "block": "fc00::0",
                            },
                            {
                                "name": "anycast",
                                "prefix": "fc00:ff00::/24",
                                "block": "fc00::0",
                                "anycast": True,
                            },
                        ],
                    },
                }],
            },
        }
        items.append(item)

# Craft Fib4
fib4 = []
for container in output["all"]["vars"]["containers"]:
    for port in container["ports"]:
        if port["type"] == "overlay":
            seg = ""
            for key in output["dplaneNode"]["hosts"]:
                if key == container["host"]:
                    dpnode = output["dplaneNode"]["hosts"][key]
                    token = dpnode["srv6_locators"][0]["token"]
                    nid = hashlib.md5(port["network"].encode()).hexdigest()[:4]
                    seg = f"{token}:{nid}::0"
            if seg == "":
                print("ERROR: sid resolving")
                sys.exit(1)
            item = {
                "prefix": "{}/32".format(port["addrs"][0]["addr"]),
                "action": {
                    "encapSeg6": {
                        "mode": "encap",
                        "segs": [seg],
                    },
                },
            }
            fib4.append(item)
configFileObj = {"fib4":fib4}

# Craft k8s manifests
for container in output["all"]["vars"]["containers"]:
    if "role" in container and container["role"] == "nnode":
        v = format(container["mfpNodeIdx"], "02x")
        configFile = yaml.dump({"fib4":fib4})
        item = {
            "apiVersion": "mfplane.mfplane.io/v1alpha1",
            "kind": "Node",
            "metadata": {
                "name": container["host"],
                "namespace": "default",
            },
            "spec": {
                "hostname":container["host"],
                "functions": [{
                    "name": container["name"],
                    "netns": container["name"],
                    "device": "eth0",
                    "type": "nat",
                    "mode": "xdpgeneric",
                    "labels": {
                      "natGroup": "natGroup1",
                    },
                    "segmentRoutingSrv6": {
                        "encapSource": "fc00:{}00::0".format(v),
                        "locators": [
                            {
                                "name": "default",
                                "prefix": "fc00:{}00::/24".format(v),
                                "block": "fc00::0",
                            },
                        ],
                    },
                    "configFile": configFile
                }],
            },
        }
        items.append(item)
output1 = {
    "apiVersion": "v1",
    "kind": "List",
    "metadata": {"resourceVersion": ""},
    "items": items,
}
with open(args.output_manifest, "w") as f:
    yaml.dump(output1, f)
