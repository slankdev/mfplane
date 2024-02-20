#!/usr/bin/env python3
import argparse
import json
import pprint
import subprocess
import tabulate


def executeGetJson(cmd):
    return json.loads(subprocess.check_output(cmd.split(),
        universal_newlines=True).strip())


def convert(direction, item):
    state = "opening"
    if item["val"]["flags"]["tcp_state_closing"]:
        state = "closing"
    elif item["val"]["flags"]["tcp_state_establish"]:
        state = "estb"
    return {
        "dir": direction,
        "match": "{}:{}:{}".format(item["key"]["proto"],
                                   item["key"]["addr"],
                                   item["key"]["port"]),
        "action": "{}:{}:{}".format(item["val"]["proto"],
                                    item["val"]["addr"],
                                    item["val"]["port"]),
        "updated": item["val"]["update_at"],
        "state": state,
    }


parser = argparse.ArgumentParser()
parser.add_argument('-n', '--name', default="n1")
args = parser.parse_args()
data = []
for item in executeGetJson(
    f"sudo mfpctl bpf map inspect nat_out -n {args.name}")["items"]:
    data.append(convert("out", item))
for item in executeGetJson(
    f"sudo mfpctl bpf map inspect nat_ret -n {args.name}")["items"]:
    data.append(convert("ret", item))
print(tabulate.tabulate(data, headers='keys'))
