#!/usr/bin/env python3
import argparse
import json
import pprint
import subprocess
import tabulate


def executeGetJson(cmd):
    return json.loads(subprocess.check_output(cmd.split(),
        universal_newlines=True).strip())


def convert(name, direction, item):
    state = "opening"
    if item["val"]["flags"]["tcp_state_closing"]:
        state = "closing"
    elif item["val"]["flags"]["tcp_state_establish"]:
        state = "estb"
    return {
        "name": name,
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
parser.add_argument('-n', '--name', nargs="*", type=str, default=["n1"])
args = parser.parse_args()
data = []
for name in args.name:
    for item in executeGetJson(
        f"sudo mfpctl bpf map inspect nat_out -n {name}")["items"]:
        data.append(convert(name, "out", item))
    for item in executeGetJson(
        f"sudo mfpctl bpf map inspect nat_ret -n {name}")["items"]:
        data.append(convert(name, "ret", item))
print(tabulate.tabulate(data, headers='keys'))
