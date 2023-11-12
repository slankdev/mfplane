#!/usr/bin/env python3
import argparse
import json
import subprocess
import pprint
import tabulate
import datetime
import re


parser = argparse.ArgumentParser()
parser.add_argument('-n', '--name', required=True)
args = parser.parse_args()


def executeGetJson(cmd):
    return json.loads(subprocess.check_output(cmd,
        universal_newlines=True).strip())


def main():
    p = re.compile(r"^btime (\d+)$", re.MULTILINE)
    m = p.search(open("/proc/stat").read())
    btime = int(m.groups()[0])

    dataOut = []
    for item in executeGetJson(
        f"mfpctl bpf map inspect nat_out -n {args.name}".split())["items"]:
        t = item["val"]["update_at"]
        t = t + btime
        dt = datetime.datetime.fromtimestamp(t)
        dt_formatted = dt.strftime('%Y-%m-%d %H:%M:%S')
        dataOut.append((
            "{}:{}:{}".format(
                item["key"]["addr"],
                item["key"]["port"],
                item["key"]["proto"],
            ),
            "{}:{}:{}".format(
                item["val"]["addr"],
                item["val"]["port"],
                item["val"]["proto"],
            ),
            "{}:{}".format(
                item["val"]["pkts"],
                item["val"]["bytes"],
            ),
            "{}".format(
                dt_formatted,
            ),
            "{}".format(
                item["val"]["flags"],
            ),
        ))
    dataRet = []
    for item in executeGetJson(
        f"mfpctl bpf map inspect nat_ret -n {args.name}".split())["items"]:
        t = item["val"]["update_at"]
        t = t + btime
        dt = datetime.datetime.fromtimestamp(t)
        dt_formatted = dt.strftime('%Y-%m-%d %H:%M:%S')
        dataRet.append((
            "{}:{}:{}".format(
                item["key"]["addr"],
                item["key"]["port"],
                item["key"]["proto"],
            ),
            "{}:{}:{}".format(
                item["val"]["addr"],
                item["val"]["port"],
                item["val"]["proto"],
            ),
            "{}:{}".format(
                item["val"]["pkts"],
                item["val"]["bytes"],
            ),
            "{}".format(
                dt_formatted,
            ),
            "{}".format(
                item["val"]["flags"],
            ),
        ))
    print(tabulate.tabulate(dataOut, headers=['org', 'nat', 'stats', 'updated', 'flags']))
    print("")
    print(tabulate.tabulate(dataRet, headers=['org', 'nat', 'stats', 'updated', 'flags']))


if __name__ == '__main__': main()
