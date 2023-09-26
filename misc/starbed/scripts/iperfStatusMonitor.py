#!/usr/bin/env python3
import sys
import yaml
import time
import pprint
import hashlib
import argparse
import subprocess
import ipaddress
import threading


tsdata = {}


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--inventory", default="hosts.large.yaml")
parser.add_argument("--debug-data-collection", action='store_true')
parser.add_argument("--debug-summarization", action='store_true')
args = parser.parse_args()


def f(host, container, lock, index):
    proc = subprocess.Popen(["docker", "-H", f"ssh://{host}", "logs", "-f",
                             f"{container}-iperf", "--tail=0"],
                           stdout=subprocess.PIPE)
    while proc.poll() is None:
        words = proc.stdout.readline().decode('utf8').split(",")
        lock.acquire()
        if str(words[0]) not in tsdata:
            tsdata[str(words[0])] = {}
        tsdata[str(words[0])][container] = words
        if args.debug_data_collection:
            print(f"update data from {container}")
        lock.release()


# Launch child thread
containers = []
with open(args.inventory, "r") as fileobj:
  obj = yaml.safe_load(fileobj)
  containers = obj["all"]["vars"]["containers"]

index = 0
lock = threading.Lock()
for c in containers:
    if "benchmark" in c and \
       "role" in c["benchmark"] and \
       c["benchmark"]["role"] == "server":
        print(f"launch monitor thread for {c['host']}:{c['name']}")
        threading.Thread(target=f, args=(c["host"], c["name"], lock,
                         index)).start()
        index = index + 1

# Wait
wait_sec = 3
print(f"wait child thread ({wait_sec}s)", end="", flush=True)
for i in range(wait_sec):
    print(".", end="", flush=True)
    time.sleep(1)
print("done")

# Data summarization
while True:
    time.sleep(1)

    lock.acquire()
    key = sorted(tsdata.keys())[0]
    data = tsdata.pop(key)
    lock.release()

    # Debug Print
    if args.debug_summarization:
        serverCandidates = {}
        for c in containers:
            if "benchmark" in c and \
            "role" in c["benchmark"] and \
            c["benchmark"]["role"] == "server":
                serverCandidates[c["name"]] = c
        for k in data.keys():
            serverCandidates.pop(k)
        for k in serverCandidates:
            print(f"NotSummarized: {k} {serverCandidates[k]['host']}")
        #pprint.pprint(serverCandidates)

    # Summarization
    total_bps = 0
    total_msg = 0
    total_err = 0
    total_rod = 0
    data_cnt = len(data.keys())
    for container in data:
        val = data[container]
        total_bps += int(val[8])
        total_err += int(val[10])
        total_msg += int(val[11])
        total_rod += int(val[13])
    err_rate = float(total_err) / total_msg
    #total_bps = total_bps / data_cnt
    #total_msg = total_msg / data_cnt
    #total_err = total_err / data_cnt
    #total_rod = total_rod / data_cnt

    # Output
    # FORMAT: timestamp,bps,error-cnt,total-msg,accuracy,reordering
    print(f"{key},{total_bps:.2f},{total_err:.2f},{total_msg:.2f},{err_rate:.2f},{total_rod:.2f},{data_cnt:.2f}")
