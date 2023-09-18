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
        lock.release()


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--inventory", default="hosts.large.yaml")
args = parser.parse_args()

# Launch child thread
lock = threading.Lock()
threading.Thread(target=f, args=("node006", "s1", lock, 0)).start()
threading.Thread(target=f, args=("node007", "s2", lock, 1)).start()

# Wait
wait_sec = 3
print(f"wait child thread ({wait_sec}s)", end="", flush=True)
for i in range(wait_sec):
    print(".", end="", flush=True)
    time.sleep(1)
print("done")

# Data summarization
while True:
    lock.acquire()
    key = sorted(tsdata.keys())[0]
    data = tsdata.pop(key)
    lock.release()

    pprint.pprint(data)
    time.sleep(1)
