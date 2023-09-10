#!/usr/bin/env python3
import csv
import sys
import json
import pprint
import argparse
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt


## ARG
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--debug', default=False, action='store_true')
args = parser.parse_args()

## Read CSV Data
names = [
    "./data/s1.iperf.server.out.csv",
    "./data/s2.iperf.server.out.csv",
    "./data/s3.iperf.server.out.csv",
    "./data/s4.iperf.server.out.csv",
]
datas = []
for name in names:
    with open(name) as f:
        reader = csv.reader(f)
        data = []
        for row in reader:
            data.append(row)
        datas.append(data)
if args.debug:
    pprint.pprint(data)

## Decide start,finish time from pararell multiple data
start_time = 0
finish_time = 99999999999999
for data in datas:
    if args.debug:
        print("DEBUG: {}".format(data[0][0]))
    if start_time < int(data[0][0]):
        start_time = int(data[0][0])
    if finish_time > int(data[-1][0]):
        finish_time = int(data[-1][0])
s = datetime.strptime(str(start_time), '%Y%m%d%H%M%S')
f = datetime.strptime(str(finish_time), '%Y%m%d%H%M%S')
diff = f - s
if diff.total_seconds() < 8: ## XXX(slankdev): hardcode
    print("ERROR: time duration is too few")
    sys.exit(1)
if args.debug:
    print(s, f)
    print(start_time, finish_time)

## Align the number of data
data_count = 8
data_aligned = []
for data in datas:
    data2 = []
    for row in data:
        if int(row[0]) >= int(start_time):
            data2.append(row)
        if len(data2) >= data_count:
            break
    data_aligned.append(data2)
if args.debug:
    pprint.pprint(data_aligned)

## Craft test data
result = {
    "start_time": start_time,
    "finish_time": finish_time,
    "data_count": data_count,
    "data": data_aligned,
}
with open("./data/figure1.data.json", "w") as f:
    f.write(json.dumps(result, indent=2))

## Figure-A
sum = 0
for item in result["data"]:
    for row in item:
        sum = sum + int(row[8])
avg = sum / 8 / 4
figA = plt.figure()
plt.bar([1], avg, tick_label=["avg throughput"], align="center")
figA.savefig("./data/figure1.bar.png")

## Figure-B
avgs = []
for i in range(8):
    avg = 0
    for item in result["data"]:
        avg = avg + int(item[i][8])
    avgs.append(avg)
#pprint.pprint(avgs)
#sys.exit(0)

left = np.array([1,2,3,4,5,6,7,8])
height = np.array(avgs)
figB = plt.figure()
plt.plot(left, height)
figB.savefig("./data/figure1.line.png")
