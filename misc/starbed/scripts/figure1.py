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
tests = [
    {
        "title": "test0",
        "files": [
            "./data/single_test/s1.iperf.server.out.csv",
            "./data/single_test/s2.iperf.server.out.csv",
            "./data/single_test/s3.iperf.server.out.csv",
            "./data/single_test/s4.iperf.server.out.csv",
        ],
    },
    {
        "title": "test2",
        "files": [
            "./data/single_test1/s1.iperf.server.out.csv",
            "./data/single_test1/s2.iperf.server.out.csv",
            "./data/single_test1/s3.iperf.server.out.csv",
            "./data/single_test1/s4.iperf.server.out.csv",
        ],
    },
]
datas = []
for test in tests:
    files = []
    for fname in test["files"]:
        # pprint.pprint(fname)
        with open(fname) as f:
            reader = csv.reader(f)
            filedata = []
            for row in reader:
                filedata.append(row)
            files.append(filedata)
    data = {}
    data["title"] = test["title"]
    data["files"] = files
    datas.append(data)
if args.debug:
    pprint.pprint(data)

## Craft datas
data_count = 6 ## XXX(slankdev): hardcode
datas_aligned = []
for data in datas:
    ## Decide start,finish time from pararell multiple data
    start_time = 0
    finish_time = 99999999999999
    for datafile in data["files"]:
        if args.debug:
            print("DEBUG: {}".format(datafile[0][0]))
        if start_time < int(datafile[0][0]):
            start_time = int(datafile[0][0])
        if finish_time > int(datafile[-1][0]):
            finish_time = int(datafile[-1][0])
    s = datetime.strptime(str(start_time), '%Y%m%d%H%M%S')
    f = datetime.strptime(str(finish_time), '%Y%m%d%H%M%S')
    diff = f - s
    if diff.total_seconds() < data_count:
        print("ERROR: total_seconds={}".format(diff.total_seconds()))
        print("ERROR: data_count={}".format(data_count))
        print("ERROR: time duration is too few")
        sys.exit(1)
    if args.debug:
        print(s, f)
        print(start_time, finish_time)

    ## Align the number of data
    data_aligned_files = []
    for datafile in data["files"]:
        data2 = []
        for row in datafile:
            if int(row[0]) >= int(start_time):
                data2.append(row)
            if len(data2) >= data_count:
                break
        data_aligned_files.append(data2)
    data_aligned = {
        "title": data["title"],
        "start_time": start_time,
        "finish_time": finish_time,
        "data_count": data_count,
        "files": data_aligned_files,
    }
    datas_aligned.append(data_aligned)
if args.debug:
    pprint.pprint(datas_aligned)

## Write back to json file
with open("./data/figure1.data.json", "w") as f:
    f.write(json.dumps(datas_aligned, indent=2))

## Figure-A
labels = []
avgs = []
for data in datas_aligned:
    sum = 0
    for item in data["files"]:
        for row in item:
            sum = sum + int(row[8])
    avg = sum / data_count / len(data["files"])
    avgs.append(avg)
    labels.append(data["title"])
figA = plt.figure()
plt.bar(np.array(range(len(avgs))), avgs, tick_label=labels, align="center")
figA.savefig("./data/figure1.bar.png")

## Figure-B
figB = plt.figure()
for data in datas_aligned:
    avgs = []
    for i in range(data_count):
        avg = 0
        for item in data["files"]:
            avg = avg + int(item[i][8])
        avgs.append(avg)
    left = np.array(range(data_count))
    height = np.array(avgs)
    plt.plot(left, height, label=data["title"])
figB.legend()
figB.savefig("./data/figure1.line.png")
