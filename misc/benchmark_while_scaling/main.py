#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from scipy import stats
import json
import sys
import pprint

plt.close("all")
plt.figure(figsize=(7, 4))
fs = 18
tfs = 16

# cat out.json | jq '.intervals[].streams[0].bits_per_second'
x = []
datas = []

with open("./out.json") as f:
    data_obj = json.load(f)
    y = []
    for interval in data_obj["intervals"]:
        for stream in interval["streams"]:
            y.append(stream["bits_per_second"])
            x.append(stream['start'])
    datas.append(y)

pprint.pprint(x)
plt.stackplot(x, datas[0])

plt.xticks(fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.ylabel("Throughput (bps)", fontsize=fs)
plt.xlabel("Time(s)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs)
plt.savefig("out.pdf")
