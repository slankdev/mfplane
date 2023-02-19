#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from scipy import stats
import json
import sys
import pprint

plt.close("all")
plt.figure(figsize=(5, 5))
fs = 18
tfs = 16

datas = [
    {"name": "no-middlebox", "file": "data1.csv", "linestyle": "dashed"},
    {"name": "ipip-x2", "file": "data3_ipip_x2.csv", "linestyle": "solid"},
    {"name": "ipip-x2-nat", "file": "data5_ipip_x2_nat.csv", "linestyle": "dotted"},
    {"name": "srv6-x2", "file": "data6_srv6_x2.csv", "linestyle": "-."},
    {"name": "mfplane", "file": "data7_mfplane.csv", "linestyle": "-"},
]

for data in datas:
    with open(data["file"]) as f:
        x = []
        for line in f:
            x.append(float(line))
        x = np.array(sorted(x))
        cdf = np.cumsum(x) / np.sum(x)
        plt.plot(x, cdf, label=data["name"], linestyle=data["linestyle"])

plt.xticks(fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.xlabel("RTT (msec)", fontsize=fs)
plt.ylabel("CDF", fontsize=fs)
plt.ylim(0, 1)
plt.title("CDF of ping-RTT (10^4 pkts)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs, loc='lower right')
plt.savefig("mfplane-nat-latency.drawio.pdf")
