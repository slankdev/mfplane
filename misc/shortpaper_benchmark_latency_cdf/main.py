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
    #{"name": "no-MB-10E3", "file": "data0.csv"},
    {"name": "no-MB-10E4", "file": "data1.csv"},
    #{"name": "no-MB-10E5", "file": "data2.csv"},
    {"name": "ipip-x2-MB-10E4", "file": "data3_ipip_x2.csv"},
    #{"name": "ipip-x2-MB-10E4-2", "file": "data4_ipip_x2.csv"},
]

for data in datas:
    with open(data["file"]) as f:
        x = []
        for line in f:
            x.append(float(line))
        x = np.array(sorted(x))
        cdf = np.cumsum(x) / np.sum(x)
        plt.plot(x, cdf, label=data["name"])

plt.xticks(fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.xlabel("RTT (msec)", fontsize=fs)
plt.ylabel("CDF", fontsize=fs)
plt.ylim(0, 1)
plt.title("CDF of ping-RTT", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs, loc='lower right')
plt.savefig("mfplane-nat-latency.drawio.pdf")
