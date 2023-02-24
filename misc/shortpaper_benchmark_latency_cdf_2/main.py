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
fs = 20
tfs = 20

datas = [
    {"name": "No Middlebox", "file": "data1.csv", "linestyle": "dashed"},
    {"name": "Plain SRv6", "file": "data6_srv6_x2.csv", "linestyle": "-."},
    {"name": "MF-nat", "file": "data8_mfplane_xdp_native.csv", "linestyle": "-"},
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
plt.tight_layout()
plt.legend(fontsize=tfs, loc='lower right')
plt.savefig("mfplane-nat-latency.drawio.pdf")
