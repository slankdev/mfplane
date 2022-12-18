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

datas = [
  "./t5_P10_b100M.json",
  "./t5_P10_b100M_4.json",
  "./t5_P10_b100M_8.json",
]

for data in datas:
    with open(data) as f:
        data_obj = json.load(f)
        x = []
        for interval in data_obj["intervals"]:
            for stream in interval["streams"]:
                x.append(stream["rtt"])
        x = np.array(sorted(x))
        cdf = np.cumsum(x) / np.sum(x)
        plt.plot(x, cdf, label=data_obj["title"])

plt.xticks(fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.xlabel("Maximum RTT (usec)", fontsize=fs)
plt.ylabel("CDF", fontsize=fs)
plt.ylim(0, 1)
plt.title("CDF of RTT", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs)
plt.savefig("out.pdf")
