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
]

for data in datas:

    data_obj = {}
    with open(data) as f:
        data_obj = json.load(f)

    title = data_obj["title"]
    x = []
    for interval in data_obj["intervals"]:
        for stream in interval["streams"]:
            x.append(stream["rtt"])

    x = sorted(x)
    x = np.array(x)
    cdf = np.cumsum(x) / np.sum(x)

    plt.plot(x, cdf, label=title)

# x = np.linspace(0,30,100)
# for i in [1,3,6,9,15]:
#     gamma_cdf = stats.gamma.cdf(x, i)
#     plt.plot(x, gamma_cdf, label='a = {}'.format(i))
# plt.legend(loc='best')

#plt.plot(y, cdf, label="CDF")
#plt.xticks(fontsize=tfs)
#plt.yticks(fontsize=tfs)
plt.xlabel("Maximum RTT (msec)", fontsize=fs)
plt.ylabel("CDF", fontsize=fs)
#plt.title("Scalability of MF-Plane (BW=50Mbps/N-node)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs)
plt.savefig("out.pdf")
