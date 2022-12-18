#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from scipy import stats
import json
import sys
import pprint

datas = [
  "./t5_P10_b100M.json",
]

dd = {}
with open("./t5_P10_b100M.json") as f:
    dd = json.load(f)

title = dd["title"]
print(title)

x = []
for interval in dd["intervals"]:
    for stream in interval["streams"]:
        x.append(stream["rtt"])

x = sorted(x)
x = np.array(x)
cdf = np.cumsum(x) / np.sum(x)

fs = 18
tfs = 16

plt.close("all")
plt.figure(figsize=(7, 4))
plt.plot(x, cdf, label="CDF", marker=".")

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
