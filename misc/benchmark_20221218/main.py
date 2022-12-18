#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import json
import sys

dd = {}
with open("./P6_b100M.json") as f:
    dd = json.load(f)

pprint.pprint(dd)
sys.exit(0)

data = pd.read_csv('./data.csv')
x = data[data.keys()[0]]
y1 = data[data.keys()[1]]
y2 = data[data.keys()[2]]
fs = 18
tfs = 16

plt.close("all")
plt.figure(figsize=(7, 4))

plt.plot(x, y1, label="downstream")
plt.plot(x, y2, label="upstream")
plt.xticks(fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.xlabel("Number of N-nodes", fontsize=fs)
plt.ylabel("Throughput (Mbps)", fontsize=fs)
plt.title("Scalability of MF-Plane (BW=50Mbps/N-node)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs)
plt.savefig("mfplane_performance.pdf")
