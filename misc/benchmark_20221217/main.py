#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd

data = pd.read_csv('./data.csv')
x = data[data.keys()[0]]
y1 = data[data.keys()[1]]
y2 = data[data.keys()[2]]
fs = 18
tfs = 16

plt.close("all")
plt.figure(figsize=(7, 2.5))

plt.plot(x, y1, label="downstream -P20")
plt.plot(x, y2, label="upstream -P20")
plt.xticks(fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.xlabel("Number of N-nodes", fontsize=fs)
plt.ylabel("BW (Mbps)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs)
plt.savefig("mfplane_performance.pdf")
