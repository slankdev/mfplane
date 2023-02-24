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

height_mfplane = [6.5, 7.05, 8.33]
left = np.arange(len(height_mfplane))
labels = ['mfplane', 'plain-srv6', 'wirerate']
width = 0.5

plt.bar(left, height_mfplane, color='steelblue', width=width, align='center', label=labels, linewidth=0.75, edgecolor='black')
# plt.bar(left-width, height_mfplane, color='steelblue', width=width, align='center', label="mfplane-nat", linewidth=0.75, edgecolor='black')
# plt.bar(left+0, height_srv6, color='lightblue', width=width, align='center', label="plain-srv6", linewidth=0.75, edgecolor='black')
# plt.bar(left+width, height_wirerate, color='darkgray', width=width, align='center', label="wirerate", linewidth=0.75, edgecolor='black')

plt.xticks(left, labels, fontsize=tfs)
plt.yticks(fontsize=tfs)
plt.xlabel("Forwarding Types", fontsize=fs)
plt.ylabel("Throughput (Gbps)", fontsize=fs)
plt.tight_layout()
#plt.legend(fontsize=tfs, loc='lower right')
plt.savefig("mfplane-nat-throughput.drawio.pdf")
