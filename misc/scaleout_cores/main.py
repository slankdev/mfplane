#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from scipy import stats
import json
import sys
import pprint
fs = 18
tfs = 16

plt.close("all")
fig, axes = plt.subplots(
        figsize=(8,4),
        nrows=1,
        ncols=2,
        sharex=False,
        sharey='all')

# Lnode
labels = ['2', '4', '6', '9', '16']
height_mfplane = [
  1656261,
  3216485,
  4690436,
  6692241,
  8343998,
]
left = np.arange(len(height_mfplane))
axes[0].set_xlabel("#Cores of L-node", fontsize=fs)
axes[0].set_xticks(left, labels, fontsize=tfs)
axes[0].bar(
        left,
        height_mfplane, 
        color='steelblue', 
        width=0.8, 
        align='center',
        label=labels,
        linewidth=1,
        edgecolor='black')

# Nnode
labels = ['2', '4', '6', '9', '16']
height_mfplane = [
  2046401,
  3851841,
  5600405,
  7265368,
  8417912,
]
left = np.arange(len(height_mfplane))
axes[1].set_xlabel("#Cores of N-node", fontsize=fs)
axes[1].set_xticks(left, labels, fontsize=tfs)
axes[1].bar(
        left,
        height_mfplane, 
        color='steelblue', 
        width=0.8, 
        align='center',
        label=labels,
        linewidth=1,
        edgecolor='black')

# Common
axes[0].tick_params(axis='y', labelsize=tfs)
axes[0].set_ylabel("Throughput (PPS)", fontsize=fs)
plt.tight_layout()
plt.savefig("out.pdf")

