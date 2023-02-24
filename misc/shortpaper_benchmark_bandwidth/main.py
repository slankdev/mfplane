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
width = 1

height_mfplane = [0, 6.5, 0]
height_srv6 = [0, 7.05, 0]
height_wirerate = [0, 8.33, 0]
left1 = np.arange(len(height_srv6))
left2 = [x + width for x in left1]
left3 = [x + width for x in left2]

labels = ['1flow']

plt.bar(left1, height_mfplane, color='steelblue', width=width, align='center', label="MF-nat", linewidth=0.75, edgecolor='black')
plt.bar(left2, height_srv6, color='lightblue', width=width, align='center', label="Plain SRv6", linewidth=0.75, edgecolor='black')
plt.bar(left3, height_wirerate, color='darkgray', width=width, align='center', label="Wirerate", linewidth=0.75, edgecolor='black')

plt.tick_params(
    axis='x',          # changes apply to the x-axis
    which='both',      # both major and minor ticks are affected
    bottom=False,      # ticks along the bottom edge are off
    top=False,         # ticks along the top edge are off
    labelbottom=False) # labels along the bottom edge are off

plt.yticks(fontsize=tfs)
plt.ylabel("Throughput (Gbps)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs, loc='lower right')
plt.savefig("mfplane-nat-throughput.drawio.pdf")
