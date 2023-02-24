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
width = 0.01

height_mfplane = [6.5]
height_srv6 = [7.05]
height_wirerate = [8.33]
left1 = np.arange(len(height_srv6))
left2 = [x + width for x in left1]
left3 = [x + width for x in left2]

labels = ['1flow']

plt.bar(left1, height_mfplane, color='steelblue', width=width, align='center', label="mfplane-nat", linewidth=0.75, edgecolor='black')
plt.bar(left2, height_srv6, color='lightblue', width=width, align='center', label="plain-srv6", linewidth=0.75, edgecolor='black')
plt.bar(left3, height_wirerate, color='darkgray', width=width, align='center', label="wirerate", linewidth=0.75, edgecolor='black')

#plt.xticks([r + width for r in range(len(height_mfplane))], labels, fontsize=tfs)

plt.tick_params(
    axis='x',          # changes apply to the x-axis
    which='both',      # both major and minor ticks are affected
    bottom=False,      # ticks along the bottom edge are off
    top=False,         # ticks along the top edge are off
    labelbottom=False) # labels along the bottom edge are off

plt.yticks(fontsize=tfs)
plt.xlabel("RTT (msec)", fontsize=fs)
plt.ylabel(" (Gbps)", fontsize=fs)
plt.tight_layout()
plt.legend(fontsize=tfs, loc='lower right')
plt.savefig("mfplane-nat-throughput.drawio.pdf")
