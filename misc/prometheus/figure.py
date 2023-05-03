#!/usr/bin/env python3
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd
import numpy as np
from scipy import stats
import json
import sys
import pprint


def format_xtick(x, pos=None):
    if x >= 1000000000:
        val, unit = float(x) / 1000000000, 'G'
    elif x >= 1000000:
        val, unit = float(x) / 1000000, 'M'
    elif x >= 1000:
        val, unit = float(x) / 1000, 'K'
    else:
        val, unit = x, ''
    return '{:,.1f}{}'.format(val, unit)


plt.close("all")
fs = 18
tfs = 16

x = []
stack_ys = {}
with open("./out.json") as f:
    data_objs = json.load(f)
    for value in data_objs[0]["values"]:
        x.append(value[0])
    for data_obj in data_objs:
        y = []
        for value in data_obj["values"]:
            y.append(float(value[1]))
        stack_ys[data_obj["metric"]["netns"]] = y

fig, ax_bw = plt.subplots(figsize=(10, 4))
ax_bw.stackplot(x, stack_ys.values(),
                labels=stack_ys.keys(), alpha=0.5)
ax_bw.set_zorder(1)
lines1, labels1 = ax_bw.get_legend_handles_labels()
#ax_rtt = ax_bw.twinx()
#ax_rtt.plot(x, y2, label="rtt")
#ax_rtt.set_zorder(2)
#lines2, labels2 = ax_rtt.get_legend_handles_labels()
ax_bw.legend(lines1, labels1, fontsize=tfs,
             loc='upper center', ncol=2,
             bbox_to_anchor=(0.5, 1.20),
             frameon=False)

ax_bw.yaxis.set_major_formatter(ticker.FuncFormatter(format_xtick))
ax_bw.tick_params(axis='both', which='major', labelsize=tfs)
#ax_rtt.tick_params(axis='both', which='major', labelsize=tfs)
ax_bw.set_xlabel("Time(s)", fontsize=fs)
ax_bw.set_ylabel("Throughput (bps)", fontsize=fs)
#ax_rtt.set_ylabel("RTT (ms)", fontsize=fs)
plt.tight_layout()
plt.savefig("out.pdf")
