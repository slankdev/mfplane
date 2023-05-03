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

LIMIT = 1683122800.892 # MY EXPECT (FROM)
LIMIT = 1683122920.092 # MY EXPECT (TO)
LIMIT = 1683122764.992 # DEBUG
plt.close("all")
fs = 18
tfs = 16


def isInRange(cnt):
    return 550 < cnt and cnt < 2000


x = []
stack_ys = {}
with open("./out1.json") as f:
    data_objs = json.load(f)
    cnt = 0
    for value in data_objs[0]["values"]:
        cnt = cnt + 1
        if isInRange(cnt):
            x.append(value[0])
    for data_obj in data_objs:
        y = []
        cnt = 0
        for value in data_obj["values"]:
            cnt = cnt + 1
            if isInRange(cnt):
                y.append(float(value[1]))
        stack_ys[data_obj["metric"]["netns"]] = y

pprint.pprint(stack_ys.keys())
pprint.pprint(stack_ys.values())
# xx = np.array(x, dtype=object)
# values = np.array(stack_ys.values(), dtype=object)
# keys = np.array(stack_ys.keys(), dtype=object)
# if xx.ndim == 0:
#     xx = [xx]
# if values.ndim == 0:
#     values = [values]
# if keys.ndim == 0:
#     keys = [keys]

fig, ax_bw = plt.subplots(figsize=(10, 4))
#ax_bw.stackplot(xx, values, labels=keys, alpha=0.5)
ax_bw.stackplot(x, stack_ys.values(), labels=stack_ys.keys(), alpha=0.5)

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
