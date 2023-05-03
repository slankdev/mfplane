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

# Ensure X
x = []
with open("./out.json") as f:
    data_obj = json.load(f)
    for interval in data_obj["intervals"]:
        x.append(interval["streams"][0]['start'])

# Ensure Y1 stack-Ys
stack_ys = {}
with open("./out.json") as f:
    data_obj = json.load(f)
    y = []
    for interval in data_obj["intervals"]:
        tot = 0
        cnt = 0
        for stream in interval["streams"]:
            cnt = cnt + 1
            tot = tot + stream["bits_per_second"]
        y.append(tot / cnt)
    stack_ys['bps'] = y

# Ensure Y2
y2 = []
with open("./out.json") as f:
    data_obj = json.load(f)
    for interval in data_obj["intervals"]:
        tot = 0
        cnt = 0
        for stream in interval["streams"]:
            cnt = cnt + 1
            tot = tot + stream["rtt"]
            # (iperf3 rtt is usec)
            # https://github.com/esnet/iperf/blob/332c31ee6512514c216077407a725b5b958b1582/src/tcp_info.c#L168
        y2.append(tot / cnt / 1000)

# Plot
fig, ax_bw = plt.subplots(figsize=(10, 4))
ax_rtt = ax_bw.twinx()
ax_bw.stackplot(x, stack_ys.values(),
                labels=stack_ys.keys(), alpha=0.5)
ax_rtt.plot(x, y2, label="rtt")
ax_bw.set_zorder(1)
ax_rtt.set_zorder(2)
ax_rtt.set_ylim(0, 3.5)
lines1, labels1 = ax_bw.get_legend_handles_labels()
lines2, labels2 = ax_rtt.get_legend_handles_labels()
ax_bw.legend(lines1+lines2, labels1+labels2, fontsize=tfs,
             loc='upper center', ncol=2,
             bbox_to_anchor=(0.5, 1.20),
             frameon=False)

ax_bw.yaxis.set_major_formatter(ticker.FuncFormatter(format_xtick))
ax_bw.tick_params(axis='both', which='major', labelsize=tfs)
ax_rtt.tick_params(axis='both', which='major', labelsize=tfs)
ax_bw.set_xlabel("Time(s)", fontsize=fs)
ax_bw.set_ylabel("Throughput (bps)", fontsize=fs)
ax_rtt.set_ylabel("RTT (ms)", fontsize=fs)
plt.tight_layout()
plt.savefig("out.pdf")
