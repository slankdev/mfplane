#!/usr/bin/env python3
import pprint
import argparse
import os
import sys
import time
import json


def conv(m, prefix):
    if isinstance(m, dict):
        for key in m:
            conv(m[key], f"{prefix}.{key}")
    elif isinstance(m, list):
        raise "ValueError"
    elif isinstance(m, int) or \
         isinstance(m, float):
        print(f"{prefix} {m}")
    else:
        raise ValueError


stats = json.load(open('in.json'))
conv(stats, "")
