#!/usr/bin/env python3
import pprint
import argparse
import os
import sys
import time
import json


stats = {}
with open('in.json') as f:
    stats = json.load(f)

pprint.pprint(stats)
# class Prof1():
#     def create_profile(self, cps, test_type, datas, datasize, send_time, recv_time):
#         data = b"\0" * datasize
#         prog_c = ASTFProgram()
#         prog_c.connect()
#         prog_c.set_tick_var("var1")
#         prog_c.set_label("a:")
#         for i in range(datas):
