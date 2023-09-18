#!/usr/bin/env python3
import sys
import yaml
import pprint
import hashlib
import argparse
import subprocess
import ipaddress


# Arg parse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-O", "--output-manifest", required=True)
args = parser.parse_args()
