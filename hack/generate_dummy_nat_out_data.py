#!/usr/bin/env python3
import json
import ipaddress
import argparse


# {
#   "items": [
#     {
#       "key": {
#         "addr": "142.0.0.1",
#         "port": 1,
#         "proto": 6
#       },
#       "val": {
#         "addr": "20.0.217.212",
#         "port": 18789,
#         "proto": 6,
#         "pkts": 1,
#         "bytes": 138,
#         "created_at": 3215957,
#         "update_at": 3215957,
#         "flags": {
#           "tcp_state_closing": false,
#           "tcp_state_establish": false
#         }
#       }
#     }
#   ]
# }
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--addrs', required=True, type=int)
    parser.add_argument('-p', '--ports', required=True, type=int)
    args = parser.parse_args()

    items = []
    for a in range(args.addrs):
        for p in range(args.ports):
            items.append({
                "key": {
                    "addr": str(ipaddress.IPv4Address('20.0.0.0') + a),
                    "port": p,
                    "proto": 6,
                },
                "val": {
                    "addr": "142.0.0.1",
                    "port": p,
                    "proto": 6,
                    "pkts": 0,
                    "bytes": 0,
                    "created_at": 1010,
                    "update_at": 1010,
                    "flags": {
                      "tcp_state_closing": False,
                      "tcp_state_establish": False
                    }
                },
            })
    data = {"items":items}
    print(json.dumps(data, indent="  "))


if __name__ == '__main__': main()
