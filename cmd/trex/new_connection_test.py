# Location
# /opt/trex/automation/trex_control_plane/interactive/trex/examples/astf
import astf_path
from trex.astf.api import *
import pprint
import argparse
import os
import sys
import time


class Prof1():
    def create_profile(self, cps, test_type, datas, datasize):
        data = b"\0" * datasize
        prog_c = ASTFProgram()
        prog_c.connect()
        for i in range(datas):
            prog_c.send(data)
        if test_type == "connectreset":
            prog_c.reset()
        prog_s = ASTFProgram()
        for i in range(datas):
            prog_s.recv(len(data), True)
        prog_s.wait_for_peer_close()

        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["20.0.0.0", "20.0.255.255"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["30.0.0.0", "30.0.255.255"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        # template
        temp_c = ASTFTCPClientTemplate(program=prog_c,  ip_gen=ip_gen, cps=cps)
        temp_s = ASTFTCPServerTemplate(program=prog_s)
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        c_glob_info = ASTFGlobalInfo()
        c_glob_info.tcp.mss = 1000
        s_glob_info = ASTFGlobalInfo()
        s_glob_info.tcp.mss = 1000

        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen,
                              templates=template,
                              default_c_glob_info=c_glob_info,
                              default_s_glob_info=s_glob_info)
        return profile


parser = argparse.ArgumentParser()
parser.add_argument('--mult', "-m", default=1, type=int)
parser.add_argument('--duration', "-d", default=3600, type=int)
parser.add_argument('--test', "-t", choices=['connectreset', 'connect'], required=True)
parser.add_argument('--datas', "-D", default=0, type=int)
parser.add_argument('--size', "-s", default=1, type=int)
args = parser.parse_args()

c = ASTFClient()
c.connect()
c.reset()
print("astfclient initialized")

c.load_profile(Prof1().create_profile(1, args.test, args.datas, args.size))
c.clear_stats()
c.start(mult=args.mult, duration=args.duration)
print("started")

def dig(d, keys):
    for key in keys:
        d = d.get(key, None)
        if d is None:
            return 0
            break
    return d

try:
    sv_tcps_connects = 0
    cl_tcps_connects = 0
    last_sv_tcps_connects = 0
    last_cl_tcps_connects = 0
    while True:
        stats = c.get_stats()
        last_sv_tcps_connects = sv_tcps_connects
        last_cl_tcps_connects = cl_tcps_connects
        cl_tcps_connects = dig(stats, ["traffic", "client", "tcps_connects"])
        sv_tcps_connects = dig(stats, ["traffic", "server", "tcps_connects"])
        rate_sv_tcps_connects = sv_tcps_connects - last_sv_tcps_connects
        rate_cl_tcps_connects = cl_tcps_connects - last_cl_tcps_connects
        print("global.tx_cps: {}".format(stats.get("global", {}).get("tx_cps", {})))
        print("global.cpu_util: {}".format(stats.get("global", {}).get("cpu_util", {})))
        print("global.rx_drop_bps: {}".format(stats.get("global", {}).get("rx_drop_bps", {})))
        print("traffic.client.tcps_connattempt: {}".format(dig(stats, ["traffic", "client", "tcps_connattempt"])))
        print("traffic.client.tcps_connects: {}".format(dig(stats, ["traffic", "client", "tcps_connects"])))
        print("traffic.server.tcps_connects: {}".format(dig(stats, ["traffic", "server", "tcps_connects"])))
        print("rate traffic.client.tcps_connects: {}".format(rate_cl_tcps_connects))
        print("rate traffic.server.tcps_connects: {}".format(rate_sv_tcps_connects))
        print("---")
        time.sleep(1)
except KeyboardInterrupt:
    c.stop()
    print("bye...")
