# Location
# /opt/trex/automation/trex_control_plane/interactive/trex/examples/astf
import astf_path
from trex.astf.api import *
import pprint
import argparse
import os
import sys
import time


def conv(f, m, prefix):
    if isinstance(m, dict):
        for key in m:
            conv(f, m[key], f"{prefix}.{key}")
    elif isinstance(m, list):
        raise "ValueError"
    elif isinstance(m, int) or \
         isinstance(m, float):
        f.write(f"counter{{key=\"{prefix}\"}} {m}\n")
    else:
        raise ValueError


class Prof1():
    def create_profile(self, cps, test_type, datas, datasize, send_time, recv_time):
        data = b"\0" * datasize
        prog_c = ASTFProgram()
        prog_c.connect()
        prog_c.set_tick_var("var1")
        prog_c.set_label("a:")
        for i in range(datas):
            prog_c.send(data)
        prog_c.jmp_dp("var1", "a:", send_time)
        if test_type == "connectreset":
            prog_c.reset()

        prog_s = ASTFProgram()
        prog_s.set_tick_var("var2")
        prog_s.set_label("b:")
        for i in range(datas):
            prog_s.recv(len(data), True)
        prog_s.jmp_dp("var2", "b:", recv_time)
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
parser.add_argument('--cps', "-c", default=1, type=float)
parser.add_argument('--mult', "-m", default=1, type=int)
parser.add_argument('--duration', "-d", default=3600, type=int)
parser.add_argument('--test', "-t", choices=['connectreset', 'connect'], required=True)
parser.add_argument('--datas', "-D", default=0, type=int)
parser.add_argument('--size', "-s", default=1, type=int)
parser.add_argument('--send-time', default=0, type=int)
parser.add_argument('--recv-time', default=0, type=int)
parser.add_argument('--metrics', default="/var/run/trex/metrics", type=str)
args = parser.parse_args()

c = ASTFClient()
c.connect()
c.reset()
print("astfclient initialized")

c.load_profile(Prof1().create_profile(args.cps, args.test, args.datas, args.size, args.send_time, args.recv_time))
c.clear_stats()
c.start(mult=args.mult, duration=args.duration)
print("started")

try:
    os.makedirs(args.metrics, exist_ok=True)
    while True:
        stats = c.get_stats()
        start = time.time()
        with open(f"{args.metrics}/counters.prom.$$", "w") as f:
            conv(f, stats, "")
        diff = time.time() - start
        os.rename(f"{args.metrics}/counters.prom.$$",
                  f"{args.metrics}/counters.prom")
        print(f"metrics files updated ({diff} sec)")
        time.sleep(1)
except KeyboardInterrupt:
    c.stop()
    print("bye...")
