FROM ghcr.io/wide-vsix/linux-flow-exporter:branch-main
RUN apt update && apt install -y --no-install-recommends --no-install-suggests \
  iputils-ping tcpdump less hping3 python3 vim frr tshark conntrack netcat \
  iperf3 linux-tools-generic linux-cloud-tools-generic
RUN useradd syslog
RUN sed -i -e "s/bgpd=no/bgpd=yes/g" /etc/frr/daemons
WORKDIR /root
