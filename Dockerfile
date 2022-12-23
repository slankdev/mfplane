FROM ghcr.io/wide-vsix/linux-flow-exporter:branch-main
RUN apt update && apt install -y iputils-ping tcpdump
RUN apt install -y less
RUN apt install -y hping3
RUN apt install -y python3
RUN apt install -y python3
RUN apt install -y linux-tools-generic linux-cloud-tools-generic
RUN apt install -y vim
WORKDIR /root
RUN useradd syslog
RUN apt install -y frr --no-install-recommends --no-install-suggests
RUN sed -i -e "s/bgpd=no/bgpd=yes/g" /etc/frr/daemons
RUN apt install -y conntrack
RUN apt install -y netcat
RUN apt install -y iperf3
RUN apt update && apt install -y tshark
