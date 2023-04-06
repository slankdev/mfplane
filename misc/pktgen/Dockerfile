# DIST
FROM ubuntu:22.04
RUN apt update \
 && apt install -y iputils-ping traceroute sudo \
    vim git tmux silversearcher-ag bash-completion \
    netcat-openbsd telnet iperf tcpdump openvswitch-switch \
		bison flex iproute2 mtr curl pppoe pppoeconf lldpd \
		tcpdump \
 &&	echo "" > ~/.bashrc \
 && echo "if [ -f /etc/bash_completion ] && ! shopt -oq posix; then" >> ~/.bashrc \
 && echo "  . /etc/bash_completion" >> ~/.bashrc \
 && echo "fi" >> ~/.bashrc

RUN apt -y install libpcap-dev build-essential wget unzip python3-pip \
 && pip3 install pyelftools meson \
 && git clone git://dpdk.org/dpdk /dpdk \
 && git clone git://dpdk.org/apps/pktgen-dpdk /pktgen-dpdk \
 && wget https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-linux.zip \
 && unzip ninja-linux.zip -d /usr/local/bin/ \
 && update-alternatives --install /usr/bin/ninja ninja /usr/local/bin/ninja 1 --force

#RUN apt -y install linux-headers-`uname -r` 
RUN cd /dpdk && meson build && ninja -C build

