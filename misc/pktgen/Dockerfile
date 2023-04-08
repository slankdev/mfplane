FROM ubuntu:22.04 as rootfs
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

RUN apt -y install libpcap-dev build-essential wget unzip python3-pip libnuma-dev \
 && pip3 install pyelftools meson \
 && git clone git://dpdk.org/dpdk /dpdk \
 && git clone git://dpdk.org/apps/pktgen-dpdk /pktgen-dpdk \
 && wget https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-linux.zip \
 && unzip ninja-linux.zip -d /usr/local/bin/ \
 && update-alternatives --install /usr/bin/ninja ninja /usr/local/bin/ninja 1 --force
RUN cd /dpdk \
 && meson setup build --prefix=/usr \
 && ninja -C build \
 && ninja -C build install
RUN cd /pktgen-dpdk \
 && meson setup build --prefix=/usr \
 && ninja -C build \
 && ninja -C build install
## SAVED

RUN apt install -y pciutils

# sysctl -w vm.nr_hugepages=128
# mkdir -p /dev/hugepages
# mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
# sysctl -w vm.nr_hugepages=128 && mkdir -p /dev/hugepages && mount -t hugetlbfs nodev /dev/hugepages

# build/app/dpdk-testpmd -c7 --vdev=net_pcap0,iface=eth0 -- -i --nb-cores=2 --nb-ports=1 --total-num-mbufs=2048
# meson setup --prefix=/bin build --reconfigure
# LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib:/usr/local/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu
# pktgen -c7 --vdev=net_pcap1,iface=dum0 -- -P -m "[1].0"

# FINAL STAGE
# FROM scratch
# COPY --from=rootfs / /
