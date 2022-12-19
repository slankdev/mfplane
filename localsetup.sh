CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:3408daa17f6490a464dfc746961e28ae31964c66
UBUNTU_IMAGE=docker.io/library/ubuntu:22.04

DEBIAN_FRONTEND=noninteractive apt update && apt install -y \
	vim curl git gcc make flex bison clang-12 libbsd-dev libbfd-dev \
	libcap-dev libelf-dev gcc-multilib pkg-config linux-tools-`uname -r`
LIBBPF_VERSION="0.8.0"
IPROUTE2_VERSION="5.18.0"
cd /tmp/
wget https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz .
tar xvf v${LIBBPF_VERSION}.tar.gz
cd libbpf-${LIBBPF_VERSION}/src && make install BUILD_STATIC_ONLY=1 && make install_pkgconfig

cd /tmp/
wget https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/snapshot/iproute2-${IPROUTE2_VERSION}.tar.gz .
tar xvf iproute2-${IPROUTE2_VERSION}.tar.gz
cd iproute2-${IPROUTE2_VERSION} && ./configure --libbpf_force=on --libbpf_dir=/ && make install

