# DIST
FROM golang:1.18 as dist
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
WORKDIR /opt
COPY ./ ./
RUN CGO_ENABLED=0 go build -o ./bin/mikanectl -ldflags "\
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.gitSHA=$GIT_SHA \
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.gitBranch=$GIT_BRANCH \
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.gitTag=$GIT_TAG \
  -X github.com/wide-vsix/linux-flow-exporter/pkg/util.buildDate=$BUILD_DATE \
  " ./cmd/mikanectl/main.go

# NETPERF
FROM networkstatic/netperf as netperf

# ROOTFS
FROM ghcr.io/wide-vsix/linux-flow-exporter:branch-main as rootfs
RUN apt update && apt install -y --no-install-recommends --no-install-suggests \
  iputils-ping tcpdump less hping3 python3 vim frr tshark conntrack netcat \
  iperf3 linux-tools-generic linux-cloud-tools-generic bash-completion \
  coturn procps less netcat hping3 iptables conntrack iperf
RUN useradd syslog
RUN sed -i -e "s/bgpd=no/bgpd=yes/g" /etc/frr/daemons
WORKDIR /root
COPY --from=dist /opt/bin/mikanectl /usr/bin/
COPY --from=netperf /usr/bin/netperf /usr/bin/netperf
COPY --from=netperf /usr/bin/netserver /usr/bin/netserver
RUN echo "source /etc/bash_completion" >> /root/.bashrc
RUN echo ". <(mikanectl completion bash)" >> /root/.bashrc

# FINAL
FROM scratch
LABEL org.opencontainers.image.source https://github.com/slankdev/mfplane
COPY --from=rootfs / /
