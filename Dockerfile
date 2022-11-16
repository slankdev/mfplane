FROM ghcr.io/wide-vsix/linux-flow-exporter:branch-main
RUN apt update && apt install -y iputils-ping tcpdump
RUN apt install -y less
RUN apt install -y hping3
RUN apt install -y python3
RUN apt install -y python3
RUN apt install -y linux-tools-generic linux-cloud-tools-generic
