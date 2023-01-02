FROM coturn/coturn
USER root
RUN apt update
RUN apt install iputils-ping tcpdump -y
RUN apt install -y iproute2
RUN apt install -y procps
RUN apt install -y less
RUN apt install -y netcat hping3
RUN apt install -y iptables conntrack
