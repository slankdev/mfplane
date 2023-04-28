# MF-plane

```
curl -Lo /usr/bin/mikanectl https://github.com/slankdev/mfplane/releases/download/branch-main/mikanectl.linux-amd64
chmod +x /usr/bin/mikanectl
. <(mikenactl completion bash)
```

```
tinet reconf | sudo sh -xe
make nat-attach-n1
make clb-attach-l1
mikanectl hash bpftoolcli -t 17 -b fc00:11:1::1 -n l1 | sudo sh -xe

sudo bpftool prog tracelog
de CLOS tcpdump -nni any not icmp6 and not tcp port 179
de VM1 curl 10.255.100.1
```

## Requirements

- **network function agnostic**: Supports multiple types of network functions.
  MF-plane is designed to scale out stateful network functions such as NAT,
  Firewall, and DPI, but its configuration does not depend on Function type.
  MF-plane provides load balancing functionality by implementing packet
  processing functions.

## System Design

**resources**:<br/>
- `nodes.mfplane.io`: common resource kind
- `functions.mfplane.io`: common resource kind
- `nats.mfplane.io`: nf resource kind

## How to Construct it
```
(1) create k8s cluster and setup it for control plane
(2) create baremetal/virtual machine for NFV service
(3) import nodes for created machines
(4) create k8s-resources to configure the network
```

## Setup

```
sudo curl -Lo /usr/bin/kubectl https://dl.k8s.io/v1.27.1/bin/linux/amd64/kubectl
sudo chmod +x /usr/bin/kubectl
sudo curl -Lo /usr/bin/kind https://kind.sigs.k8s.io/dl/v0.18.0/kind-linux-amd64
sudo chmod +x /usr/bin/kind
kind create cluster
```
```
. <(kubectl completion bash)
. <(kind completion bash)
```

## Experiment Memo

```
vim nodes.yaml
kubectl apply -f nodes.yaml
vim nats.yaml
kubectl apply -f nats.yaml
// ...start traffic test
kubectl edit ...
```

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
