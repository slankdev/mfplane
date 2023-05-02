# MF-plane

## Requirements

- **network function agnostic**: Supports multiple types of network functions.
  MF-plane is designed to scale out stateful network functions such as NAT,
  Firewall, and DPI, but its configuration does not depend on Function type.
  MF-plane provides load balancing functionality by implementing packet
  processing functions.

## System Design

**resources**:<br/>
- `nodes.mfplane.io`: common resource kind
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
wget https://go.dev/dl/go1.19.8.linux-amd64.tar.gz #https://go.dev/doc/install
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.19.8.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```

```
sudo curl -Lo /usr/bin/kubectl https://dl.k8s.io/v1.27.1/bin/linux/amd64/kubectl
sudo chmod +x /usr/bin/kubectl
sudo curl -Lo /usr/bin/kind https://kind.sigs.k8s.io/dl/v0.18.0/kind-linux-amd64
sudo chmod +x /usr/bin/kind
curl -Lo /usr/bin/mikanectl https://github.com/slankdev/mfplane/releases/download/branch-main/mikanectl.linux-amd64
chmod +x /usr/bin/mikanectl
curl -L https://github.com/ulucinar/kubectl-edit-status/releases/download/v0.3.0/kubectl-edit-status_v0.3.0_linux_amd64.tar.gz | sudo tar zx -C /usr/bin
```
```
kind create cluster
tinet reconf | sudo sh -xe
```
```
. <(kubectl completion bash)
. <(kind completion bash)
. <(mikenactl completion bash)
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
