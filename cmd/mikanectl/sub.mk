mikanectl-build:
	CGO_ENABLED=0 go build -o bin/mikanectl cmd/mikanectl/main.go
mikanectl-run: mikanectl-build
	./bin/mikanectl hash

# NAT RULES
nat-attach-n1: mikanectl-build
	docker cp ./bin/mikanectl N1:/usr/bin/mikanectl
	docker exec N1 mikanectl bpf nat attach -i net0 -f -d -n n1
nat-attach-n2: mikanectl-build
	docker cp ./bin/mikanectl N2:/usr/bin/mikanectl
	docker exec N2 mikanectl bpf nat attach -i net0 -f -d -n n2
nat-attach-n3: mikanectl-build
	docker cp ./bin/mikanectl N3:/usr/bin/mikanectl
	docker exec N3 mikanectl bpf nat attach -i net0 -f -d -n n3
nat-attach-all: nat-attach-n1 nat-attach-n2 nat-attach-n3
nat-detach-all:
	docker exec N1 mikanectl bpf nat detach -i net0
	docker exec N2 mikanectl bpf nat detach -i net0
	docker exec N3 mikanectl bpf nat detach -i net0

# CLB RULES
clb-attach-l1: mikanectl-build
	docker cp ./bin/mikanectl L1:/usr/bin/mikanectl
	docker exec L1 mikanectl bpf clb attach -i net0 -f -d -n l1
clb-attach-l2: mikanectl-build
	docker cp ./bin/mikanectl L2:/usr/bin/mikanectl
	docker exec L2 mikanectl bpf clb attach -i net0 -f -d -n l2
clb-attach-l3: mikanectl-build
	docker cp ./bin/mikanectl L3:/usr/bin/mikanectl
	docker exec L3 mikanectl bpf clb attach -i net0 -f -d -n l3
clb-attach-all: clb-attach-l1 clb-attach-l2 clb-attach-l3
clb-detach-all:
	docker exec L1 mikanectl bpf nat detach -i net0
	docker exec L2 mikanectl bpf nat detach -i net0
	docker exec L3 mikanectl bpf nat detach -i net0
