MODE := xdpgeneric
nat-build:
	clang -target bpf -O3 -g -c cmd/nat/main.c -I cmd/nat -o ./bin/nat.o
nat-off-all:
	docker exec N1 ip link set net0 $(MODE) off || true
	docker exec N2 ip link set net0 $(MODE) off || true
	docker exec N3 ip link set net0 $(MODE) off || true
nat-attach-n1: nat-build
	docker cp ./bin/nat.o N1:/nat.o
	docker exec N1 ip link set net0 $(MODE) off || true
	docker exec N1 ip link set net0 $(MODE) obj /nat.o sec xdp-ingress
nat-attach-n2: nat-build
	docker cp ./bin/nat.o N2:/nat.o
	docker exec N2 ip link set net0 $(MODE) off || true
	docker exec N2 ip link set net0 $(MODE) obj /nat.o sec xdp-ingress
nat-attach-n3: nat-build
	docker cp ./bin/nat.o N2:/nat.o
	docker exec N3 ip link set net0 $(MODE) off || true
	docker exec N3 ip link set net0 $(MODE) obj /nat.o sec xdp-ingress
nat-attach-all: nat-build \
	nat-attach-n1 \
	nat-attach-n2 \
	nat-attach-n3 \
	# END

nat-new-attach-n1: mikanectl-build
	docker cp ./bin/mikanectl N1:/usr/bin/mikanectl
	docker exec N1 rm -rf /var/run/mfplane
	docker exec N1 mikanectl bpf nat attach -i net0 -f -v
