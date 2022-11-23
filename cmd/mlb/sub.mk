MODE := xdpgeneric
mlb-build:
	clang -target bpf -O3 -g -c cmd/mlb/main.c -I cmd/mlb -o ./bin/mlb.o
mlb-off-all:
	docker exec N1 ip link set net0 $(MODE) off || true
	docker exec N2 ip link set net0 $(MODE) off || true
	docker exec N3 ip link set net0 $(MODE) off || true
mlb-attach-n1: mlb-build
	docker cp ./bin/mlb.o N1:/mlb.o
	docker exec N1 ip link set net0 $(MODE) off || true
	docker exec N1 ip link set net0 $(MODE) obj /mlb.o sec xdp-ingress
mlb-attach-n2: mlb-build
	docker cp ./bin/mlb.o N2:/mlb.o
	docker exec N2 ip link set net0 $(MODE) off || true
	docker exec N2 ip link set net0 $(MODE) obj /mlb.o sec xdp-ingress
mlb-attach-n3: mlb-build
	docker cp ./bin/mlb.o N2:/mlb.o
	docker exec N3 ip link set net0 $(MODE) off || true
	docker exec N3 ip link set net0 $(MODE) obj /mlb.o sec xdp-ingress
mlb-attach-all: mlb-build \
	mlb-attach-n1 \
	mlb-attach-n2 \
	mlb-attach-n3 \
	# END
