MODE := xdpgeneric
clb-build:
	clang -target bpf -O3 -g -c cmd/clb/main.c -I cmd/clb -o ./bin/clb.o

clb-load: clb-build
	docker cp ./bin/clb.o L1:/clb.o
	docker exec L1 ip link set net0 $(MODE) off || true
	docker exec L1 ip link set net0 $(MODE) obj /clb.o sec xdp-ingress
