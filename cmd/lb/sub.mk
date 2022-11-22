MODE := xdpgeneric
lb-build:
	clang -target bpf -O3 -g -c cmd/lb/main.c -I cmd/lb -o ./bin/main.o -Wno-int-to-pointer-cast
	docker cp ./bin/main.o L1:/main.o
	docker exec L1 ip link set net0 $(MODE) off || true
	docker exec L1 ip link set net0 $(MODE) obj /main.o sec xdp-ingress
