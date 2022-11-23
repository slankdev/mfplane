MODE := xdpgeneric
mlb-build:
	clang -target bpf -O3 -g -c cmd/mlb/main.c -I cmd/mlb -o ./bin/mlb.o
	@#docker cp ./bin/mlb.o N1:/mlb.o
	@#docker exec N1 ip link set net0 $(MODE) off || true
	@#docker exec N1 ip link set net0 $(MODE) obj /mlb.o sec xdp-ingress
	docker cp ./bin/mlb.o N2:/mlb.o
	docker exec N2 ip link set net0 $(MODE) off || true
	docker exec N2 ip link set net0 $(MODE) obj /mlb.o sec xdp-ingress
	@#docker cp ./bin/mlb.o N3:/mlb.o
	@#docker exec N3 ip link set net0 $(MODE) off || true
	@#docker exec N3 ip link set net0 $(MODE) obj /mlb.o sec xdp-ingress
mlb-off:
	docker exec N1 ip link set net0 $(MODE) off || true
	docker exec N2 ip link set net0 $(MODE) off || true
	docker exec N3 ip link set net0 $(MODE) off || true
