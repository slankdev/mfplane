lb-build:
	clang -target bpf -O3 -g -c cmd/lb/main.c -I cmd/lb -o ./bin/main.o -Wno-int-to-pointer-cast
	docker cp ./bin/main.o R1:/main.o
	docker exec R1 ip link set net0 xdp off || true
	docker exec R1 ip link set net0 xdp obj /main.o sec xdp-ingress
lb-initmap:
	sudo bpftool map update name procs key 0 0 0 0 value 10 254 0 101
	sudo bpftool map update name procs key 1 0 0 0 value 10 254 0 102
	sudo bpftool map update name procs key 2 0 0 0 value 10 254 0 103
