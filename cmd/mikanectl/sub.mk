mikanectl-build:
	CGO_ENABLED=0 go build -o bin/mikanectl cmd/mikanectl/main.go
mikanectl-run: mikanectl-build
	./bin/mikanectl hash
mikanectl-install: mikanectl-build
	docker cp ./bin/mikanectl N1:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N2:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N3:/usr/bin/mikanectl
nat-detach-all:
	docker exec N1 mikanectl bpf nat detach -i net0
	docker exec N2 mikanectl bpf nat detach -i net0
	docker exec N3 mikanectl bpf nat detach -i net0
nat-attach-all: \
	nat-attach-n1 \
	nat-attach-n2 \
	nat-attach-n3 \
	# END
nat-attach-n1: mikanectl-install
	docker exec N1 mikanectl bpf nat attach -i net0 -f
nat-attach-n2: mikanectl-install
	docker exec N2 mikanectl bpf nat attach -i net0 -f
nat-attach-n3: mikanectl-install
	docker exec N3 mikanectl bpf nat attach -i net0 -f
