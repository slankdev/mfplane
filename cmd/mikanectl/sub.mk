mikanectl-build:
	CGO_ENABLED=0 go build -o bin/mikanectl cmd/mikanectl/main.go
mikanectl-run: mikanectl-build
	./bin/mikanectl hash
mikanectl-install-n: mikanectl-build
	docker cp ./bin/mikanectl N1:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N2:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N3:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N4:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N5:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N6:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N7:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N8:/usr/bin/mikanectl
mikanectl-install-l: mikanectl-build
	docker cp ./bin/mikanectl L1:/usr/bin/mikanectl
	docker cp ./bin/mikanectl L2:/usr/bin/mikanectl
	docker cp ./bin/mikanectl L3:/usr/bin/mikanectl
nat-detach-all:
	docker exec N1 mikanectl bpf nat detach -i net0
	docker exec N2 mikanectl bpf nat detach -i net0
	docker exec N3 mikanectl bpf nat detach -i net0
nat-attach-all: \
	nat-attach-n1 \
	nat-attach-n2 \
	nat-attach-n3 \
	# END
nat-attach-n1: mikanectl-install-n
	docker exec N1 mikanectl bpf nat attach -i net0 -f
nat-attach-n2: mikanectl-install-n
	docker exec N2 mikanectl bpf nat attach -i net0 -f
nat-attach-n3: mikanectl-install-n
	docker exec N3 mikanectl bpf nat attach -i net0 -f

clb-attach-l1: mikanectl-install-l
	docker exec L1 mikanectl bpf clb attach -i net0 -f
