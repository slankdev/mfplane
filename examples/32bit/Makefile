MIKANECTL := ./../../bin/mikanectl
ebpf-attach-all:
	# docker cp $(MIKANECTL) N1:/usr/bin/mikanectl
	# docker cp $(MIKANECTL) N2:/usr/bin/mikanectl
	# docker cp $(MIKANECTL) N3:/usr/bin/mikanectl
	# docker cp $(MIKANECTL) L1:/usr/bin/mikanectl
	# docker cp $(MIKANECTL) L2:/usr/bin/mikanectl
	# docker cp $(MIKANECTL) L3:/usr/bin/mikanectl
	docker exec N1 mikanectl bpf nat attach -i net0 -f -d -n n1
	docker exec N2 mikanectl bpf nat attach -i net0 -f -d -n n2
	docker exec N3 mikanectl bpf nat attach -i net0 -f -d -n n3
	docker exec L1 mikanectl bpf clb attach -i net0 -f -d -n l1
	docker exec L2 mikanectl bpf clb attach -i net0 -f -d -n l2
	docker exec L3 mikanectl bpf clb attach -i net0 -f -d -n l3
ebpf-detach-all:
	docker exec N1 mikanectl bpf nat detach -i net0
	docker exec N2 mikanectl bpf nat detach -i net0
	docker exec N3 mikanectl bpf nat detach -i net0
	docker exec L1 mikanectl bpf clb detach -i net0
	docker exec L2 mikanectl bpf clb detach -i net0
	docker exec L3 mikanectl bpf clb detach -i net0
