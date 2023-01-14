help:
	@echo Usage \$$\{COMPONENT\}-build

include ./cmd/*/sub.mk
ifeq ($(shell test -e local.mk && echo -n yes),yes)
include local.mk
endif

# r: clb-attach-l1 nat-attach-n1 nat-attach-n2
# 	./setup_dev.sh


r: mikanectl-build
	docker cp ./bin/mikanectl N1:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N2:/usr/bin/mikanectl
	docker cp ./bin/mikanectl N3:/usr/bin/mikanectl
	#docker exec -it N3:/usr/bin/mikanectl
