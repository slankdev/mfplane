help:
	@echo Usage \$$\{COMPONENT\}-build

include ./cmd/*/sub.mk
ifeq ($(shell test -e local.mk && echo -n yes),yes)
include local.mk
endif

flush:
	docker exec N1 conntrack -F
	docker exec N2 conntrack -F
	docker exec N3 conntrack -F
