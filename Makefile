help:
	@echo Usage \$$\{COMPONENT\}-build

include ./cmd/*/sub.mk
ifeq ($(shell test -e local.mk && echo -n yes),yes)
include local.mk
endif
