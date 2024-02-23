trex_img := slankdev/mfplane-trex:develop
trex-docker-build:
	docker build -t ${trex_img} -f cmd/trex/Dockerfile .
trex-docker-push: trex-docker-build
	docker push ${trex_img}
