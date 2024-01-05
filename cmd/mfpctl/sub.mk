mfpctl-build:
	CGO_ENABLED=0 go build -o bin/mfpctl cmd/mfpctl/main.go

mfpctl_img := slankdev/mfplane-mfpctl:develop
mfpctl-docker-build:
	docker build -t ${mfpctl_img} -f cmd/mfpctl/Dockerfile.tmp .
mfpctl-docker-push: mfpctl-docker-build
	docker push ${mfpctl_img}
