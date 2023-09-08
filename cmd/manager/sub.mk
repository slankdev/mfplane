manager_img := slankdev/mfplane-manager:develop
manager-build:
	CGO_ENABLED=0 go build -o bin/manager cmd/manager/main.go
manager-docker-build: ## Build docker image with the manager.
	docker build -t ${manager_img} -f cmd/manager/Dockerfile .
manager-docker-push: manager-docker-build ## Push docker image with the manager.
	docker push ${manager_img}
manager-run: manager-build
	sudo -E ./bin/manager
