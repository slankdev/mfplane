agent_img := slankdev/mfplane-agent:develop
agent-build:
	CGO_ENABLED=0 go build -o bin/agent cmd/agent/main.go
agent-docker-build: ## Build docker image with the agent.
	docker build -t ${agent_img} -f cmd/agent/Dockerfile .
agent-docker-push: agent-docker-build ## Push docker image with the agent.
	docker push ${agent_img}
agent-run: agent-build
	sudo -E ./bin/agent
