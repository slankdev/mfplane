netns-build:
	CGO_ENABLED=0 go build -o bin/netns cmd/netns/main.go
