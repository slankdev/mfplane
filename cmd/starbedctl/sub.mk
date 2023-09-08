starbedctl-build:
	CGO_ENABLED=0 go build -o bin/starbedctl cmd/starbedctl/main.go
