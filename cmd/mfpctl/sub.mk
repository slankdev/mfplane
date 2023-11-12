mfpctl-build:
	CGO_ENABLED=0 go build -o bin/mfpctl cmd/mfpctl/main.go
