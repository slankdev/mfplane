rate-build:
	CGO_ENABLED=0 go build -o bin/rate cmd/rate/main.go
