ip3-build:
	CGO_ENABLED=0 go build -o bin/ip3 cmd/ip3/main.go
ip3-run: ip3-build
	./bin/ip3 hash
