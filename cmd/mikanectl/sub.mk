mikanectl-build:
	CGO_ENABLED=0 go build -o bin/mikanectl cmd/mikanectl/main.go
mikanectl-run: mikanectl-build
	./bin/mikanectl hash
