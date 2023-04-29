manager-build:
	CGO_ENABLED=0 go build -o bin/manager cmd/manager/main.go
manager-run: manager-build
	sudo -E ./bin/manager
