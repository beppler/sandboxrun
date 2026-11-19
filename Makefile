.PHONY: all test helpers hosts

all: test helpers hosts

test:
	go vet ./...
	go test ./...

# Static Linux helpers that get mounted into the containers.
helpers:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/sandboxinit-linux-amd64 ./cmd/sandboxinit
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/sandboxinit-linux-arm64 ./cmd/sandboxinit

# Host binaries, one per platform you run on.
hosts:
	GOOS=linux   GOARCH=amd64 go build -o dist/sandboxrun-linux-amd64   ./cmd/sandboxrun
	GOOS=darwin  GOARCH=arm64 go build -o dist/sandboxrun-darwin-arm64  ./cmd/sandboxrun
	GOOS=windows GOARCH=amd64 go build -o dist/sandboxrun-windows-amd64.exe ./cmd/sandboxrun
