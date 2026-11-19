export CGO_ENABLED=0

# Shared build command: stripped, path-free binaries for hosts and helpers.
GOBUILD = go build -trimpath -ldflags="-s -w"

.PHONY: all test hosts hosts-linux-amd64 hosts-darwin-arm64 hosts-windows-amd64 helpers helpers-linux-amd64 helpers-linux-arm64

all: test hosts helpers

test:
	go vet ./...
	go test ./...

# Host binaries, one per platform you run on.
hosts: hosts-linux-amd64 hosts-darwin-arm64 hosts-windows-amd64
hosts-linux-amd64: export GOOS=linux
hosts-linux-amd64: export GOARCH=amd64
hosts-linux-amd64:
	$(GOBUILD) -o dist/sandboxrun-linux-amd64   ./cmd/sandboxrun
hosts-darwin-arm64: export GOOS=darwin
hosts-darwin-arm64: export GOARCH=arm64
hosts-darwin-arm64:
	$(GOBUILD) -o dist/sandboxrun-darwin-arm64  ./cmd/sandboxrun
hosts-windows-amd64: export GOOS=windows
hosts-windows-amd64: export GOARCH=amd64
hosts-windows-amd64:
	$(GOBUILD) -o dist/sandboxrun-windows-amd64.exe ./cmd/sandboxrun

# Static Linux helpers that get mounted into the containers.
helpers: helpers-linux-amd64 helpers-linux-arm64
helpers-linux-amd64: export GOOS=linux
helpers-linux-amd64: export GOARCH=amd64
helpers-linux-amd64:
	$(GOBUILD) -o dist/sandboxinit-linux-amd64 ./cmd/sandboxinit
helpers-linux-arm64: export GOOS=linux
helpers-linux-arm64: export GOARCH=arm64
helpers-linux-arm64:
	$(GOBUILD) -o dist/sandboxinit-linux-arm64 ./cmd/sandboxinit
