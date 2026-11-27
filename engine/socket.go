package engine

import (
	"net"
	"os"
	"path/filepath"
)

// unixSocketListener creates a temp dir holding the proxy socket, bound and
// reachable only by this host user (podman; apple loosens the perms for the
// VM mount). Shared by the engines that mount a host socket: podman, apple.
const proxySockName = "proxy.sock"

// Where the proxy socket is mounted inside the container. A file mount needs
// an existing parent dir: /tmp exists in every image (apple); /run is never a
// user volume target (podman).
const (
	containerSock = "/tmp/sandbox-proxy.sock"
	podmanSock    = "/run/sandbox-proxy.sock"
)

func unixSocketListener() (dir string, ln net.Listener, err error) {
	dir, err = os.MkdirTemp("", "sandbox-") // created 0700
	if err != nil {
		return
	}
	ln, err = net.Listen("unix", filepath.Join(dir, proxySockName))
	if err != nil {
		os.RemoveAll(dir)
		return
	}
	_ = os.Chmod(filepath.Join(dir, proxySockName), 0o600)
	return
}
