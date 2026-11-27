package engine

import (
	"net"
	"os"
	"path/filepath"
)

// unixSocketListener creates a temp dir holding the proxy socket, bound and
// reachable only by this host user (podman; apple loosens the perms for the
// VM mount). Shared by the engines that mount a host socket: podman, apple.
func unixSocketListener() (dir string, ln net.Listener, err error) {
	dir, err = os.MkdirTemp("", "sandbox-") // created 0700
	if err != nil {
		return
	}
	ln, err = net.Listen("unix", filepath.Join(dir, podmanSockName))
	if err != nil {
		os.RemoveAll(dir)
		return
	}
	_ = os.Chmod(filepath.Join(dir, podmanSockName), 0o600)
	return
}
