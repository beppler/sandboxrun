// apple (macOS 26): the container runs with --network none (loopback only)
// and the proxy is reached through a host Unix socket bind-mounted into the
// container; sandboxinit relay exposes it as 127.0.0.1:3128. No DNS entry, no
// vmnet network and no guard (netns + caps) are needed.
package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

type apple struct{}

func (apple) Prepare(_ context.Context, s Spec) (*Plan, error) {
	if s.HelperPath == "" {
		return nil, errors.New("apple: -helper (Linux sandboxinit binary) is required")
	}
	helper, err := filepath.Abs(s.HelperPath)
	if err != nil {
		return nil, err
	}
	va, err := volumeArgs(s.Volumes, false)
	if err != nil {
		return nil, err
	}
	dir, ln, err := unixSocketListener()
	if err != nil {
		return nil, err
	}
	// The socket must be connectable from inside the VM, where the mounted
	// file's owner may not map to our host user: world-writable it is.
	sockPath := filepath.Join(dir, proxySockName)
	_ = os.Chmod(sockPath, 0o666) // virtiofs owner mapping in the VM is unknown
	runArgs := []string{
		"--rm",
		"--network", "none", // loopback only: only the mounted socket leaves the container
		"--cap-drop", "all", // like podman: the workload runs with no capabilities
		// no --security-opt: `container run` has none; relay sets no_new_privs
		// itself before exec'ing the workload.
		"-v", helper + ":/sandboxinit:ro",
		// Mount the socket file itself, read-write (like /var/run/docker.sock):
		// apple's virtiofs proxies unix sockets this way; a :ro directory mount
		// failed with EOPNOTSUPP on connect.
		"-v", sockPath + ":" + containerSock,
		"--entrypoint", "/sandboxinit",
	}
	runArgs = commonRunArgs(runArgs, s, va)
	args := []string{"relay", "--sock", containerSock, "--listen", relayListen, "--"}
	args = append(args, s.Cmd...)

	return &Plan{
		Prefix:   []string{"container", "run"},
		RunArgs:  runArgs,
		Args:     args,
		Listener: ln,
		Cleanup: func() {
			ln.Close()
			os.RemoveAll(dir)
		},
	}, nil
}
