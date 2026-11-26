package engine

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
)

// podman (rootless, Linux): the container gets NO network interface at all.
// The host proxy listens on a Unix socket that is bind-mounted into the
// container; the helper (sandboxinit relay) exposes it as 127.0.0.1:3128
// inside the container and then runs the real command.
//
// Rootless note: the host user maps to container root, so the relay (and the
// workload) run as that same user. Don't use --user with a different uid
// unless you also add --userns=keep-id.
type podman struct{}

const (
	podmanSockDir  = "/run/sandbox"
	podmanSockName = "proxy.sock"
	relayListen    = "127.0.0.1:3128"
)

func (podman) Prepare(_ context.Context, s Spec) (*Plan, error) {
	if s.HelperPath == "" {
		return nil, errors.New("podman: -helper (Linux sandboxinit binary) is required")
	}
	helper, err := filepath.Abs(s.HelperPath)
	if err != nil {
		return nil, err
	}
	va, err := volumeArgs(s.Volumes, true)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "sandbox-") // created 0700
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, podmanSockName)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)

	args := []string{
		"--rm", "--init",
		"--network", "none",
		"--cap-drop", "all",
		"--security-opt", "no-new-privileges",
		// ",z" relabels for SELinux hosts; harmless elsewhere.
		"-v", helper + ":/sandboxinit:ro,z",
		"-v", dir + ":" + podmanSockDir + ":z",
		"--entrypoint", "/sandboxinit",
	}
	args = append(args, va...)
	args = append(args, proxyEnv("http://"+relayListen)...)
	if s.Interactive {
		args = append(args, "-it")
	}
	if s.Name != "" {
		args = append(args, "--name", s.Name)
	}

	post := []string{"relay", "--sock", podmanSockDir + "/" + podmanSockName, "--listen", relayListen, "--"}
	post = append(post, s.Cmd...)

	return &Plan{
		Prefix:   []string{"podman", "run"},
		RunArgs:  args,
		Args:     post,
		Listener: ln,
		Cleanup: func() {
			ln.Close()
			os.RemoveAll(dir)
		},
	}, nil
}
