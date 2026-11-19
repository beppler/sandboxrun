package engine

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// apple (macOS 26): the container joins a host-only (--internal) vmnet
// network. It can reach the host and nothing else; the host proxy listens on
// the network's gateway address.
//
// ASSUMPTIONS to verify on your machine:
//   - the gateway is the first host address of the subnet we choose (.1).
//     Confirm with `container network inspect <name>` and adjust if not.
//   - the vmnet bridge only exists once a container is attached, so the
//     listener is created lazily (retrying) after the container starts.
//
// Hardening still to do on the host: a pf rule on the bridge allowing only
// <gateway>:<port>, since host-only mode exposes ALL host ports on that IP.
type apple struct{}

func (apple) Prepare(ctx context.Context, s Spec) (*Plan, error) {
	va, err := volumeArgs(s.Volumes, false)
	if err != nil {
		return nil, err
	}
	port := s.ProxyPort
	if port == 0 {
		port = 18080
	}
	// Only ~200 subnets, so a collision with a leftover network is possible;
	// pick a fresh subnet and retry before giving up.
	var name, subnet, gateway string
	for i := 0; ; i++ {
		third := 16 + rand.IntN(200)
		subnet = fmt.Sprintf("10.77.%d.0/24", third)
		gateway = fmt.Sprintf("10.77.%d.1", third)
		name = fmt.Sprintf("sandbox-%d-%d", os.Getpid(), rand.IntN(1<<16))
		out, err := exec.CommandContext(ctx, "container", "network", "create",
			"--internal", "--subnet", subnet, name).CombinedOutput()
		if err == nil {
			break
		}
		if i == 2 {
			return nil, fmt.Errorf("container network create (subnet clash with a leftover network? tried 3 subnets): %v: %s",
				err, strings.TrimSpace(string(out)))
		}
	}

	addr := net.JoinHostPort(gateway, fmt.Sprint(port))
	args := []string{
		"--progress", "none",
		"--rm",
		"--network", name,
	}
	args = append(args, va...)
	args = append(args, proxyEnv("http://"+addr)...)
	if s.Interactive {
		args = append(args, "-it")
	}
	if s.Name != "" {
		args = append(args, "--name", s.Name)
	}

	return &Plan{
		Prefix:  []string{"container", "run"},
		RunArgs: args,
		Args:    s.Cmd,
		ListenLate: func(ctx context.Context) (net.Listener, error) {
			t := time.NewTicker(100 * time.Millisecond)
			defer t.Stop()
			for {
				if ln, err := net.Listen("tcp", addr); err == nil {
					return ln, nil
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-t.C:
				}
			}
		},
		Cleanup: func() {
			_ = exec.Command("container", "network", "delete", name).Run()
		},
	}, nil
}
