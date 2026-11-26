package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// apple (macOS 26): the container joins a host-only (--internal) vmnet
// network and reaches the host proxy, which listens on host loopback, at the
// address that a one-time, administrator-only DNS entry maps to localhost (we
// never run sudo ourselves). The proxy URL uses that IP directly: --add-host is
// not available. The address is read from appleResolver; if it is missing,
// Prepare fails. Create the entry with:
//
//	sudo container system dns create --localhost 203.0.113.113 host.container.internal
//
// Like wslc, sandboxinit guard runs the workload in an empty network namespace
// (only lo); a relay there reaches ip:proxyPort through a unix socket. No
// firewall tool is needed in the image.
const appleHost = "host.container.internal"

var appleResolver = "/etc/resolver/containerization." + appleHost // var: tests point it at a temp file

type apple struct{}

// localhostIP finds the "options localhost:<ip>" line in the resolver file.
func localhostIP(resolver string) (string, bool) {
	for l := range strings.SplitSeq(resolver, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "options" {
			if ip, ok := strings.CutPrefix(f[1], "localhost:"); ok && ip != "" {
				return ip, true
			}
		}
	}
	return "", false
}

func (apple) Prepare(ctx context.Context, s Spec) (*Plan, error) {
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
	b, err := os.ReadFile(appleResolver)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ip, ok := localhostIP(string(b))
	if !ok {
		return nil, fmt.Errorf("DNS entry not configured (no localhost:<ip> option in %s); run once: sudo container system dns create --localhost 203.0.113.113 %s", appleResolver, appleHost)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	port := ln.Addr().(*net.TCPAddr).Port
	name := s.Name
	if name == "" {
		name = fmt.Sprintf("sandbox-%d", os.Getpid())
	}
	if o, err := exec.CommandContext(ctx, "container", "network", "create", "--internal", name).CombinedOutput(); err != nil {
		ln.Close()
		return nil, fmt.Errorf("container network create: %v: %s (if a leftover network from a killed run exists, remove it with: container network delete %s)", err, strings.TrimSpace(string(o)), name)
	}

	runArgs, args := guardRun(s, helper, va, ip, port)
	return &Plan{
		Prefix:   []string{"container", "run"},
		RunArgs:  append(runArgs, "--network", name), // host-only: even the root forwarder reaches only the host
		Args:     args,
		Listener: ln,
		Cleanup: func() {
			_ = exec.Command("container", "network", "delete", name).Run()
		},
	}, nil
}
