package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
)

// wslc (Windows): no host-only network mode was found, so the container keeps
// the default NAT network and locks itself down from the inside:
//
//	sandboxinit guard  (runs as root with SYS_ADMIN+NET_ADMIN)
//	  1. resolves host.wslc.internal (= the Windows host as seen from the container)
//	  2. runs the workload in an empty network namespace (only lo); a relay there
//	     reaches host:proxyPort through a unix socket that the parent, still in the
//	     container's netns, forwards to H:P. No nft/iptables needed in the image.
//	  3. sets no_new_privs, drops to UID/GID, execs the real command
//
// ASSUMPTIONS to verify:
//   - wslc run accepts Docker-style flags (--rm, --cap-add, --user,
//     --entrypoint, -v, -e). Check `wslc container run --help`.
//   - host.wslc.internal reaches a listener on the Windows host (confirmed;
//     the container's default gateway does NOT, it is the VM bridge).
//   - Windows path -> -v mount syntax (drive letters contain ':').
//
// The proxy always binds to 127.0.0.1: host.wslc.internal reaches the
// Windows loopback (verified), so nothing is exposed to the LAN.
type wslc struct{}

func (wslc) Prepare(_ context.Context, s Spec) (*Plan, error) {
	if s.HelperPath == "" {
		return nil, errors.New("wslc: -helper (Linux sandboxinit binary) is required")
	}
	helper, err := filepath.Abs(s.HelperPath)
	if err != nil {
		return nil, err
	}
	va, err := volumeArgs(s.Volumes, false)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	uid, gid := s.UID, s.GID
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	runArgs := []string{
		"--rm",
		"--cap-add", "SYS_ADMIN", // CLONE_NEWNET
		"--cap-add", "NET_ADMIN", // bring lo up in the new netns
		"--user", "0",
		"-v", helper + ":/sandboxinit:ro",
		"--entrypoint", "/sandboxinit",
	}
	runArgs = commonRunArgs(runArgs, s, va)
	args := []string{
		"guard",
		"--host", "host.wslc.internal",
		"--port", strconv.Itoa(port),
		"--listen", relayListen,
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),
		"--",
	}
	args = append(args, s.Cmd...)

	// The container's default gateway is only the VM's bridge, not Windows;
	// wslc exposes the Windows host as host.wslc.internal.
	return &Plan{
		Prefix:   []string{"wslc", "container", "run"},
		RunArgs:  runArgs,
		Args:     args,
		Listener: ln,
		Cleanup:  func() { ln.Close() },
	}, nil
}
