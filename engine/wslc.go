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
//	sandboxinit guard  (runs as root with NET_ADMIN)
//	  1. finds the default gateway (= the Windows host as seen from the VM)
//	  2. installs nftables: default-drop output, allow only gateway:proxyPort
//	  3. sets no_new_privs, drops to UID/GID, execs the real command
//
// ASSUMPTIONS to verify:
//   - wslc run accepts Docker-style flags (--rm, --cap-add, --user,
//     --entrypoint, -v, -e). Check `wslc container run --help`.
//   - the container's default gateway reaches a listener on the Windows host.
//     If not, find the right host address and pass it to the helper.
//   - Windows path -> -v mount syntax (drive letters contain ':').
//   - the image's nft binary exists (the helper shells out to `nft`).
//
// SECURITY NOTE: Spec.Bind defaults to 0.0.0.0 because the container reaches
// the host through the WSL virtual network's gateway address, which is not
// known until runtime (loopback would break the container path). The allowlist
// is then the only thing stopping other machines on the LAN from using this
// proxy. To scope exposure, add a Windows Firewall inbound rule for the proxy
// port restricted to the WSL subnet, or pass -bind with the host's WSL-side
// address (find it with `wsl.exe -- ip route show default`, the "via" address).
//
// Also add a Windows Firewall inbound rule scoped to the WSL/WSLC subnet for
// the proxy port, because the listener binds to Spec.Bind (default 0.0.0.0).
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
	bind := s.Bind
	if bind == "" {
		bind = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	uid, gid := s.UID, s.GID
	if uid == 0 {
		uid, gid = 1000, 1000
	}

	args := []string{
		"--rm",
		"--cap-add", "NET_ADMIN",
		"--user", "0",
		"-v", helper + ":/sandboxinit:ro",
		"--entrypoint", "/sandboxinit",
	}
	args = append(args, va...)
	if s.Interactive {
		args = append(args, "-it")
	}
	if s.Name != "" {
		args = append(args, "--name", s.Name)
	}

	post := []string{
		"guard",
		"--port", strconv.Itoa(port),
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),
		"--",
	}
	post = append(post, s.Cmd...)

	return &Plan{
		Prefix:   []string{"wslc", "container", "run"},
		RunArgs:  args,
		Args:     post,
		Listener: ln,
		Cleanup:  func() { ln.Close() },
	}, nil
}
