// Package engine builds the per-platform "run this container with no direct
// network, only a path to the host proxy" plan.
package engine

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"
)

// Volume mounts a host path into the container. Default is read-only.
type Volume struct {
	Source string // host path
	Target string // container path
	RW     bool
}

// ParseVolume parses "host:container" (read-only, default) or
// "host:container:rw" / "host:container:ro".
func ParseVolume(v string) (Volume, error) {
	var rw bool
	s := v
	if strings.HasSuffix(s, ":rw") {
		rw = true
		s = s[:len(s)-3]
	} else if strings.HasSuffix(s, ":ro") {
		s = s[:len(s)-3]
	}
	// LastIndex, not SplitN: Windows host paths contain a drive colon.
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return Volume{}, fmt.Errorf("volume %q: want host:container[:rw]", v)
	}
	// The split landed on a drive-letter colon ("C:/x:ro", "C:\data"),
	// so the container path was never given.
	if i == 1 && isDriveLetter(s[0]) {
		return Volume{}, fmt.Errorf("volume %q: want host:container[:rw]", v)
	}
	vol := Volume{Source: s[:i], Target: s[i+1:], RW: rw}
	if vol.Source == "" || vol.Target == "" {
		return Volume{}, fmt.Errorf("volume %q: empty host or container path", v)
	}
	// The container is always Linux, so the target must be absolute; this
	// also rejects windows-style targets like "C:\src:C:\dst".
	if !strings.HasPrefix(vol.Target, "/") {
		return Volume{}, fmt.Errorf("volume %q: container path must be absolute (start with /)", v)
	}
	return vol, nil
}

func isDriveLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// volumeArgs renders -v mount flags, resolving relative host paths;
// selinux adds the ",z" relabel.
func volumeArgs(vols []Volume, selinux bool) ([]string, error) {
	var a []string
	for _, v := range vols {
		src, err := filepath.Abs(v.Source)
		if err != nil {
			return nil, err
		}
		mode := "ro"
		if v.RW {
			mode = "rw"
		}
		if selinux {
			mode += ",z"
		}
		a = append(a, "-v", src+":"+v.Target+":"+mode)
	}
	return a, nil
}

// Spec is what the caller wants to run.
type Spec struct {
	Image       string
	Name        string   // optional container name (engines pass it as --name)
	Cmd         []string // required: the command to run in the container
	Interactive bool
	Volumes     []Volume

	// HelperPath: a *Linux* build of cmd/sandboxinit (podman, wslc, apple).
	HelperPath string

	// wslc, apple: unprivileged user the workload is dropped to inside the container.
	UID, GID int
}

// Plan describes how to launch the container and where the proxy must listen.
type Plan struct {
	// Prefix is the executable + subcommands, e.g. {"podman","run"}.
	Prefix []string
	// RunArgs go between Prefix and the image name.
	RunArgs []string
	// Args go after the image name (entrypoint args / command).
	Args []string

	// Exactly one of these provides the proxy listener.
	Listener   net.Listener
	ListenLate func(ctx context.Context) (net.Listener, error)

	// Cleanup is always non-nil.
	Cleanup func()
}

type Engine interface {
	Prepare(ctx context.Context, s Spec) (*Plan, error)
}

// Default returns the engine for this OS: apple (macOS), wslc (Windows), podman (Linux).
func Default() (Engine, error) {
	switch runtime.GOOS {
	case "darwin":
		return apple{}, nil
	case "windows":
		return wslc{}, nil
	case "linux":
		return podman{}, nil
	}
	return nil, fmt.Errorf("unsupported OS %q", runtime.GOOS)
}

func proxyEnv(url string) []string {
	var a []string
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		a = append(a, "-e", k+"="+url)
	}
	// Only loopback bypasses the proxy.
	const noProxy = "localhost,127.0.0.1,::1,[::1]"
	return append(a, "-e", "NO_PROXY="+noProxy, "-e", "no_proxy="+noProxy)
}
