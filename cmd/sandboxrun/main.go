// sandboxrun starts an allowlisting HTTP proxy on the host and then runs a
// container that can only reach that proxy.
//
//	sandboxrun -allow api.github.com -allow '*.githubusercontent.com' \
//	    -image alpine:3 -- \
//	    wget -qO- https://api.github.com
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go.beppler.dev.br/sandboxrun/engine"
	"go.beppler.dev.br/sandboxrun/proxy"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type volumeFlag []engine.Volume

func (v *volumeFlag) String() string {
	var b []string
	for _, vol := range *v {
		s := vol.Source + ":" + vol.Target
		if vol.RW {
			s += ":rw"
		}
		b = append(b, s)
	}
	return strings.Join(b, ",")
}

func (v *volumeFlag) Set(s string) error {
	vol, err := engine.ParseVolume(s)
	if err != nil {
		return err
	}
	*v = append(*v, vol)
	return nil
}

func main() { os.Exit(run()) }

func run() int {
	var allow, ports multi
	rtName := flag.String("runtime", defaultRuntime(), "podman | apple | wslc")
	image := flag.String("image", "", "container image")
	helper := flag.String("helper", "", "path to a LINUX build of sandboxinit (podman, wslc); default: sandboxinit-linux-<arch> next to this binary")
	uid := flag.Int("uid", 1000, "wslc: user the workload runs as")
	gid := flag.Int("gid", 1000, "wslc: group the workload runs as")
	tty := flag.Bool("it", false, "interactive TTY")
	name := flag.String("name", "", "container name (optional)")
	volumes := volumeFlag{}
	flag.Var(&volumes, "volume", "mount host path (repeatable): host:container[:rw], default read-only")
	logDest := flag.String("log", "", "proxy log destination: empty = off (default), '-' = stderr, otherwise a file path (appended)")
	flag.Var(&allow, "allow", "allowed host (repeatable): example.com or *.example.com")
	flag.Var(&ports, "port", "allowed destination port (repeatable, default 80 and 443)")
	flag.Parse()

	if *helper == "" {
		if exe, err := os.Executable(); err == nil {
			*helper = defaultHelper(filepath.Dir(exe))
		}
	}

	cmd := flag.Args()
	if *image == "" || len(cmd) == 0 {
		if *image == "" {
			fmt.Fprintln(os.Stderr, "missing -image")
		}
		if len(cmd) == 0 {
			fmt.Fprintln(os.Stderr, "missing command after --")
		}
		// No -allow is valid: the proxy denies everything, so the container
		// has no network access at all.
		fmt.Fprintln(os.Stderr, "usage: sandboxrun [-allow HOST...] -image IMG [flags] -- CMD [ARGS...]")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng, err := engine.ForName(*rtName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	plan, err := eng.Prepare(ctx, engine.Spec{
		Image: *image, Name: *name, Cmd: cmd, Interactive: *tty,
		HelperPath: *helper, UID: *uid, GID: *gid, Volumes: volumes,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "prepare:", err)
		return 1
	}
	defer plan.Cleanup()

	// Proxy logs are OFF by default so they never mix with the container's
	// own stdout/stderr, which this process passes straight through.
	var logf func(string, ...any)
	switch *logDest {
	case "":
	case "-":
		logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "[proxy] "+f+"\n", a...) }
	default:
		lf, err := os.OpenFile(*logDest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "log:", err)
			return 2
		}
		defer lf.Close()
		logger := log.New(lf, "", log.LstdFlags)
		logf = func(f string, a ...any) { logger.Printf(f, a...) }
	}

	srv := proxy.New(proxy.Config{Allow: allow, Ports: ports, Logf: logf})
	serve := func(ln net.Listener) {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "proxy:", err)
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if plan.Listener != nil {
		go serve(plan.Listener) // already bound: container can't start before it exists
	}
	if plan.ListenLate != nil {
		go func() {
			if ln, err := plan.ListenLate(runCtx); err == nil {
				serve(ln)
			}
		}()
	}

	argv := append([]string{}, plan.Prefix[1:]...)
	argv = append(argv, plan.RunArgs...)
	argv = append(argv, *image)
	argv = append(argv, plan.Args...)

	c := exec.CommandContext(ctx, plan.Prefix[0], argv...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := c.Run()

	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shCancel()
	_ = srv.Shutdown(shCtx)

	var ee *exec.ExitError
	switch {
	case runErr == nil:
		return 0
	case errors.As(runErr, &ee):
		return ee.ExitCode()
	default:
		fmt.Fprintln(os.Stderr, "run:", runErr)
		return 1
	}
}

func defaultRuntime() string {
	switch runtime.GOOS {
	case "darwin":
		return "apple"
	case "windows":
		return "wslc"
	}
	return "podman"
}

// defaultHelper returns the make-built helper beside the executable, or "".
// shortcut: assumes container arch == host arch; pass -helper otherwise.
func defaultHelper(dir string) string {
	p := filepath.Join(dir, "sandboxinit-linux-"+runtime.GOARCH)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}
