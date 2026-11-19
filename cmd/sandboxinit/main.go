//go:build linux

// sandboxinit is the tiny static helper that runs INSIDE the container.
//
//	relay  --sock S --listen A -- cmd...   (podman)  TCP A  ->  unix socket S
//	guard  --port P --uid U --gid G -- cmd (wslc)    nftables lockdown, drop privs
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: sandboxinit relay|guard ...")
	}
	switch os.Args[1] {
	case "relay":
		relay(os.Args[2:])
	case "guard":
		guard(os.Args[2:])
	default:
		die("unknown subcommand " + os.Args[1])
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "sandboxinit:", msg)
	os.Exit(125)
}

// ---- relay ----------------------------------------------------------------

func relay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	sock := fs.String("sock", "/run/sandbox/proxy.sock", "unix socket of the host proxy")
	listen := fs.String("listen", "127.0.0.1:3128", "loopback address for the workload")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		die("relay: no command")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		die("relay listen: " + err.Error())
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return // we are shutting down
				}
				// Transient (e.g. fd exhaustion): keep serving or the
				// workload's HTTP_PROXY hangs with no hint why.
				fmt.Fprintln(os.Stderr, "sandboxinit relay:", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go func() {
				u, err := net.Dial("unix", *sock)
				if err != nil {
					c.Close()
					return
				}
				done := make(chan struct{}, 2)
				cp := func(dst, src net.Conn) {
					_, _ = io.Copy(dst, src)
					if h, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = h.CloseWrite()
					}
					done <- struct{}{}
				}
				go cp(u, c)
				go cp(c, u)
				<-done
				<-done
				c.Close()
				u.Close()
			}()
		}
	}()
	os.Exit(runChild(cmd))
}

func runChild(argv []string) int {
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "sandboxinit:", err)
		return 127
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs)
	go func() {
		for s := range sigs {
			if s != syscall.SIGCHLD && s != syscall.SIGURG {
				_ = c.Process.Signal(s)
			}
		}
	}()
	err := c.Wait()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}

// ---- guard ----------------------------------------------------------------

func guard(args []string) {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	port := fs.Int("port", 0, "host proxy port")
	uid := fs.Int("uid", 1000, "uid to drop to")
	gid := fs.Int("gid", 1000, "gid to drop to")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if *port == 0 || len(cmd) == 0 {
		die("guard: --port and a command are required")
	}

	gw, err := defaultGateway()
	if err != nil {
		die("guard: " + err.Error())
	}

	rules := fmt.Sprintf(`table inet sandbox {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr %s tcp dport %d accept
  }
}
`, gw, *port)
	nft := exec.Command("nft", "-f", "-")
	nft.Stdin = strings.NewReader(rules)
	nft.Stderr = os.Stderr
	if err := nft.Run(); err != nil {
		die("guard: installing nftables rules failed (is nft in the image? NET_ADMIN granted?): " + err.Error())
	}

	// Irreversibly drop privileges before the workload starts.
	const prSetNoNewPrivs = 38
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		die("guard: prctl(no_new_privs): " + e.Error())
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		die("guard: setgroups: " + err.Error())
	}
	if err := syscall.Setgid(*gid); err != nil {
		die("guard: setgid: " + err.Error())
	}
	if err := syscall.Setuid(*uid); err != nil {
		die("guard: setuid: " + err.Error())
	}

	url := "http://" + net.JoinHostPort(gw, strconv.Itoa(*port))
	env := os.Environ()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env = append(env, k+"="+url)
	}
	env = append(env, "NO_PROXY=", "no_proxy=")

	path, err := exec.LookPath(cmd[0])
	if err != nil {
		die("guard: " + err.Error())
	}
	die("guard: exec: " + syscall.Exec(path, cmd, env).Error())
}

// defaultGateway parses /proc/net/route (IPv4, little-endian hex).
func defaultGateway() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fld := strings.Fields(sc.Text())
		if len(fld) < 3 || fld[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(fld[2], 16, 32)
		if err != nil {
			continue
		}
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String(), nil
	}
	return "", fmt.Errorf("no default route found")
}
