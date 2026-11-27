//go:build linux

// sandboxinit is the tiny static helper that runs INSIDE the container.
//
//	relay  --sock S --listen A [--uid U --gid G] -- cmd...   TCP A -> unix socket S
//	guard  --host H --port P --listen A --uid U --gid G -- cmd   (wslc) runs cmd in an empty
//	       network namespace (only lo); a relay inside reaches the host proxy through a
//	       unix socket that the parent, still in the container's netns, forwards to H:P.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"
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

// prSetNoNewPrivs: PR_SET_NO_NEW_PRIVS, set on the workload before exec.
const prSetNoNewPrivs = 38

// ---- relay ----------------------------------------------------------------

func relay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	sock := fs.String("sock", "/run/sandbox/proxy.sock", "unix socket of the host proxy")
	listen := fs.String("listen", "127.0.0.1:3128", "loopback address for the workload")
	uid := fs.Int("uid", -1, "bring lo up, then drop to this uid (guard's netns child)")
	gid := fs.Int("gid", -1, "gid to drop to")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		die("relay: no command")
	}
	if *uid >= 0 {
		if err := loUp(); err != nil {
			die("relay: bringing lo up: " + err.Error())
		}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		die("relay listen: " + err.Error())
	}
	go serve(ln, func() (net.Conn, error) { return net.Dial("unix", *sock) })
	// no_new_privs for the workload (inherited across exec): apple's
	// `container run` has no --security-opt, so the relay does it here.
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		die("relay: prctl(no_new_privs): " + e.Error())
	}
	if *uid >= 0 {
		dropPrivs(*uid, *gid)
	}
	os.Exit(runChild(cmd, nil, nil))
}

// serve copies every accepted connection to a fresh dial() result.
func serve(ln net.Listener, dial func() (net.Conn, error)) {
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
			u, err := dial()
			if err != nil {
				fmt.Fprintln(os.Stderr, "sandboxinit relay: dial:", err)
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
}

// loUp brings lo up (a fresh netns has it down) via SIOCSIFFLAGS.
func loUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr [40]byte // struct ifreq: 16-byte name, then flags (short)
	copy(ifr[:], "lo")
	const siocgifflags, siocsifflags, iffUp = 0x8913, 0x8914, 0x1
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocgifflags, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	ifr[16] |= iffUp // little-endian: low byte of ifr_flags
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocsifflags, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	return nil
}

// dropPrivs irreversibly drops root before the workload starts.
func dropPrivs(uid, gid int) {

	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		die("guard: prctl(no_new_privs): " + e.Error())
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		die("guard: setgroups: " + err.Error())
	}
	if err := syscall.Setgid(gid); err != nil {
		die("guard: setgid: " + err.Error())
	}
	if err := syscall.Setuid(uid); err != nil {
		die("guard: setuid: " + err.Error())
	}
}

func runChild(argv []string, attr *syscall.SysProcAttr, started func()) int {
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.SysProcAttr = attr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "sandboxinit:", err)
		return 127
	}
	if started != nil {
		started()
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
	host := fs.String("host", "", "host proxy address")
	listen := fs.String("listen", "", "loopback address of the relay in the workload's netns")
	_ = fs.Parse(args)
	cmd := fs.Args()
	if *port == 0 || *host == "" || *listen == "" || len(cmd) == 0 {
		die("guard: --port, --host, --listen and a command are required")
	}
	target := net.JoinHostPort(*host, strconv.Itoa(*port))

	// Filesystem unix sockets are shared across network namespaces: this is
	// the only path from the workload's empty netns to the outside.
	const dir = "/run/sandbox"
	sock := dir + "/proxy.sock"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		die("guard: " + err.Error())
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		die("guard: " + err.Error())
	}
	_ = os.Chmod(sock, 0o666) // the workload's uid must connect
	go serve(ln, func() (net.Conn, error) { return net.Dial("tcp", target) })

	// Re-exec as the relay in a new, empty netns (needs CAP_SYS_ADMIN); it
	// drops privileges itself. We drop ours once it has been cloned.
	child := append([]string{"/proc/self/exe", "relay", "--sock", sock, "--listen", *listen,
		"--uid", strconv.Itoa(*uid), "--gid", strconv.Itoa(*gid), "--"}, cmd...)
	os.Exit(runChild(child, &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET},
		func() {
			dropPrivs(*uid, *gid)
			// Explicit: the forwarder keeps the container's real network, so the
			// workload (same uid) must not be able to ptrace or read it.
			const prSetDumpable = 4
			_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
		}))
}
