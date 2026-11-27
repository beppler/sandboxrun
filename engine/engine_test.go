package engine

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNameArg(t *testing.T) {
	// All engines use the same podman-style run flags, so --name must
	// appear in RunArgs when set.
	for _, e := range []Engine{podman{}, wslc{}, apple{}} {
		plan, err := e.Prepare(context.Background(), Spec{Name: "mysandbox", HelperPath: "/tmp/sandboxinit"})
		if err != nil {
			t.Fatal(err)
		}
		args := plan.RunArgs
		found := false
		for i, a := range args {
			if a == "--name" && i+1 < len(args) && args[i+1] == "mysandbox" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%T: no --name mysandbox in RunArgs: %v", e, args)
		}
		plan.Cleanup()
	}
}

func TestWslcGuardArgs(t *testing.T) {
	has := func(args []string, a, b string) bool {
		for i := range args {
			if args[i] == a && (b == "" || (i+1 < len(args) && args[i+1] == b)) {
				return true
			}
		}
		return false
	}
	plan, err := wslc{}.Prepare(context.Background(), Spec{HelperPath: "/tmp/sandboxinit", Cmd: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Cleanup()
	if a := plan.Listener.Addr().(*net.TCPAddr); !a.IP.IsLoopback() {
		t.Errorf("listener not loopback-only: %v", a)
	}
	for _, c := range []string{"SYS_ADMIN", "NET_ADMIN"} {
		if !has(plan.RunArgs, "--cap-add", c) {
			t.Errorf("missing --cap-add %s: %v", c, plan.RunArgs)
		}
	}
	if !has(plan.Args, "--host", "host.wslc.internal") {
		t.Errorf("missing default --host: %v", plan.Args)
	}
}

func TestParseVolume(t *testing.T) {
	cases := []struct {
		in    string
		want  Volume
		fails bool
	}{
		{in: "/tmp/data:/data", want: Volume{Source: "/tmp/data", Target: "/data"}},
		{in: "/tmp/data:/data:rw", want: Volume{Source: "/tmp/data", Target: "/data", RW: true}},
		{in: "C:\\proj:/work:rw", want: Volume{Source: "C:\\proj", Target: "/work", RW: true}},
		{in: "C:\\proj:/work", want: Volume{Source: "C:\\proj", Target: "/work"}},
		{in: "/tmp/data", fails: true},
		{in: ":/data", fails: true},
		{in: "/data:", fails: true},
		{in: "/a:/b:ro", want: Volume{Source: "/a", Target: "/b"}},
		{in: "C:\\x:/y", want: Volume{Source: "C:\\x", Target: "/y"}},
		{in: "C:\\x:/y:rw", want: Volume{Source: "C:\\x", Target: "/y", RW: true}},
		// Windows also accepts forward slashes: C:/Users/...
		{in: "C:/Users/me/data:/data", want: Volume{Source: "C:/Users/me/data", Target: "/data"}},
		{in: "C:/Users/me/data:/data:rw", want: Volume{Source: "C:/Users/me/data", Target: "/data", RW: true}},
		{in: "C:/Users/me/ro:/data", want: Volume{Source: "C:/Users/me/ro", Target: "/data"}}, // folder named "ro"
		{in: "C:/x:ro", fails: true},          // missing target: split would land on the drive colon
		{in: "C:/Users/me/data", fails: true}, // missing target
		{in: "C:\\data:rw", fails: true},      // missing target
		{in: "C:\\src:C:\\dst", fails: true},  // windows-style target: container is Linux
	}
	for _, c := range cases {
		got, err := ParseVolume(c.in)
		if c.fails {
			if err == nil {
				t.Errorf("ParseVolume(%q) = %+v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVolume(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseVolume(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestVolumeArgs(t *testing.T) {
	a, err := volumeArgs([]Volume{
		{Source: "/tmp/data", Target: "/data"},
		{Source: "/tmp/out", Target: "/out", RW: true},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	// filepath.Abs yields a drive-prefixed path on Windows.
	abs := func(p string) string {
		t.Helper()
		s, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	want := []string{"-v", abs("/tmp/data") + ":/data:ro,z", "-v", abs("/tmp/out") + ":/out:rw,z"}
	for i, w := range want {
		if a[i] != w {
			t.Errorf("volumeArgs[%d] = %q, want %q", i, a[i], w)
		}
	}

	a, err = volumeArgs([]Volume{{Source: "./out", Target: "/out", RW: true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	src := a[1][:len(a[1])-len(":/out:rw")]
	if !filepath.IsAbs(src) || filepath.Base(src) != "out" {
		t.Errorf("relative source not resolved: %q", a[1])
	}

	if a, err := volumeArgs(nil, true); err != nil || len(a) != 0 {
		t.Errorf("empty volumes: %v, %v", a, err)
	}
}

func TestDefault(t *testing.T) {
	want := map[string]Engine{"linux": podman{}, "darwin": apple{}, "windows": wslc{}}[runtime.GOOS]
	if want == nil {
		t.Skip("unsupported OS")
	}
	got, err := Default()
	if err != nil || got != want {
		t.Fatalf("Default() = %T, %v; want %T", got, err, want)
	}
}

func TestProxyEnv(t *testing.T) {
	for _, e := range []Engine{podman{}, wslc{}, apple{}} {
		plan, err := e.Prepare(context.Background(), Spec{HelperPath: "/tmp/sandboxinit"})
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(plan.RunArgs, " ")
		if !strings.Contains(got, "HTTP_PROXY=http://"+relayListen) {
			t.Errorf("%T: HTTP_PROXY not set to the relay: %s", e, got)
		}
		for _, k := range []string{"NO_PROXY", "no_proxy"} {
			if !strings.Contains(got, k+"=localhost,127.0.0.1,::1,[::1]") {
				t.Errorf("%T: %s not set to loopback list: %s", e, k, got)
			}
		}
	}
}

func TestWslcGuardListen(t *testing.T) {
	plan, err := wslc{}.Prepare(context.Background(), Spec{HelperPath: "/tmp/sandboxinit"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan.Args, " "); !strings.Contains(got, "--listen "+relayListen+" ") {
		t.Errorf("guard args missing --listen %s: %s", relayListen, got)
	}
}

// apple is a podman-style run: no network, no caps, socket mount + relay.
func TestApplePodmanStyle(t *testing.T) {
	plan, err := apple{}.Prepare(context.Background(), Spec{Name: "sb", HelperPath: "/tmp/sandboxinit", Cmd: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Cleanup()
	if _, ok := plan.Listener.Addr().(*net.UnixAddr); !ok {
		t.Errorf("listener is not a unix socket: %v", plan.Listener.Addr())
	}
	run, args := strings.Join(plan.RunArgs, " "), strings.Join(plan.Args, " ")
	for _, want := range []string{"--network none", "--cap-drop all"} {
		if !strings.Contains(run, want) {
			t.Errorf("RunArgs missing %q: %s", want, run)
		}
	}
	for _, bad := range []string{"--cap-add", "--user", "guard"} {
		if strings.Contains(run, bad) {
			t.Errorf("RunArgs contains %q: %s", bad, run)
		}
	}
	if !strings.HasPrefix(args, "relay --sock "+appleSock+" --listen "+relayListen+" ") {
		t.Errorf("relay args wrong: %s", args)
	}
}

func TestAppleSocketPerms(t *testing.T) {
	plan, err := apple{}.Prepare(context.Background(), Spec{HelperPath: "/tmp/sandboxinit"})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Cleanup()
	p := plan.Listener.Addr().String()
	i, err := os.Stat(p)
	if err != nil || i.Mode().Perm()&0o666 != 0o666 {
		t.Errorf("socket %s perms: %v, %v", p, i.Mode(), err)
	}
}
