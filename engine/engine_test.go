package engine

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNameArg(t *testing.T) {
	// All engines use the same podman-style run flags, so --name must
	// appear in RunArgs when set. apple is skipped: its Prepare shells out
	// to `container network create`.
	for _, e := range []Engine{podman{}, wslc{}} {
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
