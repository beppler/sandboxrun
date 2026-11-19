package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultRuntime(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if defaultRuntime() == "" {
			t.Fatalf("no default runtime on %s", runtime.GOOS)
		}
	default:
		t.Skip("unsupported OS")
	}
}

func TestDefaultHelper(t *testing.T) {
	dir := t.TempDir()
	if got := defaultHelper(dir); got != "" {
		t.Fatalf("no helper present: got %q", got)
	}
	want := filepath.Join(dir, "sandboxinit-linux-"+runtime.GOARCH)
	if err := os.WriteFile(want, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := defaultHelper(dir); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
