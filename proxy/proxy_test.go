package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, allow ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Allow: allow, Logf: t.Logf})
	go s.Serve(ln)
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return ln.Addr().String()
}

func connectStatus(t *testing.T, proxyAddr, target string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func TestDeniedHost(t *testing.T) {
	addr := start(t, "example.com")
	if got := connectStatus(t, addr, "evil.test:443"); got != http.StatusForbidden {
		t.Fatalf("want 403, got %d", got)
	}
}

func TestDeniedPort(t *testing.T) {
	addr := start(t, "example.com")
	if got := connectStatus(t, addr, "example.com:22"); got != http.StatusForbidden {
		t.Fatalf("want 403, got %d", got)
	}
}

// Even if loopback is (mis)allowlisted, the dialer must refuse it.
func TestPrivateBlockedEvenIfAllowlisted(t *testing.T) {
	addr := start(t, "127.0.0.1", "localhost")
	if got := connectStatus(t, addr, "127.0.0.1:80"); got != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", got)
	}
	if got := connectStatus(t, addr, "localhost:80"); got != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", got)
	}
}

// A dial failure also yields 502, so check the hook directly:
// private destinations must be refused, public ones allowed.
func TestDenyNonPublic(t *testing.T) {
	for _, addr := range []string{"fd12:3456:789a::1", "fc00::1", "fe80::1", "10.0.0.5", "::ffff:10.0.0.5", "100.64.0.1", "127.0.0.1"} {
		err := denyNonPublic("tcp", net.JoinHostPort(addr, "443"), nil)
		if err == nil || !strings.Contains(err.Error(), "not publicly routable") {
			t.Errorf("denyNonPublic(%s) = %v, want 'not publicly routable'", addr, err)
		}
	}
	for _, addr := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if err := denyNonPublic("tcp", net.JoinHostPort(addr, "443"), nil); err != nil {
			t.Errorf("denyNonPublic(%s) = %v, want nil", addr, err)
		}
	}
}

func TestWildcard(t *testing.T) {
	s := New(Config{Allow: []string{"*.example.com"}})
	if !s.permit("api.example.com", "443") || s.permit("example.com", "443") || s.permit("badexample.com", "443") {
		t.Fatal("wildcard matching wrong")
	}
}

func TestNonProxyRequestRefused(t *testing.T) {
	addr := start(t, "example.com")
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}
