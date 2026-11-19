// Package proxy implements a small allowlisting HTTP/HTTPS forward proxy.
//
// Two layers of defence:
//  1. Hostname allowlist + port allowlist (policy).
//  2. A dialer Control hook that refuses loopback/private/link-local
//     destinations AFTER DNS resolution, so an allowed name can never be used
//     to reach the host itself or your LAN (SSRF / DNS rebinding).
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	// Allow holds exact hostnames ("api.github.com") or suffix wildcards
	// ("*.githubusercontent.com").
	Allow []string
	// Ports defaults to 80 and 443.
	Ports []string
	Logf  func(format string, args ...any)
}

type Server struct {
	allow     []string
	ports     map[string]bool
	logf      func(string, ...any)
	dialer    *net.Dialer
	transport *http.Transport
	srv       *http.Server
}

func New(cfg Config) *Server {
	s := &Server{ports: map[string]bool{}, logf: cfg.Logf}
	if s.logf == nil {
		s.logf = func(string, ...any) {}
	}
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = []string{"80", "443"}
	}
	for _, p := range ports {
		s.ports[p] = true
	}
	for _, a := range cfg.Allow {
		s.allow = append(s.allow, strings.ToLower(strings.TrimSpace(a)))
	}
	s.dialer = &net.Dialer{Timeout: 15 * time.Second, Control: denyNonPublic}
	s.transport = &http.Transport{
		Proxy:                 nil, // never chain through another proxy implicitly
		DialContext:           s.dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          32,
		DisableCompression:    true,
	}
	s.srv = &http.Server{Handler: s, ReadHeaderTimeout: 15 * time.Second}
	return s
}

func (s *Server) Serve(ln net.Listener) error { return s.srv.Serve(ln) }

func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	ula6  = netip.MustParsePrefix("fc00::/7") // IPv6 unique-local, the LAN of IPv6
)

// denyNonPublic runs on every outbound connection with the already-resolved IP.
func denyNonPublic(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip) ||
		(ip.Is6() && ula6.Contains(ip)) {
		return fmt.Errorf("destination %s is not publicly routable", ip)
	}
	return nil
}

func (s *Server) permit(host, port string) bool {
	if !s.ports[port] {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range s.allow {
		if p == host || (strings.HasPrefix(p, "*.") && strings.HasSuffix(host, p[1:])) {
			return true
		}
	}
	return false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.connect(w, r)
		return
	}
	s.forward(w, r)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	if !s.permit(host, port) {
		s.logf("DENY  CONNECT %s", r.Host)
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}
	upstream, err := s.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		s.logf("FAIL  CONNECT %s: %v", r.Host, err)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	s.logf("ALLOW CONNECT %s", r.Host)
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	pipe(client, upstream, brw.Reader)
}

func pipe(client, upstream net.Conn, clientIn io.Reader) {
	// Absolute cap so a stuck tunnel can't hold conns and goroutines forever.
	// shortcut: kills any single tunnel after 24h even if active, fine while
	// tunnel lifetime is bounded by the sandboxed command.
	idle := time.Now().Add(24 * time.Hour)
	client.SetDeadline(idle)
	upstream.SetDeadline(idle)
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(upstream, clientIn)
	go cp(client, upstream)
	<-done
	<-done
	client.Close()
	upstream.Close()
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// forward handles plain-HTTP proxy requests (absolute-URI form). HTTPS uses CONNECT.
func (s *Server) forward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		// Not a proxy request: never serve anything from the proxy itself.
		http.Error(w, "proxy requests only", http.StatusBadRequest)
		return
	}
	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	if !s.permit(r.URL.Hostname(), port) {
		s.logf("DENY  %s %s", r.Method, r.URL.Host)
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		s.logf("FAIL  %s %s: %v", r.Method, r.URL.Host, err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	s.logf("ALLOW %s %s", r.Method, r.URL.Host)
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
