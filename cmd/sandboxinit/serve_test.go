//go:build linux

package main

import (
	"io"
	"net"
	"testing"
)

// serve must copy bytes both ways between an accepted conn and a dialed one.
func TestServeCopiesBothWays(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, _ := backend.Accept()
		b, _ := io.ReadAll(c) // client half-closes after writing
		c.Write(append([]byte("echo:"), b...))
		c.Close()
	}()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	go serve(front, func() (net.Conn, error) { return net.Dial("tcp", backend.Addr().String()) })

	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hi"))
	c.(*net.TCPConn).CloseWrite()
	got, _ := io.ReadAll(c)
	if string(got) != "echo:hi" {
		t.Fatalf("got %q", got)
	}
}
