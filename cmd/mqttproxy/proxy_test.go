package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// startEcho runs a TCP echo server (stands in for the broker) on an ephemeral port.
func startEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// startProxy serves p on an ephemeral port and returns its address.
func startProxy(t *testing.T, p *Proxy) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve(ln)
	return ln.Addr().String(), func() { ln.Close() }
}

func TestProxy_PassForwards(t *testing.T) {
	up, stopUp := startEcho(t)
	defer stopUp()
	p := NewProxy(up)
	addr, stopP := startProxy(t, p)
	defer stopP()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("echo = %q, want hello", buf)
	}
}

func TestProxy_DownRefusesNewConns(t *testing.T) {
	up, stopUp := startEcho(t)
	defer stopUp()
	p := NewProxy(up)
	p.setFault(modeDown, 0, 0)
	addr, stopP := startProxy(t, p)
	defer stopP()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return // a refused dial is also an acceptable "down"
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Error("expected the connection to be closed in down mode")
	}
}

func TestProxy_DownDropsExisting(t *testing.T) {
	up, stopUp := startEcho(t)
	defer stopUp()
	p := NewProxy(up)
	addr, stopP := startProxy(t, p)
	defer stopP()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// confirm the conn is live (echoes)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("x"))
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("warm-up echo failed: %v", err)
	}

	// Wait for the proxy to register the conn, then fault it down.
	deadline := time.Now().Add(time.Second)
	for {
		if _, _, n := p.state(); n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy never tracked the live connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.setFault(modeDown, 0, 0)

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("expected the existing connection to be dropped on down")
	}
}

func TestProxy_FaultAutoResets(t *testing.T) {
	p := NewProxy("127.0.0.1:1")
	p.setFault(modeDown, 0, 1) // auto-reset after 1s
	if mode, _, _ := p.state(); mode != "down" {
		t.Fatalf("mode = %s, want down", mode)
	}
	time.Sleep(1300 * time.Millisecond)
	if mode, _, _ := p.state(); mode != "pass" {
		t.Errorf("mode = %s after duration, want pass (auto-reset)", mode)
	}
}
