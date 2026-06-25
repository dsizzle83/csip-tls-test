// Command mqttproxy is a QA-only fault-injecting TCP proxy that sits between the
// lexa services and the hub's mosquitto broker. The bus is the product's spinal
// cord and was the largest untested surface (docs/QA_FINDINGS.md "MQTT chaos");
// this lets the mayhem suite drive broker-level faults the in-sim injectors
// cannot: an outage / restart (drop + refuse connections), added latency, and —
// via a hand-rolled publisher — message-level chaos (malformed JSON, duplicate
// and stale retained state) onto the real broker.
//
// It runs ON the hub (the broker is localhost-bound there); the lexa services'
// mqtt_broker is pointed at this proxy's listen port during QA and back to 1883
// after. The proxy is transparent in pass mode, so leaving it in the path is
// harmless; faults are momentary and driven by the HTTP control API.
package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// faultMode is the proxy's current behaviour toward client (service) connections.
type faultMode int

const (
	modePass    faultMode = iota // transparent forward (default)
	modeDown                     // broker outage: refuse new conns, drop existing
	modeLatency                  // forward, but delay each chunk by latency
)

func (m faultMode) String() string {
	switch m {
	case modeDown:
		return "down"
	case modeLatency:
		return "latency"
	default:
		return "pass"
	}
}

// Proxy forwards TCP from listenAddr to upstreamAddr (the real broker), applying
// the current fault mode. It is safe for concurrent use; the control API mutates
// the mode while the accept/pump loops read it.
type Proxy struct {
	upstream string

	mu         sync.Mutex
	mode       faultMode
	latency    time.Duration
	conns      map[net.Conn]struct{} // live client conns, closed on a transition to down
	resetTimer *time.Timer
}

// NewProxy returns a Proxy forwarding to upstream (host:port of mosquitto).
func NewProxy(upstream string) *Proxy {
	return &Proxy{
		upstream: upstream,
		mode:     modePass,
		conns:    make(map[net.Conn]struct{}),
	}
}

// state snapshots the current fault state for the control API.
func (p *Proxy) state() (mode string, latencyMs int, liveConns int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode.String(), int(p.latency / time.Millisecond), len(p.conns)
}

// setFault applies a fault mode. A positive durationS auto-resets to pass after
// that long (so a scenario can request "broker down for 5 s" in one call).
func (p *Proxy) setFault(mode faultMode, latency time.Duration, durationS int) {
	p.mu.Lock()
	p.mode = mode
	p.latency = latency
	if p.resetTimer != nil {
		p.resetTimer.Stop()
		p.resetTimer = nil
	}
	var toClose []net.Conn
	if mode == modeDown {
		// Simulate an outage/restart: drop every live connection so the clients
		// observe a disconnect and exercise their reconnect+resubscribe path.
		for c := range p.conns {
			toClose = append(toClose, c)
		}
	}
	if durationS > 0 {
		p.resetTimer = time.AfterFunc(time.Duration(durationS)*time.Second, p.reset)
	}
	p.mu.Unlock()

	for _, c := range toClose {
		_ = c.Close()
	}
	log.Printf("[mqttproxy] fault set: mode=%s latency=%s duration=%ds (dropped %d conns)",
		mode, latency, durationS, len(toClose))
}

// reset returns the proxy to transparent pass mode.
func (p *Proxy) reset() {
	p.mu.Lock()
	p.mode = modePass
	p.latency = 0
	if p.resetTimer != nil {
		p.resetTimer.Stop()
		p.resetTimer = nil
	}
	p.mu.Unlock()
	log.Printf("[mqttproxy] fault cleared: pass mode")
}

// currentMode returns the mode and latency under the lock.
func (p *Proxy) currentMode() (faultMode, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode, p.latency
}

func (p *Proxy) track(c net.Conn)   { p.mu.Lock(); p.conns[c] = struct{}{}; p.mu.Unlock() }
func (p *Proxy) untrack(c net.Conn) { p.mu.Lock(); delete(p.conns, c); p.mu.Unlock() }

// Serve accepts client connections on ln and proxies each to the upstream
// broker. It blocks until ln is closed.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(client)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()

	if mode, _ := p.currentMode(); mode == modeDown {
		return // outage: refuse the connection immediately
	}

	upstream, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
	if err != nil {
		log.Printf("[mqttproxy] upstream dial %s: %v", p.upstream, err)
		return
	}
	defer upstream.Close()

	p.track(client)
	defer p.untrack(client)

	// Pump both directions; when either side closes (or a down-fault drops the
	// client conn), both copies unwind and the connection tears down.
	done := make(chan struct{}, 2)
	go func() { p.pump(upstream, client); done <- struct{}{} }() // client → broker
	go func() { p.pump(client, upstream); done <- struct{}{} }() // broker → client
	<-done
}

// pump copies src→dst, applying the current per-chunk latency. It returns when
// src closes, dst errors, or a down-fault closes one of the conns.
func (p *Proxy) pump(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, lat := p.currentMode(); lat > 0 {
				time.Sleep(lat)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				// expected on a fault-driven close; quiet at debug only
			}
			return
		}
	}
}
