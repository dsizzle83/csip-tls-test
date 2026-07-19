package gwmayhem

// transport_abuse.go is the transport-abuse family: a hostile aggregator that
// opens far more concurrent sessions than a well-behaved head-end, to prove the
// gateway CAPS concurrent sessions (refusing the excess post-handshake) rather than
// accepting an unbounded pile that would exhaust the session table, and that its
// session capacity RECOVERS once the flood releases (no wedge / no leak). The
// renegotiation-refusal and resume-after-drop transport policies (TCP-62 / TCP-46 /
// TCP-14) already have aggregator campaigns (qa/aggregator/renego-refusal.json,
// resumption-after-drop.json) that this suite can run as spec scenarios; the flood
// is the piece that needs concurrency, so it is Go-literal.
//
// The reserved LAN-vs-tunnel budget (MaxTunnel — vendor tunnel reads must never
// starve LAN clients) needs a tunnel/cloudlink peer to exercise and is a next-wave
// (authority/PKI/infra) item; this scenario asserts the total-session cap that a
// LAN flood runs into.

import (
	"context"

	"csip-tls-test/internal/aggregator"
)

// floodN is how many concurrent sessions the flood opens. It must exceed the
// gateway's session cap (default 8 live, smaller on the loopback) so refusals are
// observable; 12 clears both.
const floodN = 12

// sessionFlood builds the session-flood scenario.
func sessionFlood() gwScenario {
	return gwScenario{
		ID:       "transport-session-flood",
		Desc:     "flood N concurrent sessions — the gateway caps them (refuses the excess) and recovers capacity",
		Category: "mbaps-transport-abuse",
		Source:   SourceGo,
		Security: true,
		Expected: []Verdict{VerdictPass},
		arm:      armSessionFlood,
		oracle:   "sessionFlood",
	}
}

// armSessionFlood opens floodN concurrent read-only sessions (the least intrusive
// role — they only read), counts how many the gateway actually serves vs refuses,
// releases them, and then proves a fresh control session still round-trips (the
// session table recovered).
func armSessionFlood(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	f := &floodOutcome{Attempted: floodN}
	ev.Flood = f

	conns := make([]*aggregator.Conn, 0, floodN)
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	// Open all sessions and hold them concurrently, so the gateway sees floodN live
	// at once (a session it refuses is closed post-handshake, so ConnectAs succeeds
	// but a later op on it fails).
	for i := 0; i < floodN; i++ {
		c, err := w.connectAs(aggregator.RoleReadOnly)
		if err != nil {
			f.Refused++ // a refused handshake also counts as refused
			continue
		}
		conns = append(conns, c)
	}
	// A held session that still round-trips a read was truly served; one whose op
	// fails was refused (closed post-handshake).
	for _, c := range conns {
		if c == nil {
			continue
		}
		if err := c.Ping(pingUnit); err == nil {
			f.Established++
		} else {
			f.Refused++
		}
	}
	f.Cap = f.Established
	f.CapObserved = f.Refused > 0

	// Release the flood before checking LAN survival, so the check measures capacity
	// RECOVERY, not contention.
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	conns = conns[:0]

	ctrl, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		f.LanSurvived = false
		f.Note = "post-flood control session could not connect: " + err.Error()
		return nil
	}
	defer ctrl.Close()
	f.LanSurvived = ctrl.Ping(pingUnit) == nil
	if !f.LanSurvived {
		f.Note = "post-flood control session connected but could not round-trip a read"
	}
	return nil
}

// pingUnit is a unit the loopback/gateway serves, used for the flood liveness
// probes (a read of the SunSpec base marker there round-trips or returns a protocol
// exception — both prove the session works).
const pingUnit = 1
