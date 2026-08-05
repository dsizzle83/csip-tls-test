package certify

import (
	"context"
	"strings"
	"testing"
)

// A citation callback can only discover once the capture is in hand that this
// row's criterion is not on the wire for a NON-product reason — TLS resumption
// is the canonical one (RBAC-011). DeclareOffWire from inside the CiteFunc must
// then keep the PASS, exactly as an up-front Result.OffWire would, rather than
// letting the "uncited PASS -> WARN" rule mislabel it as a product WARN.
func TestCitationPhaseDeclareOffWireKeepsPass(t *testing.T) {
	lis := echoServer(t)
	obs := &observedConn{}
	cat := catalogFile(t)

	reg := NewRegistry()
	reg.Register("doc-a::A-001", "example", func(ctx context.Context, rc *RunCtx) (Result, error) {
		conn, err := rc.DialTCP(ctx, lis.Addr().String(), "example session")
		if err != nil {
			return Result{}, err
		}
		defer func() { _ = conn.Close() }()
		obs.note(conn)
		if _, err := conn.Write([]byte("hello")); err != nil {
			return Result{}, err
		}
		_, _ = conn.Read(make([]byte, 64))

		return Result{Verdict: Pass, Notes: "the gateway completed its southbound handshakes", Cite: func(_ context.Context, ev *Evidence) ([]Assertion, error) {
			// The obstacle is only knowable now: every session resumed, so the
			// certificate criterion has no frame to cite. Declare it off-wire and
			// return an honest, uncitable SKIP.
			const reason = "citation-requires-full-handshake: every observed TLS 1.3 session RESUMED (RFC 8446 §2.2)"
			ev.DeclareOffWire(reason)
			return []Assertion{ev.SkipAssertion(
				"the client certificate carries the role", "capture", reason)}, nil
		}}, nil
	})

	opts, _ := baseOptions(t, obs)
	opts.RequireCitation = true
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console(opts))
	}
	var c *CaseResult
	for i := range rep.Cases {
		if rep.Cases[i].Case.UID == "doc-a::A-001" {
			c = &rep.Cases[i]
		}
	}
	if c == nil {
		t.Fatal("no A-001 case")
	}
	if c.Verdict != Pass {
		t.Fatalf("verdict = %s, want PASS (an off-wire citation limitation must not read as a product WARN)", c.Verdict)
	}
	if c.Downgraded != "" {
		t.Errorf("case was downgraded despite the off-wire declaration: %q", c.Downgraded)
	}
	if !strings.Contains(c.Notes, "off-wire criterion") || !strings.Contains(c.Notes, "citation-requires-full-handshake") {
		t.Errorf("notes = %q, want the off-wire reason recorded", c.Notes)
	}
}

// The off-wire escape hatch must not become a way to launder a genuinely
// uncited PASS: a CiteFunc that does NOT declare off-wire is still downgraded.
func TestCitationPhaseUndeclaredUncitedPassStillDowngrades(t *testing.T) {
	lis := echoServer(t)
	obs := &observedConn{}
	cat := catalogFile(t)

	reg := NewRegistry()
	reg.Register("doc-a::A-001", "example", func(ctx context.Context, rc *RunCtx) (Result, error) {
		conn, err := rc.DialTCP(ctx, lis.Addr().String(), "example session")
		if err != nil {
			return Result{}, err
		}
		defer func() { _ = conn.Close() }()
		obs.note(conn)
		_, _ = conn.Write([]byte("hello"))
		_, _ = conn.Read(make([]byte, 64))
		return Result{Verdict: Pass, Cite: func(_ context.Context, ev *Evidence) ([]Assertion, error) {
			return []Assertion{ev.SkipAssertion("some criterion", "capture", "not shown")}, nil
		}}, nil
	})

	opts, _ := baseOptions(t, obs)
	opts.RequireCitation = true
	run, _ := New(reg, cat, opts)
	rep, _ := run.Run(context.Background())
	var c *CaseResult
	for i := range rep.Cases {
		if rep.Cases[i].Case.UID == "doc-a::A-001" {
			c = &rep.Cases[i]
		}
	}
	if c == nil || c.Verdict != Warn {
		t.Fatalf("verdict = %v, want WARN (an uncited PASS with no off-wire declaration must downgrade)", c)
	}
}
