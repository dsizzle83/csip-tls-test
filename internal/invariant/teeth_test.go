package invariant

// teeth_test.go proves the invariants FIRE.
//
// An invariant suite that has never been seen to fail is decoration: it will
// report PASS against a broken device just as cheerfully as against a working
// one, and nobody will find out until the field does. So for every invariant
// with teeth here, there are two tests — one that stands the world up in a
// state which MUST trip it, and one that stands it up in the corresponding
// healthy state and requires a pass. The pair is what makes the check
// meaningful; either alone proves nothing.
//
// The states are injected rather than produced by attacking something, because
// what is under test here is the CHECKER, not the bench. peer_test.go covers
// the other end: a real device on a real socket, read over real Modbus, driven
// into a real violation.

import (
	"context"
	"testing"
	"time"

	"lexa-proto/sunspec"
)

// ── I2 ───────────────────────────────────────────────────────────────────────

func TestI2_FailsADeviceThatDidNotConvergeToFailsafe(t *testing.T) {
	t.Parallel()
	p := DefaultParams()
	p.Values["failsafe_wmaxlimpct"] = "0"
	p.Values["failsafe_deadline"] = "30s"

	faults := NewManifest("teeth", 1)
	armed := time.Now().Add(-5 * time.Minute)
	faults.Arm(Fault{ID: "he.outage#1", Kind: "outage", Class: ClassAuthorityLoss,
		Target: "head-end", Armed: armed, Recoverable: true})

	// The device is still exporting at 90% five minutes after authority was lost.
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 90_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 90)
		}),
	})
	w := NewWorld(Sources{}, faults, nil, p)
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI2(p).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I2 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I2 = %s, want FAIL: authority lost 5m ago with a 30s deadline and the device is at 90%%\nreason: %s",
			res.Verdict, res.Reason)
	}
	t.Logf("finding: %s", res.Reason)
}

func TestI2_PassesADeviceThatConverged(t *testing.T) {
	t.Parallel()
	p := DefaultParams()
	p.Values["failsafe_wmaxlimpct"] = "0"
	p.Values["failsafe_deadline"] = "30s"

	faults := NewManifest("teeth", 1)
	faults.Arm(Fault{ID: "he.outage#1", Kind: "outage", Class: ClassAuthorityLoss,
		Target: "head-end", Armed: time.Now().Add(-5 * time.Minute), Recoverable: true})

	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 0, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 0)
		}),
	})
	w := NewWorld(Sources{}, faults, nil, p)
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI2(p).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I2 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I2 = %s (%s), want PASS", res.Verdict, res.Reason)
	}
}

// TestI2_LatchedFailsafeIsPendingThenFails is FI-03's exact shape: authority
// came back, the head-end is asking for something, and the device is still
// sitting at zero export. No deadline is invented — the claim stays PENDING and
// the run ending resolves it.
func TestI2_LatchedFailsafeIsPendingThenFails(t *testing.T) {
	p := DefaultParams()
	p.Values["failsafe_wmaxlimpct"] = "0"

	faults := NewManifest("teeth", 7)
	id := faults.Arm(Fault{Kind: "outage", Class: ClassAuthorityLoss, Target: "head-end",
		Armed: time.Now().Add(-10 * time.Minute), Recoverable: true})
	faults.Clear(id, time.Now().Add(-5*time.Minute))

	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 0, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 0) // still latched at zero export
		}),
	})
	headEnd := headEndWithControl("CTRL-1", 80_000, time.Now().Add(-4*time.Minute), 3600)

	// A scripted world, so the Monitor's own Observe builds the history the
	// "held constant since restore" test needs.
	src := Sources{
		DERs:    map[string]DERSource{"inv": &scriptedDER{name: "inv", views: []DERView{derFixture("inv", uv)}}},
		HeadEnd: &scriptedHeadEnd{view: headEnd},
	}
	w := NewWorld(src, faults, nil, p)
	inv := NewI2(p)
	mon := monitorOver(t, w, []Invariant{inv})

	var res Result
	for i := 0; i < 3; i++ {
		tr, err := mon.Tick(context.Background())
		if err != nil {
			t.Fatalf("tick: %v", err)
		}
		res = tr.By["I2"]
	}
	if res.Verdict != Pending {
		t.Fatalf("I2 = %s (%s), want PENDING while a latched device has not released", res.Verdict, res.Reason)
	}

	// Now prove Finalize resolves the pending claim into a failure.
	sum := mon.Finalize()
	if sum.OK {
		t.Fatal("the run reported OK with a claim that never resolved")
	}
	if len(sum.Violations) != 1 || sum.Violations[0].ID != "I2" || sum.Violations[0].Verdict != Fail {
		t.Fatalf("Finalize did not turn the pending I2 claim into a FAIL: %+v", sum.Violations)
	}
	if sum.Violations[0].Resolved == "" {
		t.Fatal("the resolved violation does not say it came from an undecided claim")
	}
	t.Logf("resolved finding: %s", sum.Violations[0].Reason)
}

// ── I3 ───────────────────────────────────────────────────────────────────────

func TestI3_FailsWhenARefusedValueIsPresentDownstream(t *testing.T) {
	t.Parallel()
	ledger := NewLedger()
	ledger.NoteWrite(WriteRecord{
		At: time.Now().Add(-time.Minute), Credential: "grid-service", Role: "GridServiceSunSpec",
		Unit: 1, Model: 704, Point: "WMaxLimPct", Value: Q(37, UnitPercent),
		Distinctive: true, Refused: true, ExceptionCode: 0x06, Authorized: true,
		DERs: []string{"inv"},
	})
	// The device is sitting at exactly the refused value.
	uv := unitFixture(1, map[uint16][]uint16{
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 37)
		}),
	})
	w := NewWorld(Sources{}, nil, ledger, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI3(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I3 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL: a write refused with exception 0x06 is present at the DER\nreason: %s",
			res.Verdict, res.Reason)
	}
	requireFact(t, res, "i3.write.exception", "")
	requireFact(t, res, "i3.observed.value", "%")
	t.Logf("finding: %s", res.Reason)
}

func TestI3_PassesWhenTheRefusedValueIsAbsent(t *testing.T) {
	t.Parallel()
	ledger := NewLedger()
	ledger.NoteWrite(WriteRecord{
		At: time.Now().Add(-time.Minute), Credential: "grid-service",
		Unit: 1, Model: 704, Point: "WMaxLimPct", Value: Q(37, UnitPercent),
		Distinctive: true, Refused: true, ExceptionCode: 0x06, Authorized: true,
	})
	uv := unitFixture(1, map[uint16][]uint16{
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 80)
		}),
	})
	w := NewWorld(Sources{}, nil, ledger, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI3(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I3 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I3 = %s (%s), want PASS", res.Verdict, res.Reason)
	}
}

// TestI3_RefusesToJudgeANonDistinctiveWitness locks the honesty rule: a refused
// value that the head-end could also be commanding proves nothing, and I3 must
// say so rather than bank a free pass.
func TestI3_RefusesToJudgeANonDistinctiveWitness(t *testing.T) {
	t.Parallel()
	ledger := NewLedger()
	ledger.NoteWrite(WriteRecord{
		At: time.Now().Add(-time.Minute), Unit: 1, Model: 704, Point: "WMaxLimPct",
		Value: Q(80, UnitPercent), Distinctive: false, Refused: true, ExceptionCode: 0x06,
	})
	uv := unitFixture(1, map[uint16][]uint16{
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 80) // the refused value is right there
		}),
	})
	w := NewWorld(Sources{}, nil, ledger, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI3(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I3 error: %v", err)
	}
	if res.Verdict != Skip {
		t.Fatalf("I3 = %s, want SKIP: the refused value was not distinctive, so its presence proves nothing", res.Verdict)
	}
	if res.Reason == "" {
		t.Fatal("the SKIP does not name what was missing")
	}
}

// ── I7 ───────────────────────────────────────────────────────────────────────

const derStatusConnected = `<DERStatus xmlns="urn:ieee:std:2030.5:ns">
  <genConnectStatus><value>1</value><dateTime>1753500000</dateTime></genConnectStatus>
  <operationalModeStatus><value>2</value><dateTime>1753500000</dateTime></operationalModeStatus>
  <inverterStatus><value>2</value><dateTime>1753500000</dateTime></inverterStatus>
</DERStatus>`

// TestI7_FailsAConnectivityClaimNobodyCanCorroborate is GT-01's shape exactly:
// the DUT tells the head-end everything is connected while not one inverter has
// seen a request from it.
func TestI7_FailsAConnectivityClaimNobodyCanCorroborate(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	frozen := DERView{
		Name: "inv", Source: "simapi:test", Reachable: true,
		Unit:         unitFixture(1, map[uint16][]uint16{702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000)}),
		HasPollCount: true, PollRequests: 4211, // never advances
	}
	head := HeadEndView{
		Source: "gridsim-admin:test", Reachable: true, ServerTime: time.Now(),
		Reports: []Report{{Path: "/edev/0/der/0/derstat", Resource: "DERStatus",
			Body: derStatusConnected, Received: time.Now().Add(-30 * time.Second)}},
	}
	for i := 0; i < 4; i++ {
		o := obsFixture(time.Now().Add(time.Duration(i-3)*time.Minute), frozen)
		o.HeadEnd = head
		w.Inject(o)
	}

	res, err := NewI7(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I7 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I7 = %s, want FAIL: DERStatus claims connected while the DER's request counter never moved\nreason: %s",
			res.Verdict, res.Reason)
	}
	requireFact(t, res, "i7.witness.poll_counters", "count")
	t.Logf("finding: %s", res.Reason)
}

func TestI7_PassesWhenTheClaimIsCorroborated(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	head := HeadEndView{
		Source: "gridsim-admin:test", Reachable: true, ServerTime: time.Now(),
		Reports: []Report{{Path: "/edev/0/der/0/derstat", Resource: "DERStatus",
			Body: derStatusConnected, Received: time.Now().Add(-30 * time.Second)}},
	}
	for i := 0; i < 4; i++ {
		d := DERView{
			Name: "inv", Source: "simapi:test", Reachable: true,
			Unit:         unitFixture(1, map[uint16][]uint16{702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000)}),
			HasPollCount: true, PollRequests: 4211 + i*17, // the DUT is polling
		}
		o := obsFixture(time.Now().Add(time.Duration(i-3)*time.Minute), d)
		o.HeadEnd = head
		w.Inject(o)
	}
	res, err := NewI7(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I7 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I7 = %s (%s), want PASS", res.Verdict, res.Reason)
	}
}

// ── I9 ───────────────────────────────────────────────────────────────────────

// TestI9_UnrecoveredChannelIsPendingUntilTheRunEnds proves the design decision:
// no invented deadline during the run, a definite failure at the end of it.
func TestI9_UnrecoveredChannelIsPendingUntilTheRunEnds(t *testing.T) {
	faults := NewManifest("teeth", 99)
	id := faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: "inv",
		Armed: time.Now().Add(-20 * time.Minute), Recoverable: true})
	faults.Clear(id, time.Now().Add(-15*time.Minute))

	frozen := DERView{Source: "simapi:test", Reachable: true,
		Unit: unitFixture(1, nil), HasPollCount: true, PollRequests: 900}
	src := Sources{DERs: map[string]DERSource{"inv": &scriptedDER{name: "inv", views: []DERView{frozen}}}}
	w := NewWorld(src, faults, nil, DefaultParams())

	inv := NewI9(DefaultParams())
	mon := monitorOver(t, w, []Invariant{inv})
	var res Result
	for i := 0; i < 3; i++ {
		tr, err := mon.Tick(context.Background())
		if err != nil {
			t.Fatalf("tick: %v", err)
		}
		res = tr.By["I9"]
	}
	if res.Verdict != Pending {
		t.Fatalf("I9 = %s (%s), want PENDING — the product promises eventual recovery, not prompt recovery",
			res.Verdict, res.Reason)
	}

	sum := mon.Finalize()
	if sum.OK {
		t.Fatal("a run that ended with an unrecovered channel reported OK")
	}
	if len(sum.Violations) == 0 || sum.Violations[0].Verdict != Fail {
		t.Fatalf("Finalize did not resolve the pending I9 claim: %+v", sum.Violations)
	}
	t.Logf("resolved finding: %s", sum.Violations[0].Reason)
}

func TestI9_PassesWhenTheChannelCameBack(t *testing.T) {
	t.Parallel()
	faults := NewManifest("teeth", 99)
	cleared := time.Now().Add(-4 * time.Minute)
	id := faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: "inv",
		Armed: time.Now().Add(-10 * time.Minute), Recoverable: true})
	faults.Clear(id, cleared)

	w := NewWorld(Sources{}, faults, nil, DefaultParams())
	for i := 0; i < 3; i++ {
		d := DERView{Name: "inv", Source: "simapi:test", Reachable: true,
			Unit: unitFixture(1, nil), HasPollCount: true, PollRequests: 900 + i*40}
		w.Inject(obsFixture(cleared.Add(time.Duration(i)*time.Minute), d))
	}
	res, err := NewI9(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I9 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I9 = %s (%s), want PASS: the counter advanced after the clear", res.Verdict, res.Reason)
	}
}

// TestI9_UnobservableChannelSkipsRatherThanFails is the counterpart to the
// pending-resolves-to-FAIL case above, and it exists because the first live
// campaign found the bug it guards: a DER that publishes no request counter has
// no witness for its own recovery, and I9 reported that blindness as a P1
// against the device.
//
// The two states are one field apart in the observation and worlds apart in
// meaning. A counter stuck at 900 says "the DUT stopped talking to me". No
// counter at all says "I have no way to tell". Only the first is a finding, and
// an invariant that cannot tell them apart fails an innocent device every time
// the bench is wired without a sidecar counter — which is precisely how a P1
// gate comes to be switched off.
func TestI9_UnobservableChannelSkipsRatherThanFails(t *testing.T) {
	t.Parallel()
	faults := NewManifest("teeth", 99)
	cleared := time.Now().Add(-15 * time.Minute)
	id := faults.Arm(Fault{Kind: "ack_no_apply", Class: ClassPeerLie, Target: "inv",
		Armed: time.Now().Add(-20 * time.Minute), Recoverable: true})
	faults.Clear(id, cleared)

	w := NewWorld(Sources{}, faults, nil, DefaultParams())
	for i := 0; i < 3; i++ {
		// Reachable, readable, animating — and NO request counter. Everything
		// about this device is healthy except our ability to witness its poll
		// traffic.
		d := DERView{Name: "inv", Source: "simapi:test", Reachable: true,
			Unit: unitFixture(1, nil), HasPollCount: false}
		w.Inject(obsFixture(cleared.Add(time.Duration(i+1)*time.Minute), d))
	}
	res, err := NewI9(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I9 error: %v", err)
	}
	if res.Verdict != Skip {
		t.Fatalf("I9 = %s (%s), want SKIP: the device publishes no request counter, so its recovery cannot "+
			"be witnessed — reporting that as a violation blames the device for the harness's blindness",
			res.Verdict, res.Reason)
	}

	// And the teeth on the teeth: the SAME shape WITH a counter that never
	// advances must still be undecided-and-therefore-failing, or this fix would
	// have quietly disarmed I9 altogether.
	w2 := NewWorld(Sources{}, faults, nil, DefaultParams())
	for i := 0; i < 3; i++ {
		d := DERView{Name: "inv", Source: "simapi:test", Reachable: true,
			Unit: unitFixture(1, nil), HasPollCount: true, PollRequests: 900}
		w2.Inject(obsFixture(cleared.Add(time.Duration(i+1)*time.Minute), d))
	}
	res2, err := NewI9(DefaultParams()).Check(context.Background(), w2)
	if err != nil {
		t.Fatalf("I9 error: %v", err)
	}
	if res2.Verdict != Pending {
		t.Fatalf("I9 = %s (%s), want PENDING: a counter stuck at 900 across the whole post-clear window is a "+
			"channel that has not recovered, and the run ending in that state is the failure",
			res2.Verdict, res2.Reason)
	}
}

// TestI9_ChannelThatNeverWorkedIsNotAFailureToRecover pins the precondition.
//
// A live campaign against the bench produced a confident P1 — "the flood was
// cleared 45 s ago and the DUT's northbound has not recovered" — from a run
// whose very first tick, before anything was armed, already could not read the
// DUT. The gateway had not failed to recover from the flood; it had never been
// readable by that credential at all. Blaming the adversary for a condition it
// did not create is exactly the kind of false P1 that gets a gate switched off.
func TestI9_ChannelThatNeverWorkedIsNotAFailureToRecover(t *testing.T) {
	t.Parallel()
	faults := NewManifest("teeth", 99)
	armed := time.Now().Add(-3 * time.Minute)
	cleared := time.Now().Add(-1 * time.Minute)
	id := faults.Arm(Fault{Kind: "session-flood", Class: ClassTransportAbuse, Target: "dut",
		Armed: armed, Recoverable: true})
	faults.Clear(id, cleared)

	// The DUT is unreachable at EVERY observation, including the ones before
	// the fault was armed.
	blind := NewWorld(Sources{}, faults, nil, DefaultParams())
	for i := -2; i <= 2; i++ {
		o := obsFixture(cleared.Add(time.Duration(i)*time.Minute), DERView{Name: "inv", Reachable: false})
		o.DUT = DUTView{Source: "mbaps:test", Reachable: false, Err: "denied"}
		blind.Inject(o)
	}
	res, err := NewI9(DefaultParams()).Check(context.Background(), blind)
	if err != nil {
		t.Fatalf("I9 error: %v", err)
	}
	if res.Verdict != Skip {
		t.Fatalf("I9 = %s (%s), want SKIP: the northbound was never readable in this run, so there is no "+
			"working state it could have failed to return to", res.Verdict, res.Reason)
	}

	// The teeth on the teeth: a channel that WAS readable before the fault and
	// is not after it must still be a violation, or the precondition check has
	// disarmed the invariant.
	worked := NewWorld(Sources{}, faults, nil, DefaultParams())
	for i := -3; i <= 2; i++ {
		at := cleared.Add(time.Duration(i) * time.Minute)
		o := obsFixture(at, DERView{Name: "inv", Reachable: false})
		// Readable before the fault was armed, unreadable ever since.
		o.DUT = DUTView{Source: "mbaps:test", Reachable: at.Before(armed)}
		worked.Inject(o)
	}
	res2, err := NewI9(DefaultParams()).Check(context.Background(), worked)
	if err != nil {
		t.Fatalf("I9 error: %v", err)
	}
	if res2.Verdict != Pending {
		t.Fatalf("I9 = %s (%s), want PENDING: the northbound worked before the fault and has not come back",
			res2.Verdict, res2.Reason)
	}
}

// TestI9_HonoursAnOperatorSuppliedBudget proves that a deadline enters this
// invariant only when somebody entitled to state one states it.
func TestI9_HonoursAnOperatorSuppliedBudget(t *testing.T) {
	t.Parallel()
	p := DefaultParams()
	p.Values["recovery_budget"] = "1m"

	faults := NewManifest("teeth", 99)
	id := faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: "inv",
		Armed: time.Now().Add(-20 * time.Minute), Recoverable: true})
	faults.Clear(id, time.Now().Add(-15*time.Minute))

	w := NewWorld(Sources{}, faults, nil, p)
	frozen := DERView{Name: "inv", Source: "simapi:test", Reachable: true,
		Unit: unitFixture(1, nil), HasPollCount: true, PollRequests: 900}
	for i := 0; i < 3; i++ {
		w.Inject(obsFixture(time.Now().Add(time.Duration(i-2)*time.Minute), frozen))
	}
	res, err := NewI9(p).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I9 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I9 = %s, want FAIL once an operator-supplied recovery budget is exceeded", res.Verdict)
	}
}

// ── I10 ──────────────────────────────────────────────────────────────────────

func TestI10_FailsAPartiallyAppliedControl(t *testing.T) {
	t.Parallel()
	// The control asks for an export limit AND a fixed var setpoint.
	limW := 40_000.0
	varPct := 25.0
	head := HeadEndView{
		Source: "gridsim-admin:test", Reachable: true, ServerTime: time.Now(),
		Programs: []Program{{
			ID: 0, MRID: "DERP-SP-001", Primacy: 1,
			Active: []Ctrl{{
				MRID: "CTRL-PARTIAL", Start: time.Now().Add(-time.Minute), Duration: 3600,
				Base: CtrlBase{ExpLimW: &limW, FixedVarPct: &varPct},
			}},
		}},
		Responses: []Response{{Subject: "CTRL-PARTIAL", Status: 2}},
	}
	// The device applied the watt limit but not the var setpoint.
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 30_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 30) // 30 kW <= 40 kW: the limit axis is met
			v.SetEnum("VarSetEna", 0)    // the var axis is NOT applied
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	o := obsFixture(time.Now(), derFixture("inv", uv))
	o.HeadEnd = head
	w.Inject(o)

	res, err := NewI10(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I10 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I10 = %s, want FAIL for a control applied on one axis of two\nreason: %s", res.Verdict, res.Reason)
	}
	requireFact(t, res, "i10.CTRL-PARTIAL.axes_applied", "count")
	t.Logf("finding: %s", res.Reason)
}

func TestI10_PassesAControlDeclinedInFull(t *testing.T) {
	t.Parallel()
	limW := 40_000.0
	varPct := 25.0
	head := HeadEndView{
		Source: "gridsim-admin:test", Reachable: true, ServerTime: time.Now(),
		Programs: []Program{{
			MRID: "DERP-SP-001", Primacy: 1,
			Active: []Ctrl{{
				MRID: "CTRL-NOPE", Start: time.Now().Add(-time.Minute), Duration: 3600,
				Base: CtrlBase{ExpLimW: &limW, FixedVarPct: &varPct},
			}},
		}},
		Alerts: []Alert{{Subject: "CTRL-NOPE", Status: 252, Vocab: "table27", ReceivedAt: time.Now()}},
	}
	// Nothing applied, and the DUT said it could not comply.
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 90_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 0)
			v.SetEnum("VarSetEna", 0)
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	o := obsFixture(time.Now(), derFixture("inv", uv))
	o.HeadEnd = head
	w.Inject(o)

	res, err := NewI10(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I10 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I10 = %s (%s), want PASS: nothing applied and a cannot-comply reported is the correct refusal",
			res.Verdict, res.Reason)
	}
}

// ── I4 / I5 ──────────────────────────────────────────────────────────────────

func TestI4_FailsAnAcceptedUnauthorizedWrite(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	l.NoteWrite(WriteRecord{Credential: "read-only", Role: "ReadOnlySunSpec", Authorized: false,
		Unit: 1, Model: 704, Point: "WMaxLimPct", Value: Q(10, UnitPercent), Accepted: true})
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(time.Now()))

	res, err := NewI4(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I4 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I4 = %s, want FAIL for an accepted write by a read-only credential", res.Verdict)
	}
}

func TestI4_FailsWhenDenialShapeVariesWithCause(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	l.NoteAuth(AuthRecord{Credential: "no-role", CredDomain: "nb", TargetDomain: "nb",
		Cause: CauseNoRole, Stage: "authz", ExceptionCode: 0x01})
	l.NoteAuth(AuthRecord{Credential: "read-only", CredDomain: "nb", TargetDomain: "nb",
		Cause: CauseWrongRole, Stage: "authz", ExceptionCode: 0x02}) // a different code
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(time.Now()))

	res, err := NewI4(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I4 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I4 = %s, want FAIL: two authz denial causes answered with different exception codes", res.Verdict)
	}
}

// TestI4_DoesNotFailAcrossStages locks the scope decision: a handshake
// rejection and an in-session denial are unavoidably distinguishable and must
// not be reported as a violation.
func TestI4_DoesNotFailAcrossStages(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	l.NoteAuth(AuthRecord{Credential: "expired", CredDomain: "nb", TargetDomain: "nb",
		Cause: CauseExpired, Stage: "handshake", ClosedConn: true, TLSAlert: "certificate_expired"})
	l.NoteAuth(AuthRecord{Credential: "no-role", CredDomain: "nb", TargetDomain: "nb",
		Cause: CauseNoRole, Stage: "authz", ExceptionCode: 0x01})
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(time.Now()))

	res, err := NewI4(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I4 error: %v", err)
	}
	if res.Verdict == Fail {
		t.Fatalf("I4 failed a device for distinguishing a handshake rejection from an authz denial: %s", res.Reason)
	}
}

func TestI5_FailsACrossDomainAuthentication(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	l.NoteAuth(AuthRecord{Credential: "sb-device-leaf", CredDomain: "sb-devices",
		TargetDomain: "nb-mbaps-clients", Target: "69.0.0.2:802", Authenticated: true,
		Detail: "the session served a read of model 702"})
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(time.Now()))

	res, err := NewI5(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I5 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I5 = %s, want FAIL: a southbound leaf authenticated against the northbound", res.Verdict)
	}
}

func TestI5_SkipsRatherThanPassesWithoutCoverage(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	l.NoteAuth(AuthRecord{Credential: "grid-service", CredDomain: "nb", TargetDomain: "nb", Authenticated: true})
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(time.Now()))

	res, err := NewI5(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I5 error: %v", err)
	}
	if res.Verdict != Skip {
		t.Fatalf("I5 = %s, want SKIP: the campaign made no cross-domain presentation, so nothing was proved", res.Verdict)
	}
}

// ── I6 ───────────────────────────────────────────────────────────────────────

func TestI6_FailsAMixedStateAfterAnInterruption(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	interrupted := time.Now().Add(-2 * time.Minute)

	before := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 50_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 50)
		}),
	})
	// After the cut the device holds 73% — neither the old value nor anything
	// anyone commanded.
	after := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 50_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 73)
		}),
	})
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(interrupted.Add(-time.Minute), derFixture("inv", before)))
	l.NoteRestart(RestartRecord{At: interrupted, Cause: "campaign", Detail: "SIGKILL + restart"})
	w.Inject(obsFixture(time.Now(), derFixture("inv", after)))

	res, err := NewI6(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I6 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I6 = %s, want FAIL: the recovered value is neither the old one nor a commanded one\nreason: %s",
			res.Verdict, res.Reason)
	}
	t.Logf("finding: %s", res.Reason)
}

func TestI6_PassesWhenTheNewValueWasCommanded(t *testing.T) {
	t.Parallel()
	l := NewLedger()
	interrupted := time.Now().Add(-2 * time.Minute)
	mk := func(pct float64) UnitView {
		return unitFixture(1, map[uint16][]uint16{
			701: measurementRegs(t, 50_000, 1),
			702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
			704: controlRegs(t, func(v sunspec.View) {
				v.SetEnum("WMaxLimPctEna", 1)
				v.SetFloat("WMaxLimPct", pct)
			}),
		})
	}
	w := NewWorld(Sources{}, nil, l, DefaultParams())
	w.Inject(obsFixture(interrupted.Add(-time.Minute), derFixture("inv", mk(50))))
	l.NoteRestart(RestartRecord{At: interrupted, Cause: "campaign"})
	l.NoteWrite(WriteRecord{At: interrupted.Add(time.Second), Unit: 1, Model: 704,
		Point: "WMaxLimPct", Value: Q(73, UnitPercent), Accepted: true, Authorized: true})
	w.Inject(obsFixture(time.Now(), derFixture("inv", mk(73))))

	res, err := NewI6(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I6 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I6 = %s (%s), want PASS: the new value is one that was commanded", res.Verdict, res.Reason)
	}
}

// ── I8 ───────────────────────────────────────────────────────────────────────

func TestI8_FailsAMonotoneSouthboundSessionLeak(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	for i, n := range []int{2, 4, 7, 11, 16, 22} {
		d := DERView{Name: "inv", Source: "simapi:test", Reachable: true,
			Unit: unitFixture(1, nil), HasSessions: true, Sessions: n}
		w.Inject(obsFixture(time.Now().Add(time.Duration(i)*time.Minute), d))
	}
	res, err := NewI8(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I8 error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I8 = %s, want FAIL for a session count that only ever rose\nreason: %s", res.Verdict, res.Reason)
	}
	t.Logf("finding: %s", res.Reason)
}

func TestI8_PassesWhenSessionsAreReclaimed(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	for i, n := range []int{2, 5, 3, 6, 4, 5} {
		d := DERView{Name: "inv", Source: "simapi:test", Reachable: true,
			Unit: unitFixture(1, nil), HasSessions: true, Sessions: n}
		w.Inject(obsFixture(time.Now().Add(time.Duration(i)*time.Minute), d))
	}
	res, err := NewI8(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I8 error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I8 = %s (%s), want PASS: the session count rose and fell, which is load", res.Verdict, res.Reason)
	}
}

// ── shared helpers ───────────────────────────────────────────────────────────

func headEndWithControl(mrid string, limW float64, start time.Time, durationS int) HeadEndView {
	lim := limW
	return HeadEndView{
		Source: "gridsim-admin:test", Reachable: true, ServerTime: time.Now(),
		Programs: []Program{{
			MRID: "DERP-SP-001", Primacy: 1,
			Active: []Ctrl{{MRID: mrid, Start: start, Duration: durationS,
				Base: CtrlBase{ExpLimW: &lim}}},
		}},
	}
}

// monitorOver builds a Monitor over an already-populated World. The world's
// sources are empty, so Tick re-observes into an empty snapshot; the tests that
// use it care only about Finalize's resolution of pending claims, and they arm
// a fault so the assertion floor is satisfied.
func monitorOver(t *testing.T, w *World, checks []Invariant) *Monitor {
	t.Helper()
	m, err := NewMonitor(MonitorConfig{World: w, Checks: checks, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	return m
}
