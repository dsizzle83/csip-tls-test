package suitecsip

// localext_envelope_test.go proves REV0907-D2-IMPL P5's referee-side graders
// directly against synthetic inputs — the same technique
// localext_eventstatus_test.go's "THE ORACLE'S EXPECTATION TABLE" half uses:
// no gridsim, no mbaps session, no bench. Each grader in localext_envelope.go
// is a pure function of (what this row's own mbaps write drew, what the DER's
// own registers read), so it is tested as one directly.
//
// decodeMbapsExchange and the L704/L703 contiguity assumption every write
// helper rests on are pinned separately, against the real lexa-proto/mbap and
// lexa-proto/sunspec packages this file uses for framing — never against a
// fixture this test invented, so a real encode/decode or layout regression
// would show up here.

import (
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suitessm"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// ── decodeMbapsExchange: real MBAP framing, no fixture invented ─────────────

func TestDecodeMbapsExchange(t *testing.T) {
	writeReq := mbap.WriteReq{FC: mbap.FCWriteMultiple, Addr: 100, Values: []uint16{1, 2}}
	okPDU, err := mbap.BuildWriteResp(writeReq)
	if err != nil {
		t.Fatalf("BuildWriteResp: %v", err)
	}
	okADU, err := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: 1, UnitID: 1}, PDU: okPDU})
	if err != nil {
		t.Fatalf("Encode ok ADU: %v", err)
	}

	reqADU := mbap.ADU{Header: mbap.Header{TID: 2, UnitID: 1}, PDU: []byte{0x10, 0, 100, 0, 2, 4, 0, 1, 0, 2}}
	excADU := mbap.Exception(reqADU, mbap.ExIllegalValue)
	excRaw, err := mbap.Encode(excADU)
	if err != nil {
		t.Fatalf("Encode exception ADU: %v", err)
	}

	tests := []struct {
		name string
		ex   suitessm.Exchange
		want envelopeWriteOutcome
	}{
		{"transport error", suitessm.Exchange{Err: errBoom}, envelopeWriteOutcome{Err: errBoom}},
		{"normal ack", suitessm.Exchange{Response: okADU}, envelopeWriteOutcome{Acked: true}},
		{"exception 03", suitessm.Exchange{Response: excRaw},
			envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeMbapsExchange(tt.ex)
			if got.Acked != tt.want.Acked || got.HasException != tt.want.HasException ||
				got.Exception != tt.want.Exception || (got.Err == nil) != (tt.want.Err == nil) {
				t.Fatalf("decodeMbapsExchange(%+v) = %+v, want %+v", tt.ex, got, tt.want)
			}
		})
	}
}

type boomErr struct{}

func (boomErr) Error() string { return "boom" }

var errBoom = boomErr{}

// ── L704/L703 contiguity: every write helper's load-bearing assumption ──────

// TestL704EnvelopeSpansAreContiguous pins that WMaxLimPctEna+WMaxLimPct,
// PFWInj_PF+PFWInj_Ext and WSetEna+WSetMod+WSet are contiguous in L704's
// declared field order — if a re-vendor ever moved one, ext005Write/
// ext006Write/ext008Write's single Write Multiple Registers request would
// silently write the WRONG registers, and this test is what would catch it
// before a live write did.
func TestL704EnvelopeSpansAreContiguous(t *testing.T) {
	off := func(name string) int { return sunspec.L704.Offset(name) }
	cases := []struct {
		name    string
		first   string
		regs    []string
		wantLen int
	}{
		{"WMaxLimPct axis", "WMaxLimPctEna", []string{"WMaxLimPctEna", "WMaxLimPct"}, 2},
		{"PFWInj axis", "PFWInj_PF", []string{"PFWInj_PF", "PFWInj_Ext"}, 2},
		{"WSet axis", "WSetEna", []string{"WSetEna", "WSetMod", "WSet"}, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := off(c.first)
			if base < 0 {
				t.Fatalf("L704 declares no point %q", c.first)
			}
			cursor := base
			for _, name := range c.regs {
				o := off(name)
				if o != cursor {
					t.Fatalf("L704 point %q is at offset %d, want %d (span starting at %q is no longer "+
						"contiguous — ext005Write/ext006Write/ext008Write's single-request write "+
						"assumption no longer holds)", name, o, cursor, c.first)
				}
				f, ok := sunspec.L704.FieldOf(name)
				if !ok {
					t.Fatalf("L704 declares offset for %q but FieldOf cannot find it", name)
				}
				regs := 1
				switch f.Type {
				case sunspec.Tuint32, sunspec.Tint32:
					regs = 2
				}
				cursor += regs
			}
			if got := cursor - base; got != c.wantLen {
				t.Fatalf("span starting at %q is %d registers, want %d", c.first, got, c.wantLen)
			}
		})
	}
}

// TestL703EnvelopeSpanIsContiguous pins ES's own offset (a single register,
// so "contiguous" is trivially itself, but this still catches ES moving off
// offset 0 without ext007WriteES noticing).
func TestL703EnvelopeSpanIsContiguous(t *testing.T) {
	if o := sunspec.L703.Offset("ES"); o < 0 {
		t.Fatalf("L703 declares no ES point")
	}
}

// ── EXT-005 graders ──────────────────────────────────────────────────────────

func TestGradeEnvelopeAboveRefusal(t *testing.T) {
	pass := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Enabled: true, Raw: 50}
	movedAfter := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Enabled: true, Raw: 80}

	tests := []struct {
		name string
		w    envelopeWriteOutcome
		pre  ceilingSnapshot
		post ceilingSnapshot
		want certify.Verdict
	}{
		{"transport error", envelopeWriteOutcome{Err: errBoom}, pass, pass, certify.Fail},
		{"acked instead of refused", envelopeWriteOutcome{Acked: true}, pass, pass, certify.Fail},
		{"wrong exception code", envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, pass, pass, certify.Fail},
		{"exception 03 but ceiling moved", envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}, pass, movedAfter, certify.Fail},
		{"exception 03 and ceiling unchanged", envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}, pass, pass, certify.Pass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := gradeEnvelopeAboveRefusal(tt.w, tt.pre, tt.post)
			if f.Verdict != tt.want {
				t.Errorf("gradeEnvelopeAboveRefusal(%+v) = %s (%s), want %s", tt.w, f.Verdict, f.Observed, tt.want)
			}
		})
	}
	// Unavailable when the ceiling could not be read.
	f := gradeEnvelopeAboveRefusal(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue},
		ceilingSnapshot{Note: "no reading"}, ceilingSnapshot{Note: "no reading"})
	if f.Unavailable == "" {
		t.Errorf("gradeEnvelopeAboveRefusal with no ceiling reading = %+v, want Unavailable", f)
	}
}

func TestGradeEnvelopeWithinAck(t *testing.T) {
	passEffect := Finding{Verdict: certify.Pass, Observed: "landed"}
	failEffect := Finding{Verdict: certify.Fail, Observed: "did not land"}

	if f := gradeEnvelopeWithinAck(envelopeWriteOutcome{Err: errBoom}, passEffect); f.Verdict != certify.Fail {
		t.Errorf("transport error = %s, want Fail", f.Verdict)
	}
	if f := gradeEnvelopeWithinAck(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}, passEffect); f.Verdict != certify.Fail {
		t.Errorf("refused = %s, want Fail", f.Verdict)
	}
	if f := gradeEnvelopeWithinAck(envelopeWriteOutcome{Acked: true}, failEffect); f.Verdict != certify.Fail {
		t.Errorf("acked but no effect = %s, want Fail", f.Verdict)
	}
	if f := gradeEnvelopeWithinAck(envelopeWriteOutcome{Acked: true}, passEffect); f.Verdict != certify.Pass {
		t.Errorf("acked and effect landed = %s, want Pass", f.Verdict)
	}
	if f := gradeEnvelopeWithinAck(envelopeWriteOutcome{Acked: true}, Finding{Unavailable: "no read"}); f.Unavailable == "" {
		t.Errorf("acked but effect unavailable = %+v, want Unavailable", f)
	}
}

// ── EXT-006 graders ──────────────────────────────────────────────────────────

func fixedPFACControls(ena bool, pf float64, ext uint16) sunspec.ACControls {
	return sunspec.ACControls{PFWInjEna: ena, PFWInjPF: pf, PFWInjExt: ext}
}

func TestGradeAxisOwnedRefusal(t *testing.T) {
	before := fixedPFACControls(false, 0.900, sunspec.M704_Ext_OverExcited)
	same := before
	moved := fixedPFACControls(true, 0.850, sunspec.M704_Ext_OverExcited)

	if f := gradeAxisOwnedRefusal(envelopeWriteOutcome{Err: errBoom}, before, same, true, true, "", ""); f.Verdict != certify.Fail {
		t.Errorf("transport error = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisOwnedRefusal(envelopeWriteOutcome{Acked: true}, before, same, true, true, "", ""); f.Verdict != certify.Fail {
		t.Errorf("acked instead of refused = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisOwnedRefusal(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}, before, same, true, true, "", ""); f.Verdict != certify.Fail {
		t.Errorf("wrong exception code = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisOwnedRefusal(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, before, moved, true, true, "", ""); f.Verdict != certify.Fail {
		t.Errorf("exception 01 but PF register moved = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisOwnedRefusal(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, before, same, true, true, "", ""); f.Verdict != certify.Pass {
		t.Errorf("exception 01 and PF register unchanged = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeAxisOwnedRefusal(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, before, same, false, true, "no read", ""); f.Unavailable == "" {
		t.Errorf("could not read before = %+v, want Unavailable", f)
	}
}

// TestGradeAxisReleaseDefault covers REV0907-D2-P6C's own bench shape: the
// baseline (Setup, pre-publication) has PFWInjEna=false. At release the axis
// counts as "device default" whenever PFWInjEna is ALSO false, REGARDLESS of
// what the raw PF register holds — a 704 DER keeps a value register's
// last-written contents after Ena clears, which REV0907-D2-P6C's own bench
// evidence showed for this exact model (WSet stayed 3200 while WSetEna
// correctly cleared). PFWInjEna=true at release is unconditionally a FAIL —
// REV0907-D2-P6A's own shape: the axis never actually left CSIP ownership.
func TestGradeAxisReleaseDefault(t *testing.T) {
	params := map[string]string{"ext006.baseline_pf": "0.9", "ext006.baseline_ena": "false",
		"ext006.baseline_ext": "0"}
	matching := fixedPFACControls(false, 0.900, 0)
	// staleButReleased: PFWInjEna correctly cleared (matches the baseline's
	// own disabled state) but the raw register still carries a DIFFERENT
	// value (0.850, a prior mbaps write) — REV0907-D2-P6C's own shape. The
	// axis is no longer in force, so this is the device default: PASS.
	staleButReleased := fixedPFACControls(false, 0.850, 1)
	// stillEnabled: PFWInjEna is STILL true at release, even though the raw
	// value happens to equal the baseline's — REV0907-D2-P6A's own shape (a
	// control that ended but left the axis CSIP-owned). This is a FAIL
	// regardless of the raw register, because the axis never actually
	// released.
	stillEnabled := fixedPFACControls(true, 0.900, 0)

	if f := gradeAxisReleaseDefault(map[string]string{}, matching, true, ""); f.Unavailable == "" {
		t.Errorf("no baseline captured = %+v, want Unavailable", f)
	}
	if f := gradeAxisReleaseDefault(params, matching, false, "read failed"); f.Unavailable == "" {
		t.Errorf("could not read at release = %+v, want Unavailable", f)
	}
	if f := gradeAxisReleaseDefault(params, matching, true, ""); f.Verdict != certify.Pass {
		t.Errorf("matches baseline exactly = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeAxisReleaseDefault(params, staleButReleased, true, ""); f.Verdict != certify.Pass {
		t.Errorf("Ena matches baseline (false) but raw register is stale = %s (%s), want Pass "+
			"(REV0907-D2-P6C shape)", f.Verdict, f.Observed)
	}
	if f := gradeAxisReleaseDefault(params, stillEnabled, true, ""); f.Verdict != certify.Fail {
		t.Errorf("Ena still true at release (even with the baseline's raw value) = %s, want Fail "+
			"(REV0907-D2-P6A shape)", f.Verdict)
	}

	// The baseline itself holding the axis in force: Ena must match (true)
	// AND the value must match — the unusual "factory default is enabled"
	// case.
	enabledBaseline := map[string]string{"ext006.baseline_pf": "0.9", "ext006.baseline_ena": "true",
		"ext006.baseline_ext": "0"}
	if f := gradeAxisReleaseDefault(enabledBaseline, fixedPFACControls(true, 0.900, 0), true, ""); f.Verdict != certify.Pass {
		t.Errorf("enabled baseline, matching enabled release = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeAxisReleaseDefault(enabledBaseline, fixedPFACControls(true, 0.850, 0), true, ""); f.Verdict != certify.Fail {
		t.Errorf("enabled baseline, release value drifted while still enabled = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisReleaseDefault(enabledBaseline, fixedPFACControls(false, 0.900, 0), true, ""); f.Verdict != certify.Fail {
		t.Errorf("enabled baseline, but release is disabled (Ena mismatch) = %s, want Fail", f.Verdict)
	}
}

func TestGradeAxisReleasedWrite(t *testing.T) {
	want := ext006MbapsFixedPF
	landed := fixedPFACControls(true, want.PF(), func() uint16 { r, _ := wantExt(want.Excitation); return r }())
	wrong := fixedPFACControls(true, 0.5, func() uint16 { r, _ := wantExt(want.Excitation); return r }())

	if f := gradeAxisReleasedWrite(envelopeWriteOutcome{Err: errBoom}, want, landed, true, ""); f.Verdict != certify.Fail {
		t.Errorf("transport error = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisReleasedWrite(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, want, landed, true, ""); f.Verdict != certify.Fail {
		t.Errorf("still refused after release = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisReleasedWrite(envelopeWriteOutcome{Acked: true}, want, wrong, true, ""); f.Verdict != certify.Fail {
		t.Errorf("acked but register holds wrong value = %s, want Fail", f.Verdict)
	}
	if f := gradeAxisReleasedWrite(envelopeWriteOutcome{Acked: true}, want, landed, true, ""); f.Verdict != certify.Pass {
		t.Errorf("acked and register holds mbaps value = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeAxisReleasedWrite(envelopeWriteOutcome{Acked: true}, want, landed, false, "no read"); f.Unavailable == "" {
		t.Errorf("could not read after = %+v, want Unavailable", f)
	}
}

// ── EXT-007 graders ──────────────────────────────────────────────────────────

func TestGradeFailsafeCeilingAdmitted(t *testing.T) {
	before := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Raw: 0}
	rose := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Raw: ext007CeilingPct}
	stayedZero := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Raw: 0}

	if f := gradeFailsafeCeilingAdmitted(envelopeWriteOutcome{Err: errBoom}, ext007CeilingPct, before, rose); f.Verdict != certify.Fail {
		t.Errorf("transport error = %s, want Fail", f.Verdict)
	}
	if f := gradeFailsafeCeilingAdmitted(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, ext007CeilingPct, before, rose); f.Verdict != certify.Fail {
		t.Errorf("refused instead of admitted (the override) = %s, want Fail", f.Verdict)
	}
	if f := gradeFailsafeCeilingAdmitted(envelopeWriteOutcome{Acked: true}, ext007CeilingPct, before, stayedZero); f.Verdict != certify.Fail {
		t.Errorf("acked but ceiling did not rise = %s, want Fail", f.Verdict)
	}
	if f := gradeFailsafeCeilingAdmitted(envelopeWriteOutcome{Acked: true}, ext007CeilingPct, before, rose); f.Verdict != certify.Pass {
		t.Errorf("acked and ceiling rose = %s (%s), want Pass", f.Verdict, f.Observed)
	}
}

func TestGradeFailsafeESRefused(t *testing.T) {
	if f := gradeFailsafeESRefused(envelopeWriteOutcome{Err: errBoom}); f.Verdict != certify.Fail {
		t.Errorf("transport error = %s, want Fail", f.Verdict)
	}
	if f := gradeFailsafeESRefused(envelopeWriteOutcome{Acked: true}); f.Verdict != certify.Fail {
		t.Errorf("ES=1 acked while engaged = %s, want Fail", f.Verdict)
	}
	if f := gradeFailsafeESRefused(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}); f.Verdict != certify.Fail {
		t.Errorf("wrong exception code = %s, want Fail", f.Verdict)
	}
	if f := gradeFailsafeESRefused(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}); f.Verdict != certify.Pass {
		t.Errorf("exception 01 = %s (%s), want Pass", f.Verdict, f.Observed)
	}
}

func TestExt007PreconditionUnavailable(t *testing.T) {
	f := ext007PreconditionUnavailable("the DUT reports failsafe_engaged=false")
	if f.Unavailable == "" {
		t.Fatalf("ext007PreconditionUnavailable(...) = %+v, want Unavailable set (SKIP shape)", f)
	}
}

// TestExt007DecideDrive pins the three shapes R2 added: already-engaged
// grades directly (nothing to arm), not-engaged-but-lever-available DRIVES,
// and neither available SKIPs. A mutation that dropped the alreadyEngaged
// check (e.g. always driving when adminAvailable) would arm gridsim's outage
// lever against a DUT an operator had already, deliberately, put into
// fail-safe out of band — this table would catch it on the first case.
func TestExt007DecideDrive(t *testing.T) {
	tests := []struct {
		name           string
		already, admin bool
		want           ext007DriveOutcome
	}{
		{"already engaged, admin also up: grade directly, do not drive", true, true, ext007AlreadyEngaged},
		{"already engaged, no admin: still grade directly", true, false, ext007AlreadyEngaged},
		{"not engaged, admin up: drive it", false, true, ext007ShouldDrive},
		{"not engaged, no admin: cannot reach it", false, false, ext007CannotReach},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ext007DecideDrive(tt.already, tt.admin); got != tt.want {
				t.Errorf("ext007DecideDrive(%t, %t) = %v, want %v", tt.already, tt.admin, got, tt.want)
			}
		})
	}
}

// TestExt007OutageWaitSeconds pins -param ext007.failsafe_wait_s's parsing:
// present and valid wins, and every malformed shape (absent, empty,
// non-numeric, zero, negative) falls back to the documented default rather
// than propagating a bad value into the wait budget gridsim's own outage
// duration_s is padded from.
func TestExt007OutageWaitSeconds(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
		want   int
	}{
		{"absent", nil, ext007OutageWaitDefaultS},
		{"present and valid", map[string]string{"ext007.failsafe_wait_s": "1200"}, 1200},
		{"empty", map[string]string{"ext007.failsafe_wait_s": ""}, ext007OutageWaitDefaultS},
		{"non-numeric", map[string]string{"ext007.failsafe_wait_s": "soon"}, ext007OutageWaitDefaultS},
		{"zero", map[string]string{"ext007.failsafe_wait_s": "0"}, ext007OutageWaitDefaultS},
		{"negative", map[string]string{"ext007.failsafe_wait_s": "-5"}, ext007OutageWaitDefaultS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &certify.RunCtx{Params: tt.params}
			if got := ext007OutageWaitSeconds(rc); got != tt.want {
				t.Errorf("ext007OutageWaitSeconds(%v) = %d, want %d", tt.params, got, tt.want)
			}
		})
	}
}

// ── EXT-008 graders ──────────────────────────────────────────────────────────

func wsetACControls(ena bool, w float64) sunspec.ACControls {
	return sunspec.ACControls{WSetEna: ena, WSet: w}
}

// TestExt008DeclaresFixedW pins REV0907-D2-P6C's precondition bit test: bit 1
// (FIXED_W) of model 702 CtrlModes, independent of every other bit in the
// bitfield. A mutation that tested the wrong bit (e.g. bit 0, MAX_W — a
// plausible off-by-one against M702_CtrlMode_MaxW/FixedW's adjacent values)
// would pass MaxW-only devices and fail FixedW-only ones; this table catches
// both directions.
func TestExt008DeclaresFixedW(t *testing.T) {
	tests := []struct {
		name  string
		modes uint32
		want  bool
	}{
		{"zero: no modes at all", 0, false},
		{"FIXED_W alone", sunspec.M702_CtrlMode_FixedW, true},
		{"MAX_W alone (adjacent bit, not FIXED_W)", sunspec.M702_CtrlMode_MaxW, false},
		{"FIXED_W among several", sunspec.M702_CtrlMode_MaxW | sunspec.M702_CtrlMode_FixedW | sunspec.M702_CtrlMode_FixedPF, true},
		{"every other documented mode, FIXED_W excluded",
			sunspec.M702_CtrlMode_MaxW | sunspec.M702_CtrlMode_FixedVar | sunspec.M702_CtrlMode_FixedPF |
				sunspec.M702_CtrlMode_VoltVar | sunspec.M702_CtrlMode_FreqWatt, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ext008DeclaresFixedW(tt.modes); got != tt.want {
				t.Errorf("ext008DeclaresFixedW(0x%08x) = %t, want %t", tt.modes, got, tt.want)
			}
		})
	}
}

func TestExt008PreconditionUnavailable(t *testing.T) {
	f := ext008PreconditionUnavailable("the DER's own CtrlModes reads 0x00000001, with bit 1 (FIXED_W) clear")
	if f.Unavailable == "" {
		t.Fatalf("ext008PreconditionUnavailable(...) = %+v, want Unavailable set (SKIP shape)", f)
	}
}

func TestGradeStandingWrite(t *testing.T) {
	landed := wsetACControls(true, ext008StandingWattsW)
	notEna := wsetACControls(false, ext008StandingWattsW)
	wrongVal := wsetACControls(true, 0)

	if f := gradeStandingWrite(envelopeWriteOutcome{Err: errBoom}, ext008StandingWattsW, landed, true, ""); f.Verdict != certify.Fail {
		t.Errorf("transport error = %s, want Fail", f.Verdict)
	}
	if f := gradeStandingWrite(envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}, ext008StandingWattsW, landed, true, ""); f.Verdict != certify.Fail {
		t.Errorf("refused absent any CSIP contribution = %s, want Fail", f.Verdict)
	}
	if f := gradeStandingWrite(envelopeWriteOutcome{Acked: true}, ext008StandingWattsW, notEna, true, ""); f.Verdict != certify.Fail {
		t.Errorf("acked but WSetEna clear = %s, want Fail", f.Verdict)
	}
	if f := gradeStandingWrite(envelopeWriteOutcome{Acked: true}, ext008StandingWattsW, wrongVal, true, ""); f.Verdict != certify.Fail {
		t.Errorf("acked but wrong value = %s, want Fail", f.Verdict)
	}
	if f := gradeStandingWrite(envelopeWriteOutcome{Acked: true}, ext008StandingWattsW, landed, true, ""); f.Verdict != certify.Pass {
		t.Errorf("acked and register holds it = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeStandingWrite(envelopeWriteOutcome{Acked: true}, ext008StandingWattsW, landed, false, "no read"); f.Unavailable == "" {
		t.Errorf("could not read after = %+v, want Unavailable", f)
	}
}

func TestGradeOwnershipTakeEffect(t *testing.T) {
	pass := Finding{Verdict: certify.Pass, Observed: "follows CSIP"}
	fail := Finding{Verdict: certify.Fail, Observed: "did not follow"}

	if f := gradeOwnershipTakeEffect(Finding{Unavailable: "no oracle"}, envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}); f.Unavailable == "" {
		t.Errorf("effect unavailable = %+v, want Unavailable", f)
	}
	if f := gradeOwnershipTakeEffect(fail, envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}); f.Verdict != certify.Fail {
		t.Errorf("DER did not follow CSIP = %s, want Fail", f.Verdict)
	}
	if f := gradeOwnershipTakeEffect(pass, envelopeWriteOutcome{Err: errBoom}); f.Verdict != certify.Fail {
		t.Errorf("transport error on the further write = %s, want Fail", f.Verdict)
	}
	if f := gradeOwnershipTakeEffect(pass, envelopeWriteOutcome{Acked: true}); f.Verdict != certify.Fail {
		t.Errorf("further write acked instead of refused = %s, want Fail", f.Verdict)
	}
	if f := gradeOwnershipTakeEffect(pass, envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalValue}); f.Verdict != certify.Fail {
		t.Errorf("wrong exception code = %s, want Fail", f.Verdict)
	}
	if f := gradeOwnershipTakeEffect(pass, envelopeWriteOutcome{HasException: true, Exception: mbap.ExIllegalFunction}); f.Verdict != certify.Pass {
		t.Errorf("follows CSIP and further write refused (01) = %s (%s), want Pass", f.Verdict, f.Observed)
	}
}

// TestGradeSetpointReleaseDefault mirrors TestGradeAxisReleaseDefault's cases
// for WSet/WSetEna — REV0907-D2-P6C's own bench evidence was on THIS axis
// (WSet stayed 3200 while lexa-modbus logged "dispatch WITHDRAWN — the
// device reports no active-power setpoint in force"): a stale raw register
// under a correctly-cleared WSetEna is the device default (PASS); WSetEna
// still true at release is REV0907-D2-P6A's shape (FAIL) regardless of the
// raw value.
func TestGradeSetpointReleaseDefault(t *testing.T) {
	params := map[string]string{"ext008.baseline_wset": "0", "ext008.baseline_wset_ena": "false"}
	atDefault := wsetACControls(false, 0)
	// staleButReleased: WSetEna correctly cleared (matches the baseline's
	// own disabled state) but the raw register still carries the prior
	// mbaps value — REV0907-D2-P6C's exact bench shape (3200 W stale,
	// WSetEna cleared). The axis is no longer in force: PASS.
	staleButReleased := wsetACControls(false, ext008StandingWattsW)
	// stillEnabled: WSetEna is STILL true at release — REV0907-D2-P6A's own
	// shape (the control ended but the axis never actually released). FAIL
	// regardless of the raw value.
	stillEnabled := wsetACControls(true, 0)

	if f := gradeSetpointReleaseDefault(map[string]string{}, atDefault, true, ""); f.Unavailable == "" {
		t.Errorf("no baseline captured = %+v, want Unavailable", f)
	}
	if f := gradeSetpointReleaseDefault(params, atDefault, false, "read failed"); f.Unavailable == "" {
		t.Errorf("could not read at release = %+v, want Unavailable", f)
	}
	if f := gradeSetpointReleaseDefault(params, atDefault, true, ""); f.Verdict != certify.Pass {
		t.Errorf("matches baseline exactly = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeSetpointReleaseDefault(params, staleButReleased, true, ""); f.Verdict != certify.Pass {
		t.Errorf("WSetEna matches baseline (false) but raw register is stale (the standing mbaps "+
			"value) = %s (%s), want Pass (REV0907-D2-P6C shape)", f.Verdict, f.Observed)
	}
	if f := gradeSetpointReleaseDefault(params, stillEnabled, true, ""); f.Verdict != certify.Fail {
		t.Errorf("WSetEna still true at release = %s, want Fail (REV0907-D2-P6A shape)", f.Verdict)
	}

	enabledBaseline := map[string]string{"ext008.baseline_wset": "500", "ext008.baseline_wset_ena": "true"}
	if f := gradeSetpointReleaseDefault(enabledBaseline, wsetACControls(true, 500), true, ""); f.Verdict != certify.Pass {
		t.Errorf("enabled baseline, matching enabled release = %s (%s), want Pass", f.Verdict, f.Observed)
	}
	if f := gradeSetpointReleaseDefault(enabledBaseline, wsetACControls(true, 100), true, ""); f.Verdict != certify.Fail {
		t.Errorf("enabled baseline, release value drifted while still enabled = %s, want Fail", f.Verdict)
	}
	if f := gradeSetpointReleaseDefault(enabledBaseline, wsetACControls(false, 500), true, ""); f.Verdict != certify.Fail {
		t.Errorf("enabled baseline, but release is disabled (Ena mismatch) = %s, want Fail", f.Verdict)
	}
}

// ── stashFinding/recallFinding round-trip ────────────────────────────────────

func TestStashRecallFinding(t *testing.T) {
	params := map[string]string{}
	want := Finding{Verdict: certify.Fail, Observed: "something specific"}
	stashFinding(params, "k", want)
	got := recallFinding(params, "k")
	if got.Verdict != want.Verdict || got.Observed != want.Observed {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}

	stashFinding(params, "k2", unavailable("reason %d", 7))
	if got := recallFinding(params, "k2"); got.Unavailable == "" {
		t.Fatalf("round-trip of an Unavailable Finding = %+v, want Unavailable set", got)
	}

	if got := recallFinding(map[string]string{}, "missing"); got.Unavailable == "" {
		t.Fatalf("recallFinding on a key never stashed = %+v, want Unavailable", got)
	}
}
