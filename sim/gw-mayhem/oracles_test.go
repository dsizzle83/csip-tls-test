package gwmayhem

// oracles_test.go is the pure-oracle decision table: it constructs gwEvidence
// literals and asserts each oracle's verdict, with no live gateway and no wolfSSL
// handshake (runs in make test-fast). This is the whole point of keeping the
// families' SAMPLING separate from the oracles' JUDGING — the judgment layer is a
// pure function that a unit test can pin exhaustively.

import (
	"testing"

	"csip-tls-test/internal/aggregator"
)

func cell(role string, op opClass, exp grant, outcome string, code uint8, wrote bool) authzCell {
	return authzCell{Role: role, Op: op, Unit: 2, Expected: exp, Outcome: outcome, ExCode: code, Wrote: wrote}
}

func TestDiagnoseAuthzMatrix(t *testing.T) {
	tests := []struct {
		name  string
		cells []authzCell
		want  Verdict
	}{
		{"empty", nil, VerdictInconclusive},
		{"all-correct", []authzCell{
			cell("ReadOnlySunSpec", opReadMeas, grantAllow, "granted", 0, false),
			cell("ReadOnlySunSpec", opWriteCtl, grantDeny, "denied", 0x01, false),
			cell("GridServiceSunSpec", opWriteCtl, grantAllow, "granted", 0, true),
		}, VerdictPass},
		{"deny-but-wrote", []authzCell{
			cell("ReadOnlySunSpec", opWriteCtl, grantDeny, "granted", 0, true),
		}, VerdictFail},
		{"deny-but-granted", []authzCell{
			cell("NetworkAdministratorSunSpec", opWriteCtl, grantDeny, "granted", 0, true),
		}, VerdictFail},
		{"deny-wrong-code", []authzCell{
			cell("ReadOnlySunSpec", opWriteCtl, grantDeny, "denied", 0x02, false),
		}, VerdictFail},
		{"grant-but-denied", []authzCell{
			cell("GridServiceSunSpec", opReadMeas, grantAllow, "denied", 0x01, false),
		}, VerdictFail},
		{"transport-error", []authzCell{
			cell("ReadOnlySunSpec", opWriteCtl, grantDeny, "error", 0, false),
		}, VerdictInconclusive},
		{"fail-outranks-inconclusive", []authzCell{
			cell("ReadOnlySunSpec", opWriteCtl, grantDeny, "error", 0, false),
			cell("ReadOnlySunSpec", opWriteCtl, grantDeny, "granted", 0, true),
		}, VerdictFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseAuthzMatrix(&gwEvidence{Cells: tc.cells})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDiagnoseCertAuthz(t *testing.T) {
	tests := []struct {
		name string
		c    certOutcome
		want Verdict
	}{
		{"chain-error-rejected", certOutcome{Fixture: "expired", ExpectLayer: "handshake", Handshake: "failed"}, VerdictPass},
		{"chain-error-let-in", certOutcome{Fixture: "wrong-ca", ExpectLayer: "handshake", Handshake: "ok", DeniedAll: true, AuthzExCode: 0x01}, VerdictFail},
		{"role-error-denied-authz", certOutcome{Fixture: "no-role", ExpectLayer: "authz", Handshake: "ok", DeniedAll: true, AuthzExCode: 0x01}, VerdictPass},
		{"role-error-rejected-handshake", certOutcome{Fixture: "no-role", ExpectLayer: "authz", Handshake: "failed"}, VerdictFail},
		{"role-error-not-denied", certOutcome{Fixture: "empty-role", ExpectLayer: "authz", Handshake: "ok", DeniedAll: false, AuthzExCode: 0}, VerdictFail},
		{"role-error-probe-transport", certOutcome{Fixture: "two-role", ExpectLayer: "authz", Handshake: "ok", ProbeErr: "connection reset"}, VerdictInconclusive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseCertAuthz(&gwEvidence{Certs: []certOutcome{tc.c}})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDiagnoseMalformedWrite(t *testing.T) {
	tests := []struct {
		name string
		w    writeOutcome
		want Verdict
	}{
		{"out-of-range-accepted", writeOutcome{Name: "oor", ExpectRejectCode: 0x03, Accepted: true}, VerdictFail},
		{"illegal-fc-01", writeOutcome{Name: "fc", ExpectRejectCode: 0x01, ExCode: 0x01}, VerdictPass},
		{"illegal-fc-wrong-code", writeOutcome{Name: "fc", ExpectRejectCode: 0x01, ExCode: 0x03}, VerdictFail},
		{"oversized-closed", writeOutcome{Name: "big", ExpectSessionClosed: true, SessionClosed: true}, VerdictPass},
		{"oversized-not-closed", writeOutcome{Name: "big", ExpectSessionClosed: true, ExCode: 0x03}, VerdictFail},
		{"any-reject-ok", writeOutcome{Name: "nx", AnyRejectOK: true, ExCode: 0x0A}, VerdictPass},
		{"any-reject-accepted", writeOutcome{Name: "nx", AnyRejectOK: true, Accepted: true}, VerdictFail},
		{"any-reject-no-code", writeOutcome{Name: "nx", AnyRejectOK: true}, VerdictInconclusive},
		{"transport-error", writeOutcome{Name: "fc", ExpectRejectCode: 0x01, TransportErr: "reset"}, VerdictInconclusive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseMalformedWrite(&gwEvidence{Writes: []writeOutcome{tc.w}})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDiagnoseSessionFlood(t *testing.T) {
	tests := []struct {
		name string
		f    *floodOutcome
		want Verdict
	}{
		{"nil", nil, VerdictInconclusive},
		{"cap-and-survive", &floodOutcome{Attempted: 12, Established: 4, Refused: 8, Cap: 4, CapObserved: true, LanSurvived: true}, VerdictPass},
		{"no-cap", &floodOutcome{Attempted: 12, Established: 12, Refused: 0, CapObserved: false, LanSurvived: true}, VerdictFail},
		{"lan-starved", &floodOutcome{Attempted: 12, Established: 4, Refused: 8, CapObserved: true, LanSurvived: false}, VerdictFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseSessionFlood(&gwEvidence{Flood: tc.f})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDiagnoseNBMalform(t *testing.T) {
	// A liveness-clean, cap-less baseline: gateway stayed up, never applied garbage.
	stayedUp := func(o nbMalformOutcome) nbMalformOutcome {
		o.Observed, o.LiveObs, o.LiveOK = true, 3, 3
		o.BaselinePct = 100
		return o
	}
	tests := []struct {
		name string
		o    *nbMalformOutcome
		want Verdict
	}{
		{"nil", nil, VerdictInconclusive},
		{"unobserved", &nbMalformOutcome{Observed: false}, VerdictInconclusive},
		{"contained-no-cap", ptrNB(stayedUp(nbMalformOutcome{})), VerdictPass},
		{"absurd-applied", ptrNB(stayedUp(nbMalformOutcome{AbsurdApplied: true, AbsurdPct: 150})), VerdictFail},
		{"gateway-dark", ptrNB(nbMalformOutcome{Observed: true, LiveObs: 3, LiveOK: 0, BaselinePct: 100}), VerdictFail},
		{"cap-held", ptrNB(stayedUp(nbMalformOutcome{BaselineCap: true, BaselinePct: 25})), VerdictPass},
		{"cap-unseated", ptrNB(stayedUp(nbMalformOutcome{BaselineCap: true, BaselinePct: 25, Unseated: true})), VerdictFail},
		{"liveness-unobservable-still-pass", ptrNB(nbMalformOutcome{Observed: true, LiveObs: 0, BaselinePct: 100}), VerdictPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseNBMalform(&gwEvidence{NBMalform: tc.o})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDiagnoseSBFault(t *testing.T) {
	// Isolation held: the healthy secure device kept being polled.
	isolated := sbFaultOutcome{Observed: true, Target: sbTargetPlain, Expect: sbExpectIsolation, HealthyName: "inv-secure", HealthyLiveObs: 3, HealthyLiveOK: 3}
	// Secure comm-loss that recovered.
	recovered := sbFaultOutcome{Observed: true, Target: sbTargetSecure, Expect: sbExpectCommLoss, HealthyName: "inv-plain",
		FaultedPollObservable: true, FaultedPolledAtBase: true, CommLossObserved: true, Recovered: true}
	tests := []struct {
		name string
		o    *sbFaultOutcome
		want Verdict
	}{
		{"nil", nil, VerdictInconclusive},
		{"unobserved", &sbFaultOutcome{Observed: false}, VerdictInconclusive},
		{"isolation-held", ptrSB(isolated), VerdictPass},
		{"no-isolation", ptrSB(sbFaultOutcome{Observed: true, Target: sbTargetPlain, Expect: sbExpectIsolation, HealthyName: "inv-secure", HealthyLiveObs: 3, HealthyLiveOK: 0}), VerdictFail},
		{"absurd-projection", ptrSB(sbFaultOutcome{Observed: true, Target: sbTargetPlain, Expect: sbExpectDigest, HealthyName: "inv-secure", HealthyLiveObs: 3, HealthyLiveOK: 3, AbsurdProjected: true}), VerdictFail},
		{"comm-loss-recovered", ptrSB(recovered), VerdictPass},
		{"comm-loss-stuck", ptrSB(sbFaultOutcome{Observed: true, Target: sbTargetSecure, Expect: sbExpectCommLoss, HealthyName: "inv-plain", FaultedPollObservable: true, FaultedPolledAtBase: true, CommLossObserved: true, Recovered: false}), VerdictFail},
		{"digest-clean", ptrSB(sbFaultOutcome{Observed: true, Target: sbTargetSecure, Expect: sbExpectDigest, HealthyName: "inv-plain"}), VerdictPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseSBFault(&gwEvidence{SBFault: tc.o})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func ptrNB(o nbMalformOutcome) *nbMalformOutcome { return &o }
func ptrSB(o sbFaultOutcome) *sbFaultOutcome     { return &o }

func TestDiagnosePerfectStorm(t *testing.T) {
	// The all-invariants-held baseline: cap set + held, hostile write rejected, no
	// absurd projection, responsive, recovered.
	held := perfectStormOutcome{
		Observed: true, CapSet: true, HostileWriteRejected: true,
		AbsurdProjected: false, Unseated: false, Responsive: true, Recovered: true,
	}
	// with returns a *perfectStormOutcome that is `held` mutated by fn — one FAIL axis
	// flipped per case.
	with := func(fn func(*perfectStormOutcome)) *perfectStormOutcome {
		o := held
		fn(&o)
		return &o
	}
	tests := []struct {
		name string
		ev   *gwEvidence
		want Verdict
	}{
		{"nil", &gwEvidence{}, VerdictInconclusive},
		{"unobserved", &gwEvidence{PerfectStorm: &perfectStormOutcome{Observed: false}}, VerdictInconclusive},
		{"setup-err", &gwEvidence{SetupErr: "bench not wired"}, VerdictInconclusive},
		{"all-held", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) {})}, VerdictPass},
		{"hostile-accepted", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) { o.HostileWriteRejected = false })}, VerdictFail},
		{"absurd-projected", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) { o.AbsurdProjected = true })}, VerdictFail},
		{"cap-unseated", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) { o.Unseated = true })}, VerdictFail},
		{"unresponsive", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) { o.Responsive = false })}, VerdictFail},
		{"not-recovered", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) { o.Recovered = false })}, VerdictFail},
		// A cap that never took is NOT judged for unseat: Unseated=true but CapSet=false
		// ⇒ the HOLD sub-invariant was not exercised, so it is not a FAIL on that axis.
		{"no-cap-unseat-not-judged", &gwEvidence{PerfectStorm: with(func(o *perfectStormOutcome) { o.CapSet = false; o.Unseated = true })}, VerdictPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnosePerfectStorm(tc.ev)
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func ptrCLM(o commLossMaskOutcome) *commLossMaskOutcome { return &o }

func TestDiagnoseCommLossMask(t *testing.T) {
	// The all-invariants-held baseline: real telemetry baselined, a unit masked to the
	// sentinel, its 704 echo survived, and the DER recovered.
	held := commLossMaskOutcome{
		Observed: true, TelemWasReal: true, MaskedUnit: 2, TelemMaskedNaN: true,
		EchoSurvived: true, CommandedPct: 50, HealthyRealTelem: true, Recovered: true,
	}
	// with returns a *commLossMaskOutcome that is `held` mutated by fn — one axis flipped per case.
	with := func(fn func(*commLossMaskOutcome)) *commLossMaskOutcome {
		o := held
		fn(&o)
		return &o
	}
	tests := []struct {
		name string
		ev   *gwEvidence
		want Verdict
	}{
		{"nil", &gwEvidence{}, VerdictInconclusive},
		{"setup-err", &gwEvidence{SetupErr: "bench not wired"}, VerdictInconclusive},
		{"unobserved", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) { o.Observed = false })}, VerdictInconclusive},
		{"telem-not-real", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) { o.TelemWasReal = false })}, VerdictInconclusive},
		{"pass-masked-echo-survived-recovered", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) {})}, VerdictPass},
		// The gateway never masked the offline DER's telemetry (stale-projection risk).
		{"fail-no-mask", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) { o.MaskedUnit = 0; o.TelemMaskedNaN = false })}, VerdictFail},
		// Telemetry masked but the 704 echo was wiped along with it (exemption failed).
		{"fail-echo-wiped", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) { o.EchoSurvived = false })}, VerdictFail},
		// The faulted DER never recovered after the fault cleared.
		{"fail-not-recovered", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) { o.Recovered = false })}, VerdictFail},
		// A mask with no distinct healthy peer still PASSes (isolation is only asserted when a peer exists).
		{"pass-no-peer", &gwEvidence{CommLossMask: with(func(o *commLossMaskOutcome) { o.HealthyRealTelem = false })}, VerdictPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseCommLossMask(tc.ev)
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func rbConv(label string, expect float64) ctlReadback {
	return ctlReadback{Label: label, Expect: expect, Final: expect, Tol: 1, SLAS: 6, HadRead: true, Converged: true}
}

func TestDiagnoseControlLoop(t *testing.T) {
	// rapid-recurtail: the burst's last value (80) echoed back and stayed.
	rapidOK := controlLoopOutcome{Kind: "rapid-recurtail", Observed: true, Unit: 2, LastCmd: 80,
		Readbacks: []ctlReadback{rbConv("settle", 80), rbConv("confirm-1", 80), rbConv("confirm-2", 80)}}
	// reversion: ceiling held at 40 then reverted to 100.
	reversionOK := controlLoopOutcome{Kind: "reversion", Observed: true, Unit: 2, LastCmd: 40,
		Readbacks: []ctlReadback{
			{Label: "hold", Phase: "hold", Expect: 40, Final: 40, Tol: 1, SLAS: 10, HadRead: true, Converged: true},
			{Label: "revert", Phase: "revert", Expect: 100, Final: 100, Tol: 1, SLAS: 15, HadRead: true, Converged: true},
		}}
	tests := []struct {
		name string
		o    *controlLoopOutcome
		want Verdict
	}{
		{"nil", nil, VerdictInconclusive},
		{"unobserved", &controlLoopOutcome{Observed: false}, VerdictInconclusive},
		{"rapid-converge-to-last", ptrCL(rapidOK), VerdictPass},
		{"rapid-stale-echo", ptrCL(controlLoopOutcome{Kind: "rapid-recurtail", Observed: true, LastCmd: 80,
			Readbacks: []ctlReadback{{Label: "settle", Expect: 80, Final: 30, Tol: 1, SLAS: 6, HadRead: true, Converged: false}}}), VerdictFail},
		{"went-dark", ptrCL(controlLoopOutcome{Kind: "rapid-recurtail", Observed: true, WentDark: true}), VerdictFail},
		{"blind-no-read", ptrCL(controlLoopOutcome{Kind: "rapid-recurtail", Observed: true, LastCmd: 80,
			Readbacks: []ctlReadback{{Label: "settle", Expect: 80, SLAS: 6, HadRead: false}}}), VerdictBlind},
		{"reversion-fires", ptrCL(reversionOK), VerdictPass},
		{"reversion-stuck", ptrCL(controlLoopOutcome{Kind: "reversion", Observed: true, LastCmd: 40,
			Readbacks: []ctlReadback{
				{Label: "hold", Phase: "hold", Expect: 40, Final: 40, Tol: 1, SLAS: 10, HadRead: true, Converged: true},
				{Label: "revert", Phase: "revert", Expect: 100, Final: 40, Tol: 1, SLAS: 15, HadRead: true, Converged: false},
			}}), VerdictFail},
		{"authority-held", ptrCL(controlLoopOutcome{Kind: "authority", Observed: true, LastCmd: 60, AuthorityPeer: "csip",
			Readbacks: []ctlReadback{rbConv("authority-set", 60)}}), VerdictPass},
		{"authority-override", ptrCL(controlLoopOutcome{Kind: "authority", Observed: true, LastCmd: 60, AuthorityPeer: "csip",
			OverrideSeen: true, OverridePct: 75, Readbacks: []ctlReadback{rbConv("authority-set", 60)}}), VerdictFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseControlLoop(&gwEvidence{ControlLoop: tc.o})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func ptrCL(o controlLoopOutcome) *controlLoopOutcome { return &o }

func TestDiagnoseAuthorityPKI(t *testing.T) {
	tests := []struct {
		name string
		o    *authorityPKIOutcome
		want Verdict
	}{
		{"nil", nil, VerdictInconclusive},
		{"not-armed", &authorityPKIOutcome{Kind: "authority-switch-honors-exclusive", BoardArmed: false}, VerdictInconclusive},
		{"armed-board-only", &authorityPKIOutcome{Kind: "trust-store-tamper-failclosed", BoardArmed: true, BoardOnly: true}, VerdictInconclusive},
		{"armed-unobserved", &authorityPKIOutcome{Kind: "privacy-switch-vendor-access", BoardArmed: true, Observed: false}, VerdictInconclusive},
		{"armed-effect-ok", &authorityPKIOutcome{Kind: "authority-switch-honors-exclusive", BoardArmed: true, Observed: true, EffectOK: true, Effect: "refused"}, VerdictPass},
		{"armed-effect-violation", &authorityPKIOutcome{Kind: "authority-switch-honors-exclusive", BoardArmed: true, Observed: true, EffectOK: false, Effect: "accepted"}, VerdictFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := diagnoseAuthorityPKI(&gwEvidence{AuthPKI: tc.o})
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDiagnoseCampaignPassthrough(t *testing.T) {
	ev := &gwEvidence{Campaign: &campaignResult{Verdict: VerdictPass, Findings: []string{"ok"}}}
	if got, _ := diagnoseCampaign(ev); got != VerdictPass {
		t.Errorf("verdict = %s, want PASS", got)
	}
	if got, _ := diagnoseCampaign(&gwEvidence{SetupErr: "no connect"}); got != VerdictInconclusive {
		t.Errorf("verdict = %s, want INCONCLUSIVE", got)
	}
}

// TestSetupErrInconclusive proves a scenario whose arm could not connect is scored
// INCONCLUSIVE (a setup problem, not a gateway verdict), across every family oracle.
func TestSetupErrInconclusive(t *testing.T) {
	ev := &gwEvidence{SetupErr: "could not discover a control unit"}
	for name, oracle := range oracleRegistry {
		if name == "campaignPassthrough" {
			continue
		}
		if got, _ := oracle(ev); got != VerdictInconclusive {
			t.Errorf("%s with SetupErr = %s, want INCONCLUSIVE", name, got)
		}
	}
}

// TestVerdictVocabularyMatchesAggregator guards the re-export: the gw-mayhem verdict
// constants must equal the aggregator's byte-for-byte.
func TestVerdictVocabularyMatchesAggregator(t *testing.T) {
	pairs := []struct {
		got  Verdict
		want aggregator.Verdict
	}{
		{VerdictPass, aggregator.VerdictPass},
		{VerdictDegraded, aggregator.VerdictDegraded},
		{VerdictFail, aggregator.VerdictFail},
		{VerdictBlind, aggregator.VerdictBlind},
		{VerdictInconclusive, aggregator.VerdictInconclusive},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("verdict mismatch: %q vs %q", p.got, p.want)
		}
	}
}
