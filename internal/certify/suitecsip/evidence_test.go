package suitecsip

// evidence_test.go covers the EVIDENCE run's per-scenario handshake
// precondition (audit LAB29-011).
//
// The failure it replaces was late and indirect: every COMM-004 scenario in a
// campaign ran on a session resumed from a ticket, each certificate criterion
// correctly reported "unavailable — resumed session" rather than blaming the
// DUT, and RPT-060 failed at the very end with the aggregate. The rows that
// KNEW which scenario had no handshake said nothing about it, because in an
// ordinary run it is not their business. Under -evidence it is.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// evidenceCtx is a RunCtx posed as the given kind of run.
func evidenceCtx(t *testing.T, evidence bool) *certify.RunCtx {
	t.Helper()
	rc := &certify.RunCtx{Case: &certify.Case{UID: "csip-conf-v1.3::COMM-004"}, Log: certify.DiscardLogger}
	if err := rc.SetPosture(certify.Posture{Campaign: certify.CampaignCSIP, Evidence: evidence}); err != nil {
		t.Fatal(err)
	}
	return rc
}

// handshakeTranscript builds the minimum critEvidenceFullHandshake reads.
func handshakeTranscript(chain [][]byte, resumed bool, hello bool) *Transcript {
	tr := &Transcript{}
	if hello {
		tr.Handshake.ServerHello = &tlsdis.ServerHello{}
	}
	tr.Handshake.ClientHello = &tlsdis.ClientHello{}
	tr.Handshake.ServerChain = chain
	tr.Handshake.ServerCertFrames = []int{7, 8}
	tr.Handshake.ClientHelloFrames = []int{3}
	tr.Handshake.Resumed = resumed
	if resumed {
		tr.Handshake.OfferedTicket = []byte{0xA5, 0xA5}
		tr.Handshake.ServerFlight = []tlsdis.HandshakeType{
			tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket,
		}
	}
	return tr
}

var oneCert = [][]byte{leafFixture(), leafFixture()}

// leafFixture is a byte slice standing in for a DER certificate. The criterion
// never parses it — it counts the chain and cites the frames — and using a real
// certificate here would only hide that.
func leafFixture() []byte { return []byte{0x30, 0x03, 0x02, 0x01, 0x00} }

func TestEvidenceFullHandshakePassesAFullFlight(t *testing.T) {
	f := critEvidenceFullHandshake().Wire(nil, handshakeTranscript(oneCert, false, true))
	if f.Verdict != certify.Pass {
		t.Fatalf("a full handshake was not accepted: %s / %s / %s", f.Verdict, f.Observed, f.Unavailable)
	}
	if len(f.Frames) == 0 {
		t.Error("the passing finding cites no frames, so the precondition rests on nothing re-checkable")
	}
}

// A REJECTED handshake still satisfies it, and this is the case most likely to
// be got wrong: COMM-004 D/E/F/G exist to make the DUT refuse a chain, the
// handshake therefore does NOT complete, and the Certificate message that the
// Chapter 5 trace must contain is present all the same. Failing here would fail
// the four rows whose artefact is the most interesting one in the set.
func TestEvidenceFullHandshakePassesARejectedHandshake(t *testing.T) {
	tr := handshakeTranscript(oneCert, false, true)
	tr.Handshake.Complete = false
	tr.Handshake.ClientAlerts = []tlsdis.Alert{{Level: 2, Description: 42}}
	if f := critEvidenceFullHandshake().Wire(nil, tr); f.Verdict != certify.Pass {
		t.Fatalf("a rejected-but-full handshake was not accepted: %s / %s / %s",
			f.Verdict, f.Observed, f.Unavailable)
	}
}

// The one the audit found. It must FAIL — on this scenario's own row, naming
// this scenario — rather than going unavailable and leaving RPT-060 to report
// the aggregate after the bench has gone home.
func TestEvidenceFullHandshakeFailsAResumedSession(t *testing.T) {
	f := critEvidenceFullHandshake().Wire(nil, handshakeTranscript(nil, true, true))
	if f.Verdict != certify.Fail {
		t.Fatalf("a resumed session was not failed: %s / %s / %s", f.Verdict, f.Observed, f.Unavailable)
	}
	for _, want := range []string{"RESUMED", "Chapter 5", "-no-tickets"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the failure does not mention %q: %s", want, f.Observed)
		}
	}
}

func TestEvidenceFullHandshakeFailsAWindowWithNoHandshakeAtAll(t *testing.T) {
	f := critEvidenceFullHandshake().Wire(nil, handshakeTranscript(nil, false, false))
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "no ServerHello") {
		t.Fatalf("a window with no handshake = %s / %s", f.Verdict, f.Observed)
	}
	// A capture that began mid-session: a ServerHello but no Certificate, and
	// not a detected resumption. A different sentence, because it is a
	// different bench fault.
	f = critEvidenceFullHandshake().Wire(nil, handshakeTranscript(nil, false, true))
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "mid-session") {
		t.Fatalf("a mid-session capture = %s / %s", f.Verdict, f.Observed)
	}
}

// The gate itself. An ORDINARY run measures a device, and "this window's
// session was resumed" is a fact about the bench that must not be charged to
// the DUT — so outside an evidence run the criterion is not added at all and
// the row's criteria are byte-identical to what they were.
func TestEvidenceCriteriaOnlyApplyToAnEvidenceRun(t *testing.T) {
	base := []criterion{critCipherNegotiated(), critHandshakeComplete()}

	got := evidenceCriteria(evidenceCtx(t, false), base...)
	if len(got) != len(base) {
		t.Fatalf("an ordinary run gained %d criterion(s) it did not have before", len(got)-len(base))
	}

	got = evidenceCriteria(evidenceCtx(t, true), base...)
	if len(got) != len(base)+1 {
		t.Fatalf("an evidence run has %d criteria, want %d", len(got), len(base)+1)
	}
	if !strings.Contains(got[0].Claim, "FULL TLS handshake") {
		t.Errorf("the handshake precondition is not FIRST: %q", got[0].Claim)
	}
	// It must be first: it is the precondition every other criterion in the row
	// rests on, and a reader scanning a failed scenario should meet the reason
	// before the consequences.
	for i, c := range got[1:] {
		if c.Claim != base[i].Claim {
			t.Errorf("criterion %d changed: %q, want %q", i+1, c.Claim, base[i].Claim)
		}
	}
}
