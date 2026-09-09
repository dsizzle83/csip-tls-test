package report

// uidalias_trr_test.go pins REV0907-E9 / WP7-T8: the catalog re-key that
// dropped "ss-1547-test-v1.1" in favour of "ss-1547-test-v1.0" must not
// strand an OLD evidence bundle's cases as unrouted. A bundle minted before
// the migration carries "ss-1547-test-v1.1::MOD-4" verbatim in its
// TestCaseResult.ID — that is immutable evidence and is never rewritten
// (testdata/catalog/uid_aliases.json's own _status note) — so MapVerdict and
// Collate must still route it to CertTypeModbus via
// testdata/catalog/uid_aliases.json, exactly as a current-keyed case does.

import (
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

// TestMapVerdict_OldSS1547UIDStillRoutes is the fail-before/pass-after case
// for the alias wiring (certTypeFor/noCertBasisFor, trr.go) added alongside
// the SS-1547-TEST-v1.1 -> SS-1547-TEST-v1.0 rename. Before that wiring
// existed, DocKeyOf("ss-1547-test-v1.1::MOD-4") = "ss-1547-test-v1.1", which
// is no longer a DocCertType key once the rename lands, so MapVerdict fell
// through to GapUnrouted for every case in an old bundle — a false "no
// Results Reporting specification governs this document", not a fact about
// the evidence.
func TestMapVerdict_OldSS1547UIDStillRoutes(t *testing.T) {
	oldCase := bundle.TestCaseResult{ID: "ss-1547-test-v1.1::MOD-4", Verdict: bundle.Pass}
	newCase := bundle.TestCaseResult{ID: "ss-1547-test-v1.0::MOD-4", Verdict: bundle.Pass}

	oldTV, oldGap := MapVerdict(oldCase, nil, "runs/pre-rekey-bundle")
	newTV, newGap := MapVerdict(newCase, nil, "runs/post-rekey-bundle")

	if newGap != nil || newTV == nil || newTV.Verdict != "PASS" {
		t.Fatalf("sanity: the CURRENT-keyed uid does not route: tv=%+v gap=%+v", newTV, newGap)
	}
	if oldGap != nil {
		t.Fatalf("an OLD-keyed bundle case (pre-REV0907-E9 uid) was not routed: gap=%+v — "+
			"testdata/catalog/uid_aliases.json exists precisely so this still resolves", oldGap)
	}
	if oldTV == nil || oldTV.Verdict != "PASS" {
		t.Fatalf("old-uid MapVerdict = %+v, want a PASS Test row matching the current-uid case", oldTV)
	}
	if oldTV.ID != newTV.ID {
		t.Errorf("old-uid Test row ID = %q, new-uid = %q — both name the same procedure (MOD-4) and must "+
			"produce the same Test <Test ID> row", oldTV.ID, newTV.ID)
	}
}

// TestCollate_OldSS1547UIDRoutesToModbus is the same fact one layer out:
// Collate's own certTypeFor lookup (used only to bucket a gap before
// MapVerdict runs) must resolve the retired key too, so a whole source bundle
// keyed under the old prefix lands in the Modbus certificate type rather than
// silently bucketing under a default that happens, today, to coincide with
// it — asserting the alias resolved, not the accident that both buckets are
// CertTypeModbus.
func TestCollate_OldSS1547UIDRoutesToModbus(t *testing.T) {
	certType, routed := certTypeFor("ss-1547-test-v1.1")
	if !routed {
		t.Fatalf("certTypeFor(%q) reports unrouted; want it resolved via uid_aliases.json to %q",
			"ss-1547-test-v1.1", "ss-1547-test-v1.0")
	}
	if certType != CertTypeModbus {
		t.Errorf("certTypeFor(%q) = %q, want %q", "ss-1547-test-v1.1", certType, CertTypeModbus)
	}
}
