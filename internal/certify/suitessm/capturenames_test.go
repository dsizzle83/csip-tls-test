package suitessm

// capturenames_test.go holds the transcription of SSM-CONF-v0.8's Reporting
// Requirements against the two things that can silently break it: a typo in a
// file name nobody reads until a lab does, and a row that grows a check but
// never gets its capture declared.

import (
	"regexp"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// normativeName is the shape every name in the document has: lower case,
// digits, underscores, ending .pcap. A capital letter or a hyphen here is the
// typo this catches, and it is exactly the kind a reviewer's file listing
// catches instead if it gets through.
var normativeName = regexp.MustCompile(`^[a-z]+_[0-9]{3}(_[a-z]+)?\.pcap$`)

func TestCaptureNamesAreNormativelyShaped(t *testing.T) {
	seen := map[string]string{}
	for id, names := range captureNames {
		if len(names) == 0 {
			t.Errorf("%s has an empty name list; omit the row instead, so \"the document names none\" "+
				"and \"somebody left this blank\" stay distinguishable", id)
		}
		for _, n := range names {
			if !normativeName.MatchString(n) {
				t.Errorf("%s: %q is not the lower-case form the document prints", id, n)
			}
			if prev, dup := seen[n]; dup && prev != id {
				t.Errorf("%q is claimed by both %s and %s; two rows writing one file means the "+
					"second silently overwrites the first's evidence", n, prev, id)
			}
			seen[n] = id
		}
	}
}

// TestCaptureNamesFollowTheDocumentsPattern asserts the mechanical majority
// still match id-lower-cased-with-underscore, so the transcription cannot drift
// into inventing names — while leaving the five genuine exceptions
// (TLSF-003's three, TLSF-005's second) as exceptions.
func TestCaptureNamesFollowTheDocumentsPattern(t *testing.T) {
	exceptions := map[string]bool{"TLSF-003": true, "TLSF-005": true}
	for id, names := range captureNames {
		want := strings.ToLower(strings.Replace(id, "-", "_", 1)) + ".pcap"
		if exceptions[id] {
			// The exception still has to START from the row's own name.
			if !strings.HasPrefix(names[0], strings.TrimSuffix(want, ".pcap")) {
				t.Errorf("%s's first capture %q does not begin with the row's own name", id, names[0])
			}
			continue
		}
		if len(names) != 1 || names[0] != want {
			t.Errorf("%s = %v, want exactly [%s]", id, names, want)
		}
	}
}

// TestTLSF003AndTLSF005KeepTheirSubCaptures pins the two rows the document
// splits, because their split is the only part of this table a reader cannot
// re-derive and the only part where getting the ORDER wrong produces a file
// that parses and lies: tlsf_003_untrusted.pcap holding the expired
// certificate's handshake is worse than no file at all.
func TestTLSF003AndTLSF005KeepTheirSubCaptures(t *testing.T) {
	// §2.4.3.3: "One capture per bad certificate type named
	// tlsf_003_expired.pcap, tlsf_003_badsig.pcap, and tlsf_003_untrusted.pcap."
	got := CaptureNames("TLSF-003")
	want := []string{"tlsf_003_expired.pcap", "tlsf_003_badsig.pcap", "tlsf_003_untrusted.pcap"}
	if len(got) != len(want) {
		t.Fatalf("TLSF-003 names %d capture(s), the document names %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("TLSF-003 capture %d = %q, the document lists %q at that position", i, got[i], want[i])
		}
	}

	// §2.4.5.3: the session, then "A packet capture (.pcap) of the resumption
	// attempt named tlsf_005_resume.pcap."
	got = CaptureNames("TLSF-005")
	if len(got) != 2 || got[0] != "tlsf_005.pcap" || got[1] != "tlsf_005_resume.pcap" {
		t.Errorf("TLSF-005 = %v, want [tlsf_005.pcap tlsf_005_resume.pcap] in that order", got)
	}

	// CaptureNames must hand out a copy: a caller that sorted or truncated the
	// result would reorder the document for every later caller.
	got[0] = "clobbered"
	if CaptureNames("TLSF-005")[0] != "tlsf_005.pcap" {
		t.Error("CaptureNames returns the table's own slice; a caller can mutate the document")
	}

	if CaptureNames("NOPE-999") != nil {
		t.Error("an unknown id must return nil, not an empty non-nil list")
	}
}

// TestEveryRegisteredTrafficRowDeclaresItsCapture is the coverage half: a row
// this suite implements and that puts packets on the wire must declare the file
// its Reporting Requirements name, or the submission is missing evidence the
// reviewer was told to expect.
//
// The three audit rows are named explicitly rather than derived, so adding a
// fourth is a decision somebody makes here rather than a silent omission.
func TestEveryRegisteredTrafficRowDeclaresItsCapture(t *testing.T) {
	// RBAC-004: the vendor's roles-to-rights map. RBAC-005: the vendor's AuthZ
	// algorithm description. OPS-001: the export declaration. All three ask for
	// documents; none names a pcap.
	audits := map[string]bool{"RBAC-004": true, "RBAC-005": true, "OPS-001": true}

	reg := certify.NewRegistry()
	Register(reg)
	for _, r := range reg.Registrations() {
		id := r.UID
		if _, after, ok := strings.Cut(r.UID, "::"); ok {
			id = after
		}
		switch {
		case audits[id]:
			if len(r.CaptureArtifacts) != 0 {
				t.Errorf("%s is a document audit but declares captures %v", id, r.CaptureArtifacts)
			}
		case len(r.CaptureArtifacts) == 0:
			t.Errorf("%s is registered and produces traffic but declares no capture file name; "+
				"a reviewer following its Reporting Requirements will look for one", id)
		default:
			if want := CaptureNames(id); len(want) != len(r.CaptureArtifacts) {
				t.Errorf("%s declares %v but the document names %v", id, r.CaptureArtifacts, want)
			}
		}
	}
}
