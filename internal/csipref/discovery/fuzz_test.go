package discovery

// Go-native fuzz targets for the IEEE 2030.5 XML unmarshal surface
// (TASK-048), client side. This repo's own client-side unmarshal
// (fetchAndParse, below the walker) is the mirror of lexa-hub's
// internal/northbound/discovery.fetchAndParse; both decode into the SAME
// shared lexa-proto/csipmodel types (TASK-023) — the only thing that
// differs between the two repos is the walker/scheduler LOGIC built on top,
// which internal/csipref (TASK-082, AD-003(f)) deliberately keeps
// independent for conformance-referee value. This target does not touch
// that logic at all: it fuzzes xml.Unmarshal itself, which is now shared
// code, plus TestSharedSeedDecodeEquivalence below, which is a decode-only
// cross-check against the identical corpus committed to lexa-hub — not a
// walker/scheduler comparison, so it does not violate AD-003(f).
//
// Unlike lexa-hub's sibling target (internal/northbound/scheduler/fuzz_test.go),
// this repo's internal/csipref/scheduler has no plausibility gate at all
// (verified: no plausibleControl/plausibleLimit/maxPlausibleLimitW
// equivalent exists here) — so there is nothing to drive beyond decode
// correctness itself. That asymmetry is itself a finding, noted in the PR
// description: the bench referee currently has no defense against an
// implausible-but-well-formed OpModXxxLimW the way the product does. Per
// the task's "do not invent assertions" rule, this fuzz target does not add
// one here (scheduler is out of scope / would blur the referee's
// independence) — it is reported, not fixed.
//
// Run locally (nightly CI runs the same two at 15m each; see the `fuzz`
// Makefile target and .github/workflows/ci.yml):
//
//	go test -fuzz=FuzzUnmarshalDeviceCapability -fuzztime=15m ./internal/csipref/discovery/
//	go test -fuzz=FuzzUnmarshalDERControlList   -fuzztime=15m ./internal/csipref/discovery/

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// sharedSeedsDir is the repo-root shared 2030.5 XML corpus, committed
// identically to lexa-hub in the same TASK-048 session (05 §11 lockstep;
// see that repo's copy of this same directory for the mirror).
const sharedSeedsDir = "../../../testdata/fuzz/shared-2030_5"

func sharedXMLSeeds(f *testing.F) [][]byte {
	f.Helper()
	entries, err := os.ReadDir(sharedSeedsDir)
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".xml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sharedSeedsDir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, data)
	}
	return out
}

func stripNamespace(doc []byte) []byte {
	return bytes.Replace(doc, []byte(` xmlns="`+model.XMLNamespace+`"`), nil, 1)
}

func wrongNamespace(doc []byte) []byte {
	return bytes.Replace(doc, []byte(model.XMLNamespace), []byte("urn:evil:not-2030.5"), -1)
}

// assertRootMatches fails t if a successfully-decoded root element's XMLName
// doesn't carry the mandatory 2030.5 namespace + expected local name — see
// the identical helper and its doc comment in lexa-hub's
// internal/northbound/scheduler/fuzz_test.go for the empirical namespace
// behavior this pins as a regression tripwire.
func assertRootMatches(t *testing.T, got xml.Name, wantLocal string) {
	t.Helper()
	if got.Space != model.XMLNamespace || got.Local != wantLocal {
		t.Fatalf("decoded with no error but wrong root name/namespace: got %+v, want space=%q local=%q — "+
			"this is the namespace-or-zero-value hazard (CLAUDE.md invariant) reproducing",
			got, model.XMLNamespace, wantLocal)
	}
}

func FuzzUnmarshalDeviceCapability(f *testing.F) {
	for _, seed := range sharedXMLSeeds(f) {
		f.Add(seed)
		f.Add(stripNamespace(seed))
		f.Add(wrongNamespace(seed))
	}
	f.Add([]byte(`<DeviceCapability href="/dcap"></DeviceCapability>`)) // no xmlns at all
	f.Add([]byte(``))
	f.Add([]byte(`not xml at all`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var dest model.DeviceCapability
		if err := xml.Unmarshal(data, &dest); err != nil {
			// Matches fetchAndParse: on any error the caller returns
			// immediately and never touches dest.
			return
		}
		assertRootMatches(t, dest.XMLName, "DeviceCapability")
	})
}

func FuzzUnmarshalDERControlList(f *testing.F) {
	for _, seed := range sharedXMLSeeds(f) {
		f.Add(seed)
		f.Add(stripNamespace(seed))
		f.Add(wrongNamespace(seed))
	}
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?><DERControlList xmlns="` + model.XMLNamespace + `" href="/derp/0/derc" all="0" results="0"></DERControlList>`)) // empty list
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var dest model.DERControlList
		if err := xml.Unmarshal(data, &dest); err != nil {
			return
		}
		assertRootMatches(t, dest.XMLName, "DERControlList")
		// No plausibility gate to drive here — see package doc comment.
		// The property under test is exactly assertRootMatches above: a
		// successful decode never carries the wrong namespace/name.
	})
}

// TestNamespaceStrippedDERControlListIsZeroValueAndNonAdoptable mirrors the
// identically-named test in lexa-hub's fuzz_test.go against the same shared
// seed file, pinning the same acceptance criterion here.
func TestNamespaceStrippedDERControlListIsZeroValueAndNonAdoptable(t *testing.T) {
	seed, err := os.ReadFile(filepath.Join(sharedSeedsDir, "dercontrollist.xml"))
	if err != nil {
		t.Fatalf("read shared seed: %v", err)
	}
	stripped := stripNamespace(seed)
	if bytes.Equal(stripped, seed) {
		t.Fatalf("stripNamespace was a no-op — seed fixture or helper changed shape")
	}

	var dest model.DERControlList
	err = xml.Unmarshal(stripped, &dest)
	if err == nil {
		t.Fatalf("expected a decode error for a namespace-stripped root element; got nil " +
			"(namespace enforcement regressed)")
	}

	var zero model.DERControlList
	if !reflect.DeepEqual(dest, zero) {
		t.Fatalf("namespace-stripped root did not yield a zero-value struct: %+v", dest)
	}
	if len(dest.DERControl) != 0 {
		t.Fatalf("zero-value DERControlList unexpectedly carries %d DERControl entries", len(dest.DERControl))
	}
}

// TestSharedSeedDecodeEquivalence pins specific expected field values
// decoded from the shared corpus (testdata/fuzz/shared-2030_5/, identical
// bytes committed to both repos in this task's session). lexa-hub commits
// the same test with the same literal expected values against its own copy
// of the file — if the two repos' corpus copies or the shared csipmodel
// decode behavior ever diverge, one side's copy of this test starts
// failing. This is the "PARSER divergence between the twins" cross-check
// the task calls for, adapted to the post-TASK-023 world where both repos
// already share the model/decode layer (only the walker/scheduler logic
// built on top stays deliberately independent, AD-003(f)) — so today this
// is expected to pass identically in both, and its value is as a tripwire
// against a future accidental fork of either the corpus or csipmodel itself.
func TestSharedSeedDecodeEquivalence(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(sharedSeedsDir, "dercontrollist.xml"))
	if err != nil {
		t.Fatalf("read shared seed: %v", err)
	}
	var dest model.DERControlList
	if err := xml.Unmarshal(data, &dest); err != nil {
		t.Fatalf("unmarshal shared seed: %v", err)
	}
	if dest.All != 4 || dest.Results != 4 {
		t.Fatalf("all/results mismatch: got All=%d Results=%d, want 4/4", dest.All, dest.Results)
	}
	if len(dest.DERControl) != 4 {
		t.Fatalf("got %d DERControl entries, want 4", len(dest.DERControl))
	}
	wantMRIDs := []string{"DERC-SP-001", "DERC-SP-002", "DERC-SP-003", "DERC-SP-004"}
	for i, want := range wantMRIDs {
		if dest.DERControl[i].MRID != want {
			t.Fatalf("DERControl[%d].MRID = %q, want %q", i, dest.DERControl[i].MRID, want)
		}
	}
	// SP-003 is the cancelled event (currentStatus=6) in the fixture.
	if dest.DERControl[2].EventStatus == nil || dest.DERControl[2].EventStatus.CurrentStatus != 6 {
		t.Fatalf("DERControl[2] (SP-003) expected currentStatus=6 (cancelled), got %+v", dest.DERControl[2].EventStatus)
	}
}
