package gridsim

// golden_default_test.go pins the DEFAULT resource tree byte for byte.
//
// The DER AGGREGATOR CLIENT work (fleet.go, subscribe.go) added two levers that
// change what this simulator serves: a five-EndDevice topology and a
// Subscription function set that puts a SubscriptionListLink on every EndDevice
// and a subscribable attribute on the FunctionSetAssignmentsList. Both are off
// by default, and "off by default" is a claim that has to be checkable — the
// direct-DER-client rows of CSIP-CONF-v1.3 were certified against the
// single-EndDevice tree, and a lever that leaked one byte into it would
// re-measure them against a fixture nobody agreed to.
//
// The golden was generated from the tree as it stood at a51e13d, BEFORE either
// lever existed (git worktree at that commit, this same dumper). So the file
// this test compares against is not a snapshot of the new code's own output —
// it is the old code's, and a difference is a regression rather than a
// disagreement with a golden somebody regenerated.
//
// Regenerate ONLY when the default tree is deliberately changed:
//
//	go test ./sim/gridsim -run TestDefaultTreeIsByteIdentical -update-golden
//
// # REGENERATIONS, and why each one was allowed
//
// Every entry here is a departure from the a51e13d baseline and has to justify
// itself, because a golden that moves without a stated reason is not a golden.
//
//  1. 2026-08-15, ONE line: /tp/0/rc's RateComponent roleFlags,
//     "<roleFlags>4</roleFlags>" -> "<roleFlags>0002</roleFlags>". Two
//     independent corrections landed on the same element.
//
//     THE TEXT changed because lexa-proto 72d91be stopped writing hexBinary
//     ELEMENTS in decimal. roleFlags is a RoleFlagsType, base HexBinary16 —
//     IEEE Std 2030.5-2018 p.169, which the draft schema (xsd:2291 ->
//     xsd:5826) and 2030.5-2023 p.179 agree with bit for bit
//     (NORMATIVE_ANCHOR.md §3.9); the citation here was the draft's until
//     IW15-027 made it under-cited rather than wrong. csipmodel had been
//     emitting a Go integer — so a value this bench meant as N went onto the
//     wire as a string a conformant reader parsed as 0xN. The new encoding is
//     uppercase and zero-padded to the type's width. This alone would have
//     turned "4" into "0004" with no change of meaning.
//
//     THE VALUE changed because 0x0004 was never right. RoleFlagsType bit 2 is
//     isPEV (2018 p.169) and this is a residential time-of-use tariff; the
//     "isPrimary (forward)" the old comment claimed is not a role the type
//     defines at all, and the forward/reverse distinction it was reaching for
//     lives in ReadingType.flowDirection. The rate describes a premises point
//     of delivery, which is bit 1, isPremisesAggregationPoint (2018 p.169).
//     Full adjudication in pricing.go.
//
//     ONE CLAUSE OF THIS ENTRY IS WITHDRAWN (IW15-028). It used to end "— the
//     same role the DUT's own site-meter MirrorUsagePoint declares", offered as
//     corroboration for the value chosen here. The DUT's MirrorUsagePoint does
//     declare 0x0002, and that is a DEFECT of the product rather than a
//     precedent: on a MirrorUsagePoint, bit 0 isMirror is an unconditional
//     SHALL (2018 p.169 — the server is by definition not the measurement
//     device) and this product leaves it clear. See suitecsip's
//     critMUPElementsAndRoleFlags, which red-proves it. A tariff fixture and a
//     mirror registration are different resources under different rules, and
//     citing one to justify the other was reasoning from a bug. The VALUE here
//     is still right, on its own merits, stated above.
//
//     WHY THIS IS SAFE FOR PUBLISHED EVIDENCE. Nothing in this tree reads
//     RateComponent.RoleFlags, and no CSIP-CONF-v1.3 row this bench runs
//     asserts on it — the tariff fixture exists for the pricing function set,
//     which the certified direct-DER-client rows do not exercise. Bundles
//     already published are unaffected: they hold their own captures, and
//     `certify -verify` re-derives assertions from those bytes, not from this
//     fixture.
//
//  2. 2026-08-15, TWO lines: the static Volt-VAr curve's
//     "<curveType>0</curveType>" -> "<curveType>11</curveType>", at
//     /derp/0/dc (inside the list) and at /derp/0/dc/0 (the individually
//     addressable copy of the same curve). Registry IW15-027.
//
//     WHY. The fixture never named a number — it sets model.CurveTypeVoltVar
//     — and that constant moved when lexa-proto re-derived DERCurveType
//     against the PUBLISHED standard instead of against
//     docs/schema/sep-2.0.4.xsd, which is the pre-publication ZigBee draft.
//     IEEE Std 2030.5-2018 p.254 assigns opModVoltVar the code 11, and p.250
//     says it a second time in the element's own prose ("Specify DERCurveLink
//     for curveType == 11"). The draft's 0 is opModFreqWatt's code under 2018,
//     so this bench had been serving a volt-var curve labelled
//     frequency-watt to every DUT that walked the tree.
//
//     THE CATALOG SAID 11 ALL ALONG. CSIP CTP v1.3's Figure 6 prints
//     DERCurve.curveType 11 in both its Default and Test Values columns, and
//     this suite carried a standing "curveTypeDivergence" note explaining why
//     the bench deliberately did not follow it. The note was wrong and is
//     withdrawn; the divergence was the bench's.
//
//     WHY THIS IS SAFE FOR PUBLISHED EVIDENCE. It is a fixture correction, not
//     a re-measurement: bundles already published hold their own captures, and
//     `certify -verify` re-derives every assertion from those bytes. A bundle
//     recorded before this change shows curveType 0 because that is what the
//     bench served that day, and it re-verifies against itself exactly as
//     before. What changes is what the NEXT run puts on the wire.
//
//  3. 2026-08-15, ONE line: /tp/0's TariffProfile gains
//     "<serviceCategoryKind>0</serviceCategoryKind>".
//
//     WHY. Nothing in this repository changed. lexa-proto 13e9106 removed
//     `omitempty` from TariffProfile.serviceCategoryKind, which IEEE Std
//     2030.5-2018 p.220-221 and Figure B.27 p.218 declare [1] — mandatory —
//     and whose value on this fixture is 0 (electricity), which is exactly
//     what `omitempty` deletes. So every TariffProfile this bench has ever
//     served omitted a mandatory element, and the omission was invisible
//     because the field was set correctly in Go and dropped on the way out.
//     Same defect class, and the same upstream sweep, as the MirrorUsagePoint
//     findings IW15-028 is about.
//
//     WHY THIS IS SAFE FOR PUBLISHED EVIDENCE. Same reasoning as (2), plus:
//     the change only ADDS a mandatory element to a document that was missing
//     one, so no reader that accepted the old bytes can reject the new ones.

//  4. 2026-08-17, SEVEN lines: all three DefaultDERControls lose
//     "<opModConnect>true</opModConnect>" and
//     "<opModEnergize>true</opModEnergize>" (/derp/0/dderc, /derp/1/dderc,
//     /derp/2/dderc), and program 0's description loses ", connect and
//     energize".
//
//     WHY. A DefaultDERControl is not an event — it is what the DER falls back
//     to whenever no control is active — so those two elements were a
//     CONTINUOUS STANDING COMMAND to connect and energize underneath every row
//     any bench ran, and they confounded two rows in two successive campaigns:
//     BENCH-000 row (j) (a pre-disconnected DER a gateway must leave alone,
//     which it cannot while the head end says "energize" every poll cycle) and
//     BASIC-009's ES half (which commands connect=false/energize=false and
//     therefore measured which of the two commands won, not whether the DUT
//     honoured the control). They are ABSENT rather than false because absence
//     and false are different documents: false is still a command, and the rows
//     this serves need the axis unspoken. See server.go's
//     defaultConnectEnergizeAbsent for the lever that engages either axis when
//     a row wants it, and note that the catalog's own BASIC-009 Figure 9 row
//     prints "opmodConnect: Default (blank/not specified)".
//
//     The description moved in the same breath because it named a command the
//     document no longer carries, and it is served on the wire — a stale claim
//     a reader of a captured bundle has no way to check.
//
//     WHAT DID NOT MOVE, deliberately: line 194's
//     "<opModConnect>true</opModConnect>" inside /derp/0/derc is DERControl
//     SP-004, an EVENT that commands connect for its interval. It is untouched,
//     and the fact that exactly one such line survives is the cheapest available
//     proof that this change reached the defaults and nothing else.
//
//     WHY THIS IS SAFE FOR PUBLISHED EVIDENCE. The change only REMOVES optional
//     elements (both are minOccurs="0" on DERControlBase), so no reader that
//     accepted the old bytes can reject the new ones, and no bundle's claims
//     rest on the fixture having commanded connect: the rows that grade those
//     axes command them on a DERControl of their own. Bundles captured before
//     this date were taken against a fixture that DID assert the axes, which is
//     precisely the confound this entry removes — so old and new evidence must
//     not be compared on the connect/energize axes without accounting for it.

import (
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false,
	"rewrite testdata/default-tree.golden from this run's output")

// unixSeconds matches the ten-digit epoch stamps the tree carries (creationTime,
// changedTime, currentTime, interval starts). They move every run and are the
// only thing in the tree that legitimately does, so they are normalised and
// everything else is compared literally.
var unixSeconds = regexp.MustCompile(`\b1[0-9]{9}\b`)

// defaultTreeDump renders every resource in the tree as "path\n<xml>", sorted by
// path, with epoch stamps normalised.
func defaultTreeDump(t *testing.T, s *Server) string {
	t.Helper()
	s.mu.RLock()
	paths := make([]string, 0, len(s.resources))
	for p := range s.resources {
		paths = append(paths, p)
	}
	s.mu.RUnlock()
	sort.Strings(paths)

	var b strings.Builder
	for _, p := range paths {
		s.mu.RLock()
		res := s.resources[p]
		s.mu.RUnlock()
		// Through the SAME wire-shape conversion serveXML applies (curvexml.go),
		// so this golden pins the DOCUMENT a DUT receives rather than the Go
		// struct this server happens to store.
		//
		// It did not before, and that was a hole in this file's own claim.
		// DERCurve is served through a schema-shaped local type because the
		// vendored struct drops three minOccurs="1" elements and orders two of
		// them out of the XSD's sequence; a golden marshalling the STORED struct
		// would go on passing through any change to that conversion, including
		// its removal. Every other resource marshals identically either way.
		wire, _ := curveForWire(res)
		data, err := xml.MarshalIndent(wire, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", p, err)
		}
		b.WriteString("=== " + p + "\n")
		b.Write(unixSeconds.ReplaceAll(data, []byte("EPOCH")))
		b.WriteString("\n")
	}
	return b.String()
}

func TestDefaultTreeIsByteIdentical(t *testing.T) {
	got := defaultTreeDump(t, NewServer("ABCDEF0123456789ABCDEF0123456789ABCDEF01"))

	golden := filepath.Join("testdata", "default-tree.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", golden, len(got))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read the golden default tree: %v", err)
	}
	if got == string(want) {
		return
	}
	// Report the first differing line rather than two multi-kilobyte blobs.
	gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gl) && i < len(wl); i++ {
		if gl[i] != wl[i] {
			t.Fatalf("the default resource tree changed at line %d — the single-EndDevice tree is what the "+
				"direct-DER-client rows were certified against, so a change here is a change to evidence "+
				"already published:\n  was: %s\n  now: %s", i+1, wl[i], gl[i])
		}
	}
	t.Fatalf("the default resource tree changed length: %d lines, was %d", len(gl), len(wl))
}

// TestNeitherLeverIsOnByDefault is the same claim stated the other way round,
// so that a future change which regenerates the golden without thinking still
// trips over the property the golden exists to protect.
func TestNeitherLeverIsOnByDefault(t *testing.T) {
	s := NewServer("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
	if s.FleetEnabled() {
		t.Error("the CTP Figure-15 fleet is on without EnableFleet")
	}
	if s.SubscriptionsEnabled() {
		t.Error("the Subscription function set is on without EnableSubscriptions")
	}
	dump := defaultTreeDump(t, s)
	for _, forbidden := range []string{"SubscriptionListLink", "subscribable", "/edev/3", "/derp/spa1"} {
		if strings.Contains(dump, forbidden) {
			t.Errorf("the default tree carries %q, which belongs to a lever that is supposed to be off",
				forbidden)
		}
	}
}
