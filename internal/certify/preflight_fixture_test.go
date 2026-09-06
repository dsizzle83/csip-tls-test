package certify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"csip-tls-test/internal/certify/manifest"
	"lexa-proto/sunspec"
)

// sunspecRegisterImage builds a valid SunSpec register image at base 40000
// serving the given models (in order), as the addr-string->value map the simapi
// /registers endpoint returns. Model data is zero-filled — Scan walks only the
// id/len chain, so the content does not matter, and the chain terminates with
// an End marker.
func sunspecRegisterImage(models []uint16) map[string]uint16 {
	regs := map[uint16]uint16{
		sunspec.SunSpecBase:     sunspec.SunSMagic0,
		sunspec.SunSpecBase + 1: sunspec.SunSMagic1,
	}
	cursor := sunspec.SunSpecBase + 2
	const dataLen = uint16(2)
	for _, id := range models {
		regs[cursor] = id
		regs[cursor+1] = dataLen
		cursor += 2 + dataLen
	}
	regs[cursor] = sunspec.EndMarker
	out := make(map[string]uint16, len(regs))
	for a, v := range regs {
		out[strconv.Itoa(int(a))] = v
	}
	return out
}

func serveModelChain(t *testing.T, models []uint16) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sunspecRegisterImage(models))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestReadSimModelChain_DecodesTheServedChain proves the sim's served chain is
// read back as its sorted, deduped model list.
func TestReadSimModelChain_DecodesTheServedChain(t *testing.T) {
	url := serveModelChain(t, []uint16{1, 704, 703, 123})
	sim := NewSimClient("modsim", url, http.DefaultClient)
	got, err := readSimModelChain(context.Background(), sim)
	if err != nil {
		t.Fatalf("readSimModelChain: %v", err)
	}
	want := []int{1, 123, 703, 704}
	if len(got) != len(want) {
		t.Fatalf("served chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("served chain = %v, want %v", got, want)
		}
	}
}

// fullChainManifestJSON declares the full served set the lexa-gw candidate
// manifest is being expanded to IN LOCKSTEP with the advanced fixture:
// legacy compat models + the 7xx DER/curve/trip models.
var fullChainManifestJSON = strings.Replace(validManifestJSON,
	"[1, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712]",
	"[1, 103, 120, 121, 122, 123, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712]", 1)

var fullChainModels = []uint16{1, 103, 120, 121, 122, 123, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712}

func gatingRunner(m *manifest.Manifest, url string) *Runner {
	return &Runner{manifest: m, campaign: CampaignSpec{Name: "csip"},
		opts: Options{Targets: Targets{ModSimAPI: url}, HTTP: http.DefaultClient}}
}

func exploratoryRunner(m *manifest.Manifest, url string) *Runner {
	return &Runner{manifest: m, // no campaign declared -> NOT gating
		opts: Options{Targets: Targets{ModSimAPI: url}, HTTP: http.DefaultClient}}
}

// TestPreflightFixture_FullChainPasses proves the real gating campaign starts
// cleanly: the manifest expanded to the full 18-model served set matches the
// advanced fixture serving exactly those models.
func TestPreflightFixture_FullChainPasses(t *testing.T) {
	m := loadManifest(t, fullChainManifestJSON)
	url := serveModelChain(t, fullChainModels)
	if err := gatingRunner(m, url).preflightFixture(context.Background(), NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("preflightFixture refused the full 18-model set against a matching fixture: %v", err)
	}
}

// TestPreflightFixture_GatingMismatchIsFatal proves the campaign refuses to
// start on a GENUINE both-direction mismatch — a model the sim serves that the
// manifest omits (123), AND a model the manifest declares that the sim does not
// serve (705) — when a campaign is declared (the gating path).
func TestPreflightFixture_GatingMismatchIsFatal(t *testing.T) {
	m := loadManifest(t, validManifestJSON) // declares 1, 701..712
	// The sim serves 1, 701..712 EXCEPT 705, PLUS a legacy 123.
	served := []uint16{1, 701, 702, 703, 704, 706, 707, 708, 709, 710, 711, 712, 123}
	url := serveModelChain(t, served)
	err := gatingRunner(m, url).preflightFixture(context.Background(), NewReporter(&strings.Builder{}))
	if err == nil {
		t.Fatal("preflightFixture did not refuse a gating run whose fixture disagrees with the manifest in " +
			"both directions")
	}
	for _, want := range []string{"[123]", "[705]", "SERVES", "DECLARES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}
}

// TestPreflightFixture_ExploratoryMismatchWarns proves the SAME mismatch is a
// WARNING, not a refusal, on an exploratory run (no -campaign) — consistent
// with preflightManifest's own posture split, and so a quick poke is not blocked
// by drift a gating campaign must reject.
func TestPreflightFixture_ExploratoryMismatchWarns(t *testing.T) {
	m := loadManifest(t, validManifestJSON)
	served := []uint16{1, 701, 702, 703, 704, 706, 707, 708, 709, 710, 711, 712, 123}
	url := serveModelChain(t, served)
	if err := exploratoryRunner(m, url).preflightFixture(context.Background(), NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("preflightFixture REFUSED an exploratory run on a mismatch, want a WARN: %v", err)
	}
}

// TestPreflightFixture_NoSimFatalOnGatingWarnsOnExploratory proves the fail-
// closed flip: a fixture whose served chain could not be read AT ALL (no
// -modsim-api) is now FATAL on a GATING campaign — the southbound oracle reads
// every register verdict from that fixture, so a cert bundle may not be graded
// on one nothing confirmed — and a WARN (continue) on an exploratory poke. A run
// with no manifest is a no-op on either path.
func TestPreflightFixture_NoSimFatalOnGatingWarnsOnExploratory(t *testing.T) {
	m := loadManifest(t, validManifestJSON)

	// GATING + no DER sim -> FATAL.
	gating := &Runner{manifest: m, campaign: CampaignSpec{Name: "csip"}, opts: Options{HTTP: http.DefaultClient}}
	err := gating.preflightFixture(context.Background(), NewReporter(&strings.Builder{}))
	if err == nil {
		t.Fatal("preflightFixture did not refuse a GATING run whose fixture could not be read at all " +
			"(no -modsim-api) — a cert bundle may not be graded on an unchecked fixture")
	}
	for _, want := range []string{"GATING", "-modsim-api"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}

	// EXPLORATORY + no DER sim -> WARN (continue), not a refusal.
	explor := &Runner{manifest: m, opts: Options{HTTP: http.DefaultClient}}
	if err := explor.preflightFixture(context.Background(), NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("preflightFixture REFUSED an EXPLORATORY run with no DER sim, want a WARN: %v", err)
	}

	// No manifest at all -> a no-op on either path.
	rn := gatingRunner(nil, serveModelChain(t, []uint16{1, 704}))
	if err := rn.preflightFixture(context.Background(), NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("preflightFixture FAILed with no manifest, want a no-op: %v", err)
	}
}

// TestPreflightFixture_UnreadableSimFatalOnGating proves the OTHER can't-read-at-
// all case: a DER sim that IS configured but whose /registers cannot be read
// (here an endpoint that errors) is UNPROVEN — fatal on gating, a warn on an
// exploratory run — exactly like the missing sim above.
func TestPreflightFixture_UnreadableSimFatalOnGating(t *testing.T) {
	m := loadManifest(t, validManifestJSON)
	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	gating := gatingRunner(m, srv.URL)
	err := gating.preflightFixture(context.Background(), NewReporter(&strings.Builder{}))
	if err == nil {
		t.Fatal("preflightFixture did not refuse a GATING run whose DER sim could not be read")
	}
	if !strings.Contains(err.Error(), "GATING") {
		t.Errorf("the refusal does not name the gating posture:\n%v", err)
	}
	// Exploratory: the same unreadable sim is a warn, not a refusal.
	if err := exploratoryRunner(m, srv.URL).preflightFixture(context.Background(), NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("preflightFixture REFUSED an EXPLORATORY run whose sim could not be read, want a WARN: %v", err)
	}
}
