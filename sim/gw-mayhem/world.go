package gwmayhem

// world.go is the gw-mayhem "world" — the shared driver a scenario's arm/perTick
// reach through to fault the gateway and sample its response, the analogue of
// Mayhem's mayhemDriver. It is a thin hostile layer over the aggregator emulator:
// connect AS a role (the RBAC subject), connect with a RAW negative cert (the
// cert-authz adversary), and discover a served control unit to target. Every
// method returns the aggregator's own *Conn, so the typed control/readback/denial
// primitives and the mbtls transport are reused unchanged (referee independence
// C9 — the QA never touches the product's securemodbus).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"csip-tls-test/internal/aggregator"
	"lexa-proto/sunspec"
)

// gwWorld holds everything a scenario needs to drive the gateway: the target
// address, the role PKI, the negative-fixture set, and a ready aggregator engine
// for spec scenarios. It is built once per run (NewWorld) and shared read-only by
// every scenario.
type gwWorld struct {
	target   string
	pkiDir   string
	serverCA string
	refs     aggregator.PKIRefs
	eng      *aggregator.Engine
	neg      map[string]negFixture

	// bench wires the wave-2 families (nb-malform / sb-fault) to the desktop
	// sims' admin APIs; the zero value disables them (their arms report a setup
	// error the oracle turns into INCONCLUSIVE). The wave-1 authz families ignore
	// it — they drive the gateway's :802 server directly.
	bench BenchConfig

	// Control-unit discovery is done ONCE per run and cached: every family that
	// needs a 704 target shares the result, so the suite opens one discovery session
	// instead of one per scenario (less session churn, no per-scenario flakiness).
	ctrlMu       sync.Mutex
	ctrlResolved bool
	ctrlUnit     uint8
	ctrlHasMeas  bool
	ctrlOK       bool
}

// negFixture is one cert-authz negative from the manifest: a hostile client leaf
// and the enforcement layer the spec says it must fail at (derived from whether
// its chain is valid).
type negFixture struct {
	name        string
	certFile    string
	keyFile     string
	expectLayer string // "handshake" (chain invalid) | "authz" (chain valid)
	note        string
}

// manifestNegatives is the slice of certs/mbaps/manifest.json this package reads on
// top of what LoadPKI already parsed: the negative fixtures + their chain validity.
type manifestNegatives struct {
	Negatives []struct {
		Name       string `json:"name"`
		Cert       string `json:"cert"`
		Key        string `json:"key"`
		ChainValid bool   `json:"chain_valid"`
		Note       string `json:"note"`
	} `json:"negatives"`
}

// NewWorld builds the world for a run: it loads the role PKI (LoadPKI), applies an
// optional server-CA override, wires an aggregator engine bound to target, and
// loads the negative fixtures. serverCA override is for a live gateway whose server
// cert is verified by a CA other than the manifest device CA; empty keeps the
// manifest default (which, for the single-root bench PKI, verifies the live
// gateway's mbaps-signed :802 leaf).
func NewWorld(target, pkiDir, serverCAOverride string) (*gwWorld, error) {
	refs, err := aggregator.LoadPKI(pkiDir)
	if err != nil {
		return nil, err
	}
	if serverCAOverride != "" {
		refs.ServerCA = serverCAOverride
	}
	w := &gwWorld{
		target:   target,
		pkiDir:   pkiDir,
		serverCA: refs.ServerCA,
		refs:     refs,
	}
	// Both aggregator campaign targets resolve to the one address the runner points
	// at (the gateway, or the loopback), exactly like sim/aggregator's CLI.
	addrs := map[string]string{
		aggregator.TargetGateway: target,
		aggregator.TargetDevice:  target,
	}
	w.eng = aggregator.NewEngine(aggregator.RunOptions{
		ConnectAs: func(addr string, r aggregator.Role) (*aggregator.Conn, error) {
			return aggregator.ConnectAs(addr, r, refs)
		},
		Resolve: func(tgt string) (string, error) {
			if a, ok := addrs[tgt]; ok && a != "" {
				return a, nil
			}
			return "", fmt.Errorf("no address configured for target %q", tgt)
		},
	})
	if err := w.loadNegatives(); err != nil {
		return nil, err
	}
	return w, nil
}

// loadNegatives reads the manifest's negative-fixture table, resolving cert/key
// paths relative to the PKI dir and deriving each fixture's expected enforcement
// layer from its chain validity.
func (w *gwWorld) loadNegatives() error {
	raw, err := os.ReadFile(filepath.Join(w.pkiDir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("gwmayhem: read manifest negatives: %w", err)
	}
	var mf manifestNegatives
	if err := json.Unmarshal(raw, &mf); err != nil {
		return fmt.Errorf("gwmayhem: parse manifest negatives: %w", err)
	}
	w.neg = make(map[string]negFixture, len(mf.Negatives))
	for _, n := range mf.Negatives {
		if n.Name == "" || n.Cert == "" || n.Key == "" {
			continue
		}
		layer := "authz"
		if !n.ChainValid {
			layer = "handshake"
		}
		w.neg[n.Name] = negFixture{
			name:        n.Name,
			certFile:    resolvePath(w.pkiDir, n.Cert),
			keyFile:     resolvePath(w.pkiDir, n.Key),
			expectLayer: layer,
			note:        n.Note,
		}
	}
	return nil
}

// SetBench wires the wave-2 bench driver (the desktop sims' admin APIs) into the
// world after construction — main sets it from the -gridsim-admin / -inv-* flags;
// a hermetic test sets it to httptest bench-stub URLs. Left unset, the wave-2
// families are INCONCLUSIVE (no bench to drive/observe).
func (w *gwWorld) SetBench(b BenchConfig) { w.bench = b }

// connectAs dials the target presenting role r's certificate (with the aggregator's
// own role self-check), returning the live Conn.
func (w *gwWorld) connectAs(r aggregator.Role) (*aggregator.Conn, error) {
	return aggregator.ConnectAs(w.target, r, w.refs)
}

// connectCred dials the target presenting a hostile/negative leaf (NO role
// self-check), returning the live Conn or the handshake error — the cert-authz
// adversary's connect.
func (w *gwWorld) connectCred(certFile, keyFile, assertedRole string) (*aggregator.Conn, error) {
	return aggregator.ConnectCred(w.target, w.serverCA, certFile, keyFile, assertedRole)
}

// roles returns the roles the PKI actually has credentials for, in stable order.
func (w *gwWorld) roles() []aggregator.Role { return w.refs.Roles() }

// discoverControlUnit returns the first served unit that advertises the control
// model (704) plus a measurement model (701 if present), so the matrix/malformed
// families have a real target. The result is resolved ONCE per run (with a few
// retries to ride out transient session churn) and cached; ok is false if nothing
// with a control model responds.
func (w *gwWorld) discoverControlUnit(ctx context.Context) (unit uint8, hasMeas bool, ok bool) {
	w.ctrlMu.Lock()
	defer w.ctrlMu.Unlock()
	if w.ctrlResolved {
		return w.ctrlUnit, w.ctrlHasMeas, w.ctrlOK
	}
	for attempt := 0; attempt < 3; attempt++ {
		if u, meas, found := w.discoverOnce(ctx); found {
			w.ctrlUnit, w.ctrlHasMeas, w.ctrlOK, w.ctrlResolved = u, meas, true, true
			return u, meas, true
		}
	}
	w.ctrlResolved = true
	return 0, false, false
}

// discoverOnce performs one GridService discovery walk over units 1..8.
func (w *gwWorld) discoverOnce(ctx context.Context) (unit uint8, hasMeas bool, ok bool) {
	conn, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		return 0, false, false
	}
	defer conn.Close()
	devs, err := conn.Discover(ctx, 1, 2, 3, 4, 5, 6, 7, 8)
	if err != nil && len(devs) == 0 {
		return 0, false, false
	}
	for _, d := range devs {
		hasCtl, meas := false, false
		for _, m := range d.Models {
			if m == sunspec.ModelDERCtlAC {
				hasCtl = true
			}
			if m == sunspec.ModelDERMeasureAC {
				meas = true
			}
		}
		if hasCtl {
			return d.Unit, meas, true
		}
	}
	return 0, false, false
}

// resolvePath joins a manifest-relative path onto dir (absolute paths pass through).
func resolvePath(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}
