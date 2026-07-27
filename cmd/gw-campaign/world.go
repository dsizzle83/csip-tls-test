package main

// world.go builds the two worlds a campaign can run against — the hermetic
// in-process one and the live bench — and, crucially, builds them so that
// EVERYTHING ABOVE THIS FILE IS IDENTICAL between them.
//
// That symmetry is the argument for trusting the hermetic run at all. A
// hermetic mode that exercised a different scheduler, a different monitor or a
// different shrinker would prove nothing about the live path; here it differs
// only in which addresses the same [campaign.Inventory] and
// [invariant.Sources] point at.
//
// # The hermetic world is ONE device seen twice
//
// The loopback gateway serves a real SunSpec device (gwloopback.Device), and
// the campaign observes that same device through two independent channels: the
// loopback's mbaps projection of it (the DUT's claim, read over :802) and the
// device's own register bank (ground truth, read through a sidecar this file
// stands up). Those are the two witnesses internal/invariant is built around.
//
// It also means a peer-lie armed on the device intercepts the writes that
// arrive over :802 — the sim's own OnWriteAttempt hooks sit under the
// loopback's write path — so `ack_no_apply` hermetically produces exactly the
// condition it produces on the bench: an ACK for a value nothing stored.
//
// # The live world never touches the gateway's configuration
//
// The bench is shared and the campaign is READ-ONLY with respect to the DUT: it
// faults the SIMS and the head-end, and it attacks :802 as a client would. It
// does not restart a service, edit a file, or reboot anything. The one
// gateway-side channel is [invariant.SSHHost], which runs a read-only command
// allowlist (stat, df, ss) enforced inside internal/certify.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/campaign"
	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"csip-tls-test/internal/mbtls"
	sim "csip-tls-test/sim/southbound"

	"csip-tls-test/sim/gw-mayhem/gwloopback"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

// trustDomain is the northbound mTLS trust domain the bench PKI issues into.
// I5 compares a credential's domain against the endpoint's; naming it once here
// keeps the two halves of that comparison from drifting apart.
const trustDomain = "nb-mbaps-clients"

// foreignDomain is the domain the wrong-CA negative fixture belongs to. It is a
// different string from trustDomain and that is the entire point: I5's
// falsification is a credential from one domain authenticating in another, and
// it cannot fire unless the campaign actually presents one.
const foreignDomain = "foreign-ca"

// worldWiring is the CLI's flags, in one place.
type worldWiring struct {
	Target       string
	PKIDir       string
	ServerCA     string
	Loopback     bool
	Teeth        bool
	GridsimAdmin string
	InvPlain     string
	InvSecure    string
	GatewaySSH   string
	Log          invariant.Logger

	addr string // resolved DUT address (the loopback's, once started)
}

func (w *worldWiring) dutAddr() string {
	if w.addr != "" {
		return w.addr
	}
	return w.Target
}

// envFunc returns the builder the campaign (and the shrinker) call once per
// attempt.
//
// A FRESH environment per attempt is not an optimisation to skip. A shrink that
// reused a world whose device had already been lied to, whose register bank
// still held the previous attempt's setpoint, and whose session table was still
// draining would be measuring residue, and would happily report a "minimal"
// action set that reproduces nothing on its own.
func (w *worldWiring) envFunc() (campaign.EnvFunc, error) {
	refs, err := aggregator.LoadPKI(w.PKIDir)
	if err != nil {
		return nil, err
	}
	negs, err := loadNegatives(w.PKIDir)
	if err != nil {
		return nil, err
	}
	if w.Loopback {
		return w.hermetic(refs, negs), nil
	}
	if w.ServerCA != "" {
		refs.ServerCA = w.ServerCA
	}
	return w.live(refs, negs), nil
}

// ── hermetic ─────────────────────────────────────────────────────────────────

// hermetic stands up a loopback gateway plus a sidecar over its own device.
func (w *worldWiring) hermetic(refs aggregator.PKIRefs, negs []negative) campaign.EnvFunc {
	return func(ctx context.Context) (campaign.Env, error) {
		profile := mbtls.DefaultServerProfile(
			filepath.Join(w.PKIDir, "ca-cert.pem"),
			filepath.Join(w.PKIDir, "dev-server-cert.pem"),
			filepath.Join(w.PKIDir, "dev-server-key.pem"),
		)
		// THE TEETH. With -teeth the loopback's write-allow set is widened to
		// include ReadOnly, which is precisely the RBAC-009 defect I4 exists to
		// catch. The credential's own MayWrite stays false — it is still a
		// read-only credential — so the campaign attempts a write it must not be
		// allowed, the bad peer allows it, and I4 falsifies. A run against this
		// peer that comes back clean has proved the harness blind.
		writeRoles := gwloopback.LoopbackWriteRoles()
		if w.Teeth {
			writeRoles = append(writeRoles, aggregator.RoleReadOnly)
		}
		lb, err := gwloopback.StartLoopbackWriteRoles(profile, 0, writeRoles)
		if err != nil {
			return campaign.Env{}, fmt.Errorf("start the loopback gateway: %w", err)
		}
		w.addr = lb.Addr()

		dev := lb.Device()
		side := startSidecar(dev)
		hc := &http.Client{Timeout: 6 * time.Second}
		simClient := certify.NewSimClient(hermeticDER, side.URL, hc)

		inv := campaign.Inventory{
			Hermetic: true,
			DERs: []campaign.DERTarget{{
				Name: hermeticDER,
				// The kinds advertised are the ones that actually DO something
				// against a device wired this way. tcp_drop is omitted on
				// purpose: nothing dials this sim's Modbus port (the loopback
				// reaches its register bank directly), so arming it would put a
				// fault in the manifest that had no effect anywhere — a
				// manifest that overstates the adversary is worse than a
				// smaller one.
				Kinds: hermeticFaultKinds,
				Fault: func(ctx context.Context, body map[string]any) error {
					raw, _ := json.Marshal(body)
					return dev.ApplyFault(raw)
				},
				Pause:  func(context.Context) error { dev.Pause(); return nil },
				Resume: func(context.Context) error { dev.Resume(); return nil },
			}},
		}
		inv.DUT = w.dutTarget(ctx, lb.Addr(), refs, negs)

		src := invariant.Sources{
			DUT:  w.northbound(lb.Addr(), refs),
			DERs: map[string]invariant.DERSource{hermeticDER: invariant.NewSimAPIDER(hermeticDER, simClient, 1)},
		}
		return campaign.Env{
			Inventory: inv,
			Sources:   src,
			Close: func() {
				side.Close()
				lb.Close()
			},
		}, nil
	}
}

// hermeticDER is the name the loopback's own device is observed under. It is
// deliberately not "inv-plain": that name means a specific bench sim, and a
// report that used it would invite a reader to think this ran against the
// bench.
const hermeticDER = "loopback-der"

// hermeticFaultKinds are the fault kinds the in-process device advertises. They
// are the subset of sim/southbound's catalogue that has an OBSERVABLE effect
// when the device is reached through the loopback's register bank rather than
// over its own Modbus socket.
var hermeticFaultKinds = []string{
	"ack_no_apply", "revert_after", "freeze_block", "sentinel_field",
	"exception_on_applied_write", "reboot_forget", "layout_shift",
	"ack_before_effect", "reject_write", "ramp_limit", "nan_sentinel", "bad_scale",
}

// sidecar serves the in-process device's own account of itself over the SAME
// simapi shape the bench sims serve, so [invariant.SimAPIDER] — the exact type
// the live run uses — is the hermetic run's DER source too.
//
// Reusing the source implementation rather than writing an in-process shortcut
// is the point: a hermetic run that read the device through a different code
// path would not be evidence that the live path works.
func startSidecar(dev *sim.SolarServer) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, dev.Registers())
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"paused": dev.IsPaused(),
			// The in-process device is not polled over Modbus by anything, so
			// it has no request counter to publish. Publishing a zero would be
			// worse than publishing nothing: I7 reads a frozen counter as
			// evidence the DUT stopped polling, and would then report a finding
			// about a bench arrangement rather than about the device.
			"sessions": []any{},
		})
	})
	mux.HandleFunc("/fault", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ── live ─────────────────────────────────────────────────────────────────────

// live builds the bench world: the real gateway's :802, the desktop sims, the
// head-end, and (optionally) read-only host accounting.
func (w *worldWiring) live(refs aggregator.PKIRefs, negs []negative) campaign.EnvFunc {
	return func(ctx context.Context) (campaign.Env, error) {
		hc := &http.Client{Timeout: 8 * time.Second}
		inv := campaign.Inventory{}
		src := invariant.Sources{DUT: w.northbound(w.Target, refs)}
		ders := map[string]invariant.DERSource{}

		for _, d := range []struct{ name, url string }{
			{"inv-plain", w.InvPlain},
			{"inv-secure", w.InvSecure},
		} {
			if d.url == "" {
				continue
			}
			client := certify.NewSimClient(d.name, d.url, hc)
			ders[d.name] = invariant.NewSimAPIDER(d.name, client, 1)
			// Ask the sim what it can actually arm, rather than assuming it is
			// as new as this checkout. See probeFaultKinds.
			kinds, refusedKinds := probeFaultKinds(ctx, client,
				append(append([]string(nil), hermeticFaultKinds...), "slow_poll", "tcp_drop"))
			if len(refusedKinds) > 0 && w.Log != nil {
				w.Log.Printf("%s does not know %d fault kind(s) and they are excluded from the plan: %v",
					d.name, len(refusedKinds), refusedKinds)
			}
			inv.DERs = append(inv.DERs, campaign.DERTarget{
				Name:  d.name,
				Kinds: kinds,
				Fault: func(ctx context.Context, body map[string]any) error {
					return client.Fault(ctx, body, nil)
				},
				Pause: func(ctx context.Context) error {
					return client.Control(ctx, map[string]any{"cmd": "pause"}, nil)
				},
				Resume: func(ctx context.Context) error {
					return client.Control(ctx, map[string]any{"cmd": "resume"}, nil)
				},
			})
		}
		if len(ders) > 0 {
			src.DERs = ders
		}

		if w.GridsimAdmin != "" {
			admin := certify.NewAdminClient(w.GridsimAdmin, hc)
			src.HeadEnd = invariant.NewGridsimHeadEnd(admin)
			inv.HeadEnd = headEndTarget(admin)
		}
		if w.GatewaySSH != "" {
			gw := &certify.Gateway{SSH: w.GatewaySSH}
			src.Host = invariant.NewSSHHost(gw, watchedFiles, watchedMounts)
		}
		inv.DUT = w.dutTarget(ctx, w.Target, refs, negs)
		return campaign.Env{Inventory: inv, Sources: src}, nil
	}
}

// watchedFiles and watchedMounts are what I8's growth arm samples on a device
// we have a read-only shell on. They are the stores whose unbounded growth has
// actually been observed (CCP-01: an outbox with no compaction caller).
var (
	watchedFiles  = []string{"/var/lib/lexa/outbox.db", "/var/lib/lexa/state.json"}
	watchedMounts = []string{"/", "/var"}
)

// headEndTarget maps gridsim's per-mode admin endpoints onto the single
// Mode/Clock surface the layers use.
//
// The mapping lives here rather than in the layer because it is a fact about
// THIS simulator's HTTP API, and a layer that knew it would have to change
// whenever the sim did. What the layer knows is what the modes MEAN.
func headEndTarget(admin *certify.AdminClient) campaign.HeadEndTarget {
	arm := map[string]func(bool) (string, map[string]any){
		"outage": func(on bool) (string, map[string]any) {
			return "outage", map[string]any{"mode": "down", "clear": !on}
		},
		"malform": func(on bool) (string, map[string]any) {
			return "malform", map[string]any{"kind": "dup_mrid", "clear": !on}
		},
		"delay": func(on bool) (string, map[string]any) {
			return "delay", map[string]any{"path": "", "delay_ms": 8000, "clear": !on}
		},
		"gone": func(on bool) (string, map[string]any) {
			return "gone", map[string]any{"path": "/dcap", "count": -1, "clear": !on}
		},
		"cannotcomply": func(on bool) (string, map[string]any) {
			return "malform", map[string]any{"kind": "huge_activepower", "clear": !on}
		},
	}
	modes := make([]string, 0, len(arm))
	for m := range arm {
		modes = append(modes, m)
	}
	return campaign.HeadEndTarget{
		Name: "gridsim", Modes: modes,
		Mode: func(ctx context.Context, mode string, on bool, _ map[string]any) error {
			f, ok := arm[mode]
			if !ok {
				return fmt.Errorf("gridsim advertises no fault mode %q", mode)
			}
			path, body := f(on)
			return admin.Post(ctx, path, body, nil)
		},
		Clock: func(ctx context.Context, offsetS int) error {
			return admin.Clock(ctx, map[string]any{"offset_s": offsetS}, nil)
		},
	}
}

// ── shared: the DUT as an attack surface ─────────────────────────────────────

// northbound builds the read-only witness onto the DUT's register map.
//
// The credential is the LEAST privileged one that can read. A monitor auditing
// a device has no business holding a write-capable session open against it for
// the length of a campaign — and if it did, an I4 finding could no longer
// distinguish the campaign's own session from the adversary's.
func (w *worldWiring) northbound(addr string, refs aggregator.PKIRefs) invariant.NorthboundSource {
	return invariant.NewMbapsNorthbound("mbaps:"+addr, func(ctx context.Context) (modbus.Transport, func(), error) {
		c, err := aggregator.ConnectAs(addr, aggregator.RoleReadOnly, refs)
		if err != nil {
			return nil, nil, err
		}
		return c.Transport(), func() { _ = c.Close() }, nil
	}, []uint8{1, 2, 3})
}

// dutTarget builds the attack half: the credentials, the write and present
// probes, and the session flood.
func (w *worldWiring) dutTarget(ctx context.Context, addr string, refs aggregator.PKIRefs, negs []negative) campaign.DUTTarget {
	byName := make(map[string]negative, len(negs))
	for _, n := range negs {
		byName[n.Name] = n
	}
	unit, detail := discoverControlUnit(ctx, addr, refs)
	t := campaign.DUTTarget{
		Addr: addr, Domain: trustDomain, Creds: credentials(refs, negs),
		Unit: unit, UnitDetail: detail,
	}
	t.Write = func(ctx context.Context, c campaign.Credential, unit uint8, point string, value float64) campaign.WriteOutcome {
		return writeAs(addr, refs, c, byName, unit, point, value)
	}
	t.Present = func(ctx context.Context, c campaign.Credential) campaign.AuthOutcome {
		return presentAs(addr, refs, c, byName)
	}
	t.Flood = func(ctx context.Context, n int) (int, int, func(), error) {
		return floodSessions(addr, refs, n)
	}
	return t
}

// negative is one hostile fixture from the PKI manifest.
type negative struct {
	Name       string `json:"name"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	ChainValid bool   `json:"chain_valid"`
	Note       string `json:"note"`
}

func loadNegatives(dir string) ([]negative, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read the PKI manifest: %w", err)
	}
	var mf struct {
		Negatives []negative `json:"negatives"`
	}
	if err := json.Unmarshal(raw, &mf); err != nil {
		return nil, fmt.Errorf("parse the PKI manifest: %w", err)
	}
	for i := range mf.Negatives {
		mf.Negatives[i].Cert = filepath.Join(dir, mf.Negatives[i].Cert)
		mf.Negatives[i].Key = filepath.Join(dir, mf.Negatives[i].Key)
	}
	return mf.Negatives, nil
}

// writeRoles is the bench's faithful write-allow set — the same set the
// loopback models and the live gateway implements. It is what makes
// [campaign.Credential.MayWrite] a fact rather than a guess, and getting it
// wrong would turn I4 into a liar in either direction.
var writeCapable = map[aggregator.Role]bool{
	aggregator.RoleGridService: true,
	aggregator.RoleSuperAdmin:  true,
}

// negativeCause maps each hostile fixture onto the reason its denial is
// expected. I4's indistinguishability arm groups denials by cause WITHIN a
// stage, so a fixture filed under the wrong cause would make the invariant
// compare things that are not comparable.
var negativeCause = map[string]invariant.DenialCause{
	"no-role":       invariant.CauseNoRole,
	"two-role":      invariant.CauseMalformedRBC,
	"bad-encoding":  invariant.CauseMalformedRBC,
	"empty-role":    invariant.CauseMalformedRBC,
	"oversize-role": invariant.CauseMalformedRBC,
	"expired":       invariant.CauseExpired,
	"wrong-ca":      invariant.CauseWrongCA,
}

// credentials assembles every identity the campaign can present: the role certs
// (in-domain) and the negative fixtures.
func credentials(refs aggregator.PKIRefs, negs []negative) []campaign.Credential {
	var out []campaign.Credential
	for _, r := range refs.Roles() {
		out = append(out, campaign.Credential{
			Name: string(r), Role: string(r), Domain: trustDomain,
			MayWrite: writeCapable[r],
			// A role credential's PRESENTATION is expected to succeed — it is a
			// legitimate identity. Only its write may be denied, and that is
			// the write probe's business, not the presentation probe's. Leaving
			// the cause empty keeps a legitimate session out of I4's
			// denial-shape comparison, where it does not belong.
		})
	}
	for _, n := range negs {
		// wrong-ca is the only fixture issued OUTSIDE the northbound trust
		// domain, and it is therefore the only one that can falsify I5. The
		// others are in-domain certificates that are merely wrong.
		domain := trustDomain
		if n.Name == "wrong-ca" {
			domain = foreignDomain
		}
		out = append(out, campaign.Credential{
			Name: n.Name, Role: "", Domain: domain, MayWrite: false,
			DenialCause: negativeCause[n.Name],
		})
	}
	return out
}

// isNegative reports whether a credential is a hostile fixture rather than a
// role cert.
func isNegative(c campaign.Credential) bool { return c.DenialCause != "" || c.Role == "" }

// connect opens a session with a credential, using the role path for a role
// cert and the raw-credential path for a negative (which by design carries a
// role the dialer must not self-check).
func connect(addr string, refs aggregator.PKIRefs, c campaign.Credential, negs map[string]negative) (*aggregator.Conn, error) {
	if !isNegative(c) {
		return aggregator.ConnectAs(addr, aggregator.Role(c.Role), refs)
	}
	n, ok := negs[c.Name]
	if !ok {
		return nil, fmt.Errorf("no fixture on disk for negative credential %q", c.Name)
	}
	return aggregator.ConnectCred(addr, refs.ServerCA, n.Cert, n.Key, "")
}

// connectReady is connect with a bounded retry over a TRANSIENT session-cap
// refusal, and it exists because the first campaign run caught the harness
// attacking itself.
//
// The transport-abuse layer deliberately fills the DUT's session table. The
// authz probes then run while it is full, and a device at its cap refuses an
// over-cap session POST-handshake: the dial succeeds and the first operation
// fails with a transport read error. Without this retry, every authz probe in
// an overlapping window recorded "transport error" instead of the DUT's actual
// answer — so the ledger held no refusals, and I3 and I4 SKIPped for the whole
// run with "the campaign has recorded no refused write". The campaign had
// silenced its own most important invariants by succeeding at a different
// attack.
//
// The retry is narrow on purpose. A DENIAL is not transient: if the probe read
// comes back as a protocol EXCEPTION the session is up and the credential is
// simply refused, which is the answer we came for, and it is returned
// immediately. Only a TRANSPORT failure — the shape of an over-cap shed —
// retries. Riding out the harness's own contention is legitimate; riding out
// the device's answer would be fabricating one.
func connectReady(addr string, refs aggregator.PKIRefs, c campaign.Credential, negs map[string]negative) (*aggregator.Conn, error) {
	const attempts = 5
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(connectBackoff(i))
		}
		conn, err := connect(addr, refs, c, negs)
		if err != nil {
			// A handshake failure is the ANSWER for a negative fixture (expired,
			// wrong-CA), not a transient — retrying it would only slow the run
			// down and would never change the outcome.
			if isNegative(c) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if perr := conn.Ping(1); perr != nil {
			if _, isEx := aggregator.AsException(perr); !isEx {
				lastErr = perr
				_ = conn.Close()
				continue
			}
		}
		return conn, nil
	}
	return nil, lastErr
}

// connectBackoff is 100,200,400,800 ms — long enough for a DUT to reap a freed
// slot, short enough that five attempts cost under two seconds and cannot stall
// a scheduled probe past its window.
func connectBackoff(i int) time.Duration {
	d := (100 * time.Millisecond) << uint(i-1)
	if d > 800*time.Millisecond {
		d = 800 * time.Millisecond
	}
	return d
}

// writeAs attempts one control write and classifies the answer.
func writeAs(addr string, refs aggregator.PKIRefs, c campaign.Credential, negs map[string]negative,
	unit uint8, point string, value float64) campaign.WriteOutcome {
	start := time.Now()
	conn, err := connectReady(addr, refs, c, negs)
	if err != nil {
		// A handshake failure IS a refusal of the write, and recording it as a
		// transport error rather than silently as "not accepted" is what keeps
		// I4 from reading a rejected certificate as a successful denial it
		// never actually observed.
		return campaign.WriteOutcome{TransportErr: err.Error(), ClosedConn: true, RTTns: int64(time.Since(start))}
	}
	defer conn.Close()
	werr := conn.WritePoint(unit, sunspec.ModelDERCtlAC, point, value)
	out := campaign.WriteOutcome{RTTns: int64(time.Since(start))}
	switch {
	case werr == nil:
		out.Accepted = true
	default:
		if ex, ok := aggregator.AsException(werr); ok {
			out.Refused, out.Exception = true, uint8(ex.Code)
		} else {
			out.TransportErr = werr.Error()
			out.ClosedConn = true
		}
	}
	return out
}

// presentAs opens a session with a credential and reports whether it
// authenticated.
//
// Authentication here means the handshake completed AND the peer then served a
// request. A session that handshakes and is refused everything is NOT
// authenticated for I5's purposes — conflating the two would make I5 fire on a
// device that is behaving exactly correctly, which is the fastest way to teach
// an operator to ignore a P1.
func presentAs(addr string, refs aggregator.PKIRefs, c campaign.Credential, negs map[string]negative) campaign.AuthOutcome {
	start := time.Now()
	conn, err := connectReady(addr, refs, c, negs)
	if err != nil {
		return campaign.AuthOutcome{
			Stage: "handshake", ClosedConn: true, Detail: err.Error(),
			RTTns: int64(time.Since(start)),
		}
	}
	defer conn.Close()

	// A RAW read, deliberately not Conn.Ping. Ping's contract is "did the
	// session round-trip a frame", so it returns success for a protocol
	// exception — which is exactly right for a liveness probe and exactly wrong
	// here. Using it made every chain-valid negative fixture (no-role,
	// oversize-role, bad-encoding) come back Authenticated=true: the loopback
	// had refused all of them 0x01, and the probe reported the refusal as a
	// successful authentication.
	//
	// That would corrupt I5 in the worst direction. I5 falsifies on a
	// credential from one trust domain AUTHENTICATING in another, and its own
	// definition is explicit that a session which handshakes and is then
	// refused every request is not authentication. A probe that could not tell
	// those apart would either miss a real cross-domain break or invent one.
	_, rerr := conn.ReadHolding(1, sunspec.SunSpecBase, 2)
	out := campaign.AuthOutcome{Stage: "authz", RTTns: int64(time.Since(start))}
	switch {
	case rerr == nil:
		// Handshake completed AND the peer served a request. That is
		// authentication, and for an out-of-domain credential it is I5's
		// falsification.
		out.Authenticated, out.Stage = true, ""
	default:
		if ex, ok := aggregator.AsException(rerr); ok {
			out.Exception = uint8(ex.Code)
		} else {
			out.ClosedConn, out.Detail = true, rerr.Error()
		}
	}
	return out
}

// floodResidual is how many sessions the flood keeps held after it has measured
// the DUT's response to the burst. See floodSessions for why it is not n.
const floodResidual = 2

// floodSessions opens n concurrent sessions, measures what the DUT did with
// them, then TRIMS the held set to floodResidual and returns a release for the
// remainder.
//
// # Why it trims, which is the whole design of this function
//
// The first campaign run held all n for the fault's whole life, and it worked
// exactly as intended: with n equal to the DUT's session cap, the table stayed
// full for sixteen seconds and every other client was shed. Every other client
// included the campaign's own instrumentation. The authz probes recorded
// "transport error" instead of the DUT's answer, so the ledger held no
// refusals, and I3 and I4 SKIPped for the entire run. The campaign had used one
// successful attack to blind itself to five others.
//
// That is not a device finding and it is not a bug in the invariants. It is a
// measurement conflict: an instrument cannot read a channel it is saturating.
// The resolution keeps both halves of the claim:
//
//	the EXHAUSTION EVENT is real and is measured — n sessions are genuinely
//	opened at once and the served/refused split is recorded, which is the only
//	part of the flood that tests the shed path at all; and
//
//	the SUSTAINED CONDITION is pressure rather than starvation — a small
//	residual stays held for the fault's life, so the table is contended (which
//	is what makes the compound conditions this campaign exists to create) but
//	the DUT can still serve the monitor and the probes.
//
// The alternative — leaving the flood at full strength and accepting that it
// silences I3 and I4 whenever it is scheduled — trades the campaign's two
// sharpest invariants for one blunt one, and would do it silently.
func floodSessions(addr string, refs aggregator.PKIRefs, n int) (int, int, func(), error) {
	var (
		mu       sync.Mutex
		conns    []*aggregator.Conn
		served   int
		refused  int
		wg       sync.WaitGroup
		firstErr error
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := aggregator.ConnectAs(addr, aggregator.RoleReadOnly, refs)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				refused++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			// A session the DUT accepted but will not serve is a REFUSAL, not a
			// success: over-cap sessions are shed post-handshake, and counting
			// them as served would make a device that correctly sheds load look
			// like one that leaked slots.
			if perr := c.Ping(1); perr != nil {
				if _, isEx := aggregator.AsException(perr); !isEx {
					refused++
					_ = c.Close()
					return
				}
			}
			served++
			conns = append(conns, c)
		}()
	}
	wg.Wait()

	// The burst has been measured. Drop back to the residual so the DUT can
	// serve the campaign's own instrumentation for the rest of the fault's life.
	mu.Lock()
	for len(conns) > floodResidual {
		last := len(conns) - 1
		_ = conns[last].Close()
		conns = conns[:last]
	}
	mu.Unlock()

	release := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		conns = nil
	}
	// firstErr is deliberately NOT returned as the action's error: refusals are
	// the expected, correct behaviour of a device with a session cap, and
	// reporting them as an arm failure would remove the fault from the manifest
	// exactly when it worked.
	_ = firstErr
	return served, refused, release, nil
}

// discoverControlUnit finds the served unit that advertises the control model,
// and — just as importantly — says what happened when it does not.
//
// It used to return a bare zero on every failure path, and the first live
// campaign showed what that costs: the whole authz layer declined, I3, I4 and I5
// all SKIPped, and nothing anywhere said whether the gateway served no control
// model, the GridService credential had been refused, or the session had died.
// Three very different problems presenting as the same silence is precisely the
// defect class this suite exists to find, and a harness is not exempt from it.
func discoverControlUnit(ctx context.Context, addr string, refs aggregator.PKIRefs) (uint8, string) {
	conn, err := aggregator.ConnectAs(addr, aggregator.RoleGridService, refs)
	if err != nil {
		return 0, fmt.Sprintf("could not open a GridService session to %s: %v", addr, err)
	}
	defer conn.Close()
	devs, err := conn.Discover(ctx, 1, 2, 3, 4, 5, 6, 7, 8)
	if err != nil && len(devs) == 0 {
		return 0, fmt.Sprintf("the GridService session opened but discovery over units 1..8 returned nothing: %v", err)
	}
	var seen []string
	for _, d := range devs {
		for _, m := range d.Models {
			if m == sunspec.ModelDERCtlAC {
				return d.Unit, fmt.Sprintf("unit %d advertises model 704", d.Unit)
			}
		}
		seen = append(seen, fmt.Sprintf("unit %d: models %v", d.Unit, d.Models))
	}
	if len(seen) == 0 {
		return 0, fmt.Sprintf("discovery over units 1..8 found no SunSpec device at all (err=%v)", err)
	}
	return 0, "no served unit advertises model 704; discovery saw " + strings.Join(seen, "; ")
}

// probeFaultKinds asks a live sim which of the candidate kinds it actually
// knows, by posting a CLEAR for each and keeping the ones it does not reject.
//
// It exists because the alternative is worse in a specific way. The deployed
// bench sims can be older than this checkout — the first live campaign hit four
// arm errors out of nine actions because the sims predate the lying-device
// layer — and an inventory that advertises kinds the peer cannot arm produces a
// manifest that OVERSTATES the adversary. The run then looks like a nine-fault
// campaign and was a five-fault one. Probing first makes the plan describe what
// will actually happen.
//
// Clearing an unarmed kind is a no-op on every sim, so the probe changes
// nothing that was not already going to change: a campaign arms and clears
// faults on these sims anyway, which is why a live run needs the bench to
// itself. It is not free of consequence on a SHARED bench — if another agent
// has armed one of these kinds, this clears it — and that is one more reason
// the runbook says to serialize.
func probeFaultKinds(ctx context.Context, client *certify.SimClient, candidates []string) ([]string, []string) {
	var ok, refused []string
	for _, kind := range candidates {
		if ctx.Err() != nil {
			break
		}
		err := client.Fault(ctx, map[string]any{"kind": kind, "clear": true}, nil)
		if err != nil {
			refused = append(refused, kind)
			continue
		}
		ok = append(ok, kind)
	}
	return ok, refused
}
