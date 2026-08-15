package campaign

// layers.go is the concrete adversary: six families, each mapping one section
// of the strategy's attack-layer list onto actions the engine can schedule.
//
//	peer-lie        §L4 southbound — a device that answers promptly, in range,
//	                and falsely. The richest and most under-covered class.
//	comm-loss       §L4 southbound — the device that simply stops, which is the
//	                control group: the gateway is SUPPOSED to handle this, so a
//	                violation here is a much louder finding than one under a lie.
//	authz-probe     §L2/§L3 — writes and credential presentations that feed the
//	                ledger, so I3, I4 and I5 have attempts to judge.
//	transport-abuse §L3 — session-slot exhaustion against the reachable :802.
//	head-end        §L4 northbound — malform, outage, delay, 429/500 storms.
//	clock-warp      §L7 — the head-end's notion of now moves under the DUT.
//
// # What is deliberately NOT here
//
// §L5 (resource hostility) and §L6 (crash consistency) are absent, and their
// absence is a decision rather than an oversight. Both require mutating the
// DUT's host — filling its disk, exhausting its descriptors, cutting its power
// — and the operating constraint on this bench is that a campaign is READ-ONLY
// with respect to gateway configuration and services. A layer that violated
// that would be unrunnable on the only device we have. They are covered instead
// by lexa-gw's own `make hostile` and the powercut harness, against a device the
// runner owns; see the runbook's cadence table. Saying so here is the point:
// the campaign's silence about I6 is a scope boundary, and I6 duly SKIPs with a
// reason rather than passing for free.
//
// # Every layer plans against the inventory and never probes
//
// A layer that discovered its own targets would produce a different action set
// on a bench where one sim was briefly down, and the campaign would stop being
// reproducible from its seed. So each layer reads [Inventory], plans, and
// returns; if a target is absent the layer offers nothing and [BuildPlan]
// records it as declined, which is visible in the manifest.

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"csip-tls-test/internal/invariant"
)

// Standard returns every layer, in a stable order.
func Standard() []Layer {
	return []Layer{
		PeerLie{}, CommLoss{}, AuthzProbe{}, TransportAbuse{}, HeadEnd{}, ClockWarp{},
	}
}

// Select returns the layers whose ids appear in ids (empty selects all), plus
// the names of any id that matched nothing — so `-layers peer-lei` is reported
// rather than silently running five.
func Select(ids []string) ([]Layer, []string) {
	if len(ids) == 0 {
		return Standard(), nil
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []Layer
	for _, l := range Standard() {
		if want[l.ID()] {
			out = append(out, l)
			delete(want, l.ID())
		}
	}
	unknown := make([]string, 0, len(want))
	for k := range want {
		unknown = append(unknown, k)
	}
	return out, unknown
}

// ── peer-lie ─────────────────────────────────────────────────────────────────

// PeerLie arms the lying-device family on each DER that advertises it.
type PeerLie struct{}

// ID identifies the layer.
func (PeerLie) ID() string { return "peer-lie" }

// Describe says what it is trying to falsify.
func (PeerLie) Describe() string {
	return "a southbound DER that answers promptly, in range, and falsely — ACKs a curtailment it never " +
		"stored, reverts it silently, freezes its measurements, or comes back from a 'firmware update' " +
		"with a different model layout. Falsifies I1/I2/I7: the gateway's own view stays coherent while " +
		"the operator's instruction is not being carried out."
}

// lieCatalog is the set of lies this layer knows how to arm, with the
// parameters that make each one dangerous rather than merely present.
//
// The parameters are chosen, not random. delay_s on a revert has to be short
// enough that the run observes the revert and long enough that the gateway's
// own readback verification passes first — a revert at 0 s is just a rejected
// write, which is a different (and already-covered) fault.
var lieCatalog = []struct {
	kind   string
	params map[string]any
	why    string
}{
	{"ack_no_apply", map[string]any{"echo": true},
		"the device ACKs a curtailment, stores none of it, and echoes it on readback — readback " +
			"verification is defeated and only the device's own register image reveals it"},
	{"ack_no_apply", map[string]any{},
		"the device ACKs a curtailment and stores none of it; the readback still tells the truth, so a " +
			"gateway that verifies its writes must catch this one"},
	{"revert_after", map[string]any{"delay_s": 12},
		"the device accepts a curtailment, confirms it, then silently reverts — a limit that stopped " +
			"being in force must stop being reported as applied"},
	{"freeze_block", map[string]any{},
		"the measurement block is frozen at arm time while the machine keeps moving — the gateway is " +
			"reporting telemetry that is no longer true"},
	// sentinel_field REQUIRES a target: the sim refuses "blank nothing", and it
	// is right to. W and VAr are named because they are the two points a
	// gateway most readily mistakes for a measurement — 0x8000 read as a signed
	// int16 is -32768 W, a plausible-looking import that never happened.
	//
	// TWO ENTRIES, ONE FAULT KIND, because the bare names are MODEL-SPECIFIC
	// and the bench's inverters serve both models. sim/southbound's installLies
	// maps "W"/"VAr" to model 103 and registers the model 701 points under the
	// SUFFIXED names "W_701"/"VAr_701". A gateway that prefers 701 — which the
	// sim's own comment says it does, and which is why installLies moves the
	// default freeze window to 701 on an advanced sim — never reads the block
	// the first entry blanks, so against the bench's advanced inverters that
	// entry arms a probe the DUT cannot see. That is not a reason to replace
	// it: a legacy 103-only device has no "_701" names at all, and the sim
	// refuses an unknown field BY NAME (resolveTargetsLocked), which the
	// campaign records as an ARM-ERR against that one action and carries on.
	// So both spellings are offered and whichever the device actually has is
	// the one that arms.
	{"sentinel_field", map[string]any{"fields": []string{"W", "VAr"}},
		"the device serves the SunSpec not-implemented sentinel where a real measurement belongs (model " +
			"103's W/VAr); a gateway that treats 0x8000 as -32768 will report a plausible, wrong number"},
	{"sentinel_field", map[string]any{"fields": []string{"W_701", "VAr_701"}},
		"the same sentinel, in model 701 — the measurement block a 7xx-capable gateway actually reads, " +
			"so this is the entry that reaches a DUT polling the advanced models. It arms only on a sim " +
			"that serves 701; elsewhere it is an honest ARM-ERR naming the field that is missing"},
	// This entry's rationale was wrong, and IW15-031 is the adjudication that
	// corrected it. It used to read "I3's exact shape", which is what invited a
	// P1 every time it armed: the value IS at the device afterwards, but the
	// DEVICE put it there in response to this very write and then denied it, so
	// nothing about the DUT's durable state follows. I3 now reports that run
	// WARN with the confound named (see internal/invariant/i3.go). What the lie
	// is genuinely worth is stated here instead — it is a read-back-and-
	// reconcile probe, TRM-01's shape, and the gateway that trusts a write's
	// answer over a read-back is the one it catches.
	{"exception_on_applied_write", map[string]any{"ex_code": 4, "every": 1},
		"the device REFUSES a write it has already applied. It is NOT a ghost-commit probe — the value's " +
			"presence afterwards is the lie, not the DUT's durable state, and I3 says so rather than " +
			"reporting a P1 (IW15-031). What it probes is TRM-01: a gateway that trusts the write's answer " +
			"instead of reading back is now reporting a refusal for a limit that is in force"},
	{"slow_poll", map[string]any{"hold_ms": 2500},
		"the device answers, but slowly enough to stack the gateway's requests — the failure mode that " +
			"turns into a livelock rather than an error"},
	{"reboot_forget", map[string]any{},
		"the device reboots and forgets its setpoints without telling anyone; the gateway must notice " +
			"its limit is no longer in force"},
	{"layout_shift", map[string]any{"delta": 8},
		"the device comes back from a 'firmware update' with every model eight registers further along " +
			"— a hub that cached model offsets will now read the wrong register and believe it"},
}

// Plan offers every catalog lie each DER can actually arm.
func (p PeerLie) Plan(inv Inventory, rng *rand.Rand) []Action {
	var out []Action
	for _, der := range inv.DERs {
		if der.Fault == nil {
			continue
		}
		for _, l := range lieCatalog {
			if !der.Has(l.kind) {
				continue
			}
			out = append(out, faultAction(p.ID(), l.kind, der, invariant.ClassPeerLie, l.params, l.why))
		}
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// faultAction builds the arm/clear pair for a POST /fault kind. Clear is
// idempotent by construction — the sims treat a clear of an unarmed kind as a
// no-op — which is what lets the runner tear down unconditionally.
func faultAction(layer, kind string, der DERTarget, class invariant.FaultClass, params map[string]any, why string) Action {
	body := map[string]any{"kind": kind}
	for k, v := range params {
		body[k] = v
	}
	target := der
	return Action{
		Layer: layer, Kind: kind, Target: der.Name, Class: class,
		Params: flatten(params), Recoverable: true, Why: why,
		Arm: func(ctx context.Context, rt *Runtime) error {
			return target.Fault(ctx, body)
		},
		Clear: func(ctx context.Context, rt *Runtime) error {
			return target.Fault(ctx, map[string]any{"kind": kind, "clear": true})
		},
	}
}

func flatten(m map[string]any) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// ── comm-loss ────────────────────────────────────────────────────────────────

// CommLoss stops a device talking — the honest failure, as a control group.
type CommLoss struct{}

// ID identifies the layer.
func (CommLoss) ID() string { return "comm-loss" }

// Describe says what it is trying to falsify.
func (CommLoss) Describe() string {
	return "a southbound device that goes silent or drops the DUT's connections. The gateway is SUPPOSED " +
		"to handle this, which is why it is worth running: a violation under a fault the device handles " +
		"correctly by design is a much louder finding than one under a novel lie. Falsifies I7 (a stale " +
		"reading reported as current) and I9 (recovery without a human)."
}

// Plan offers a socket drop and an animation freeze per device.
func (c CommLoss) Plan(inv Inventory, rng *rand.Rand) []Action {
	var out []Action
	for _, der := range inv.DERs {
		d := der
		if d.Fault != nil && d.Has("tcp_drop") {
			out = append(out, Action{
				Layer: c.ID(), Kind: "tcp_drop", Target: d.Name, Class: invariant.ClassCommLoss,
				Recoverable: true,
				Why: "the device drops every live connection and rebinds; the DUT must reconnect without " +
					"human intervention and must not report the interval as healthy",
				Arm: func(ctx context.Context, rt *Runtime) error {
					return d.Fault(ctx, map[string]any{"kind": "tcp_drop"})
				},
				// tcp_drop is self-clearing (the sim rebinds), so the clear is a
				// no-op that exists so teardown can be unconditional.
				Clear: func(ctx context.Context, rt *Runtime) error { return nil },
			})
		}
		if d.Pause != nil && d.Resume != nil {
			out = append(out, Action{
				Layer: c.ID(), Kind: "freeze-animation", Target: d.Name, Class: invariant.ClassCommLoss,
				Recoverable: true,
				Why: "the device's physical simulation stops while it keeps answering — every reading it " +
					"serves is now stale, and a gateway that reports them as current is claiming " +
					"something that did not happen",
				Arm:   func(ctx context.Context, rt *Runtime) error { return d.Pause(ctx) },
				Clear: func(ctx context.Context, rt *Runtime) error { return d.Resume(ctx) },
			})
		}
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// ── authz-probe ──────────────────────────────────────────────────────────────

// AuthzProbe attempts writes and credential presentations against the DUT and
// records every one in the ledger.
//
// It is the layer that gives I3, I4 and I5 anything to judge. Without it those
// three invariants SKIP for the entire run with "the campaign attempted no
// write and no authentication", which is honest but useless.
type AuthzProbe struct{}

// ID identifies the layer.
func (AuthzProbe) ID() string { return "authz-probe" }

// Describe says what it is trying to falsify.
func (AuthzProbe) Describe() string {
	return "writes and credential presentations from every role the bench PKI holds, recorded in the " +
		"ledger with what the DUT answered. Falsifies I4 (an unauthorized credential causing a write, " +
		"or a denial whose shape reveals its cause), I5 (a credential authenticating outside its trust " +
		"domain) and I3 (a refused write leaving a ghost downstream)."
}

// probeValues are the distinctive setpoints the probes command.
//
// Distinctiveness is a REQUIREMENT, not a nicety: I3 infers "the refused value
// never reached the device" from the device's register image, and that
// inference is only sound if the value could not have arrived by another route.
// A round number like 50 is exactly what a scheduler default would land on, so
// these are deliberately unround and each probe gets its own.
//
// # The list ran out, and the campaign lied about it
//
// Found while validating IW15-031, on the run that closed it. The list held SIX
// values and the assignment was `probeValues[i%len(probeValues)]`, while the
// bench PKI offers more than six credentials — so a `-teeth` run at seed
// 1096004868 gave BOTH `ReadOnlySunSpec` and `oversize-role` the value 29, and
// marked both records Distinctive. The teeth peer accepted ReadOnlySunSpec's
// write, oversize-role's was refused 0x01, and I3 then reported a P1: "the DUT
// REFUSED it with exception 0x01, yet dut.unit1 now reads 29 % — the refusal did
// not prevent the value taking effect". The 29 came from the OTHER probe.
//
// That is precisely the failure i3.go's own distinctiveness section describes —
// "seeing 50 at the DER proves nothing at all, and an invariant that reported
// PASS on that basis would be lying by construction" — arriving from the FAIL
// direction instead, and it is the campaign's fault rather than I3's: I3 is
// entitled to believe [invariant.WriteRecord.Distinctive], because only the
// party that issued the write knows what else it issued.
//
// So the list is long enough for any PKI this bench will hold, and
// [probeValue] refuses to assert distinctiveness once it runs out rather than
// wrapping. A SKIP naming the exhausted supply is a true statement; a repeated
// witness value is a false one.
var probeValues = []float64{
	37, 63, 41, 29, 71, 53, 17, 83, 47, 23, 67, 31, 79, 43, 59, 89,
	13, 91, 27, 61, 39, 73, 19, 87, 33, 69, 21, 77, 49, 93,
}

// probeValue returns the setpoint for the i-th credential's write probe, and
// whether it may be asserted DISTINCTIVE — that is, whether it is a value no
// other probe in this run also commands.
//
// Wrapping the list would be the obvious thing and is the bug above: two
// credentials commanding the same witness value make every downstream
// observation of it ambiguous, and the record that claims otherwise poisons I3
// in both directions. Past the end of the supply the probe still runs (the
// write itself is I4's evidence, and I4 does not depend on the value being
// unique) but the record says the value is not a witness.
func probeValue(i int) (float64, bool) {
	if i < len(probeValues) {
		return probeValues[i], true
	}
	// Keep probing, keep the value legal, and stop claiming distinctiveness.
	return probeValues[i%len(probeValues)], false
}

// Explain says why the layer offered nothing, which is nearly always that no
// served unit advertises the control model — and therefore that the campaign
// ran with I3, I4 and I5 all skipped. That is a big enough hole in a run's
// coverage that the manifest must name it rather than leave a reader to infer
// it from three SKIPs.
func (a AuthzProbe) Explain(inv Inventory) string {
	switch {
	case inv.DUT.Unit == 0:
		detail := inv.DUT.UnitDetail
		if detail == "" {
			detail = "no reason was recorded"
		}
		return "no served unit advertises the control model (704), so there is nothing to attempt a write " +
			"against: " + detail + ". I3, I4 and I5 are therefore NOT under test in this run."
	case inv.DUT.Write == nil && inv.DUT.Present == nil:
		return "the DUT has no write or credential-presentation surface wired, so no authorization attempt " +
			"could be made. I3, I4 and I5 are NOT under test in this run."
	case len(inv.DUT.Creds) == 0:
		return "the PKI yielded no credentials to present. I3, I4 and I5 are NOT under test in this run."
	default:
		return ""
	}
}

// Plan offers one write probe per credential plus one presentation probe per
// credential, capped so a large PKI does not swamp the run.
func (a AuthzProbe) Plan(inv Inventory, rng *rand.Rand) []Action {
	if inv.DUT.Unit == 0 {
		return nil
	}
	var out []Action
	for i, cred := range inv.DUT.Creds {
		c := cred
		value, distinctive := probeValue(i)
		if inv.DUT.Write != nil {
			out = append(out, Action{
				Layer: a.ID(), Kind: "write-" + credSlug(c), Target: "dut", Class: invariant.ClassTransportAbuse,
				Oneshot: true,
				Params:  map[string]string{"credential": c.Name, "role": c.Role, "may_write": fmt.Sprint(c.MayWrite), "pct": trim(value)},
				Why: fmt.Sprintf("credential %q (role %s, may-write=%t) attempts WMaxLimPct=%s%%; the answer and "+
					"everything downstream of it is the ledger record I3 and I4 judge%s",
					c.Name, c.Role, c.MayWrite, trim(value), distinctiveNote(distinctive)),
				Arm: writeProbe(inv.DUT, c, value, distinctive),
			})
		}
		if inv.DUT.Present != nil {
			out = append(out, Action{
				Layer: a.ID(), Kind: "present-" + credSlug(c), Target: "dut", Class: invariant.ClassTransportAbuse,
				Oneshot: true,
				Params:  map[string]string{"credential": c.Name, "cred_domain": c.Domain, "target_domain": inv.DUT.Domain},
				Why: fmt.Sprintf("credential %q from trust domain %q is presented to an endpoint in domain %q; "+
					"I5 falsifies on a credential that authenticates outside its own domain",
					c.Name, c.Domain, inv.DUT.Domain),
				Arm: presentProbe(inv.DUT, c),
			})
		}
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// distinctiveNote appends the disclosure to a probe's Why when the run has more
// credentials than distinct witness values, so the manifest a reader sees says
// which probes I3 will decline to judge.
func distinctiveNote(distinctive bool) string {
	if distinctive {
		return ""
	}
	return " — NOT marked distinctive: this run has more credentials than the probe value list has distinct " +
		"entries, so seeing this value downstream would not prove it came from this write, and I3 SKIPs it"
}

// writeProbe returns the probe that attempts one write and records it.
func writeProbe(dut DUTTarget, c Credential, value float64, distinctive bool) func(context.Context, *Runtime) error {
	return func(ctx context.Context, rt *Runtime) error {
		start := time.Now()
		res := dut.Write(ctx, c, dut.Unit, "WMaxLimPct", value)
		rtt := time.Duration(res.RTTns)
		if rtt == 0 {
			rtt = time.Since(start)
		}
		rt.Ledger.NoteWrite(invariant.WriteRecord{
			At: start, Credential: c.Name, Role: c.Role, Domain: c.Domain,
			Authorized: c.MayWrite, Unit: dut.Unit, Model: 704, Point: "WMaxLimPct",
			Value:       invariant.Quantity{Val: value, Unit: invariant.UnitPercent},
			Ref:         invariant.RefWMax,
			Distinctive: distinctive,
			Accepted:    res.Accepted, Refused: res.Refused, ExceptionCode: res.Exception,
			TransportErr: res.TransportErr, ClosedConn: res.ClosedConn, RTT: rtt,
			Note: probeNote(distinctive),
		})
		rt.Logf("PROBE   write %-24s may-write=%-5t accepted=%t refused=%t ex=0x%02X",
			c.Name, c.MayWrite, res.Accepted, res.Refused, res.Exception)
		// A transport error is a bench condition, not a device finding, and must
		// not abort the campaign — it is recorded in the ledger and the
		// invariants decide what it means.
		return nil
	}
}

// probeNote is the ledger record's own account of why its value may or may not
// be used as a witness. It is written into the record rather than left implicit
// because I3 names the note when it SKIPs.
func probeNote(distinctive bool) string {
	if distinctive {
		return "a deliberately unround curtailment, unique among this run's probes, so seeing it downstream " +
			"can only have come from this write and not from a scheduler default or another probe"
	}
	return "NOT distinctive: this run has more credentials than the probe value list has distinct entries, " +
		"so this value is also commanded by another probe and observing it downstream proves nothing about " +
		"THIS write. The attempt is still recorded — I4 judges the ANSWER, which needs no unique value — but " +
		"I3 must skip it rather than attribute the value to this write"
}

// presentProbe returns the probe that presents one credential and records it.
func presentProbe(dut DUTTarget, c Credential) func(context.Context, *Runtime) error {
	return func(ctx context.Context, rt *Runtime) error {
		start := time.Now()
		res := dut.Present(ctx, c)
		rtt := time.Duration(res.RTTns)
		if rtt == 0 {
			rtt = time.Since(start)
		}
		rt.Ledger.NoteAuth(invariant.AuthRecord{
			At: start, Credential: c.Name, CredDomain: c.Domain, TargetDomain: dut.Domain,
			Target: dut.Addr, Cause: c.DenialCause, Authenticated: res.Authenticated,
			Stage: res.Stage, ExceptionCode: res.Exception, ClosedConn: res.ClosedConn,
			RTT: rtt, TLSAlert: res.TLSAlert, Detail: res.Detail,
		})
		rt.Logf("PROBE   present %-22s domain=%s authenticated=%t stage=%s",
			c.Name, c.Domain, res.Authenticated, res.Stage)
		return nil
	}
}

func credSlug(c Credential) string {
	out := make([]rune, 0, len(c.Name))
	for _, r := range c.Name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

func trim(v float64) string { return fmt.Sprintf("%g", v) }

// ── transport-abuse ──────────────────────────────────────────────────────────

// TransportAbuse exhausts the DUT's session budget on the one reachable port.
type TransportAbuse struct{}

// ID identifies the layer.
func (TransportAbuse) ID() string { return "transport-abuse" }

// Describe says what it is trying to falsify.
func (TransportAbuse) Describe() string {
	return ":802 is the entire remote attack surface, and it caps concurrent sessions. This layer opens a " +
		"burst large enough to overrun the cap, records the served/shed split, then holds a residual so " +
		"the rest of the campaign runs under session pressure rather than under a self-inflicted " +
		"blackout. Falsifies I8 (a session table that does not drain is unbounded growth) and I9 (the " +
		"port must serve again, unaided, once the pressure stops)."
}

// Plan offers one flood sized to overrun a typical cap.
func (t TransportAbuse) Plan(inv Inventory, rng *rand.Rand) []Action {
	if inv.DUT.Flood == nil {
		return nil
	}
	// Two sizes: one at the cap (contention without refusal) and one over it
	// (refusals, and therefore a reaping path to exercise). The seed picks the
	// order they are offered in, not the sizes — a flood whose size moved with
	// the seed would make two runs incomparable.
	sizes := []int{8, 14}
	var out []Action
	for _, n := range sizes {
		count := n
		// The release closure is held per action instance, so Clear tears down
		// exactly the sessions this action opened. An action is armed at most
		// once per run, so no locking is needed beyond the runner's own
		// happens-before between Arm and Clear.
		var release func()
		out = append(out, Action{
			Layer: t.ID(), Kind: fmt.Sprintf("session-flood-%d", count), Target: "dut",
			Class: invariant.ClassTransportAbuse, Recoverable: true,
			Params: map[string]string{"sessions": fmt.Sprint(count)},
			Why: fmt.Sprintf("open %d concurrent mbaps sessions at once, record how many the DUT served and how "+
				"many it shed, then hold a small residual for the fault's life; the DUT must shed the "+
				"excess without leaking a slot, must keep serving under the residual pressure, and must "+
				"be back to normal once it is released", count),
			Arm: func(ctx context.Context, rt *Runtime) error {
				served, refused, rel, err := inv.DUT.Flood(ctx, count)
				release = rel
				rt.Logf("FLOOD   %d sessions -> served=%d refused=%d err=%v", count, served, refused, err)
				return err
			},
			Clear: func(ctx context.Context, rt *Runtime) error {
				if release != nil {
					release()
					release = nil
				}
				return nil
			},
		})
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// ── head-end ─────────────────────────────────────────────────────────────────

// HeadEnd makes the utility server misbehave.
type HeadEnd struct{}

// ID identifies the layer.
func (HeadEnd) ID() string { return "head-end" }

// Describe says what it is trying to falsify.
func (HeadEnd) Describe() string {
	return "the utility head-end returns malformed bodies, disappears, stalls, or refuses. Falsifies I2 " +
		"(with control authority lost the device must converge to its configured failsafe, and must " +
		"LEAVE failsafe when authority returns) and I9 (a recoverable outage recovers unaided)."
}

// headEndModes maps gridsim's fault modes onto their fault class and the claim
// each one is attacking. The class matters: an outage is a loss of AUTHORITY
// (I2's precondition) while a malformed body is not — the head-end is still
// there and still authoritative, it is merely unparseable.
var headEndModes = []struct {
	mode  string
	class invariant.FaultClass
	why   string
}{
	{"outage", invariant.ClassAuthorityLoss,
		"the head-end is unreachable; the device must converge to its configured failsafe within the " +
			"stated deadline, and must leave failsafe when the head-end returns"},
	{"malform", invariant.ClassMalform,
		"the head-end serves structurally invalid 2030.5; a parser that accepts half a document and " +
			"acts on it is the quiet failure this is aimed at"},
	{"delay", invariant.ClassMalform,
		"the head-end stalls its responses; the device must not stack requests unboundedly or report " +
			"the interval as a healthy poll"},
	{"gone", invariant.ClassAuthorityLoss,
		"the head-end answers 410 Gone for the resources the device depends on — authority is lost in a " +
			"way that looks deliberate rather than accidental"},
	{"cannotcomply", invariant.ClassMalform,
		"the head-end rejects the device's responses; the device must keep its own state coherent rather " +
			"than assuming its report landed"},
}

// Plan offers each advertised mode.
func (h HeadEnd) Plan(inv Inventory, rng *rand.Rand) []Action {
	if inv.HeadEnd.Mode == nil {
		return nil
	}
	var out []Action
	for _, m := range headEndModes {
		if !inv.HeadEnd.Has(m.mode) {
			continue
		}
		mode := m
		out = append(out, Action{
			Layer: h.ID(), Kind: mode.mode, Target: "head-end", Class: mode.class,
			Recoverable: true, Why: mode.why,
			Arm: func(ctx context.Context, rt *Runtime) error {
				return inv.HeadEnd.Mode(ctx, mode.mode, true, nil)
			},
			Clear: func(ctx context.Context, rt *Runtime) error {
				return inv.HeadEnd.Mode(ctx, mode.mode, false, nil)
			},
		})
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// ── clock-warp ───────────────────────────────────────────────────────────────

// ClockWarp moves the head-end's notion of now under the DUT.
type ClockWarp struct{}

// ID identifies the layer.
func (ClockWarp) ID() string { return "clock-warp" }

// Describe says what it is trying to falsify.
func (ClockWarp) Describe() string {
	return "the head-end's clock steps forward or backward under the device — a control window opens or " +
		"closes during the jump. Grounded in GT-04, where the board's RTC reads 1970 and NTP never " +
		"syncs; time bugs are disproportionately represented in 'worked in the lab, failed in the field'."
}

// clockOffsets are the warps worth arming: a backward step large enough to
// reopen an expired window, and a forward step large enough to expire a live
// one. They are fixed rather than seeded for the same reason the flood sizes
// are — two runs must be comparable.
var clockOffsets = []int{-3600, 3600}

// Plan offers each offset.
func (c ClockWarp) Plan(inv Inventory, rng *rand.Rand) []Action {
	if inv.HeadEnd.Clock == nil {
		return nil
	}
	var out []Action
	for _, off := range clockOffsets {
		o := off
		dir := "forward"
		if o < 0 {
			dir = "backward"
		}
		out = append(out, Action{
			Layer: c.ID(), Kind: fmt.Sprintf("clock-%s", dir), Target: "head-end",
			Class: invariant.ClassClockWarp, Recoverable: true,
			Params: map[string]string{"offset_s": fmt.Sprint(o)},
			Why: fmt.Sprintf("step the head-end's clock %s by %ds; a control window that opens or expires "+
				"during the jump must not produce a setpoint nobody commanded", dir, o),
			Arm:   func(ctx context.Context, rt *Runtime) error { return inv.HeadEnd.Clock(ctx, o) },
			Clear: func(ctx context.Context, rt *Runtime) error { return inv.HeadEnd.Clock(ctx, 0) },
		})
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
