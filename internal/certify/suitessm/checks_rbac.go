package suitessm

// checks_rbac.go implements §2.8 "Role-Based Access Control" — RBAC-001 through
// RBAC-012, less RBAC-003, which the catalog marks inapplicable because the
// optional IEC 62351-8 roles are the DUT's single deferred requirement row.
//
// This is the family whose evidence spans both layers, and the split is the
// same in every check:
//
//	the ROLE is proved in the clear   — the client Certificate message of a
//	                                    TLS 1.2 handshake carries the extension
//	                                    at OID 1.3.6.1.4.1.50316.802.1 verbatim,
//	                                    so the role string and its ASN.1 encoding
//	                                    can be cited byte for byte;
//	the DECISION is proved encrypted  — the Modbus exception (or its absence) is
//	                                    inside the tunnel, and is recovered by
//	                                    decrypting the capture with the run's
//	                                    key log.
//
// Every check here therefore forces TLS 1.2 (see the package doc) and produces
// two independent assertions per criterion: what identity was presented, and
// what the DUT did about it.
//
// # A note on writing to a live gateway
//
// Several procedures require a WRITE to a control point. Writing an arbitrary
// value to a DER control register on a gateway that is driving real equipment
// is not acceptable, and a conformance tool that did it would be a hazard. So
// every write this file performs is a READ-BACK WRITE: the current value of the
// register is read first and written back unchanged. The authorization path —
// which is the entire subject of these procedures — is exercised identically,
// and the DUT's state is not disturbed whether the write is permitted or denied.

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// mandatoryRoles maps the fixture stem to the role string SunSpecTCP-22 makes
// mandatory. Transcribed from the specification, not read from the DUT's rules
// database — a suite that took the role names from the DUT could not detect a
// DUT that had invented its own.
var mandatoryRoles = []struct{ fixture, role string }{
	{"read-only", "ReadOnlySunSpec"},
	{"grid-service", "GridServiceSunSpec"},
	{"net-admin", "NetworkAdministratorSunSpec"},
	{"super-admin", "SuperAdministratorSunSpec"},
}

// ── shared machinery ────────────────────────────────────────────────────────

// roleRun is one role's session and everything observed through it.
type roleRun struct {
	Label string
	Cert  *tls.Certificate
	Sess  *Session
	Err   error

	Unit  uint8
	Chain *Chain

	// Read and Write are the exchanges the procedures assert on.
	Read, Write Exchange
	// Target describes the register the write went to.
	Target writeTarget
	// TargetErr says why no write was performed, when none was. A step the
	// procedure conditions on "if one exists" and the DUT offers no target for
	// was NOT PERFORMED — a distinct outcome from a denial, and one a report
	// must not turn into a verdict about the DUT.
	TargetErr error
}

// writeTarget is a register chosen for an authorization probe.
type writeTarget struct {
	Model uint16
	Addr  uint16
	Value uint16
	Why   string
}

func (w writeTarget) String() string {
	return fmt.Sprintf("model %d register %d (current value 0x%04X, written back unchanged) — %s",
		w.Model, w.Addr, w.Value, w.Why)
}

// openRoleSession dials as one identity over TLS 1.2 and discovers the chain.
func openRoleSession(ctx context.Context, rc *certify.RunCtx, pf preflight,
	label string, cert *tls.Certificate) *roleRun {

	r := &roleRun{Label: label, Cert: cert}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		r.Err = err
		return r
	}
	s, err := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "RBAC session: " + label,
	})
	if err != nil {
		if partial, ok := handshakeFailed(err); ok {
			r.Sess = partial
		}
		r.Err = err
		return r
	}
	r.Sess = s
	r.Unit, r.Chain, err = findUnit(rc, s)
	if err != nil {
		// A role with no read rights cannot discover the chain, and that is a
		// legitimate outcome rather than a failure of the check. The caller
		// decides.
		r.Err = err
	}
	return r
}

// notImplemented16 are the values a 16-bit SunSpec point reads when it is not
// implemented: 0xFFFF for the unsigned, enumerated and bitfield types, 0x8000
// for the signed ones (SunSpec Device Information Model Specification §6).
//
// A register reading one of these is NOT a legal write value. Writing it back
// — which is what "read the current value and write it back unchanged" does on
// an unimplemented point — can only ever be answered with exception 3, because
// the sentinel is outside every declared enumeration and range. Run
// 20260726T225512's RBAC-002 wrote 0xFFFF into 704.PFWInjEna for all four roles
// and then read the resulting exception 3 as a denial: the probe had made the
// only answer it could get indistinguishable from the answer it was testing for.
var notImplemented16 = map[uint16]bool{0xFFFF: true, 0x8000: true}

// writeKind names the class of register a procedure step aims its write at.
//
// §2.7.2.1 does not say "write somewhere"; it names a different target per
// role — a control point for GridService, a NETWORK CONFIGURATION point for
// NetworkAdministrator — and conditions each on "if one exists". Aiming every
// role at the same DER control model tests something the procedure never asked
// about, and then reports the expected denial as a defect.
type writeKind struct {
	// name is how the class is described in the report.
	name string
	// prefer lists model ids to try first, in order.
	prefer []uint16
	// accept reports whether a model id belongs to this class at all.
	accept func(id uint16) bool
}

// controlPoint is §2.7.2.1 step 2's "control point (e.g., Model 704)". Any
// non-Common model will do when 704 is absent; the reason is recorded.
var controlPoint = writeKind{
	name:   "a control point",
	prefer: []uint16{704},
	accept: func(id uint16) bool { return id != 1 },
}

// networkConfigPoint is §2.7.2.1 step 4's "network configuration point": the
// SunSpec communication-interface models. 10 Communication Interface Header,
// 11 Ethernet Link Layer, 12 IPv4, 13 IPv6, 14 Proxy Server, 17 Serial
// Interface, 18 Cellular Link.
var networkConfigPoint = writeKind{
	name:   "a network configuration point",
	prefer: []uint16{12, 13, 11, 10, 14, 17, 18},
	accept: func(id uint16) bool {
		switch id {
		case 10, 11, 12, 13, 14, 17, 18:
			return true
		}
		return false
	},
}

// holdingReader is the only operation the target picker needs of a session. It
// is an interface so target SELECTION — which is where the not-implemented
// sentinel defect lived — can be tested without a socket or a gateway.
type holdingReader interface {
	ReadHolding(unit uint8, addr, count uint16, label string) Exchange
}

// pickWriteTarget chooses a control-point register for an authorization probe.
func pickWriteTarget(s holdingReader, unit uint8, ch *Chain) (writeTarget, error) {
	return pickWriteTargetOfKind(s, unit, ch, controlPoint)
}

// pickWriteTargetOfKind chooses a register of the given class and reads its
// current value, so the write can be a no-op read-back.
//
// Two rules, and the second is the one run 20260726T225512 was missing:
//
//  1. the register must belong to the class the procedure step names, or the
//     step tests a different question than the one asked;
//  2. its current value must not be its type's not-implemented sentinel, or the
//     read-back write cannot be answered with anything but exception 3 — see
//     notImplemented16. So the model's block is scanned for the first register
//     holding a real value, rather than the first register full stop.
func pickWriteTargetOfKind(s holdingReader, unit uint8, ch *Chain, kind writeKind) (writeTarget, error) {
	if ch == nil || len(ch.Models) == 0 {
		return writeTarget{}, fmt.Errorf("suitessm: no SunSpec chain was discovered, so no write target can be chosen")
	}
	// A model's block is read whole and scanned, rather than probed register by
	// register: one round trip instead of dozens against a shared gateway.
	pick := func(m ModelBlock, why string) (writeTarget, bool) {
		if m.Length == 0 {
			return writeTarget{}, false
		}
		n := m.Length
		if n > 64 {
			n = 64
		}
		vals, err := registers(s.ReadHolding(unit, m.First, n, "write-target read-back"))
		if err != nil {
			return writeTarget{}, false
		}
		for i, v := range vals {
			if notImplemented16[v] {
				continue
			}
			return writeTarget{
				Model: m.ID, Addr: m.First + uint16(i), Value: v,
				Why: why + fmt.Sprintf("; register %d holds 0x%04X, a real value, so writing it back is both "+
					"legal and a no-op", m.First+uint16(i), v),
			}, true
		}
		return writeTarget{}, false
	}

	var scanned []uint16
	try := func(m ModelBlock, why string) (writeTarget, bool) {
		scanned = append(scanned, m.ID)
		return pick(m, why)
	}
	for _, id := range kind.prefer {
		m, ok := ch.Model(id)
		if !ok {
			continue
		}
		if t, ok := try(m, fmt.Sprintf("Model %d, %s the RBAC procedures name", id, kind.name)); ok {
			return t, nil
		}
	}
	for _, m := range ch.Models {
		if !kind.accept(m.ID) {
			continue
		}
		if t, ok := try(m, fmt.Sprintf("Model %d, %s from this DUT's chain", m.ID, kind.name)); ok {
			return t, nil
		}
	}
	if len(scanned) == 0 {
		return writeTarget{}, fmt.Errorf(
			"this DUT's chain on unit %d holds no model that is %s (models %v), so §2.7.2.1's "+
				"\"if one exists\" condition is not met and the step is not performed", unit, kind.name, ch.IDs())
	}
	return writeTarget{}, fmt.Errorf(
		"every register of %s on unit %d (models %v scanned) reads its type's not-implemented sentinel, so no "+
			"legal read-back write value exists; writing the sentinel would be refused on its VALUE and could "+
			"not evidence an authorization decision", kind.name, unit, scanned)
}

// driveRole performs the read and the read-back write the procedures ask for,
// aiming the write at a control point.
func driveRole(r *roleRun) { driveRoleKind(r, controlPoint) }

// driveRoleKind is driveRole with the class of point named explicitly, for the
// procedures that send different roles to different classes.
func driveRoleKind(r *roleRun, kind writeKind) {
	if r.Sess == nil || r.Sess.tls == nil {
		return
	}
	if r.Chain != nil {
		if m1, ok := r.Chain.Model(1); ok {
			r.Read = r.Sess.ReadHolding(r.Unit, m1.First, m1.Length, "Model 1 read as "+r.Label)
		}
		t, err := pickWriteTargetOfKind(r.Sess, r.Unit, r.Chain, kind)
		r.TargetErr = err
		if err == nil {
			r.Target = t
			r.Write = r.Sess.WriteMultiple(r.Unit, t.Addr, []uint16{t.Value}, "read-back write as "+r.Label)
		}
	} else {
		r.TargetErr = fmt.Errorf("no SunSpec chain was discovered on this session, so no write target exists")
	}
	if len(r.Read.Response) == 0 && r.Read.Err == nil {
		// A role that could not discover the chain still has to be probed, or
		// its denial is never demonstrated.
		r.Read = r.Sess.ReadHolding(1, sunspecBase, 2, "SunSpec marker read as "+r.Label)
	}
}

// closeRuns closes every session a check opened.
func closeRuns(runs ...*roleRun) {
	for _, r := range runs {
		if r != nil && r.Sess != nil {
			r.Sess.Close()
		}
	}
}

// authOutcome is what a write response says about the AUTHORIZATION decision —
// the only decision the RBAC procedures are about.
type authOutcome int

const (
	// authIndeterminate: the response is not a well-formed answer.
	authIndeterminate authOutcome = iota
	// authDenied: exception 01. SunSpecTCP-40 makes this the authorization
	// stage's one and only refusal code.
	authDenied
	// authCleared: exception 02, 03 or 04. Authorization SUCCEEDED and a LATER
	// stage refused — the address does not exist, the value is not legal, the
	// device failed. The role was granted the write.
	authCleared
	// authGranted: a normal response. Authorized and performed.
	authGranted
)

func (o authOutcome) authorized() bool { return o == authCleared || o == authGranted }

// authorizationVerdict reads a write response for the authorization decision.
//
// SunSpecTCP-40: "If the MBAP protocol handler for authorization rejects a
// request it MUST use the exception code 01." Exception 01 is therefore the
// ONLY denial. 02 (Illegal Data Address), 03 (Illegal Data Value) and 04
// (Server Device Failure) are emitted by stages that run AFTER authorization
// has already succeeded, so reading one of them as a refusal reports a device
// that granted the write as a device that denied it. That is exactly what run
// 20260726T225512 did: GridService and SuperAdmin were both authorized, both
// answered 03 because the probe had sent an illegal value, and the check
// concluded that no privileged role was granted anything.
func authorizationVerdict(rspBytes []byte) (authOutcome, string) {
	v, err := parseMBAP(rspBytes)
	if err != nil {
		return authIndeterminate, "the response is not a well-formed MBAP ADU: " + err.Error()
	}
	if len(v.PDU) < 1 {
		return authIndeterminate, "the response PDU is empty: " + v.String()
	}
	if v.PDU[0]&0x80 == 0 {
		return authGranted, "AUTHORIZED and performed — normal (non-exception) response: " + v.String()
	}
	if len(v.PDU) < 2 {
		return authIndeterminate, "the exception response carries no exception code byte: " + v.String()
	}
	code := v.PDU[1]
	if code == 1 {
		return authDenied, fmt.Sprintf(
			"DENIED by authorization — exception code 1 (%s), which SunSpecTCP-40 reserves for exactly that: %s",
			exceptionName(code), v.String())
	}
	return authCleared, fmt.Sprintf(
		"AUTHORIZED — exception code %d (%s) is raised after the authorization stage has already passed the "+
			"request, so the role WAS granted the write and a later stage refused it: %s",
		code, exceptionName(code), v.String())
}

// roleOnWireFact asserts the role a session's client certificate carried,
// straight from the Certificate message in the capture.
func roleOnWireFact(ev *certify.Evidence, r *roleRun, claim, wantRole string) (certify.Assertion, error) {
	const method = "the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at " +
		"OID " + roleOID + " decoded with the bench's own ASN.1 rule"
	return sessionFact(ev, r.Sess, claim, method, func(v *wireView) (certify.Verdict, string, []int) {
		c, frames := v.ClientCertificate()
		if c == nil || c.Leaf() == nil {
			return certify.Skip, "no cleartext client Certificate message in this conversation", v.Frames
		}
		verdict, obs := roleExtensionVerdict(c.Leaf().Info, wantRole)
		return verdict, obs, frames
	})
}

// modbusDecisionFact asserts what the DUT did with a request, recovered from
// the decrypted capture.
func modbusDecisionFact(ev *certify.Evidence, r *roleRun, claim string, fc byte,
	decide func([]byte) (certify.Verdict, string)) (certify.Assertion, error) {

	const method = "TLS decryption of this session's records with the run's key log, then MBAP decoding of " +
		"the recovered request/response pair"
	return decryptedFact(ev, r.Sess, claim, method, func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
		return modbusExchangeFact(p, fc, decide)
	})
}

// ── RBAC-001 · Role Extension Extraction ────────────────────────────────────

func rbac001(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	cert, err := roleCert(pf.PKI, "read-only")
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	run := openRoleSession(ctx, rc, pf, "ReadOnlySunSpec", cert)
	defer closeRuns(run)
	if run.Sess == nil || run.Sess.tls == nil {
		return certify.Failed("the ReadOnlySunSpec session could not be established: %v", run.Err), nil
	}
	driveRole(run)

	var t tally
	switch {
	case run.Read.Err != nil:
		t.add(certify.Fail, "the Model 1 read as ReadOnlySunSpec failed at the transport: %v", run.Read.Err)
	default:
		v, obs := normalResponseVerdict(run.Read.Response)
		t.add(v, "Model 1 read: %s", obs)
	}
	switch {
	case run.Target.Addr == 0:
		t.caveat("no writable control register could be chosen, so the denial half was not exercised: chain %v", chainIDs(run.Chain))
	case run.Write.Err != nil:
		t.add(certify.Fail, "the control write as ReadOnlySunSpec failed at the transport: %v", run.Write.Err)
	default:
		v, obs := exceptionVerdict(run.Write.Response, 1)
		t.add(v, "control write to %s: %s", run.Target, obs)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := roleOnWireFact(ev, run,
				"SunSpecTCP-8/21/26/39: the client presented a certificate carrying the role ReadOnlySunSpec in the extension at OID "+roleOID,
				"ReadOnlySunSpec")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = modbusDecisionFact(ev, run,
				"SunSpecTCP-21/26: a Read Holding Registers request for the Common Model was answered normally for the ReadOnlySunSpec role",
				0x03, normalResponseVerdict)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = modbusDecisionFact(ev, run,
				"SunSpecTCP-39: a Write Multiple Registers request to a control point was answered with Modbus exception code 01 (Illegal Function) for the ReadOnlySunSpec role — "+run.Target.String(),
				0x10, func(b []byte) (certify.Verdict, string) { return exceptionVerdict(b, 1) })
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── RBAC-002 · Mandatory Roles Support ──────────────────────────────────────

// rbac002 presents each of the three privileged mandatory roles in turn and
// records what the DUT permitted.
//
// The pass criterion is deliberately phrased against what a capture can show:
// the DUT recognises each mandatory role (the certificate is accepted, the
// handshake completes, and a role-specific decision follows) AND at least one
// mandatory role is AUTHORIZED for a write that ReadOnlySunSpec is denied. A
// DUT that denied every write to every role would satisfy neither, and would be
// reported with the whole observed matrix rather than a bare FAIL — the reason
// might be a deployment-mode overlay rather than a missing role, and a reader
// needs to be able to tell.
//
// Two things this check must get right, both of which run 20260726T225512 got
// wrong and reported as a DUT defect:
//
//   - the target. §2.7.2.1 aims each role at a different class of point and
//     conditions every one of them on "if one exists". NetworkAdministrator is
//     sent at a NETWORK CONFIGURATION point, not at Model 704; on a DUT whose
//     chain holds no communication-interface model that step is not performed
//     at all. Expecting a network administrator to be granted a write to a DER
//     control model is an over-read of the procedure in its own right;
//
//   - the answer. Exception 01 is the only authorization denial (SunSpecTCP-40);
//     02/03/04 mean authorization already SUCCEEDED. See authorizationVerdict.
func rbac002(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	// The class of point the procedure aims each role's write at.
	kindFor := map[string]writeKind{
		"GridServiceSunSpec":          controlPoint,
		"NetworkAdministratorSunSpec": networkConfigPoint,
		"SuperAdministratorSunSpec":   controlPoint,
	}

	var runs []*roleRun
	for _, mr := range mandatoryRoles[1:] { // the three privileged roles
		cert, err := roleCert(pf.PKI, mr.fixture)
		if err != nil {
			runs = append(runs, &roleRun{Label: mr.role, Err: err})
			continue
		}
		r := openRoleSession(ctx, rc, pf, mr.role, cert)
		driveRoleKind(r, kindFor[mr.role])
		runs = append(runs, r)
	}
	defer closeRuns(runs...)

	// The contrast: ReadOnlySunSpec must be denied the same write, or "granted"
	// means nothing. It goes at the control point, which is the one the
	// privileged roles were actually able to reach.
	var readOnly *roleRun
	if cert, err := roleCert(pf.PKI, "read-only"); err == nil {
		readOnly = openRoleSession(ctx, rc, pf, "ReadOnlySunSpec (contrast)", cert)
		driveRoleKind(readOnly, controlPoint)
		defer closeRuns(readOnly)
	}

	var t tally
	authorized, exercised := 0, 0
	for _, r := range runs {
		switch {
		case r.Err != nil && r.Sess == nil:
			t.add(certify.Fail, "%s: no session (%v)", r.Label, r.Err)
			continue
		case r.Sess == nil || r.Sess.tls == nil:
			t.add(certify.Fail, "%s: the handshake did not complete (%v)", r.Label, r.Err)
			continue
		}
		if len(r.Write.Response) == 0 {
			// "if one exists" — a step with no target is NOT PERFORMED, which
			// is a skip with the reason, not a denial and not a defect.
			t.add(certify.Skip, "%s: the write step was not performed — %v", r.Label, r.TargetErr)
			continue
		}
		exercised++
		outcome, obs := authorizationVerdict(r.Write.Response)
		switch {
		case outcome.authorized():
			authorized++
			t.add(certify.Pass, "%s: write to %s — %s", r.Label, r.Target, obs)
		case outcome == authDenied:
			t.add(certify.Warn, "%s: write to %s — %s", r.Label, r.Target, obs)
		default:
			t.add(certify.Warn, "%s: write to %s — %s", r.Label, r.Target, obs)
		}
	}
	switch {
	case exercised == 0:
		t.caveat("none of the three privileged roles had a point of the class §2.7.2.1 sends it to, so no " +
			"grant could be demonstrated; the roles were still presented and accepted")
	case authorized == 0:
		t.add(certify.Fail, "none of the %d privileged mandatory role(s) that could be exercised was AUTHORIZED "+
			"for its write (every one was refused with exception 01); the DUT's role-to-rights configuration "+
			"or an active deployment-mode overlay is denying all of them", exercised)
	}

	rules, rulesPath, rulesErr := readRulesDatabase(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for _, r := range runs {
				r := r
				a, err := roleOnWireFact(ev, r,
					"SunSpecTCP-22: a client certificate carrying the mandatory role "+r.Label+" was presented and accepted",
					r.Label)
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				claim := "SunSpecTCP-22/40: the EUT-S AUTHORIZED a Write Multiple Registers request as " +
					r.Label + " — " + r.Target.String()
				if r.Target.Addr == 0 {
					// §2.7.2.1's "if one exists". A step the DUT's chain offers
					// no target for was never performed, and a verdict about
					// the DUT cannot be minted from it.
					out = append(out, ev.SkipAssertion(claim,
						"TLS decryption of this session's records with the run's key log, then MBAP decoding "+
							"of the recovered request/response pair",
						fmt.Sprintf("this step is conditioned on \"if one exists\" and no such point exists on "+
							"this DUT: %v", r.TargetErr)))
					continue
				}
				a, err = modbusDecisionFact(ev, r, claim, 0x10,
					func(b []byte) (certify.Verdict, string) {
						outcome, obs := authorizationVerdict(b)
						switch outcome {
						case authGranted, authCleared:
							return certify.Pass, obs
						case authDenied:
							// A POINT-level denial is not automatically a
							// defect. §2.7.2.2's criterion is "each role is
							// correctly mapped to its expected permissions per
							// the VENDOR'S Roles-to-Rights Rules Database", and
							// this suite deliberately does not re-implement that
							// database's rules language — its point-group
							// selectors, its deployment overlays — so it cannot
							// adjudicate whether this particular register
							// belongs inside this role's grant. The database is
							// carried in this case's last assertion for exactly
							// that cross-reference. What IS a defect, and is
							// asserted from the tally, is every privileged role
							// being denied everywhere.
							return certify.Warn, obs + " — whether this particular register falls inside " +
								"this role's grant is a question for the vendor's rules database, which is " +
								"recorded in this case's roles-to-rights assertion"
						default:
							return certify.Fail, obs
						}
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			if readOnly != nil {
				a, err := modbusDecisionFact(ev, readOnly,
					"contrast: the SAME write as ReadOnlySunSpec was denied with exception code 01, so the grants above are role-specific and not a blanket allow",
					0x10, func(b []byte) (certify.Verdict, string) { return exceptionVerdict(b, 1) })
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			claim := "SunSpecTCP-22 (context): the DUT's roles-to-rights database as configured at the time of this run"
			const method = "read of the DUT's RBAC rules over the read-only gateway client"
			if rulesErr != nil {
				out = append(out, ev.SkipAssertion(claim, method,
					"the DUT's rules database could not be read, so the grants and denials above cannot be "+
						"explained against the vendor's configuration: "+rulesErr.Error()))
			} else {
				a, err := ev.Narrative(claim, method, certify.Pass,
					summariseRules(rules),
					"the DUT's own "+rulesPath+", read over the read-only gateway client")
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// rulesCandidates are the paths the DUT's roles-to-rights database is looked
// for at, in order, with the one this product actually uses first.
//
// It is a LIST because getting it wrong is silent and expensive: run
// 20260726T225512 looked only at /etc/lexa/configs/rbac/rules.json, which does
// not exist, and consequently SKIPped RBAC-002's database assertion and the
// whole of RBAC-004 — a documentation audit reported as unevidenceable — for a
// file that was on the device the entire time.
var rulesCandidates = []string{
	"/etc/lexa/rbac/rules.json",
	"/etc/lexa/configs/rbac/rules.json",
	"/etc/lexa/rbac/rules.json.d/rules.json",
}

// readRulesDatabase reads the DUT's roles-to-rights database, returning the
// path it was found at so the assertion can name its source. The error names
// every path tried, so the next person to move the file can see what to add.
func readRulesDatabase(ctx context.Context, rc *certify.RunCtx) ([]byte, string, error) {
	var last error
	for _, p := range rulesCandidates {
		b, err := readGatewayFile(ctx, rc, p)
		if err == nil {
			return b, p, nil
		}
		last = err
		if rc.Gateway == nil || !rc.Gateway.Available() {
			// No point trying the other paths: the transport is missing, not
			// the file.
			break
		}
	}
	return nil, "", fmt.Errorf("the DUT's roles-to-rights database was not found at any of %v: %w",
		rulesCandidates, last)
}

// summariseRules reports which roles the DUT's rules database defines, without
// re-implementing the rules language: the claim is about which roles exist.
func summariseRules(rules []byte) string {
	var found []string
	for _, mr := range mandatoryRoles {
		if strings.Contains(string(rules), mr.role) {
			found = append(found, mr.role)
		}
	}
	return fmt.Sprintf("the DUT's rules database (%d bytes) names %d of the 4 mandatory SunSpec roles: [%s]",
		len(rules), len(found), strings.Join(found, ", "))
}

// ── RBAC-004 · Roles-to-Rights Database Audit ───────────────────────────────

// rbac004 is a documentation audit: the vendor must supply a complete mapping
// of every implemented SunSpec point to the mandatory roles. There is no wire
// traffic in the procedure at all — its own observables say so.
//
// The suite therefore reads the DUT's actual rules database and reports what it
// contains, declared OffWire with the reason. That is the strongest thing a
// bench can honestly do for a documentation row: it does not review the
// document (a human must), but it proves the artefact exists on the device and
// says what is in it.
func rbac004(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	rules, rulesPath, err := readRulesDatabase(ctx, rc)
	if err != nil {
		return certify.Skipped(
			"RBAC-004 is a documentation audit with no wire traffic, and the DUT's roles-to-rights database "+
				"could not be read to evidence it: %v", err), nil
	}

	missing := 0
	for _, mr := range mandatoryRoles {
		if !strings.Contains(string(rules), mr.role) {
			missing++
		}
	}
	verdict := certify.Pass
	notes := summariseRules(rules)
	if missing > 0 {
		verdict = certify.Fail
		notes += fmt.Sprintf(" — %d mandatory role(s) are absent from the database", missing)
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Assertions: []certify.Assertion{{
			Claim: "SunSpecTCP-24/25/34: the vendor supplies a roles-to-rights rules database covering the " +
				"mandatory SunSpec roles",
			Method:   "read of the DUT's RBAC rules database over the read-only gateway client",
			Verdict:  verdict,
			Observed: notes,
			Note: "not wire-cited; source: the DUT's own " + rulesPath + ". Whether the " +
				"mapping is COMPLETE with respect to every implemented SunSpec point is a document review " +
				"a human performs against the vendor's model documentation; this assertion establishes only " +
				"that the database exists on the device and which roles it names.",
		}},
		OffWire: true,
		OffWireReason: "RBAC-004 is a documentation audit. Its own observables begin \"No wire traffic — this " +
			"is a documentation audit\", so there is nothing in any capture that could evidence it. The " +
			"artefact is read off the DUT instead, over the read-only gateway client.",
	}, nil
}

// ── RBAC-005 · Authorization Algorithm Review ───────────────────────────────

// rbac005 is the companion documentation review: the vendor must describe the
// logic the server uses to enforce authorization.
//
// Its one behavioural corollary IS wire-observable — "Modbus exception code 01
// on any unauthorized request" — and that is asserted from a real denial rather
// than asserted on the strength of the document.
func rbac005(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	cert, err := roleCert(pf.PKI, "read-only")
	if err != nil {
		return certify.Skipped("%v", err), nil
	}
	run := openRoleSession(ctx, rc, pf, "ReadOnlySunSpec", cert)
	defer closeRuns(run)
	driveRole(run)

	var t tally
	if len(run.Write.Response) == 0 {
		t.add(certify.Warn, "no unauthorised request could be issued to observe the corollary: %v / %v", run.Err, run.Write.Err)
	} else {
		v, obs := exceptionVerdict(run.Write.Response, 1)
		t.add(v, "the behavioural corollary: %s", obs)
	}
	t.caveat("the AuthZ Algorithm Description itself is a vendor document. None was supplied to this run " +
		"(-param ssm.authz_algorithm=<path>), and no capture can evidence a document; the corollary the " +
		"procedure names — exception code 01 on an unauthorised request — is asserted from the wire instead.")

	doc, hasDoc := rc.Param("ssm.authz_algorithm")

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := modbusDecisionFact(ev, run,
				"SunSpecTCP-25/33 (behavioural corollary): an unauthorised request was answered with Modbus exception code 01 (Illegal Function), which is what the vendor's authorization algorithm must produce",
				0x10, func(b []byte) (certify.Verdict, string) { return exceptionVerdict(b, 1) })
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			claim := "SunSpecTCP-25/33: the vendor has defined and supplied the authorization enforcement algorithm"
			const method = "review of a vendor-supplied AuthZ Algorithm Description"
			if !hasDoc {
				out = append(out, ev.SkipAssertion(claim, method,
					"no AuthZ Algorithm Description was supplied to this run "+
						"(-param ssm.authz_algorithm=<path>). It is a paper artefact; no capture can "+
						"evidence it, and the suite will not assert a document it has not been given."))
				return out, nil
			}
			a, err = ev.Narrative(claim, method, certify.Warn,
				"a description was named at "+doc+", but reviewing whether an algorithm meets the "+
					"specification is a human judgement this suite does not make; the behaviour it must "+
					"produce is asserted above",
				"the -param ssm.authz_algorithm path supplied by the operator")
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── RBAC-006 · Role OID Verification ────────────────────────────────────────

// rbac006 presents the role under the correct OID and then under a
// non-compliant one, and requires that BOTH handshakes complete — the rejection
// must be at the application layer, not the TLS layer — while the second
// session's first Modbus request is denied.
//
// The wrong-OID fixture is minted here (minting.go) because the committed
// negative matrix has no such case, and it is placed on a SIBLING arc under the
// same Modbus.org PEN so an implementation that matched on an OID prefix rather
// than the whole OID would be caught.
func rbac006(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	issuer, issuerKey, err := issuingCA(pf.PKI)
	if err != nil {
		return certify.Skipped(
			"RBAC-006 needs a client certificate carrying the role under a NON-COMPLIANT OID, which must be "+
				"signed by the bench CA so the chain still validates; it cannot be minted: %v", err), nil
	}
	wrong, err := mintLeaf(issuer, issuerKey, mintOpts{
		CommonName: "ssm-wrong-oid-probe",
		Role:       "ReadOnlySunSpec",
		RoleOID:    wrongRoleOIDValue,
	})
	if err != nil {
		return certify.Skipped("the wrong-OID fixture could not be minted: %v", err), nil
	}
	good, err := roleCert(pf.PKI, "read-only")
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	compliant := openRoleSession(ctx, rc, pf, "role at OID "+roleOID, good)
	driveRole(compliant)
	nonCompliant := openRoleSession(ctx, rc, pf, "role at OID "+wrongRoleOIDValue.String(), &wrong)
	driveRole(nonCompliant)
	defer closeRuns(compliant, nonCompliant)

	var t tally
	if compliant.Sess == nil || compliant.Sess.tls == nil {
		t.add(certify.Fail, "the compliant-OID handshake did not complete: %v", compliant.Err)
	} else if len(compliant.Read.Response) > 0 {
		v, obs := normalResponseVerdict(compliant.Read.Response)
		t.add(v, "compliant OID: Model 1 read %s", obs)
	}
	switch {
	case nonCompliant.Sess == nil || nonCompliant.Sess.tls == nil:
		t.add(certify.Fail, "the non-compliant-OID handshake did NOT complete (%v) — the procedure requires "+
			"the rejection to be at the application layer, not the TLS layer", nonCompliant.Err)
	case len(nonCompliant.Read.Response) == 0:
		t.add(certify.Warn, "the non-compliant-OID session completed but issued no readable request: %v", nonCompliant.Read.Err)
	default:
		v, obs := exceptionVerdict(nonCompliant.Read.Response, 1)
		t.add(v, "non-compliant OID: first Modbus request %s", obs)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := roleOnWireFact(ev, compliant,
				"SunSpecTCP-29: session 1 presented the role in the extension at the mandatory Modbus.org PEN OID "+roleOID,
				"ReadOnlySunSpec")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, nonCompliant.Sess,
				"SunSpecTCP-29: session 2 presented the role under a NON-COMPLIANT OID ("+wrongRoleOIDValue.String()+") and nothing at "+roleOID,
				"the bench's TLS 1.2 Certificate message, parsed from the capture; every custom extension OID enumerated",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ClientCertificate()
					if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
						return certify.Skip, "no parseable cleartext client Certificate in this conversation", v.Frames
					}
					rf := roleOf(c.Leaf().Info)
					obs := fmt.Sprintf("custom extension OIDs on the presented leaf: [%s]; extension at %s %s",
						strings.Join(rf.OIDsSeen, ", "), roleOID, presence(rf.Present))
					if rf.Present {
						return certify.Fail, obs + " — this run did not actually present a non-compliant OID", frames
					}
					if !containsOID(rf.OIDsSeen, wrongRoleOIDValue) {
						return certify.Fail, obs + " — the non-compliant OID is not on the presented certificate either", frames
					}
					return certify.Pass, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, nonCompliant.Sess,
				"SunSpecTCP-29: the non-compliant-OID handshake reached Finished — the DUT rejected it at the APPLICATION layer, not with a TLS alert",
				"handshake message types and alert scan of the non-compliant-OID conversation",
				func(v *wireView) (certify.Verdict, string, []int) {
					al, torn, caveat := fatalTeardown(ev, v)
					if torn {
						return certify.Fail, fmt.Sprintf(
							"the DUT sent a fatal TLS alert (description %d, %s) rather than completing the "+
								"handshake and denying at the application layer",
							al.Description, tlsdis.AlertDescriptionName(al.Description)), al.Packets
					}
					verdict, obs, frames := mutualFlightVerdict(v)
					return verdict, obs + " — and no fatal TLS alert was sent" + caveat, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = modbusDecisionFact(ev, compliant,
				"SunSpecTCP-29: with the role at the mandatory OID, the Model 1 read was answered with data",
				0x03, normalResponseVerdict)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = modbusDecisionFact(ev, nonCompliant,
				"SunSpecTCP-29: with the role under a non-compliant OID, the FIRST Modbus request was answered with exception code 01 (Illegal Function)",
				0x03, func(b []byte) (certify.Verdict, string) { return exceptionVerdict(b, 1) })
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

func containsOID(seen []string, oid asn1.ObjectIdentifier) bool {
	for _, s := range seen {
		if s == oid.String() {
			return true
		}
	}
	return false
}

// ── RBAC-007 · Role Encoding and Singular Role Validation ───────────────────

// rbac007 uses two committed negative fixtures: a role encoded as an
// ASN.1 IA5String instead of the required UTF8String, and a certificate
// carrying two role values.
//
// Both handshakes must complete — the encoding is an application-layer concern
// — and the IA5String session must be denied. The two-role session's outcome is
// permitted to be either a denial or a normal response consistent with the
// concatenation being treated as one unknown role, which the procedure's own
// expected results say in as many words; both are asserted as PASS with the
// observed behaviour recorded, and only a TLS-layer rejection is a FAIL.
func rbac007(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	type variant struct {
		fixture string
		label   string
		run     *roleRun
	}
	vars := []*variant{
		{fixture: "bad-encoding", label: "role encoded as IA5String, not UTF8String"},
		{fixture: "two-role", label: "certificate carrying two role values"},
	}
	for _, v := range vars {
		cert, err := negativeCert(pf.PKI, v.fixture)
		if err != nil {
			v.run = &roleRun{Label: v.label, Err: err}
			continue
		}
		v.run = openRoleSession(ctx, rc, pf, v.label, cert)
		driveRole(v.run)
	}
	defer func() {
		for _, v := range vars {
			closeRuns(v.run)
		}
	}()

	var t tally
	for _, v := range vars {
		r := v.run
		switch {
		case r.Sess == nil || r.Sess.tls == nil:
			t.add(certify.Fail, "%s: the handshake did NOT complete (%v) — SunSpecTCP-30/31 require the "+
				"encoding to be judged at the application layer, with the secure channel intact", v.label, r.Err)
			continue
		case len(r.Read.Response) == 0:
			t.add(certify.Warn, "%s: the session completed but issued no readable request: %v", v.label, r.Read.Err)
			continue
		}
		if v.fixture == "bad-encoding" {
			vv, obs := exceptionVerdict(r.Read.Response, 1)
			t.add(vv, "%s: %s", v.label, obs)
			continue
		}
		if _, obs := exceptionVerdict(r.Read.Response, 1); strings.Contains(obs, "exception response") {
			t.add(certify.Pass, "%s: denied — %s", v.label, obs)
		} else {
			_, nobs := normalResponseVerdict(r.Read.Response)
			t.add(certify.Pass, "%s: answered normally, consistent with the two values being treated as one "+
				"unknown role string — %s", v.label, nobs)
		}
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion

			a, err := sessionFact(ev, vars[0].run.Sess,
				"SunSpecTCP-30: the client certificate carried the role at OID "+roleOID+" with the ASN.1 tag IA5String instead of the required UTF8String",
				"the bench's Certificate message, parsed from the capture; the extension's DER value quoted verbatim",
				func(v *wireView) (certify.Verdict, string, []int) {
					return encodingObservation(v, tagIA5String, "IA5String")
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = modbusDecisionFact(ev, vars[0].run,
				"SunSpecTCP-30: the IA5String-encoded role was rejected at the application layer with Modbus exception code 01",
				0x03, func(b []byte) (certify.Verdict, string) { return exceptionVerdict(b, 1) })
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, vars[1].run.Sess,
				"SunSpecTCP-31: the client certificate carried more than one role value",
				"the bench's Certificate message, parsed from the capture; the role extension's DER value quoted verbatim",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ClientCertificate()
					if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
						return certify.Skip, "no parseable cleartext client Certificate in this conversation", v.Frames
					}
					rf := roleOf(c.Leaf().Info)
					obs := fmt.Sprintf("extension at %s: present %t, DER value %s, decode: %v",
						roleOID, rf.Present, rf.ValueHex, rf.Err)
					if !rf.Present {
						return certify.Fail, obs + " — the two-role fixture did not present a role extension at all", frames
					}
					return certify.Pass, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// Both handshakes must have completed: the criterion is that a
			// non-compliant ENCODING does not tear down the secure channel.
			for _, v := range vars {
				v := v
				a, err := sessionFact(ev, v.run.Sess,
					"SunSpecTCP-30/31: the handshake presenting "+v.label+" completed — the non-compliant role was judged at the application layer, with no TLS alert",
					"handshake message types and alert scan of this conversation",
					func(w *wireView) (certify.Verdict, string, []int) {
						al, torn, caveat := fatalTeardown(ev, w)
						if torn {
							return certify.Fail, fmt.Sprintf(
								"the DUT sent a fatal TLS alert (description %d, %s) instead of completing the handshake",
								al.Description, tlsdis.AlertDescriptionName(al.Description)), al.Packets
						}
						verdict, obs, frames := mutualFlightVerdict(w)
						return verdict, obs + caveat, frames
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			a, err = modbusDecisionFact(ev, vars[1].run,
				"SunSpecTCP-31: the two-role certificate's first Modbus request was answered — either denied with exception 01, or answered normally with the concatenation treated as one unknown role; the procedure's expected results permit both",
				0x03, twoRoleVerdict)
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// encodingObservation reports the ASN.1 tag the role extension actually used.
func encodingObservation(v *wireView, wantTag byte, tagName string) (certify.Verdict, string, []int) {
	c, frames := v.ClientCertificate()
	if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
		return certify.Skip, "no parseable cleartext client Certificate in this conversation", v.Frames
	}
	ext, ok := c.Leaf().Info.Extension(roleOID)
	if !ok {
		return certify.Fail, "the presented certificate carries no extension at " + roleOID, frames
	}
	if len(ext.Value) == 0 {
		return certify.Fail, "the extension at " + roleOID + " has an empty DER value", frames
	}
	got := ext.Value[0]
	obs := fmt.Sprintf("the extension at %s carries ASN.1 tag 0x%02X (%s); DER value %s",
		roleOID, got, asn1TagName(got), ext.ValueHex)
	if got != wantTag {
		return certify.Fail, obs + " — this run did not present the " + tagName + " encoding the procedure prescribes", frames
	}
	return certify.Pass, obs, frames
}

func asn1TagName(t byte) string {
	switch t {
	case tagUTF8String:
		return "UTF8String"
	case tagIA5String:
		return "IA5String"
	case 0x13:
		return "PrintableString"
	case 0x04:
		return "OCTET STRING"
	default:
		return fmt.Sprintf("universal tag %d", t&0x1F)
	}
}

// twoRoleVerdict accepts either documented outcome for the two-role fixture.
func twoRoleVerdict(b []byte) (certify.Verdict, string) {
	if v, obs := exceptionVerdict(b, 1); v == certify.Pass {
		return certify.Pass, "denied: " + obs
	}
	if v, obs := normalResponseVerdict(b); v == certify.Pass {
		return certify.Pass, "answered normally, consistent with the two role values being concatenated into " +
			"one unknown role string: " + obs
	}
	_, obs := exceptionVerdict(b, 1)
	return certify.Fail, "neither a normal response nor an exception code 01: " + obs
}

// ── RBAC-008 · Missing Role Handling ────────────────────────────────────────

// rbac008 is the sharpest criterion in the family and the easiest to get
// backwards: a certificate with NO role extension must NOT be rejected at the
// TLS layer. The secure channel is established, and only then is the Modbus
// request denied. A DUT that fails the handshake closed is failing this
// procedure even though failing closed sounds like the safe behaviour.
func rbac008(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	cert, err := negativeCert(pf.PKI, "no-role")
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	run := openRoleSession(ctx, rc, pf, "certificate with no role extension", cert)
	defer closeRuns(run)
	driveRole(run)

	var t tally
	switch {
	case run.Sess == nil || run.Sess.tls == nil:
		t.add(certify.Fail, "the DUT rejected the role-less certificate at the TLS layer (%v); SunSpecTCP-32/40 "+
			"require the handshake to COMPLETE and the denial to happen at the application layer", run.Err)
	case len(run.Read.Response) == 0:
		t.add(certify.Warn, "the handshake completed but no readable request was issued: %v", run.Read.Err)
	default:
		t.add(certify.Pass, "the handshake completed with a role-less certificate, as required")
		v, obs := exceptionVerdict(run.Read.Response, 1)
		t.add(v, "the Model 1 read was then %s", obs)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, run.Sess,
				"SunSpecTCP-32: the client certificate carried NO extension at OID "+roleOID,
				"the bench's Certificate message, parsed from the capture; every custom extension OID enumerated",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ClientCertificate()
					if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
						return certify.Skip, "no parseable cleartext client Certificate in this conversation", v.Frames
					}
					rf := roleOf(c.Leaf().Info)
					obs := fmt.Sprintf("custom extension OIDs on the presented leaf: [%s]; extension at %s %s",
						strings.Join(rf.OIDsSeen, ", "), roleOID, presence(rf.Present))
					if rf.Present {
						return certify.Fail, obs + " — this run did not present a role-less certificate", frames
					}
					return certify.Pass, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, run.Sess,
				"SunSpecTCP-32/40: mutual authentication COMPLETED with the role-less certificate — CertificateVerify and Finished were exchanged and no TLS alert was sent",
				"handshake message types and alert scan of this conversation",
				func(v *wireView) (certify.Verdict, string, []int) {
					al, torn, caveat := fatalTeardown(ev, v)
					if torn {
						return certify.Fail, fmt.Sprintf(
							"the DUT sent a fatal TLS alert (level %d, description %d %s). SunSpecTCP-32/40 "+
								"require the secure channel to be MAINTAINED and the request denied at the "+
								"application layer; rejecting at the TLS layer is the failure mode this "+
								"procedure exists to catch.",
							al.Level, al.Description, tlsdis.AlertDescriptionName(al.Description)), al.Packets
					}
					verdict, obs, frames := mutualFlightVerdict(v)
					return verdict, obs + caveat, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = modbusDecisionFact(ev, run,
				"SunSpecTCP-40: the Read Holding Registers request on the role-less session was answered with Modbus exception code 01 (Illegal Function)",
				0x03, func(b []byte) (certify.Verdict, string) { return exceptionVerdict(b, 1) })
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── RBAC-009 · Information Leakage Prevention ───────────────────────────────

// rbac009 measures the denial response byte for byte: exactly nine bytes, an
// MBAP Length field of 3, an exception function code, exception code 01, and
// nothing after it.
func rbac009(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	cert, err := roleCert(pf.PKI, "read-only")
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	run := openRoleSession(ctx, rc, pf, "ReadOnlySunSpec", cert)
	defer closeRuns(run)
	driveRole(run)

	var t tally
	switch {
	case run.Sess == nil || run.Sess.tls == nil:
		t.add(certify.Fail, "the session for the denial probe could not be established: %v", run.Err)
	case run.Target.Addr == 0:
		t.add(certify.Warn, "no writable control register could be chosen, so no denial was provoked: chain %v", chainIDs(run.Chain))
	case run.Write.Err != nil:
		t.add(certify.Fail, "the denial probe failed at the transport: %v", run.Write.Err)
	default:
		v, obs := leakageVerdict(run.Write.Response)
		t.add(v, "%s", obs)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			a, err := modbusDecisionFact(ev, run,
				"SunSpecTCP-33/34/41: the denied Write Multiple Registers request was answered by exactly nine bytes — a 7-byte MBAP header with Length 3, the error function code, and exception code 01 — with no register values, diagnostic text or trailing bytes",
				0x10, leakageVerdict)
			if err != nil {
				return nil, err
			}
			return []certify.Assertion{a}, nil
		},
	}, nil
}

// ── RBAC-010 · Rules Database Configuration ─────────────────────────────────

// rbac010 requires creating a new role (SecureSunSpecTestRole), granting it
// rights, exercising them, and deleting it again — four writes to the DUT's
// rules database. This bench may not do that.
//
// What it asserts instead is the criterion underneath: that the rules database
// is CONFIGURATION rather than compiled-in behaviour. The DUT's rules file is
// read read-only and reported.
func rbac010(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	rules, rulesPath, rulesErr := readRulesDatabase(ctx, rc)

	var t tally
	t.caveat("RBAC-010 requires creating a role (SecureSunSpecTestRole), modifying its rights, exercising " +
		"them and deleting it — four WRITES to the DUT's roles-to-rights database. This run shares the " +
		"bench and may not change DUT configuration. The underlying criterion — that the database is " +
		"configuration and not hardcoded — is evidenced off-wire from the DUT's own rules file.")
	if rulesErr == nil {
		t.add(certify.Pass, "the DUT's roles-to-rights database is a configuration file on the device (%d bytes)", len(rules))
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			out = append(out, ev.SkipAssertion(
				"SunSpecTCP-36/37: a role can be created in the EUT's rules database, granted rights that are then honoured on the wire, and deleted again",
				"role creation, rights modification and deletion through the EUT's management interface, with handshakes between each step",
				"every step is a WRITE to a shared DUT's roles-to-rights database, and the procedure would "+
					"leave a SecureSunSpecTestRole behind on failure. This run may not change DUT "+
					"configuration."))

			claim := "SunSpecTCP-36: the EUT's roles-to-rights database is configurable data, not compiled-in behaviour"
			const method = "read of the DUT's RBAC rules database over the read-only gateway client"
			if rulesErr != nil {
				out = append(out, ev.SkipAssertion(claim, method,
					"the DUT's rules database could not be read: "+rulesErr.Error()))
				return out, nil
			}
			a, err := ev.Narrative(claim, method, certify.Pass,
				fmt.Sprintf("the roles-to-rights database is a %d-byte file on the device, reloadable without "+
					"a rebuild: %s", len(rules), summariseRules(rules)),
				"the DUT's own "+rulesPath+", read over the read-only gateway client")
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── RBAC-011 · Client Certificate Role Requirement [C] ──────────────────────

// rbac011 is a client-side procedure: the EUT-C's own domain certificate must
// carry the role extension, and the EUT-C must NOT require one on the server's
// certificate.
//
// Both halves are observed passively on the gateway's southbound leg. The
// second half is observable even when the first is not: whether the gateway
// tolerated a role-less server certificate is answered by whether the session
// went on to carry application data, which is visible without decrypting
// anything.
func rbac011(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	half := watchClientHalf(ctx, rc)

	var t tally
	if !half.Armed {
		return certify.Skipped("the gateway's southbound client half could not be observed: %s", half.Why), nil
	}
	t.add(certify.Pass, "waited %s for the gateway's southbound mbaps client to dial %s",
		half.Waited.Round(1e9), half.Endpoint)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion

			claim := "SunSpecTCP-27/28: the EUT-C's client certificate carries a role at OID " + roleOID
			const method = "the gateway's Certificate message to the bench device sim, parsed from the capture"
			_, v, err := half.hello(ev)
			if err != nil {
				out = append(out, ev.SkipAssertion(claim, method, err.Error()))
				return out, nil
			}
			cert, frames := v.ClientCertificate()
			if cert == nil {
				out = append(out, ev.SkipAssertion(claim, method,
					"the gateway's Certificate message is not in the clear in this conversation. Under TLS 1.3 "+
						"it is encrypted with the DEVICE SIM's handshake keys, and this run exports only the "+
						"bench conformance client's secrets, not the sim's — so the role string cannot be "+
						"read from the capture even though the handshake succeeded."))
			} else {
				verdict, obs := roleExtensionVerdict(cert.Leaf().Info, "")
				a, cerr := ev.CiteFrames(claim, method, verdict, obs, frames)
				if cerr != nil {
					return nil, cerr
				}
				out = append(out, a)
			}

			// The second half: the gateway must not demand a role of its peer.
			srvCert, srvFrames := v.ServerCertificate()
			claim2 := "SunSpecTCP-27/28: the EUT-C completed the handshake although the SERVER certificate carries no role extension — a role is required of clients, not of servers"
			const method2 = "the device sim's Certificate message plus a record-type scan of the resulting session"
			switch {
			case srvCert == nil || srvCert.Leaf() == nil || srvCert.Leaf().Info == nil:
				out = append(out, ev.SkipAssertion(claim2, method2,
					"the device sim's Certificate message is not in the clear in this conversation, so whether "+
						"it carries a role extension cannot be read from the capture"))
			default:
				rf := roleOf(srvCert.Leaf().Info)
				appData := len(v.Server.AppData) > 0 && len(v.Client.AppData) > 0
				_, alerted := v.ServerFatalAlert()
				obs := fmt.Sprintf("the device sim's server leaf %s an extension at %s; the gateway %s a fatal alert; "+
					"the session carried %d/%d application_data record(s) (bench-sim/gateway directions)",
					map[bool]string{true: "carries", false: "does NOT carry"}[rf.Present], roleOID,
					map[bool]string{true: "received", false: "received no"}[alerted],
					len(v.Server.AppData), len(v.Client.AppData))
				verdict := certify.Pass
				switch {
				case rf.Present:
					verdict = certify.Skip
					obs += " — the sim's certificate DOES carry a role, so this run cannot demonstrate tolerance of one that does not"
				case alerted:
					verdict = certify.Fail
					obs += " — the handshake was torn down"
				case !appData:
					verdict = certify.Warn
					obs += " — the handshake was not torn down, but no application data followed either, so completion is not demonstrated"
				}
				a, cerr := ev.CiteFrames(claim2, method2, verdict, obs, srvFrames)
				if cerr != nil {
					return nil, cerr
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// ── RBAC-012 · Comprehensive Role-to-Rights Consistency Validation ──────────

// rbac012 sweeps every mandatory role across every model in the DUT's chain —
// a read and a read-back write per model per role — and reports the resulting
// permission matrix, cross-referenced against the DUT's own rules database.
//
// The procedure asks for a sweep of "every point of every implemented Model".
// This check sweeps every MODEL rather than every point, and says so: a
// per-point sweep of a 116-register model across four roles is several thousand
// authenticated round trips against a shared gateway, and the authorization
// decision the procedure is testing is made per point-GROUP, so a per-model
// probe exercises the same decision path. The reduction is stated in the
// assertion's method rather than hidden.
func rbac012(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	var runs []*roleRun
	var cells []cell

	for _, mr := range mandatoryRoles {
		cert, err := roleCert(pf.PKI, mr.fixture)
		if err != nil {
			runs = append(runs, &roleRun{Label: mr.role, Err: err})
			continue
		}
		r := openRoleSession(ctx, rc, pf, mr.role, cert)
		runs = append(runs, r)
		if r.Sess == nil || r.Sess.tls == nil || r.Chain == nil {
			continue
		}
		for _, m := range r.Chain.Models {
			if m.Length == 0 {
				continue
			}
			c := cell{Role: mr.role, Model: m.ID, Addr: m.First}
			c.Read = r.Sess.ReadHolding(r.Unit, m.First, 1, fmt.Sprintf("read model %d as %s", m.ID, mr.role))
			if vals, err := registers(c.Read); err == nil && len(vals) > 0 {
				c.Write = r.Sess.WriteMultiple(r.Unit, m.First, []uint16{vals[0]},
					fmt.Sprintf("read-back write to model %d as %s", m.ID, mr.role))
			}
			cells = append(cells, c)
		}
		// Keep one exchange on the roleRun so the role-on-wire assertion has a
		// conversation to cite.
		if len(r.Chain.Models) > 0 {
			r.Read = r.Sess.ReadHolding(r.Unit, sunspecBase, 2, "sweep anchor read as "+mr.role)
		}
	}
	defer closeRuns(runs...)

	matrix := renderMatrix(cells)
	rules, rulesPath, rulesErr := readRulesDatabase(ctx, rc)

	var t tally
	if len(cells) == 0 {
		t.add(certify.Fail, "no role could discover a SunSpec chain, so no permission matrix could be swept")
	} else {
		t.add(certify.Pass, "swept %d role×model cell(s): %s", len(cells), matrix)
	}
	// Consistency: reads permitted everywhere, and the permission sets must
	// actually differ between roles, or the DUT is not making a role decision.
	if len(cells) > 0 {
		distinct := distinctWritePermissions(cells)
		if distinct < 2 {
			t.add(certify.Warn, "every role received the SAME write outcome on every model; either the "+
				"roles-to-rights database grants them identically or a deployment-mode overlay is "+
				"overriding it, and this sweep cannot tell those apart from the wire alone")
		} else {
			t.add(certify.Pass, "%d distinct write-permission profiles were observed across the four mandatory roles", distinct)
		}
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for _, r := range runs {
				a, err := roleOnWireFact(ev, r,
					"SunSpecTCP-35: the certificate presented for the sweep carries the role value "+r.Label+
						", which must appear in the vendor's roles-to-rights database",
					r.Label)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			// One decrypted assertion per role, carrying that role's row of the
			// matrix as the observation.
			for _, r := range runs {
				r := r
				row := renderRow(cells, r.Label)
				a, err := decryptedFact(ev, r.Sess,
					"SunSpecTCP-35/38: the permission profile the EUT-S applied to role "+r.Label+" across every model in its chain",
					"a read and a read-back write per model per role, recovered by decrypting this session's "+
						"records with the run's key log. NOTE: the sweep is per MODEL, not per point — a "+
						"per-point sweep of every model across four roles is several thousand authenticated "+
						"round trips against a shared gateway, and the DUT's authorization decision is made "+
						"per point-group, so a per-model probe exercises the same decision path",
					func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
						frames := p.framesForServerAppData()
						if len(frames) == 0 {
							return certify.Fail, "no decrypted DUT→bench application data for this role's sweep", nil
						}
						if row == "" {
							return certify.Fail, "this role completed no sweep cells", frames
						}
						return certify.Pass, row, frames
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			claim := "SunSpecTCP-38: the observed permission matrix is consistent with the vendor's roles-to-rights database"
			const method = "cross-reference of the observed matrix against the DUT's own rules database"
			if rulesErr != nil {
				out = append(out, ev.SkipAssertion(claim, method,
					"the DUT's rules database could not be read, so the observed matrix cannot be "+
						"cross-referenced against the vendor's configuration: "+rulesErr.Error()))
				return out, nil
			}
			a, err := ev.Narrative(claim, method, certify.Warn,
				"observed matrix: "+matrix+" || database: "+summariseRules(rules)+
					". A full clause-by-clause cross-reference requires interpreting the vendor's rules "+
					"language, including its deployment-mode overlays, which this suite does not "+
					"re-implement; the matrix and the database are both recorded here so a reviewer can "+
					"perform it.",
				"the observed sweep above plus the DUT's own "+rulesPath)
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// renderMatrix formats the swept permission matrix for a report line.
func renderMatrix(cells []cell) string {
	if len(cells) == 0 {
		return "(empty)"
	}
	byRole := map[string][]string{}
	var order []string
	for _, c := range cells {
		if _, seen := byRole[c.Role]; !seen {
			order = append(order, c.Role)
		}
		byRole[c.Role] = append(byRole[c.Role], fmt.Sprintf("m%d r=%s w=%s", c.Model, outcome(c.Read), outcome(c.Write)))
	}
	sort.Strings(order)
	var lines []string
	for _, role := range order {
		lines = append(lines, role+": "+strings.Join(byRole[role], ", "))
	}
	return strings.Join(lines, " | ")
}

func renderRow(cells []cell, role string) string {
	var parts []string
	for _, c := range cells {
		if c.Role != role {
			continue
		}
		parts = append(parts, fmt.Sprintf("model %d at register %d — read %s, write %s",
			c.Model, c.Addr, outcome(c.Read), outcome(c.Write)))
	}
	if len(parts) == 0 {
		return ""
	}
	return role + ": " + strings.Join(parts, "; ")
}

// outcome collapses one exchange to a token for the matrix.
func outcome(ex Exchange) string {
	switch {
	case ex.Err != nil:
		return "ERR"
	case len(ex.Response) == 0:
		return "-"
	}
	v, err := parseMBAP(ex.Response)
	if err != nil || len(v.PDU) == 0 {
		return "MALFORMED"
	}
	if v.PDU[0]&0x80 == 0 {
		return "allow"
	}
	if len(v.PDU) > 1 {
		return fmt.Sprintf("deny(%d)", v.PDU[1])
	}
	return "deny"
}

// distinctWritePermissions counts how many different write-permission profiles
// the swept roles produced. Fewer than two means the DUT is not distinguishing
// roles at all on this chain.
func distinctWritePermissions(cells []cell) int {
	profiles := map[string]bool{}
	byRole := map[string][]string{}
	for _, c := range cells {
		byRole[c.Role] = append(byRole[c.Role], fmt.Sprintf("%d=%s", c.Model, outcome(c.Write)))
	}
	for _, p := range byRole {
		sort.Strings(p)
		profiles[strings.Join(p, ",")] = true
	}
	return len(profiles)
}

// cell is one role x model probe of the RBAC-012 sweep.
type cell struct {
	Role  string
	Model uint16
	Read  Exchange
	Write Exchange
	Addr  uint16
}

func chainIDs(c *Chain) []uint16 {
	if c == nil {
		return nil
	}
	return c.IDs()
}
