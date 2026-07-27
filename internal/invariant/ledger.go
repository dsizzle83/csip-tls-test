package invariant

// ledger.go is the record of what the ADVERSARY attempted and how the DUT
// answered. It is the second half of the observable world, and without it three
// invariants cannot exist.
//
// I3 asks whether a REFUSED write leaves durable state asserting it applied.
// Nothing in a register image says "this value was refused"; only the party that
// issued the write knows it was refused, and only they know what value to look
// for afterwards. I4 asks whether an unauthorised credential can cause a write —
// again a fact about attempts, not about state. I5 asks whether a certificate
// from one trust domain ever authenticates in another, which is a fact about
// handshakes.
//
// So the campaign writes here as it attacks, and the invariants read. The split
// matters: the invariant never issues the write itself. A checker that could
// write would be an actor in the campaign, its own verdict would depend on its
// own side effects, and a shrinker replaying the fault set without the checker
// would get a different answer.
//
// # Distinctiveness, and why it is mandatory
//
// I3's check is "the refused value never appears downstream". That inference is
// only sound if the value could not have arrived by any other route. If the
// adversary writes WMaxLimPct = 50 and the head-end is independently commanding
// 50, then seeing 50 at the DER proves nothing, and an invariant that reported
// PASS on that basis would be lying by construction. [WriteRecord.Distinctive]
// is the campaign's assertion that it chose a value no legitimate path was
// commanding at the time; I3 SKIPs every record that lacks it, with that as the
// reason. It is a deliberate friction: making the campaign choose distinguishable
// witnesses is cheap, and the alternative is an invariant that passes for free.

import (
	"sync"
	"time"
)

// WriteRecord is one write the adversary attempted against the DUT and the
// DUT's own answer to it.
type WriteRecord struct {
	Seq int       `json:"seq"`
	At  time.Time `json:"at"`

	// Credential names the certificate/identity used, e.g. "read-only" or
	// "grid-service".
	Credential string `json:"credential"`
	// Role is the role the credential asserted.
	Role string `json:"role,omitempty"`
	// Domain is the trust domain the credential belongs to, e.g.
	// "nb-mbaps-clients" or "sb-devices". I5 compares it against the target.
	Domain string `json:"domain,omitempty"`
	// Authorized records whether this credential was SUPPOSED to be able to
	// perform this write. An accepted write by an unauthorized credential is
	// I4's falsification.
	Authorized bool `json:"authorized"`

	// Target
	Unit  uint8  `json:"unit"`
	Model uint16 `json:"model"`
	Point string `json:"point"`
	// Value is what was commanded, in the point's own declared unit.
	Value Quantity `json:"value"`
	// Ref is the percentage base when Value is a percent.
	Ref RefBase `json:"ref,omitempty"`
	// Distinctive asserts the value was chosen so that observing it downstream
	// can only have come from THIS write. I3 SKIPs records without it.
	Distinctive bool `json:"distinctive"`
	// DERs names the downstream devices this write could reach, so I3 knows
	// where to look. Empty means "every observed DER".
	DERs []string `json:"ders,omitempty"`

	// Outcome — exactly one of Refused / Accepted / TransportErr is meaningful.
	Refused bool `json:"refused"`
	// ExceptionCode is the Modbus exception the DUT answered with, when it
	// refused. I4 compares these across denial causes for indistinguishability.
	ExceptionCode uint8 `json:"exception_code,omitempty"`
	Accepted      bool  `json:"accepted"`
	// TransportErr is set when the session broke rather than answering.
	TransportErr string `json:"transport_err,omitempty"`
	// RTT is how long the DUT took to answer, the coarse timing signal I4
	// reports (as a WARN — a timing side channel needs statistics a monitor
	// tick cannot honestly produce).
	RTT time.Duration `json:"rtt_ns,omitempty"`
	// ClosedConn records that the DUT tore the connection down rather than
	// answering, which is itself a distinguishing signal across denial causes.
	ClosedConn bool `json:"closed_conn,omitempty"`

	// Frames cite the attempt in the run's capture, when the campaign
	// attributed them.
	Frames []int `json:"frames,omitempty"`
	// Note carries anything a reader needs in order not to over-read the record.
	Note string `json:"note,omitempty"`
}

// DenialCause is the reason a request was expected to be denied. I4's
// indistinguishability arm compares the DUT's ANSWER across causes: a device
// that answers 0x01 for a role denial and 0x02 for a revoked certificate has
// told an attacker which of the two they hit.
type DenialCause string

// The denial causes worth distinguishing between (and therefore worth proving
// are NOT distinguishable on the wire).
const (
	CauseNoRole       DenialCause = "no-role"
	CauseWrongRole    DenialCause = "wrong-role"
	CauseExpired      DenialCause = "expired-cert"
	CauseWrongCA      DenialCause = "wrong-trust-domain"
	CauseRevoked      DenialCause = "revoked"
	CauseMalformedRBC DenialCause = "malformed-role"
	CauseUnknownPoint DenialCause = "unknown-point"
)

// AuthRecord is one authentication/authorization attempt, for I4 and I5.
type AuthRecord struct {
	Seq int       `json:"seq"`
	At  time.Time `json:"at"`
	// Credential names the fixture presented.
	Credential string `json:"credential"`
	// CredDomain is the trust domain the credential was issued in.
	CredDomain string `json:"cred_domain"`
	// TargetDomain is the trust domain of the endpoint it was presented to.
	// A credential that authenticates where CredDomain != TargetDomain is I5's
	// falsification.
	TargetDomain string `json:"target_domain"`
	// Target names the endpoint, e.g. "69.0.0.2:802".
	Target string `json:"target"`
	// Cause is why the attempt was expected to be denied; empty for an attempt
	// that was expected to succeed.
	Cause DenialCause `json:"cause,omitempty"`
	// Authenticated reports whether the handshake completed AND the peer then
	// served at least one request. A completed handshake that is refused every
	// request is NOT authentication for I5's purposes, and conflating the two
	// would make I5 fire on a device that is behaving correctly.
	Authenticated bool `json:"authenticated"`
	// Stage says where it failed: "handshake" or "authz".
	Stage string `json:"stage,omitempty"`
	// ExceptionCode / ClosedConn / RTT are the observable SHAPE of the denial,
	// which I4 requires to be identical across causes.
	ExceptionCode uint8         `json:"exception_code,omitempty"`
	ClosedConn    bool          `json:"closed_conn,omitempty"`
	RTT           time.Duration `json:"rtt_ns,omitempty"`
	// TLSAlert is the alert description the peer sent, when one was observed.
	TLSAlert string `json:"tls_alert,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Frames   []int  `json:"frames,omitempty"`
}

// RestartRecord marks a DUT interruption — one the campaign caused, or one the
// Monitor inferred from a discontinuity in an independent witness.
type RestartRecord struct {
	At time.Time `json:"at"`
	// Cause is "campaign" for a deliberate interruption or "inferred" for one
	// detected from a peer's session/counter discontinuity.
	Cause string `json:"cause"`
	// Detail says what was observed.
	Detail string `json:"detail,omitempty"`
}

// Ledger is the append-only record of the adversary's attempts. It is safe for
// concurrent use.
type Ledger struct {
	mu       sync.RWMutex
	seq      int
	writes   []WriteRecord
	auths    []AuthRecord
	restarts []RestartRecord
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger { return &Ledger{} }

// NoteWrite records a write attempt and its outcome, returning the assigned
// sequence number.
func (l *Ledger) NoteWrite(r WriteRecord) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	if r.At.IsZero() {
		r.At = time.Now()
	}
	l.writes = append(l.writes, r)
	return r.Seq
}

// NoteAuth records an authentication attempt.
func (l *Ledger) NoteAuth(r AuthRecord) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	if r.At.IsZero() {
		r.At = time.Now()
	}
	l.auths = append(l.auths, r)
	return r.Seq
}

// NoteRestart records an interruption of the DUT.
func (l *Ledger) NoteRestart(r RestartRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.At.IsZero() {
		r.At = time.Now()
	}
	l.restarts = append(l.restarts, r)
}

// Writes returns a copy of the write records, in attempt order.
func (l *Ledger) Writes() []WriteRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]WriteRecord, len(l.writes))
	copy(out, l.writes)
	return out
}

// Refused returns the writes the DUT answered with a Modbus exception — I3's
// input.
func (l *Ledger) Refused() []WriteRecord {
	var out []WriteRecord
	for _, w := range l.Writes() {
		if w.Refused {
			out = append(out, w)
		}
	}
	return out
}

// Auths returns a copy of the authentication records.
func (l *Ledger) Auths() []AuthRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]AuthRecord, len(l.auths))
	copy(out, l.auths)
	return out
}

// Restarts returns a copy of the restart records.
func (l *Ledger) Restarts() []RestartRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]RestartRecord, len(l.restarts))
	copy(out, l.restarts)
	return out
}

// RestartsSince returns the restarts at or after t.
func (l *Ledger) RestartsSince(t time.Time) []RestartRecord {
	var out []RestartRecord
	for _, r := range l.Restarts() {
		if !r.At.Before(t) {
			out = append(out, r)
		}
	}
	return out
}

// Empty reports whether the adversary attempted nothing at all. The Monitor
// uses it, with ManifestSnapshot.AnyArmed, to refuse to call a run that did
// nothing a pass.
func (l *Ledger) Empty() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.writes) == 0 && len(l.auths) == 0 && len(l.restarts) == 0
}
