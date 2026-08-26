package suitemodbusclient

// ledger.go is this suite's reader for the simulator's own transaction record,
// and the shapes of the deterministic control plane's answers.
//
// # A third witness, and what it is and is not for
//
// Every row in this document has had two sources of truth and both are
// indirect. The pcap is the strongest — third-party checkable, no key material,
// no trust in this tool — but it is attributed to a test case by TIME, so a
// provocation the DUT meets a moment outside the window cites nothing. The
// DUT's journal is the product's own account of itself, which is the thing
// under test and can never settle a question about the product's behaviour on
// its own.
//
// The ledger is what the SERVER saw, written by the sim's wire layer as the
// bytes crossed it and keyed to an epoch fence rather than to a wall clock. It
// is not the product's log — the product does not write it, cannot influence
// it, and does not know it exists.
//
// It does NOT replace the pcap, and no row here treats it as though it did.
// Every criterion that can be cited from the capture still is. What the ledger
// changes is the LIVE PHASE: a row can now know, before the citation phase
// runs, whether the thing it provoked actually happened and which transactions
// it happened to — so its window contains the traffic it is about to cite,
// instead of hoping.
//
// Where a criterion genuinely cannot reach the capture, a ledger-backed
// assertion is a Narrative naming the sim's ledger as its source, exactly as
// the journal-backed ones name journalctl. The verdict rules in doc.go are
// unchanged: an observation adjacent to a criterion still carries SKIP.
//
// # Decoded by field name, on purpose
//
// The structs below are written here rather than imported from
// csip-tls-test/sim/southbound. The suite already refuses to decode the DUT's
// framing with the DUT's own parser (modbuswire.go's doc comment); the same
// discipline applied to the sim costs one small struct and keeps the harness
// able to run against a sim it was not compiled with. A field the sim adds
// later is ignored here rather than breaking the run.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// simAPIVersionNeeded is the control-plane version the deterministic rows
// require. A sim older than this has no ledger, no barrier and no epoch, and
// the rows say so by name rather than reporting an empty ledger as "the client
// did nothing".
const simAPIVersionNeeded = "1.1.0"

// Transaction outcomes, as the sim's wire layer classifies them. Mirrored from
// the control-plane contract (sim/simapi/API.md), not imported.
const (
	outcomeAnswered  = "answered"
	outcomeException = "exception"
	outcomeDropped   = "dropped"
	outcomeTruncated = "truncated"
	outcomeDelayed   = "delayed"
	outcomeAbandoned = "abandoned"
)

// LedgerEntry is one Modbus transaction as the simulator's wire layer recorded
// it.
type LedgerEntry struct {
	Seq    uint64 `json:"seq"`
	Epoch  uint64 `json:"epoch"`
	Poll   uint64 `json:"poll"`
	Conn   uint64 `json:"conn"`
	Peer   string `json:"peer"`
	TxnID  uint16 `json:"txn_id"`
	UnitID uint8  `json:"unit_id"`
	FC     uint8  `json:"fc"`
	Addr   uint16 `json:"addr"`
	Count  uint16 `json:"count"`
	// Request and Response are the complete ADUs in hex, MBAP header included.
	// Response is what was DELIVERED to the client: a truncated response is
	// recorded truncated and a dropped one is empty.
	Request    string     `json:"request"`
	Response   string     `json:"response"`
	Exception  uint8      `json:"exception"`
	Outcome    string     `json:"outcome"`
	Fault      string     `json:"fault"`
	RequestAt  time.Time  `json:"request_at"`
	ResponseAt *time.Time `json:"response_at"`
	LatencyMS  float64    `json:"latency_ms"`
}

// IsRead reports whether the transaction was a register read.
func (e LedgerEntry) IsRead() bool {
	return e.FC == FCReadHoldingRegisters || e.FC == FCReadInputRegisters
}

// IsWrite reports whether the transaction was a register write.
func (e LedgerEntry) IsWrite() bool {
	return e.FC == FCWriteSingleRegister || e.FC == FCWriteMultipleRegisters
}

// Covers reports whether the transaction's register range includes addr.
func (e LedgerEntry) Covers(addr uint16) bool {
	n := e.Count
	if n == 0 {
		n = 1
	}
	return addr >= e.Addr && uint32(addr) < uint32(e.Addr)+uint32(n)
}

// Values decodes the register words of a read response. It returns ok=false
// for anything that is not a well-formed read response — an exception, a
// truncated body, a write echo — so a caller never mistakes a short answer for
// a short block.
func (e LedgerEntry) Values() ([]uint16, bool) {
	raw, err := hex.DecodeString(e.Response)
	if err != nil || len(raw) < mbapHeaderBytes+2 {
		return nil, false
	}
	pdu := raw[mbapHeaderBytes:]
	if pdu[0] != e.FC || !e.IsRead() {
		return nil, false
	}
	n := int(pdu[1])
	if len(pdu) < 2+n || n%2 != 0 {
		return nil, false
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = uint16(pdu[2+2*i])<<8 | uint16(pdu[3+2*i])
	}
	return out, true
}

// WriteValues decodes the register words an FC 0x10 request carried.
func (e LedgerEntry) WriteValues() ([]uint16, bool) {
	raw, err := hex.DecodeString(e.Request)
	if err != nil || len(raw) < mbapHeaderBytes+6 {
		return nil, false
	}
	pdu := raw[mbapHeaderBytes:]
	if pdu[0] != FCWriteMultipleRegisters {
		return nil, false
	}
	n := int(pdu[5])
	if len(pdu) < 6+n || n%2 != 0 {
		return nil, false
	}
	out := make([]uint16, n/2)
	for i := range out {
		out[i] = uint16(pdu[6+2*i])<<8 | uint16(pdu[7+2*i])
	}
	return out, true
}

// String renders a transaction for an assertion's Observed text.
func (e LedgerEntry) String() string {
	s := fmt.Sprintf("seq %d, epoch %d, poll %d, conn %d: unit %d, FC 0x%02x at %d×%d → %s",
		e.Seq, e.Epoch, e.Poll, e.Conn, e.UnitID, e.FC, e.Addr, e.Count, e.Outcome)
	if e.Outcome == outcomeException {
		s += fmt.Sprintf(" 0x%02x %s", e.Exception, ExceptionName(e.Exception))
	}
	if e.Fault != "" {
		s += " (shaped by " + e.Fault + ")"
	}
	return s
}

// mbapHeaderBytes is the Modbus/TCP header length. Restated here rather than
// reached for across files so this decoder stands alone.
const mbapHeaderBytes = 7

// LedgerPage is GET /ledger's answer.
type LedgerPage struct {
	APIVersion string        `json:"api_version"`
	Epoch      uint64        `json:"epoch"`
	Poll       PollState     `json:"poll"`
	Entries    []LedgerEntry `json:"entries"`
	Total      int           `json:"total"`
	NextSeq    uint64        `json:"next_seq"`
	HighSeq    uint64        `json:"high_seq"`
	Evicted    uint64        `json:"evicted"`
	// Truncated says this page may be missing transactions the query asked
	// for, because they aged out of the sim's ring. A row must not read a
	// truncated page as an absence.
	Truncated bool `json:"truncated"`
}

// Reads returns the read transactions on the page.
func (p LedgerPage) Reads() []LedgerEntry { return p.filter(LedgerEntry.IsRead) }

// Writes returns the write transactions on the page.
func (p LedgerPage) Writes() []LedgerEntry { return p.filter(LedgerEntry.IsWrite) }

func (p LedgerPage) filter(keep func(LedgerEntry) bool) []LedgerEntry {
	var out []LedgerEntry
	for _, e := range p.Entries {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

// WithOutcome returns the transactions the sim resolved a particular way.
func (p LedgerPage) WithOutcome(outcome string) []LedgerEntry {
	var out []LedgerEntry
	for _, e := range p.Entries {
		if e.Outcome == outcome {
			out = append(out, e)
		}
	}
	return out
}

// Exceptions returns the transactions the device answered with an exception,
// keyed by code.
func (p LedgerPage) Exceptions() map[uint8][]LedgerEntry {
	out := map[uint8][]LedgerEntry{}
	for _, e := range p.Entries {
		if e.Outcome == outcomeException {
			out[e.Exception] = append(out[e.Exception], e)
		}
	}
	return out
}

// Addresses lists the distinct start addresses read on the page, sorted — the
// shape a base-probe or coverage assertion reasons about.
func (p LedgerPage) Addresses() []uint16 {
	seen := map[uint16]bool{}
	for _, e := range p.Entries {
		if e.IsRead() {
			seen[e.Addr] = true
		}
	}
	out := make([]uint16, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Summary renders a page for an assertion's Observed text.
func (p LedgerPage) Summary() string {
	if len(p.Entries) == 0 {
		return fmt.Sprintf("no transaction (the sim's ledger has seen %d in all)", p.HighSeq)
	}
	var parts []string
	byOutcome := map[string]int{}
	for _, e := range p.Entries {
		byOutcome[e.Outcome]++
	}
	for _, o := range []string{outcomeAnswered, outcomeException, outcomeDropped, outcomeTruncated,
		outcomeDelayed, outcomeAbandoned} {
		if n := byOutcome[o]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, o))
		}
	}
	s := fmt.Sprintf("%d transaction(s) (%s)", len(p.Entries), strings.Join(parts, ", "))
	if p.Truncated {
		s += "; NOTE: this window reached past the sim's retained ledger, so it may be incomplete"
	}
	return s
}

// PollState is the sim's poll-cycle accounting.
type PollState struct {
	Completed    uint64          `json:"completed"`
	Open         uint64          `json:"open"`
	OpenReads    int             `json:"open_reads"`
	OpenPending  int             `json:"open_pending"`
	Anchor       PollAnchor      `json:"anchor"`
	AnchorLocked bool            `json:"anchor_locked"`
	AnchorSource string          `json:"anchor_source"`
	Learning     []PollCandidate `json:"learning"`
	Sessions     uint64          `json:"sessions"`
	Abandoned    uint64          `json:"abandoned"`
	// Rule is the sim's own one-line statement of the detection rule, carried
	// into the bundle so a reader sees the definition beside the number rather
	// than having to take the tool's word for what a "cycle" is.
	Rule string `json:"rule"`
}

// PollAnchor is the read request that delimits a poll cycle.
type PollAnchor struct {
	UnitID uint8  `json:"unit_id"`
	Addr   uint16 `json:"addr"`
	Count  uint16 `json:"count"`
}

func (a PollAnchor) String() string {
	if a.Addr == 0 && a.Count == 0 {
		return "none"
	}
	if a.Count == 0 {
		return fmt.Sprintf("any read at %d", a.Addr)
	}
	return fmt.Sprintf("FC 0x03 at %d×%d", a.Addr, a.Count)
}

// PollCandidate is one key the sim is weighing as the anchor.
type PollCandidate struct {
	Key PollAnchor `json:"key"`
	N   int        `json:"n"`
}

// PollReport is GET /poll and GET /poll/wait's answer.
type PollReport struct {
	APIVersion string    `json:"api_version"`
	Reached    bool      `json:"reached"`
	Want       uint64    `json:"want"`
	Epoch      uint64    `json:"epoch"`
	Poll       PollState `json:"poll"`
	Tap        TapStats  `json:"tap"`
}

// TapStats is the sim wire tap's own account of what it relayed.
type TapStats struct {
	Connections  uint64 `json:"connections"`
	Requests     uint64 `json:"requests"`
	Responses    uint64 `json:"responses"`
	Dropped      uint64 `json:"dropped"`
	Truncated    uint64 `json:"truncated"`
	Delayed      uint64 `json:"delayed"`
	UnitRefused  uint64 `json:"unit_refused"`
	Abandoned    uint64 `json:"abandoned"`
	Ledger       int    `json:"ledger_entries"`
	UnitID       uint8  `json:"unit_id"`
	OneShotArmed bool   `json:"one_shot_armed"`
}

// simAck is the acknowledgement every accepted mutation returns.
type simAck struct {
	APIVersion string          `json:"api_version"`
	Epoch      uint64          `json:"epoch"`
	Result     json.RawMessage `json:"result"`
}

// simVersion is GET /version's answer.
type simVersion struct {
	APIVersion string   `json:"api_version"`
	Endpoints  []string `json:"endpoints"`
}

// resetResult is POST /reset's report of what it put back.
type resetResult struct {
	Baseline         string     `json:"baseline"`
	Cleared          []string   `json:"cleared"`
	Baselines        []string   `json:"baselines"`
	PollAnchor       PollAnchor `json:"poll_anchor"`
	PollAnchorSource string     `json:"poll_anchor_source"`
}

// ── The client for the deterministic endpoints ────────────────────────────────
//
// These go through SimClient.Raw rather than through named methods, because
// the framework's SimClient is shared with every other suite and this suite
// should not be the reason it grows an endpoint set. Raw is the escape hatch it
// documents for exactly this.

// simVersionOf reads the sim's control-plane version and endpoint list.
func simVersionOf(ctx context.Context, sim *certify.SimClient) (simVersion, error) {
	var v simVersion
	raw, err := sim.Raw(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("decode /version: %w", err)
	}
	return v, nil
}

// postForEpoch posts a mutation and returns the epoch it is in force from.
//
// A sim too old to answer with an epoch is an error naming the version needed,
// not a silent zero: an epoch of 0 fences nothing, and a row that fenced on it
// would grade the whole run's traffic and call the result a product finding.
func postForEpoch(ctx context.Context, sim *certify.SimClient, path string, body any) (simAck, error) {
	var ack simAck
	raw, err := sim.Raw(ctx, http.MethodPost, path, body)
	if err != nil {
		return ack, err
	}
	if len(raw) == 0 {
		return ack, fmt.Errorf("the sim acknowledged %s with an empty body: it is older than simapi "+
			"%s, which is the version that returns the epoch a fence needs", path, simAPIVersionNeeded)
	}
	if err := json.Unmarshal(raw, &ack); err != nil {
		return ack, fmt.Errorf("decode the %s acknowledgement: %w (body: %s)", path, err, snippet(raw))
	}
	if ack.Epoch == 0 {
		return ack, fmt.Errorf("the sim acknowledged %s without an epoch (api_version %q); simapi %s or "+
			"later is needed for a deterministic fence", path, ack.APIVersion, simAPIVersionNeeded)
	}
	return ack, nil
}

// pollNow reads the sim's poll accounting without blocking.
func pollNow(ctx context.Context, sim *certify.SimClient) (PollReport, error) {
	var rep PollReport
	raw, err := sim.Raw(ctx, http.MethodGet, "/poll", nil)
	if err != nil {
		return rep, err
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("decode /poll: %w (body: %s)", err, snippet(raw))
	}
	return rep, nil
}

// pollWaitOnce issues one bounded /poll/wait request.
func pollWaitOnce(ctx context.Context, sim *certify.SimClient, want uint64, slice time.Duration) (PollReport, error) {
	var rep PollReport
	path := fmt.Sprintf("/poll/wait?epoch=%d&timeout=%s", want, slice)
	raw, err := sim.Raw(ctx, http.MethodGet, path, nil)
	if err != nil {
		return rep, err
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("decode /poll/wait: %w (body: %s)", err, snippet(raw))
	}
	return rep, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// ledgerWaitOnce issues one bounded GET /ledger?min_entries= request — the
// ledger's own barrier. See sim/simapi/API.md for why a row sometimes needs it
// rather than the poll barrier.
func ledgerWaitOnce(ctx context.Context, sim *certify.SimClient, epoch uint64, min int,
	slice time.Duration) (LedgerPage, error) {

	var page LedgerPage
	q := url.Values{}
	if epoch > 0 {
		q.Set("since_epoch", fmt.Sprint(epoch))
	}
	q.Set("min_entries", fmt.Sprint(min))
	q.Set("timeout", slice.String())
	raw, err := sim.Raw(ctx, http.MethodGet, "/ledger?"+q.Encode(), nil)
	if err != nil {
		return page, err
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return page, fmt.Errorf("decode /ledger: %w (body: %s)", err, snippet(raw))
	}
	return page, nil
}

// sortUint16 sorts a small slice of register addresses in place. The suite
// carries its own rather than reaching for a generic, so an assertion's
// Observed text lists addresses in a stable order however small the slice.
func sortUint16(s []uint16) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

// sortInts sorts a small slice of ints in place, for an assertion's Observed
// text.
func sortInts(s []int) { sort.Ints(s) }
