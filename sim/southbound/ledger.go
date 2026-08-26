package sim

// ledger.go — THE SIM'S OWN, INDEPENDENT ACCOUNT OF EVERY MODBUS TRANSACTION.
//
// # Why a second witness
//
// SS-MODBUS-CLIENT-CONF-v1.1 is a CLIENT conformance document: the device
// under test dials the bench, and every criterion is about what the client
// asked for and what it did with the answer. The bench has had two ways to
// find that out, and both are indirect:
//
//	the pcap        — true, third-party checkable, and attributed to a test
//	                  case by TIME, so a row whose provocation lands outside
//	                  its own window silently cites nothing;
//	the DUT journal — the product's own account of itself, which is exactly
//	                  the thing under test and can therefore never settle a
//	                  question about the product's behaviour on its own.
//
// The ledger is the third: what the SERVER saw, written by the sim's wire
// layer as the bytes crossed it, keyed to the epoch fence rather than to a
// wall clock. It is not the product's log — the product does not write it,
// cannot influence it, and does not know it exists — and it is not a
// substitute for the pcap. It is the record that lets a row know, before it
// ever opens the capture, whether the thing it provoked actually happened, and
// which transactions it happened to.
//
// # Append-only, and what that costs
//
// An entry is appended ONCE, when its transaction is RESOLVED — the response
// was delivered, an exception came back, the response was dropped or truncated
// by an armed fault, or the connection died with the request outstanding. An
// in-flight transaction is not in the ledger yet; nothing in the ledger is
// ever edited afterwards.
//
// That costs a little latency in the record (a delayed response's entry
// appears when the delay ends, not when the request arrived) and buys the
// property that matters: a reader who fetched entries up to sequence N will
// never see a different answer for those entries later. Every entry carries
// both its request and its response timestamp, so the ordering the reader
// wants is always reconstructible from the data rather than from the order it
// happened to be appended in.
//
// # Bounded, and honest about it
//
// The ring holds DefaultLedgerCapacity entries. A bench left running for days
// must not grow a slice without limit (the same I8 "no unbounded growth"
// invariant the wire mangler's own framer respects), so the oldest entries are
// evicted. A query whose window starts before the oldest surviving entry is
// answered with Truncated=true rather than with a silently short list: a
// missing transaction and an evicted one are different facts, and a row that
// could not tell them apart would report the wrong one.

import (
	"encoding/hex"
	"sync"
	"time"
)

// DefaultLedgerCapacity is how many resolved transactions the ring holds.
//
// A ten-second poll of a dozen model blocks is a few transactions a second at
// the very most; 20 000 is therefore several hours of steady-state polling,
// which comfortably spans any single conformance run while bounding the
// sim's memory at a few megabytes.
const DefaultLedgerCapacity = 20000

// Transaction outcomes, as the sim's wire layer resolved them. These are the
// sim's OWN classification of what it did, not an inference from the client's
// reaction.
const (
	// OutcomeAnswered — a well-formed response was written to the client in
	// full.
	OutcomeAnswered = "answered"
	// OutcomeException — the device answered with a Modbus exception PDU
	// (function code with the high bit set). That is a legitimate answer, and
	// for §2.9.2 it is the answer under test.
	OutcomeException = "exception"
	// OutcomeDropped — an armed one-shot fault swallowed the response
	// entirely; the connection stayed open and the client was left waiting.
	OutcomeDropped = "dropped"
	// OutcomeTruncated — an armed one-shot fault wrote a prefix of the
	// response, MBAP length field untouched, so the header promises bytes the
	// client will never receive.
	OutcomeTruncated = "truncated"
	// OutcomeDelayed — an armed one-shot fault held the response for a while
	// and then wrote it in full. The entry's LatencyMS says how long.
	OutcomeDelayed = "delayed"
	// OutcomeAbandoned — the connection ended with this request outstanding.
	// The client's own severed-transaction case, and PROT-1's reading (a).
	OutcomeAbandoned = "abandoned"
)

// LedgerEntry is one Modbus transaction as the sim's wire layer saw it.
//
// Field names are chosen to be readable in a bundle by someone who has the
// Modbus specification open and nothing else: every one of them is either an
// MBAP header field, a PDU field, or a fact about what the sim did with it.
type LedgerEntry struct {
	// Seq is the ledger's own monotonically increasing sequence number,
	// assigned at append. It is the cursor a caller pages with.
	Seq uint64 `json:"seq"`
	// Epoch is the control-plane epoch in force when the REQUEST arrived —
	// the fence a row uses to select the transactions its provocation could
	// have touched. See epoch.go.
	Epoch uint64 `json:"epoch"`
	// Poll is the poll-cycle ordinal this request fell inside, as the poll
	// tracker counted them (poll.go). 0 means "before the first cycle the
	// tracker recognised".
	Poll uint64 `json:"poll"`
	// Conn numbers the client connection, in the order the sim accepted them.
	// Two entries with different Conn values are on different sockets, which
	// is how a reconnect is visible here without a pcap.
	Conn uint64 `json:"conn"`
	// Peer is the client's own address:port, i.e. the DUT's ephemeral socket.
	Peer string `json:"peer"`

	// TxnID and UnitID are the MBAP transaction and unit identifiers verbatim.
	TxnID  uint16 `json:"txn_id"`
	UnitID uint8  `json:"unit_id"`
	// FC is the request's function code.
	FC uint8 `json:"fc"`
	// Addr and Count are the request's starting register address and register
	// count, decoded per function code: quantity for FC 0x03/0x04/0x10, and 1
	// for FC 0x06 (which writes exactly one register). Both are zero for a
	// function code whose PDU this decoder does not model, in which case
	// Request still carries every byte.
	Addr  uint16 `json:"addr"`
	Count uint16 `json:"count"`

	// Request is the complete request ADU, MBAP header included, in hex —
	// the bytes the client sent, as the sim received them.
	Request string `json:"request"`
	// Response is the complete response ADU in hex AS DELIVERED TO THE CLIENT:
	// a truncated response is recorded truncated, and a dropped one is empty.
	// The distinction matters — this field is the record of what the client
	// had to work with, not of what the device composed.
	Response string `json:"response,omitempty"`
	// Exception is the Modbus exception code when Outcome is
	// OutcomeException, and 0 otherwise.
	Exception uint8 `json:"exception,omitempty"`

	// Outcome is one of the Outcome* constants.
	Outcome string `json:"outcome"`
	// Fault names the armed one-shot fault that shaped this transaction, when
	// one did. Empty for a transaction the sim did not interfere with.
	Fault string `json:"fault,omitempty"`

	// RequestAt and ResponseAt are the instants the sim's wire layer read the
	// last byte of the request and wrote the last byte of the response. UTC.
	RequestAt time.Time `json:"request_at"`
	// ResponseAt is nil for a dropped or abandoned transaction — there was no
	// response instant, and a zero time in its place would read as one.
	ResponseAt *time.Time `json:"response_at,omitempty"`
	// LatencyMS is the milliseconds between the two, for a transaction that
	// has both.
	LatencyMS float64 `json:"latency_ms,omitempty"`
}

// IsRead reports whether the entry's function code is a register read.
func (e LedgerEntry) IsRead() bool {
	return e.FC == fcReadHolding || e.FC == fcReadInput
}

// IsWrite reports whether the entry's function code is a register write.
func (e LedgerEntry) IsWrite() bool {
	return e.FC == fcWriteSingle || e.FC == fcWriteMultiple
}

// Ledger is the append-only transaction record. Safe for concurrent use.
type Ledger struct {
	mu   sync.Mutex
	cap  int
	seq  uint64
	ring []LedgerEntry
	// evicted counts entries dropped off the front of the ring, and
	// evictedMaxEpoch is the highest epoch among them, so a query can say
	// whether ITS window may be incomplete rather than warning every caller
	// the moment anything at all has aged out.
	evicted         uint64
	evictedMaxEpoch uint64
}

// NewLedger returns a ledger holding at most capacity resolved transactions.
// A capacity ≤ 0 uses DefaultLedgerCapacity.
func NewLedger(capacity int) *Ledger {
	if capacity <= 0 {
		capacity = DefaultLedgerCapacity
	}
	return &Ledger{cap: capacity, ring: make([]LedgerEntry, 0, capacity)}
}

// Append records a resolved transaction and returns its assigned sequence
// number. The caller supplies everything except Seq.
func (l *Ledger) Append(e LedgerEntry) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	if len(l.ring) == l.cap {
		if e := l.ring[0].Epoch; e > l.evictedMaxEpoch {
			l.evictedMaxEpoch = e
		}
		copy(l.ring, l.ring[1:])
		l.ring = l.ring[:l.cap-1]
		l.evicted++
	}
	l.ring = append(l.ring, e)
	return e.Seq
}

// LedgerQuery selects a slice of the ledger.
//
// The two cursors are ANDed: SinceEpoch selects the transactions a
// provocation could have touched, SinceSeq pages through them. A caller that
// sets neither gets everything the ring still holds.
type LedgerQuery struct {
	// SinceEpoch keeps entries whose Epoch is ≥ this value — the fence form.
	SinceEpoch uint64
	// SinceSeq keeps entries whose Seq is > this value — the paging form.
	SinceSeq uint64
	// Limit caps the number of entries returned (0 = no cap beyond the ring).
	Limit int
}

// LedgerPage is the answer to a LedgerQuery.
type LedgerPage struct {
	// Entries are the matching transactions, oldest first.
	Entries []LedgerEntry `json:"entries"`
	// Total is how many entries matched before Limit was applied.
	Total int `json:"total"`
	// NextSeq is the Seq of the last entry returned, i.e. the cursor to pass
	// as SinceSeq to continue. It is the query's own SinceSeq when nothing
	// matched, so a polling caller never rewinds.
	NextSeq uint64 `json:"next_seq"`
	// HighSeq is the highest sequence number the ledger has ever assigned,
	// whether or not it matched. A caller can tell "nothing happened" from
	// "nothing that matched happened" by comparing it with NextSeq.
	HighSeq uint64 `json:"high_seq"`
	// Evicted is how many entries have aged out of the ring over the sim's
	// whole life.
	Evicted uint64 `json:"evicted"`
	// Truncated reports that entries older than the surviving window were
	// evicted, so this page may be missing transactions the query asked for.
	Truncated bool `json:"truncated"`
}

// Since answers a query.
func (l *Ledger) Since(q LedgerQuery) LedgerPage {
	l.mu.Lock()
	defer l.mu.Unlock()

	page := LedgerPage{
		NextSeq: q.SinceSeq,
		HighSeq: l.seq,
		Evicted: l.evicted,
	}
	var matched []LedgerEntry
	for _, e := range l.ring {
		if e.Epoch < q.SinceEpoch {
			continue
		}
		if e.Seq <= q.SinceSeq {
			continue
		}
		matched = append(matched, e)
	}
	page.Total = len(matched)
	// The window is incomplete only when something was evicted AND THIS
	// query's window could have reached into what is gone. Two independent
	// escapes, because either cursor alone can rule it out:
	//
	//	a seq cursor at or past the last evicted entry is already paging
	//	inside the surviving ring;
	//	an epoch fence later than every evicted entry's epoch excludes them
	//	all by definition.
	//
	// Warning every caller the moment anything at all has aged out would make
	// the flag meaningless within minutes of a bench coming up, and a flag
	// nobody can act on is worse than none.
	page.Truncated = l.evicted > 0
	if page.Truncated && len(l.ring) > 0 && q.SinceSeq+1 >= l.ring[0].Seq {
		page.Truncated = false
	}
	if page.Truncated && q.SinceEpoch > l.evictedMaxEpoch {
		page.Truncated = false
	}
	if q.Limit > 0 && len(matched) > q.Limit {
		matched = matched[:q.Limit]
	}
	page.Entries = matched
	if n := len(matched); n > 0 {
		page.NextSeq = matched[n-1].Seq
	}
	return page
}

// Len returns how many entries the ring currently holds.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ring)
}

// hexOf renders bytes the way every entry in this file records them: lower-case
// hex with no separators, so a reader can paste the string straight into a
// Wireshark "Decode as" or a byte comparison without stripping anything.
func hexOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
