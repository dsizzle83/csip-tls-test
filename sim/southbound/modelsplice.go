package sim

// modelsplice.go — insert an unregistered SunSpec model id into the chain.
//
// §2.9.3 ERR-3 step 1 wants a model whose ID is absent from the client's own
// model-definition directory spliced into the discovery chain, so the test
// can watch the client step over it BY LENGTH rather than choke or mis-walk
// — see runs/final-fullsuite-20260731T234821/REPORT.md ERR-3#4. Every model
// this bench serves (solar.go/solar_adv.go/trip1547.go) is a registered
// SunSpec id; there was no way to get an unrecognised one onto the wire
// without literally writing one into the register image, which is what this
// file does: find the end-of-map marker (id 0xFFFF) and push a new header
// (id, length, and length registers of don't-care body) in front of it.

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"lexa-proto/sunspec"
)

// maxChainWalk bounds the end-marker search. A real chain here is a handful
// of models (18 at most, the "full" DER set); 64 is generous headroom
// against a corrupt or unpopulated map, so a bad map fails fast with an
// error instead of walking off into an unbounded loop (this package's own
// I8 — see wire.go's maxFrameLen for the same discipline applied to a
// length field instead of a chain walk).
const maxChainWalk = 64

// ModelSplicer inserts (and can retract) exactly one extra model header into
// a *RegisterMap's SunSpec chain, immediately before the end marker. One
// slot, not a list: a second Insert without a Clear first retracts the
// earlier splice before inserting the new one, so re-arming is idempotent
// and never stacks phantom models nor leaks an orphaned end marker.
type ModelSplicer struct {
	regs *RegisterMap
	mu   sync.Mutex

	active bool
	at     uint16 // address of the spliced header (== the OLD end-marker address)
	length uint16 // the spliced model's declared length, for the retraction math
}

// NewModelSplicer wraps regs. Construction alone never touches the chain.
func NewModelSplicer(regs *RegisterMap) *ModelSplicer {
	return &ModelSplicer{regs: regs}
}

// Insert splices a model with the given id and length into the chain,
// immediately before the current end marker. length is the number of DATA
// registers the header declares; a client that steps over it by length,
// rather than reading its body, never has to make sense of the content —
// this bench writes none (unset registers read back as zero, which is a
// legal — if uninteresting — SunSpec value for any type).
func (ms *ModelSplicer) Insert(id, length uint16) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.active {
		ms.clearLocked()
	}
	end, err := findEndMarker(ms.regs)
	if err != nil {
		return err
	}
	ms.regs.Set(end+0, id)
	ms.regs.Set(end+1, length)
	newEnd := end + 2 + length
	ms.regs.Set(newEnd+0, sunspec.EndMarker)
	ms.regs.Set(newEnd+1, 0)
	ms.active, ms.at, ms.length = true, end, length
	log.Printf("[fault] insert_model: spliced model id=%d len=%d at %d (chain end now %d)", id, length, end, newEnd)
	return nil
}

// Clear retracts a previously-spliced model, restoring the end marker to
// where it stood before Insert. A Clear with nothing armed is a no-op.
func (ms *ModelSplicer) Clear() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.clearLocked()
}

func (ms *ModelSplicer) clearLocked() {
	if !ms.active {
		return
	}
	ms.regs.Set(ms.at+0, sunspec.EndMarker)
	ms.regs.Set(ms.at+1, 0)
	// The old end-marker pair beyond the retracted splice is left in place:
	// nothing ever walks past the (now-restored) end marker at ms.at, so it
	// is inert, unreachable data, not a second chain terminator.
	log.Printf("[fault] insert_model: retracted the splice at %d", ms.at)
	ms.active = false
}

// findEndMarker walks the chain from the SunSpec header and returns the
// address of the id/length pair holding the 0xFFFF end marker.
//
// It always starts from the DEFAULT sunspec.SunSpecBase, the same known
// limitation relocate.go documents for Snapshot/Inject/faultController: if
// the map has been relocated (see Relocator) this walk starts from the
// wrong address and fails closed with an error rather than splicing into
// garbage — restore the default base (Relocator.Relocate(sunspec.SunSpecBase))
// before using insert_model.
func findEndMarker(r *RegisterMap) (uint16, error) {
	cursor := sunspec.SunSpecBase + 2
	for i := 0; i < maxChainWalk; i++ {
		id := r.Get(cursor)
		if id == sunspec.EndMarker {
			return cursor, nil
		}
		length := r.Get(cursor + 1)
		cursor += 2 + length
	}
	return 0, fmt.Errorf("modelsplice: no end marker found within %d models — is the register map populated?", maxChainWalk)
}

// ── POST /inject {"insert_model":{"id":65000,"len":4}} ────────────────────

// modelSpliceInjectSpec is the POST /inject body this file additionally
// recognises, independent of whatever fields the classic Inject path reads
// (see simapi's doc comment: "override fields: {"W_W":4500.0,...}"). A body
// with neither key is left for that path entirely unchanged.
type modelSpliceInjectSpec struct {
	InsertModel *struct {
		ID  uint16 `json:"id"`
		Len uint16 `json:"len"`
	} `json:"insert_model,omitempty"`
	ClearInsertModel bool `json:"clear_insert_model,omitempty"`
}

// ApplyInject claims a POST /inject body that carries "insert_model" or
// "clear_insert_model"; every other body (the classic field-override form)
// is left unhandled so the caller falls through to srv.Inject unchanged.
func (ms *ModelSplicer) ApplyInject(body []byte) (handled bool, err error) {
	var spec modelSpliceInjectSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, nil
	}
	if spec.InsertModel == nil && !spec.ClearInsertModel {
		return false, nil
	}
	if spec.ClearInsertModel {
		ms.Clear()
		if spec.InsertModel == nil {
			return true, nil
		}
	}
	if err := ms.Insert(spec.InsertModel.ID, spec.InsertModel.Len); err != nil {
		return true, err
	}
	return true, nil
}
