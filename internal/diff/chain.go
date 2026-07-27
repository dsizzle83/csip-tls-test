package diff

// chain.go is the chain-walking differential: the same register space is walked
// by the product's SunSpec scanner and by an independent walker written here,
// and the two block lists are compared.
//
// # Why this is worth a family of its own
//
// The chain walk is the first thing that happens to any device, and everything
// downstream is addressed relative to what it returns. A walker that reports a
// block at the wrong base does not produce a wrong VALUE; it produces the value
// of a DIFFERENT POINT, decoded with someone else's scale factor, and there is
// no consistency check anywhere below it that would notice. Getting the chain
// wrong is how a gateway reads a frequency register as a power setpoint.
//
// It is also the part of the SunSpec stack most exposed to a hostile southbound
// peer. A device that lies about its own model lengths costs nothing to build,
// is indistinguishable from a firmware bug, and sits behind the trust boundary
// the strategy names as the most under-covered
// (docs/ADVERSARIAL_QA_STRATEGY.md §4, L4). So the inputs here are not merely
// generated; they are constructed to be hostile in specific ways.
//
// # The referee's bounds reasoning, stated so it can be argued with
//
// [walk] enforces four bounds the SunSpec Device Information Model implies but
// which a naive walker does not check:
//
//  1. A model header must lie inside the 16-bit Modbus address space. A cursor
//     that would advance past 65535 has run off the end of the device, and the
//     next read wraps to address 0 — a different device's registers, or the
//     SunS header again, which walks forever.
//  2. A model's DATA must lie inside the address space too, for the same reason.
//  3. The list must terminate. A walker with no step limit on a device with no
//     end marker reads until something errors, and a device that answers
//     everything with zeros never errors — model 0, length 0, repeat.
//  4. A zero-length model is legal in the model list (some models genuinely
//     carry no data registers) but a chain made ENTIRELY of them cannot
//     terminate by advancing, so the step limit is what catches it, not a
//     special case.
//
// The oracle is agreement: both walkers return the same blocks, or both refuse.
// A case where the referee refuses and the product returns a block list is the
// interesting one, and it says so.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// maxChainSteps bounds the referee's walk. It is far above any real device
// (SunSpec chains are a handful of models) and far below the address space, so
// it catches a non-terminating list without ever refusing a plausible one.
const maxChainSteps = 256

// refBlock is the referee's view of one model block.
type refBlock struct {
	ModelID uint16
	Base    uint16
	Length  uint16
}

func (b refBlock) String() string { return fmt.Sprintf("%d@%d+%d", b.ModelID, b.Base, b.Length) }

// walk is the referee's chain walker. It reads through the same transport the
// product uses, so the two see identical bytes, and differs only in what it is
// willing to conclude from them.
func walk(t interface {
	ReadHolding(addr, quantity uint16) ([]uint16, error)
}, base uint16) ([]refBlock, error) {
	hdr, err := t.ReadHolding(base, 2)
	if err != nil {
		return nil, fmt.Errorf("referee: read SunS header at %d: %w", base, err)
	}
	if hdr[0] != sunspec.SunSMagic0 || hdr[1] != sunspec.SunSMagic1 {
		return nil, fmt.Errorf("referee: no SunS header at %d (got 0x%04X 0x%04X)", base, hdr[0], hdr[1])
	}

	var out []refBlock
	cursor := uint32(base) + 2
	for step := 0; ; step++ {
		if step >= maxChainSteps {
			return nil, fmt.Errorf("referee: the model list did not terminate within %d models — a chain "+
				"this long is not a device, it is a walk that will not stop", maxChainSteps)
		}
		if cursor+1 > 0xFFFF {
			return nil, fmt.Errorf("referee: the model header at %d would run past the end of the 16-bit "+
				"address space; the next read wraps to address 0 and the walk restarts somewhere else",
				cursor)
		}
		meta, err := t.ReadHolding(uint16(cursor), 2)
		if err != nil {
			return nil, fmt.Errorf("referee: read model header at %d: %w", cursor, err)
		}
		id, length := meta[0], meta[1]
		if id == sunspec.EndMarker {
			return out, nil
		}
		dataBase := cursor + 2
		if dataBase+uint32(length) > 0x10000 {
			return nil, fmt.Errorf("referee: model %d at %d declares %d registers, which runs past the end "+
				"of the address space (%d > 65536); the declared length is not believable and the blocks "+
				"after it cannot be located", id, dataBase, length, dataBase+uint32(length))
		}
		out = append(out, refBlock{ModelID: id, Base: uint16(dataBase), Length: length})
		cursor = dataBase + uint32(length)
	}
}

// ChainCase is one chain-walk probe.
type ChainCase struct {
	ID    string
	Title string
	// Regs is the register space, sparse; unset addresses read zero, which is
	// what an unmapped holding register reads on most devices.
	Regs map[uint16]uint16
	// Base is the address the SunS header is expected at.
	Base uint16
	// Why records what shape of device this is imitating.
	Why string
}

// chainDevice serves a raw register map with no SunSpec structure imposed.
type chainDevice struct {
	regs map[uint16]uint16
	// reads counts transactions, so a walk that will not terminate is visible
	// as a number rather than as a hang.
	reads int
	// limit stops a non-terminating product walk from running forever. It is
	// NOT a device behaviour; it is the harness refusing to hang, and the case
	// reports when it fired.
	limit    int
	exceeded bool
}

func (d *chainDevice) Open() error              { return nil }
func (d *chainDevice) Close() error             { return nil }
func (d *chainDevice) SetUnitID(id uint8) error { return nil }

func (d *chainDevice) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	d.reads++
	if d.limit > 0 && d.reads > d.limit {
		d.exceeded = true
		return nil, fmt.Errorf("chain harness: refusing a %dth read — this walk is not terminating", d.reads)
	}
	if quantity == 0 || quantity > 125 {
		return nil, fmt.Errorf("chain harness: illegal quantity %d", quantity)
	}
	out := make([]uint16, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = d.regs[addr+i]
	}
	return out, nil
}

func (d *chainDevice) ReadInput(addr, quantity uint16) ([]uint16, error) {
	return d.ReadHolding(addr, quantity)
}

func (d *chainDevice) WriteHolding(uint16, []uint16) error {
	return fmt.Errorf("chain harness is read-only")
}

// RunChain adjudicates one chain-walk case.
func RunChain(_ context.Context, c ChainCase) Case {
	out := Case{
		ID:      c.ID,
		Family:  "chain",
		Title:   c.Title,
		Input:   describeChain(c),
		Product: Side{Name: "product", Lineage: "lexa-proto/sunspec — Scan/ScanAt"},
		Referee: Side{Name: "referee", Lineage: "csip-tls-test/internal/diff — walk(), independent bounds reasoning"},
		Limitation: "both walkers read the same bytes through the same transport; this compares what each " +
			"is willing to CONCLUDE from a register space, not how either reads it",
	}
	if c.Why != "" {
		out.Title += " — " + c.Why
	}

	// Each side gets its own device instance so one side's read budget cannot
	// exhaust the other's, and so the read counts are separately meaningful.
	prodDev := &chainDevice{regs: c.Regs, limit: 4096}
	refDev := &chainDevice{regs: c.Regs, limit: 4096}

	prodBlocks, prodErr := sunspec.ScanAt(prodDev, c.Base)
	refBlocks, refErr := walk(refDev, c.Base)

	prodText := renderProductBlocks(prodBlocks, prodErr)
	refText := renderRefBlocks(refBlocks, refErr)

	product := T(ProductSide.Name, "chain.blocks", "%s", prodText).
		WithNote("%d reads", prodDev.reads)
	referee := T(RefereeSide.Name, "chain.blocks", "%s", refText).
		WithNote("%d reads", refDev.reads)

	out.Compare(CompareBool("chain.refused",
		product, referee,
		prodErr != nil, refErr != nil,
		"whether each walker refused this register space"))

	// Termination is adjudicated separately from refusal, because "both
	// refused" hides the distinction that matters most here: the referee
	// refused because it decided the chain was unwalkable, and the product
	// refused only because the harness cut it off after thousands of reads. A
	// walk that stops solely because somebody else stopped it has not
	// terminated, and a comparison that scored those two refusals as agreement
	// would be reporting a pass on the worst case in the family.
	out.Compare(CompareBool("chain.terminates",
		product, referee,
		!prodDev.exceeded, !refDev.exceeded,
		fmt.Sprintf("whether each walk stopped on its own (product made %d reads, referee %d, harness "+
			"ceiling %d)", prodDev.reads, refDev.reads, prodDev.limit)))

	if prodErr == nil && refErr == nil {
		out.Compare(CompareText("chain.blocks", product, referee))
	} else {
		out.Compare(SkipComparison("chain.blocks", "at least one walker refused, so there are not two "+
			"block lists to compare; the refusal comparison above is the adjudication"))
	}

	if refErr != nil && prodErr == nil {
		out.Note(Finding{
			ID:       out.ID + "/accepted-hostile-chain",
			Title:    "the product accepted a model chain the referee refuses as unwalkable",
			Severity: "P2",
			Input:    out.Input,
			Product:  product,
			Referee:  referee,
			Impact: "every register address the gateway uses on this device comes from this block list. " +
				"A block list derived from a chain that cannot be walked coherently addresses points " +
				"that are not where it thinks they are, and every value read afterwards is a different " +
				"point's value wearing the right name",
			Limitation: "the referee's bounds are stated in chain.go's package comment and are its reading " +
				"of the Device Information Model; a reviewer should check them before treating this as a " +
				"product defect",
			Facts: []invariant.Fact{
				invariant.F("chain.product", "", ProductSide.Name, "%s", prodText),
				invariant.F("chain.referee", "", RefereeSide.Name, "%s", refText),
			},
		})
	}
	if prodDev.exceeded {
		out.Note(Finding{
			ID:       out.ID + "/non-terminating",
			Title:    "the product's walk did not terminate and was stopped by the harness",
			Severity: "P1",
			Input:    out.Input,
			Product:  product.WithNote("stopped after %d reads by the harness, not by the walker", prodDev.reads),
			Referee:  referee,
			Impact: "a southbound device that presents this register space makes the gateway's discovery " +
				"loop issue Modbus transactions without bound. On a shared RTU bus that is a denial of " +
				"service against every other device on it",
		})
	}

	out.Finalize("neither walker produced anything to compare, which should be impossible")
	return out
}

// renderBlocks is the shared, BOUNDED rendering both sides get.
//
// It is bounded because a hostile chain can produce a thousand blocks, and a
// report that pastes all of them is a report nobody reads. The elision keeps
// the head and the total, which is what a comparison needs: two block lists
// that differ do so within the first few entries or in their length, and both
// survive the truncation.
func renderBlocks(parts []string, err error) string {
	if err != nil {
		return "REFUSED: " + err.Error()
	}
	if len(parts) == 0 {
		return "(no blocks)"
	}
	const show = 8
	if len(parts) <= show {
		return strings.Join(parts, " ")
	}
	return fmt.Sprintf("%s … (%d blocks in total, last %s)",
		strings.Join(parts[:show], " "), len(parts), parts[len(parts)-1])
}

func renderProductBlocks(blocks []sunspec.Block, err error) string {
	parts := make([]string, 0, len(blocks))
	for _, b := range blocks {
		parts = append(parts, fmt.Sprintf("%d@%d+%d", b.ModelID, b.BaseAddr, b.Length))
	}
	return renderBlocks(parts, err)
}

func renderRefBlocks(blocks []refBlock, err error) string {
	parts := make([]string, 0, len(blocks))
	for _, b := range blocks {
		parts = append(parts, b.String())
	}
	return renderBlocks(parts, err)
}

func describeChain(c ChainCase) string {
	return fmt.Sprintf("base=%d regs=%d entries", c.Base, len(c.Regs))
}

// ── Fixture construction ─────────────────────────────────────────────────────

// chainBuilder assembles a register space model by model.
type chainBuilder struct {
	regs   map[uint16]uint16
	cursor uint16
	base   uint16
}

func newChain(base uint16) *chainBuilder {
	b := &chainBuilder{regs: map[uint16]uint16{}, base: base, cursor: base}
	b.regs[base] = sunspec.SunSMagic0
	b.regs[base+1] = sunspec.SunSMagic1
	b.cursor = base + 2
	return b
}

// model appends a model header and declaredLen registers of data, where the
// header CLAIMS declaredLen. A device that lies is built by declaring one length
// and writing another.
func (b *chainBuilder) model(id, declaredLen, actualLen uint16) *chainBuilder {
	b.regs[b.cursor] = id
	b.regs[b.cursor+1] = declaredLen
	for i := uint16(0); i < actualLen; i++ {
		b.regs[b.cursor+2+i] = 0x1000 + i
	}
	b.cursor += 2 + actualLen
	return b
}

func (b *chainBuilder) end() map[uint16]uint16 {
	b.regs[b.cursor] = sunspec.EndMarker
	b.regs[b.cursor+1] = 0
	return b.regs
}

// noEnd finishes without an end marker.
func (b *chainBuilder) noEnd() map[uint16]uint16 { return b.regs }

// ChainCatalog is the standing set of chain-walk probes. Every entry is a
// register space a real (broken or hostile) device could present.
func ChainCatalog() []ChainCase {
	const base = 40000
	return []ChainCase{
		{
			ID: "DIFF-CHAIN-001", Title: "an ordinary three-model chain",
			Base: base, Regs: newChain(base).model(1, 66, 66).model(701, 153, 153).model(702, 50, 50).end(),
			Why: "the control case — both walkers must agree exactly",
		},
		{
			ID: "DIFF-CHAIN-002", Title: "no end marker at all",
			Base: base, Regs: newChain(base).model(701, 153, 153).noEnd(),
			Why: "the registers past the chain read zero, so the list continues as model 0 length 0 forever",
		},
		{
			ID: "DIFF-CHAIN-003", Title: "a zero-length model in the middle",
			Base: base, Regs: newChain(base).model(701, 153, 153).model(999, 0, 0).model(702, 50, 50).end(),
			Why: "legal, and must not stall either walker",
		},
		{
			ID: "DIFF-CHAIN-004", Title: "a model declaring 65535 registers",
			Base: base, Regs: newChain(base).model(701, 65535, 4).end(),
			Why: "the declared length runs past the end of the address space",
		},
		{
			ID: "DIFF-CHAIN-005", Title: "a chain that runs off the top of the address space",
			Base: 65000, Regs: newChain(65000).model(701, 600, 8).end(),
			Why: "65002 + 2 + 600 wraps; the next header read lands at a low address",
		},
		{
			ID: "DIFF-CHAIN-006", Title: "the end marker carrying a non-zero length",
			Base: base, Regs: newChain(base).model(701, 4, 4).model(sunspec.EndMarker, 99, 0).end(),
			Why: "0xFFFF terminates whatever length says; a walker that trusts the length instead walks on",
		},
		{
			ID: "DIFF-CHAIN-007", Title: "the same model id twice",
			Base: base, Regs: newChain(base).model(702, 50, 50).model(702, 50, 50).end(),
			Why: "which one wins is a resolution question both sides must answer the same way",
		},
		{
			ID: "DIFF-CHAIN-008", Title: "a header that lies: declares 4, the next header is 8 later",
			Base: base, Regs: newChain(base).model(701, 4, 8).model(702, 50, 50).end(),
			Why: "the declared length misaddresses every following block",
		},
		{
			ID: "DIFF-CHAIN-009", Title: "no SunS magic at the base",
			Base: base, Regs: map[uint16]uint16{base: 0x0000, base + 1: 0x0000},
			Why: "both walkers must refuse; a walker that proceeds is reading someone else's registers",
		},
		{
			ID: "DIFF-CHAIN-010", Title: "a chain of a thousand zero-length models",
			Base: base, Regs: manyZeroLengthModels(base, 1000),
			Why: "each step advances by two registers, so it terminates eventually — but not before a " +
				"thousand Modbus transactions",
		},
	}
}

func manyZeroLengthModels(base uint16, n int) map[uint16]uint16 {
	b := newChain(base)
	for i := 0; i < n; i++ {
		b.model(uint16(500+i%50), 0, 0)
	}
	return b.end()
}

// RunChainCatalog runs the standing chain cases into a report.
func RunChainCatalog(ctx context.Context, r *Report) {
	for _, c := range ChainCatalog() {
		r.Add(RunChain(ctx, c))
	}
}
