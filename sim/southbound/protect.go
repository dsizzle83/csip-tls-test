package sim

// protect.go — write-protection for SunSpec scale-factor registers.
//
// A real device's SF registers are read-only, and the sims accepting writes to
// them turned a hub bug into silent, permanent corruption (audit E1: during a
// nan_sentinel READ-fault window the hub's derbase whole-block 704
// read-modify-write read all-0x8000 and wrote it straight back, poisoning the
// register bank — including the scale factors — until a sim restart). Masking
// only the protected cells while the rest of the write lands keeps the
// behaviour device-realistic and makes the bad write-back an OBSERVABLE
// divergence (a counter on /state plus a log line) instead of a silent one.
// The nan_sentinel READ fault itself is untouched — QA depends on it.
//
// The protected set is derived from the same layout metadata the hub decodes
// with (every Tsunssf field of each 7xx model served); the legacy models
// predate the Layout engine, so their SF cells are listed explicitly from the
// models.go constants.

import (
	"log"

	"lexa-proto/sunspec"
)

// Protect marks addrs as immune to Modbus writes: HandleHoldingRegisters
// masks the protected cells back to their currently-stored values while
// applying the rest of the write. Sim-internal Set is unaffected, so
// populate/animation/fault code still owns these registers.
func (r *RegisterMap) Protect(addrs ...uint16) {
	r.mu.Lock()
	if r.protected == nil {
		r.protected = make(map[uint16]bool, len(addrs))
	}
	for _, a := range addrs {
		r.protected[a] = true
	}
	r.mu.Unlock()
}

// ProtectedRejects returns how many Modbus write cells tried to CHANGE a
// protected register and were masked. Writing the value already stored (the
// hub's routine whole-block read-modify-write echoing the true SFs back) is
// not a divergence and is not counted.
func (r *RegisterMap) ProtectedRejects() uint64 {
	r.mu.Lock()
	n := r.protectedRejects
	r.mu.Unlock()
	return n
}

// maskProtected returns vals with every protected cell in [start, start+len)
// forced back to its currently-stored value, counting value-changing masks.
// One log line per write transaction that masked anything — writes arrive at
// control-loop cadence, so the log is naturally rate-limited.
func (r *RegisterMap) maskProtected(start uint16, vals []uint16) []uint16 {
	r.mu.Lock()
	if len(r.protected) == 0 {
		r.mu.Unlock()
		return vals
	}
	out := vals
	masked := 0
	for i := range vals {
		addr := start + uint16(i)
		if !r.protected[addr] || vals[i] == r.regs[addr] {
			continue
		}
		if masked == 0 {
			out = append([]uint16(nil), vals...)
		}
		out[i] = r.regs[addr]
		masked++
	}
	r.protectedRejects += uint64(masked)
	total := r.protectedRejects
	r.mu.Unlock()
	if masked > 0 {
		log.Printf("[sim] masked %d write(s) to protected SF register(s) in [%d..%d] (read-only on a real device; sf_write_rejects=%d)",
			masked, start, int(start)+len(vals)-1, total)
	}
	return out
}

// protectLayoutSFs write-protects every scale-factor (Tsunssf) field of a
// layout-described model whose data block starts at base. Deriving from the
// layout keeps the protected set in lockstep with the models the sim serves.
func protectLayoutSFs(r *RegisterMap, base uint16, l *sunspec.Layout) {
	for _, f := range l.Fields {
		if f.Type == sunspec.Tsunssf {
			r.Protect(base + uint16(l.Offset(f.Name)))
		}
	}
}

// protectSolarLegacySFs write-protects the SF registers of the legacy solar
// models (120/121/122/103/123). These predate the Layout engine — their
// offsets are hand-declared constants, not Layout fields — so the cells are
// listed explicitly; keep the list in step with models.go if a model is added.
func protectSolarLegacySFs(r *RegisterMap, b SolarBases) {
	protectM123SFs(r, b.M123Base)
	r.Protect(
		b.M120Base+sunspec.M120_W_SF,
		b.M120Base+sunspec.M120_VARtg_SF,
		b.M120Base+sunspec.M120_VArRtg_SF,
		b.M120Base+sunspec.M120_ARtg_SF,
		b.M120Base+sunspec.M120_PFRtg_SF,
		b.M120Base+sunspec.M120_WHRtg_SF,
		b.M120Base+sunspec.M120_AhrRtg_SF,
		b.M120Base+sunspec.M120_MaxChaRte_SF,
		b.M120Base+sunspec.M120_MaxDisChaRte_SF,
		b.M121Base+sunspec.M121_WMax_SF,
		b.M122Base+sunspec.M122_WAval_SF,
		b.M103Base+sunspec.M103_A_SF,
		b.M103Base+sunspec.M103_V_SF,
		b.M103Base+sunspec.M103_W_SF,
		b.M103Base+sunspec.M103_Hz_SF,
		b.M103Base+sunspec.M103_VA_SF,
		b.M103Base+sunspec.M103_VAr_SF,
		b.M103Base+sunspec.M103_PF_SF,
		b.M103Base+sunspec.M103_WH_SF,
		b.M103Base+sunspec.M103_DCA_SF,
		b.M103Base+sunspec.M103_DCV_SF,
		b.M103Base+sunspec.M103_DCW_SF,
		b.M103Base+sunspec.M103_Tmp_SF,
	)
}

// protectM123SFs write-protects model 123's three scale factors.
//
// Model 123's three scale factors, layout-derived (A3 adjudication,
// 2026-08-15).
//
// THE ANSWER IS YES, AND THE BATTERY HAD NO PROTECTION AT ALL. The question
// raised was whether M123's SFs should join the layout-driven protection
// the 7xx models get. They should, and the reason is not symmetry: the
// battery decodes its commanded ceiling THROUGH this scale factor
// (battery.go and battery_pack.go both read M123_WMaxLimPct_SF to turn the
// raw register into a percentage), so a writable SF lets a client change
// the MEANING of every subsequent ceiling read without touching the ceiling
// register. The solar sim listed the three cells by hand and was covered;
// the battery sims protected 701/702/703/704/713 and never mentioned 123.
//
// It goes through protectLayoutSFs rather than three more hand-listed cells
// because sunspec.L123 now EXISTS (lexa-proto 32150e1). The hand-listed
// path was only ever a workaround for a model with no layout — and a
// hand-maintained list of a hand-transcribed map is precisely the pairing
// that produced the wrong register map in the first place.
func protectM123SFs(r *RegisterMap, base uint16) {
	protectLayoutSFs(r, base, sunspec.L123)
}
