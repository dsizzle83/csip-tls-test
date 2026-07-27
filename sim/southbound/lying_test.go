package sim

// lying_test.go — TEETH for the lying-device layer.
//
// Every test here is a pair: the lie armed must produce the false observation,
// and the SAME probe with the lie clear must produce the true one. A one-sided
// test ("with the fault armed, the value was 3000") proves only that a number
// exists; it is the contrast that proves the injector is the cause, and the
// clear-side assertion is what keeps a future refactor from turning a lie into
// a no-op that still passes.
//
// Two of them go further and assert the property that makes the lie USEFUL
// rather than merely present: that the sim's own ground truth (the register
// bank, which is what /registers and /state serve) stays HONEST while the
// Modbus read path lies. That divergence is the entire observable an oracle
// has, so a lie that corrupted the bank as well would be worse than useless —
// it would be undetectable — and these tests are what stop that regression.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// newLyingSolar builds a solar sim wired exactly as a real one — populate,
// fault hooks, lie hooks — but with no listener, so the register-level lies can
// be driven through the RegisterMap's own handler without a socket.
func newLyingSolar(t *testing.T, wmax float64) *SolarServer {
	t.Helper()
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	bases := populateSolar(regs, wmax, "")
	ss := &SolarServer{Server: &Server{Regs: regs}, bases: bases, wmaxW: wmax}
	ss.faults.label = "solar"
	ss.faults.configureGate(bases.M123Base + sunspec.M123_WMaxLimPct_Ena)
	ss.faults.configureScale(bases.M103Base + sunspec.M103_W_SF)
	regs.OnWriteAttempt = ss.interceptWrite
	regs.OnRead = ss.faults.transportRead
	// The real constructors pass Server.dropConnections; there is no listener
	// here, so the re-announce is a no-op the tests do not exercise.
	ss.lies.configure("solar", regs, bases.M123Base+sunspec.M123_WMaxLimPct,
		bases.M103Base, 50, map[string]uint16{
			"W":   bases.M103Base + sunspec.M103_W,
			"VAr": bases.M103Base + sunspec.M103_VAr,
		}, ss.powerOnReset, nil)
	ss.lies.wrap(regs)
	return ss
}

// arm posts a fault body to the sim exactly as simapi would.
func arm(t *testing.T, ss *SolarServer, body string) {
	t.Helper()
	if err := ss.ApplyFault([]byte(body)); err != nil {
		t.Fatalf("arm %s: %v", body, err)
	}
}

// modbusRead drives a read through the full server handler, so the lies are
// exercised on the path a real client uses rather than through a back door.
func modbusRead(t *testing.T, ss *SolarServer, addr, quantity uint16) ([]uint16, error) {
	t.Helper()
	return ss.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: addr, Quantity: quantity,
	})
}

// modbusWrite drives a write through the full server handler.
func modbusWrite(t *testing.T, ss *SolarServer, addr uint16, vals ...uint16) error {
	t.Helper()
	_, err := ss.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: addr, Quantity: uint16(len(vals)), IsWrite: true, Args: vals,
	})
	return err
}

// ── revert_after ─────────────────────────────────────────────────────────────

// TestRevertAfter_UndoesTheCommandSilently is the teeth for the nastiest of the
// seven: a curtailment that is accepted, confirmed on readback, and then gone.
// The test asserts both halves of what makes it a LIE — the readback right after
// the write agrees with the command (so a hub that verifies once is satisfied),
// and the register later holds the value the hub never asked for, with no error
// and no notification in between.
func TestRevertAfter_UndoesTheCommandSilently(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	prior := ss.Regs.Get(cmd)

	arm(t, ss, `{"kind":"revert_after","delay_s":0.05}`)
	if err := modbusWrite(t, ss, cmd, 5000); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The verification a hub actually performs: read the value straight back.
	got, err := modbusRead(t, ss, cmd, 1)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if got[0] != 5000 {
		t.Fatalf("immediate readback = %d, want 5000 — the fault must let the write LAND, "+
			"or it is reject_write and catches a hub that never verifies", got[0])
	}

	waitFor(t, time.Second, func() bool { return ss.Regs.Get(cmd) == prior })
	if n := ss.lies.Stats().Fired["revert_after"]; n != 1 {
		t.Fatalf("revert fired %d times, want 1", n)
	}
}

// TestRevertAfter_ClearedLeavesTheCommandAlone is the other half of the pair:
// with the lie cleared, the same write survives. Without this, a revert_after
// that had been broken into "always revert" would still pass the test above.
func TestRevertAfter_ClearedLeavesTheCommandAlone(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct

	arm(t, ss, `{"kind":"revert_after","delay_s":0.05}`)
	arm(t, ss, `{"kind":"revert_after","clear":true}`)
	if err := modbusWrite(t, ss, cmd, 5000); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if v := ss.Regs.Get(cmd); v != 5000 {
		t.Fatalf("cleared revert_after still moved the register to %d — the clear does not disarm", v)
	}
}

// TestRevertAfter_RearmsOnEachWrite proves the timer tracks the LATEST command:
// a hub that re-asserts its limit inside the window keeps it, which is what
// makes the fault a test of re-assertion cadence rather than a fixed fuse.
func TestRevertAfter_RearmsOnEachWrite(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct

	arm(t, ss, `{"kind":"revert_after","delay_s":0.2}`)
	for i := 0; i < 4; i++ {
		if err := modbusWrite(t, ss, cmd, 5000); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(60 * time.Millisecond)
		if v := ss.Regs.Get(cmd); v != 5000 {
			t.Fatalf("after re-assertion %d the register is %d — the timer did not re-arm", i, v)
		}
	}
}

// ── freeze_block ─────────────────────────────────────────────────────────────

// TestFreezeBlock_ReadsAreStaleWhileTheBankMoves is the load-bearing test of the
// whole file: the Modbus read path must lie WHILE the register bank tells the
// truth, because the divergence between the two is the only thing an external
// oracle can observe. If a future change made the freeze act on the bank, this
// test fails — and it should, because such a device could not be caught.
func TestFreezeBlock_ReadsAreStaleWhileTheBankMoves(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	wAddr := ss.bases.M103Base + sunspec.M103_W

	ss.Regs.Set(wAddr, 3000)
	arm(t, ss, `{"kind":"freeze_block"}`)

	// The world moves on: the animation would do this; the test does it directly.
	ss.Regs.Set(wAddr, 7000)

	got, err := modbusRead(t, ss, wAddr, 1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[0] != 3000 {
		t.Fatalf("frozen read = %d, want the 3000 snapshotted at arm time", got[0])
	}
	if truth := ss.Regs.Get(wAddr); truth != 7000 {
		t.Fatalf("ground truth = %d, want 7000 — freeze_block must NOT touch the bank, "+
			"or the sidecar stops being an independent witness and the lie is undetectable", truth)
	}

	arm(t, ss, `{"kind":"freeze_block","clear":true}`)
	got, err = modbusRead(t, ss, wAddr, 1)
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if got[0] != 7000 {
		t.Fatalf("read after clear = %d, want the live 7000 — the clear does not thaw", got[0])
	}
}

// TestFreezeBlock_LeavesRegistersOutsideTheWindowLive keeps the fault surgical:
// a device whose telemetry is stuck still answers its control registers, so a
// scenario can freeze measurements and still drive the control loop.
func TestFreezeBlock_LeavesRegistersOutsideTheWindowLive(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	arm(t, ss, `{"kind":"freeze_block"}`)
	ss.Regs.Set(cmd, 4200)

	got, err := modbusRead(t, ss, cmd, 1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[0] != 4200 {
		t.Fatalf("control register read = %d, want the live 4200 — the freeze window leaked past model 103", got[0])
	}
}

// ── sentinel_field ───────────────────────────────────────────────────────────

// TestSentinelField_BlanksOnlyTheNamedFields is the difference from
// nan_sentinel, stated as an assertion: model discovery must survive. A hub can
// only be fooled by a not-implemented value if it can still find the model the
// value is in.
func TestSentinelField_BlanksOnlyTheNamedFields(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	wAddr := ss.bases.M103Base + sunspec.M103_W
	vaAddr := ss.bases.M103Base + sunspec.M103_VA

	arm(t, ss, `{"kind":"sentinel_field","fields":["W"]}`)
	got, err := modbusRead(t, ss, ss.bases.M103Base, 20)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if v := got[wAddr-ss.bases.M103Base]; v != sunSpecNA {
		t.Fatalf("W = 0x%04x, want the 0x8000 not-implemented sentinel", v)
	}
	if v := got[vaAddr-ss.bases.M103Base]; v != ss.Regs.Get(vaAddr) {
		t.Fatalf("VA = %d but the bank holds %d — sentinel_field blanked a field it was not given", v, ss.Regs.Get(vaAddr))
	}
	// Model discovery: the id/len pair two registers below the data block.
	hdr, err := modbusRead(t, ss, ss.bases.M103Base-2, 2)
	if err != nil {
		t.Fatalf("discovery read: %v", err)
	}
	if hdr[0] != sunspec.ModelInverterThreePh {
		t.Fatalf("model id reads %d — sentinel_field broke the chain and became nan_sentinel", hdr[0])
	}

	arm(t, ss, `{"kind":"sentinel_field","clear":true}`)
	got, err = modbusRead(t, ss, wAddr, 1)
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if got[0] == sunSpecNA {
		t.Fatalf("W still reads the sentinel after clear")
	}
}

// TestSentinelField_RefusesToBlankNothing is the anti-vacuous-fault check: an
// arm with neither addrs nor fields must be an error. A fault that silently
// arms as a no-op is how a scenario comes back PASS having tested nothing.
func TestSentinelField_RefusesToBlankNothing(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	if err := ss.ApplyFault([]byte(`{"kind":"sentinel_field"}`)); err == nil {
		t.Fatal("arming sentinel_field with no addrs and no fields must be an error, not a no-op fault")
	}
	if err := ss.ApplyFault([]byte(`{"kind":"sentinel_field","fields":["Nonesuch"]}`)); err == nil {
		t.Fatal("an unknown field name must be an error naming the known ones")
	}
}

// ── reboot_forget ────────────────────────────────────────────────────────────

// TestRebootForget_DropsTheCommandedLimit asserts the state really is gone — the
// point being that a hub which sees the device reappear and assumes its
// curtailment survived is now running an uncurtailed inverter.
func TestRebootForget_DropsTheCommandedLimit(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	b := ss.bases
	if err := modbusWrite(t, ss, b.M123Base+sunspec.M123_WMaxLimPct, 3000); err != nil {
		t.Fatalf("write limit: %v", err)
	}
	ss.Regs.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)

	arm(t, ss, `{"kind":"reboot_forget"}`)

	if v := ss.Regs.Get(b.M123Base + sunspec.M123_WMaxLimPct); v != 10000 {
		t.Fatalf("WMaxLimPct = %d after the reboot, want the 10000 power-on default", v)
	}
	if v := ss.Regs.Get(b.M123Base + sunspec.M123_WMaxLimPct_Ena); v != 0 {
		t.Fatalf("the limit is still ENABLED after the reboot — the device did not forget")
	}
}

// TestRebootForget_ClearIsNotASecondReboot pins the one-shot contract. A
// teardown that clears every armed fault must not reboot the device again, or
// the scenario's own cleanup becomes an unlogged second fault.
func TestRebootForget_ClearIsNotASecondReboot(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	arm(t, ss, `{"kind":"reboot_forget"}`)
	arm(t, ss, `{"kind":"reboot_forget","clear":true}`)
	if n := ss.lies.Stats().Fired["reboot_forget"]; n != 1 {
		t.Fatalf("reboot fired %d times across arm+clear, want exactly 1", n)
	}
}

// ── layout_shift ─────────────────────────────────────────────────────────────

// TestLayoutShift_MovesEveryModelAfterTheSplice is the "firmware update" test.
// It asserts three things at once, because the fault is only interesting if all
// three hold: the chain the client walks is still WELL-FORMED (so a re-walking
// hub is fine), every later model has MOVED (so a caching hub is wrong), and
// the bank is untouched (so the sidecar still tells the truth).
func TestLayoutShift_MovesEveryModelAfterTheSplice(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	const delta = 8
	base := uint16(sunspec.SunSpecBase)
	m1Len := ss.Regs.Get(base + 3)
	spliceAt := base + 4 + m1Len // the second model's id register

	// What the client saw before the "update".
	before, err := modbusRead(t, ss, spliceAt, 2)
	if err != nil {
		t.Fatalf("pre-shift read: %v", err)
	}

	arm(t, ss, fmt.Sprintf(`{"kind":"layout_shift","delta":%d}`, delta))

	after, err := modbusRead(t, ss, spliceAt, 2+delta)
	if err != nil {
		t.Fatalf("post-shift read: %v", err)
	}
	if after[0] != defaultFillerModel || after[1] != delta-2 {
		t.Fatalf("spliced header = id %d len %d, want id %d len %d — the chain is not well-formed, "+
			"so a conformant re-walking hub would fail for the wrong reason",
			after[0], after[1], defaultFillerModel, delta-2)
	}
	if after[delta] != before[0] || after[delta+1] != before[1] {
		t.Fatalf("the model that was at %d did not move to %d — a caching hub would still be right",
			spliceAt, spliceAt+delta)
	}
	if got := ss.Regs.Get(spliceAt); got != before[0] {
		t.Fatalf("the register BANK moved (%d at %d) — layout_shift must be a read-path remap, "+
			"or the sim's own /registers stops being ground truth", got, spliceAt)
	}
}

// TestLayoutShift_SwallowsAWriteAtAPreUpdateAddress is the payload of the fault:
// the hub that cached its model bases writes its power limit into the vendor
// block that now occupies those addresses, the write ACKs, and nothing happens.
func TestLayoutShift_SwallowsAWriteAtAPreUpdateAddress(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	prior := ss.Regs.Get(cmd)

	arm(t, ss, `{"kind":"layout_shift","delta":8}`)

	// The stale hub writes to the OLD control address.
	if err := modbusWrite(t, ss, cmd, 2500); err != nil {
		t.Fatalf("stale write: %v", err)
	}
	if v := ss.Regs.Get(cmd); v != prior {
		t.Fatalf("the pre-update address still reached the control register (%d) — "+
			"the remap is not applied to writes, so the fault cannot catch a caching hub", v)
	}

	// The hub that re-walked the chain writes to the NEW address and it lands.
	if err := modbusWrite(t, ss, cmd+8, 2500); err != nil {
		t.Fatalf("re-walked write: %v", err)
	}
	if v := ss.Regs.Get(cmd); v != 2500 {
		t.Fatalf("a write at the SHIFTED address landed at %d, want 2500 — "+
			"the fault punishes a conformant hub, which makes it a bad fault", v)
	}
}

// ── exception_on_applied_write ───────────────────────────────────────────────

// TestExceptionOnApplied_RefusesAWriteItApplied is I3's grounding shape, which
// the bench could not produce before this file: the protocol says refused, the
// device says applied. Everything a hub concludes from the refusal — retry,
// fall back, report CannotComply, persist the failure and re-actuate later — is
// now wrong in the direction that moves real power.
func TestExceptionOnApplied_RefusesAWriteItApplied(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct

	arm(t, ss, `{"kind":"exception_on_applied_write","ex_code":4}`)
	err := modbusWrite(t, ss, cmd, 3300)
	if err == nil {
		t.Fatal("the write must be REFUSED at the protocol layer")
	}
	if err != modbuslib.ErrServerDeviceFailure {
		t.Fatalf("refused with %v, want the requested 0x04 server-device-failure — "+
			"an oracle keyed on the code cannot be falsified if the code is arbitrary", err)
	}
	if v := ss.Regs.Get(cmd); v != 3300 {
		t.Fatalf("the register holds %d — the write must have APPLIED, or this is an honest refusal "+
			"and I3 has nothing to catch", v)
	}

	arm(t, ss, `{"kind":"exception_on_applied_write","clear":true}`)
	if err := modbusWrite(t, ss, cmd, 4400); err != nil {
		t.Fatalf("cleared fault still refuses: %v", err)
	}
}

// TestExceptionOnApplied_EveryNRefusesIntermittently covers the harder shape: a
// device that refuses one write in N is far more likely to be shrugged off as a
// transient than one that refuses every time, and a hub's retry path is exactly
// where a refused-but-applied write gets actuated twice.
func TestExceptionOnApplied_EveryNRefusesIntermittently(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	arm(t, ss, `{"kind":"exception_on_applied_write","every":3}`)

	var refused int
	for i := 0; i < 9; i++ {
		if err := modbusWrite(t, ss, cmd, uint16(1000+i)); err != nil {
			refused++
		}
	}
	if refused != 3 {
		t.Fatalf("refused %d of 9 writes with every=3, want 3", refused)
	}
	if v := ss.Regs.Get(cmd); v != 1008 {
		t.Fatalf("the last write left %d, want 1008 — every write must land regardless of the answer", v)
	}
}

// TestExceptionOnApplied_RejectsAnUnencodableCode keeps the arm honest: the
// operator asked for a specific exception code, and quietly substituting a
// different one would make any oracle keyed on the code untrustworthy.
func TestExceptionOnApplied_RejectsAnUnencodableCode(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	if err := ss.ApplyFault([]byte(`{"kind":"exception_on_applied_write","ex_code":99}`)); err == nil {
		t.Fatal("an exception code with no Modbus encoding must be refused at arm time, not substituted")
	}
}

// ── slow_poll ────────────────────────────────────────────────────────────────

// TestSlowPoll_StacksConcurrentReads proves the fault's actual claim. A test
// that only measured elapsed time would prove the sleep happened; what matters
// is that a second poll STARTED while the first was still being served, because
// that is the condition — not the latency — that finds a hub's connection and
// goroutine accounting.
func TestSlowPoll_StacksConcurrentReads(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	arm(t, ss, `{"kind":"slow_poll","hold_ms":120}`)

	const n = 4
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			_, _ = modbusRead(t, ss, ss.bases.M103Base, 4)
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	st := ss.lies.Stats()
	if st.PeakInFlight < 2 {
		t.Fatalf("peak in-flight = %d, want >= 2 — the hold did not actually stack requests, "+
			"so slow_poll is only a latency fault under another name", st.PeakInFlight)
	}
	if st.Stacked == 0 {
		t.Fatal("no read began while another was held")
	}

	arm(t, ss, `{"kind":"slow_poll","clear":true}`)
	start := time.Now()
	if _, err := modbusRead(t, ss, ss.bases.M103Base, 4); err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if el := time.Since(start); el > 60*time.Millisecond {
		t.Fatalf("a read after clear took %s — the hold is still armed", el)
	}
}

// ── ack_no_apply ─────────────────────────────────────────────────────────────

// TestAckNoApply_AcceptsTheWriteAndStoresNothing is the classic in its
// detectable form. The write must succeed at the Modbus layer — no exception,
// nothing a client could log — while the register never moves. A hub that
// verifies its writes catches this one, and that is the point: the fault
// separates hubs that read back from hubs that trust an ACK, and only the second
// kind reports a curtailment that is not in force.
func TestAckNoApply_AcceptsTheWriteAndStoresNothing(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	prior := ss.Regs.Get(cmd)

	arm(t, ss, `{"kind":"ack_no_apply"}`)
	if err := modbusWrite(t, ss, cmd, 3700); err != nil {
		t.Fatalf("the write must be ACCEPTED — an exception here is reject_write, a different and safer device: %v", err)
	}
	if v := ss.Regs.Get(cmd); v != prior {
		t.Fatalf("the register moved to %d — ack_no_apply must store NOTHING", v)
	}
	got, err := modbusRead(t, ss, cmd, 1)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if got[0] != prior {
		t.Fatalf("readback = %d, want the unchanged %d — without echo, a readback must tell the TRUTH, "+
			"or the fault has no version a verifying hub can catch", got[0], prior)
	}
	if n := ss.lies.Stats().Fired["ack_no_apply"]; n != 1 {
		t.Fatalf("ack_no_apply fired %d times, want 1", n)
	}
}

// TestAckNoApply_EchoDefeatsReadbackWhileGroundTruthStaysHonest is the version
// no Modbus client can detect. The write is ACKed, nothing is stored, and every
// readback returns the value that was never stored — so write-then-verify, and
// verify again on every poll thereafter, all agree on a limit that is not in
// force.
//
// The second half is what makes it testable at all: the register BANK still
// holds the old value, and the bank is what /registers and /state serve. The
// only observer that can see this lie is one comparing the device's own account
// of itself against what the device tells the hub — which is precisely the
// divergence internal/invariant's World is built from. If this assertion ever
// fails, the fault has become undetectable rather than merely nasty.
func TestAckNoApply_EchoDefeatsReadbackWhileGroundTruthStaysHonest(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	prior := ss.Regs.Get(cmd)

	arm(t, ss, `{"kind":"ack_no_apply","echo":true}`)
	if err := modbusWrite(t, ss, cmd, 3700); err != nil {
		t.Fatalf("write: %v", err)
	}
	for i := 0; i < 3; i++ {
		got, err := modbusRead(t, ss, cmd, 1)
		if err != nil {
			t.Fatalf("readback %d: %v", i, err)
		}
		if got[0] != 3700 {
			t.Fatalf("readback %d = %d, want the phantom 3700 — the echo must survive REPEATED verification, "+
				"or a hub that polls its own limit notices on the second poll", i, got[0])
		}
	}
	if v := ss.Regs.Get(cmd); v != prior {
		t.Fatalf("the register bank moved to %d — ground truth must stay honest or the lie is undetectable "+
			"by anyone, which is untestable rather than adversarial", v)
	}

	arm(t, ss, `{"kind":"ack_no_apply","clear":true}`)
	got, err := modbusRead(t, ss, cmd, 1)
	if err != nil {
		t.Fatalf("readback after clear: %v", err)
	}
	if got[0] != prior {
		t.Fatalf("readback after clear = %d, want %d — clearing must drop the phantom, or no recovery arm "+
			"of any scenario can ever be falsified", got[0], prior)
	}
}

// TestAckNoApply_ClearedLetsTheWriteLand is the healthy pair. Without it, an
// ack_no_apply broken into "always swallow" would still pass both tests above.
func TestAckNoApply_ClearedLetsTheWriteLand(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct

	arm(t, ss, `{"kind":"ack_no_apply","echo":true}`)
	arm(t, ss, `{"kind":"ack_no_apply","clear":true}`)
	if err := modbusWrite(t, ss, cmd, 4200); err != nil {
		t.Fatalf("write: %v", err)
	}
	if v := ss.Regs.Get(cmd); v != 4200 {
		t.Fatalf("register = %d after a write with the lie cleared, want 4200 — the clear does not disarm", v)
	}
}

// TestAckNoApply_LeavesUntargetedRegistersAlone is the scope guard. Arming the
// lie on one field must not turn the device into one that drops every write:
// the blast radius has to be exactly the targeted addresses, or a scenario
// cannot attribute what it observes to the fault it armed.
func TestAckNoApply_LeavesUntargetedRegistersAlone(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	ena := ss.bases.M123Base + sunspec.M123_WMaxLimPct_Ena

	arm(t, ss, fmt.Sprintf(`{"kind":"ack_no_apply","addrs":[%d]}`, cmd))
	if err := modbusWrite(t, ss, ena, 1); err != nil {
		t.Fatalf("write to an untargeted register: %v", err)
	}
	if v := ss.Regs.Get(ena); v != 1 {
		t.Fatalf("an untargeted register did not take its write (= %d) — the lie is not scoped", v)
	}
	if n := ss.lies.Stats().Fired["ack_no_apply"]; n != 0 {
		t.Fatalf("the lie fired %d times on a write it does not target", n)
	}
}

// TestAckNoApply_MixedBlockDropsOnlyTheTarget covers the case the write path had
// to be written carefully for: one block write spanning a targeted and an
// untargeted register. The surviving register must take its value — a device
// that dropped the whole block would be a much cruder fault, and would mask the
// enable/limit split that makes SunSpec control writes worth attacking.
func TestAckNoApply_MixedBlockDropsOnlyTheTarget(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	cmd := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	ena := ss.bases.M123Base + sunspec.M123_WMaxLimPct_Ena
	if ena != cmd+1 {
		t.Skipf("this fixture assumes WMaxLimPct_Ena directly follows WMaxLimPct (got %d, %d)", cmd, ena)
	}
	prior := ss.Regs.Get(cmd)

	arm(t, ss, fmt.Sprintf(`{"kind":"ack_no_apply","addrs":[%d]}`, cmd))
	if err := modbusWrite(t, ss, cmd, 3700, 1); err != nil {
		t.Fatalf("block write: %v", err)
	}
	if v := ss.Regs.Get(cmd); v != prior {
		t.Fatalf("the targeted register moved to %d in a mixed block", v)
	}
	if v := ss.Regs.Get(ena); v != 1 {
		t.Fatalf("the untargeted register in the same block = %d, want 1 — the whole block was dropped", v)
	}
}

// TestAckNoApply_RefusesWhenItHasNothingToTarget: a sim with no control register
// and no addrs given must ERROR rather than arm a fault that targets nothing. An
// injector that arms successfully and does nothing is the worst outcome
// available — the scenario reports its adversary as armed and observes a device
// behaving perfectly.
func TestAckNoApply_RefusesWhenItHasNothingToTarget(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	ss.lies.cmdAddr = 0
	if err := ss.ApplyFault([]byte(`{"kind":"ack_no_apply"}`)); err == nil {
		t.Fatal("arming with no target and no default must be an error")
	}
	if err := ss.ApplyFault([]byte(`{"kind":"ack_no_apply","fields":["nope"]}`)); err == nil {
		t.Fatal("an unknown field name must be an error, not a silently empty target set")
	}
}

// ── routing ──────────────────────────────────────────────────────────────────

// TestLieKindsDoNotCollideWithFaultKinds guards the one structural hazard of
// adding a second controller behind one endpoint: a kind claimed by both would
// be routed by declaration order, silently, and the fault a scenario armed
// would not be the fault it got.
func TestLieKindsDoNotCollideWithFaultKinds(t *testing.T) {
	for k := range lieKinds {
		if solarAdvFaultKinds[k] {
			t.Errorf("%q is claimed by BOTH the lie controller and the fault controller", k)
		}
		if wireKinds[k] {
			t.Errorf("%q is claimed by BOTH the lie controller and the wire mangler", k)
		}
	}
	for k := range wireKinds {
		if solarAdvFaultKinds[k] {
			t.Errorf("%q is claimed by BOTH the wire mangler and the fault controller", k)
		}
	}
}

// TestUnknownKindStillReachesTheFaultController proves the lie controller is
// transparent to kinds it does not own: an unrelated fault must still work, and
// an unknown one must still produce the fault controller's own error rather
// than being swallowed here.
func TestUnknownKindStillReachesTheFaultController(t *testing.T) {
	ss := newLyingSolar(t, 8000)
	if err := ss.ApplyFault([]byte(`{"kind":"reject_write"}`)); err != nil {
		t.Fatalf("a pre-existing fault kind no longer arms: %v", err)
	}
	err := ss.ApplyFault([]byte(`{"kind":"no_such_fault"}`))
	if err == nil {
		t.Fatal("an unknown kind must be an error")
	}
	var js map[string]any
	if json.Unmarshal([]byte(`{"kind":"no_such_fault"}`), &js) != nil {
		t.Fatal("fixture is not JSON")
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition did not hold within %s", d)
}
