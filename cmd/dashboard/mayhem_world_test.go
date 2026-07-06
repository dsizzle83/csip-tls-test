package main

import (
	"strconv"
	"strings"
	"testing"
)

// TestFillDiskCommand_HasFloorGuardAndReserve locks the size math and floor
// guard TASK-050 requires: refuse below diskFloorKiB free, and always
// subtract diskReserveKiB before fallocating — the two properties that keep
// the ballast from ever bricking a tight partition. fillDiskCommand is a pure
// string builder specifically so this is testable without SSH.
func TestFillDiskCommand_HasFloorGuardAndReserve(t *testing.T) {
	cmd := fillDiskCommand()

	if !strings.Contains(cmd, "fallocate") {
		t.Error("command must use fallocate (not dd — RSK-14, no SD-card write churn)")
	}
	if strings.Contains(cmd, "dd ") || strings.Contains(cmd, "dd if=") {
		t.Error("command must not shell out to dd")
	}
	if !strings.Contains(cmd, ballastPath) {
		t.Errorf("command must target the fixed, greppable ballast path %q", ballastPath)
	}
	if !strings.Contains(cmd, ballastDir) {
		t.Errorf("command must size against %q (mosquitto/journald's partition)", ballastDir)
	}

	floorStr := strconv.Itoa(diskFloorKiB)
	if !strings.Contains(cmd, floorStr) {
		t.Errorf("command must guard on the %d KiB floor", diskFloorKiB)
	}
	reserveStr := strconv.Itoa(diskReserveKiB)
	if !strings.Contains(cmd, reserveStr) {
		t.Errorf("command must reserve %d KiB", diskReserveKiB)
	}
	if !strings.Contains(cmd, "exit 1") {
		t.Error("command must refuse (non-zero exit) when free space is below the floor, not fill anyway")
	}
	// The arithmetic must subtract the reserve from avail, not just the
	// floor: avail - diskReserveKiB is the size fallocate gets.
	if !strings.Contains(cmd, "avail - "+reserveStr) {
		t.Errorf("command must fallocate (avail - %d) KiB, got: %s", diskReserveKiB, cmd)
	}
	// Reserve must never exceed the floor, or a partition just above the
	// floor could compute a negative/zero fallocate size.
	if diskReserveKiB > diskFloorKiB {
		t.Errorf("diskReserveKiB (%d) must not exceed diskFloorKiB (%d)", diskReserveKiB, diskFloorKiB)
	}
}
