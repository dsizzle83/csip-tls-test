package gridsim

import (
	"testing"
	"time"
)

func TestDelay_StallsMatchedPath(t *testing.T) {
	s := &Server{}
	s.SetDelay("/dcap", 300, 0) // 300ms stall on /dcap

	start := time.Now()
	s.delayIntercept("/dcap")
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Errorf("delay on /dcap returned after %v, want ≥ ~300ms", elapsed)
	}

	// A different path is not delayed.
	start = time.Now()
	s.delayIntercept("/tm")
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("delay fired on a non-armed path (%v)", elapsed)
	}
}

func TestDelay_EmptyPathDelaysEverything(t *testing.T) {
	s := &Server{}
	s.SetDelay("", 250, 0)
	start := time.Now()
	s.delayIntercept("/anything")
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("empty-path delay did not stall /anything (%v)", elapsed)
	}
}

func TestDelay_ClearDisarms(t *testing.T) {
	s := &Server{}
	s.SetDelay("/dcap", 300, 0)
	s.SetDelay("/dcap", 0, 0) // clear
	start := time.Now()
	s.delayIntercept("/dcap")
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("cleared delay still stalling (%v)", elapsed)
	}
}

func TestDelay_AutoClearAndSupersede(t *testing.T) {
	s := &Server{}
	s.SetDelay("/dcap", 300, 1) // auto-clear after 1s

	deadline := time.Now().Add(3 * time.Second)
	for {
		start := time.Now()
		s.delayIntercept("/dcap")
		if time.Since(start) < 100*time.Millisecond {
			break // cleared
		}
		if time.Now().After(deadline) {
			t.Fatal("delay did not auto-clear within its duration")
		}
	}

	// A newer arm must not be clobbered by the previous arm's pending auto-clear.
	s.SetDelay("/dcap", 300, 1) // will auto-clear ~1s from now
	s.SetDelay("/dcap", 300, 0) // supersede: no auto-clear
	time.Sleep(1500 * time.Millisecond)
	start := time.Now()
	s.delayIntercept("/dcap")
	if time.Since(start) < 250*time.Millisecond {
		t.Error("superseding delay arm was cleared by the stale auto-clear timer")
	}
}
