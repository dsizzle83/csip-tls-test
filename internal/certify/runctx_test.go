package certify

// runctx_test.go pins Logf's nil-Case guard: a diagnostic helper must not
// panic for want of the thing it is diagnosing.

import (
	"fmt"
	"testing"
)

// recordingLogger captures what was printed, so the test can check the
// message rather than just that nothing panicked.
type recordingLogger struct{ got string }

func (r *recordingLogger) Printf(format string, v ...any) { r.got = fmt.Sprintf(format, v...) }

func TestLogfWithNilCaseDoesNotPanicAndOmitsThePrefix(t *testing.T) {
	log := &recordingLogger{}
	rc := &RunCtx{Log: log} // Case deliberately left nil

	rc.Logf("bench is up")

	if log.got != "bench is up" {
		t.Errorf("Logf with a nil Case = %q, want the bare message with no [uid] prefix", log.got)
	}
}
