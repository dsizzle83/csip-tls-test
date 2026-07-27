package diff

import (
	"context"

	"testing"
)

// TestCtlCatalogRuns exercises every standing case and prints the report, so a
// change in the product's control path shows up here as a diff in the artifact
// rather than as a silent behavioural change.
func TestCtlCatalogRuns(t *testing.T) {
	r := NewReport(0)
	if err := RunCtlCatalog(context.Background(), r); err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	sum := r.Summary()
	if sum.Cases != len(CtlCatalog()) {
		t.Fatalf("ran %d cases, catalogue has %d", sum.Cases, len(CtlCatalog()))
	}
	if sum.Compared == 0 {
		t.Fatal("the whole catalogue evaluated zero comparisons — the harness is not comparing anything")
	}
	t.Log("\n" + r.Markdown())
}
