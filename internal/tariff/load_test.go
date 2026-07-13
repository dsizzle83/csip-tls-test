package tariff

import "testing"

// TestLoadTestdata confirms Load reads every *.json in a directory, validates
// them, and keys the result by tariff id.
func TestLoadTestdata(t *testing.T) {
	got, err := Load("testdata")
	if err != nil {
		t.Fatalf("Load(testdata): %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d tariffs, want 2: %v", len(got), keys(got))
	}
	for _, id := range []string{"test-tou-freenight", "test-tiered-demand"} {
		tar, ok := got[id]
		if !ok {
			t.Errorf("missing tariff %q (have %v)", id, keys(got))
			continue
		}
		if tar.ID != id {
			t.Errorf("tariff keyed %q has ID %q", id, tar.ID)
		}
	}
}

// TestLoadMissingDir confirms Load errors on a nonexistent directory.
func TestLoadMissingDir(t *testing.T) {
	if _, err := Load("testdata/does-not-exist"); err == nil {
		t.Fatal("expected error for missing dir, got nil")
	}
}

func keys(m map[string]*Tariff) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
