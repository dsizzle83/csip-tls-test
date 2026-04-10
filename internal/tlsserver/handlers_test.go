package tlsserver

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "update golden test files")

func TestRoute_DcapMatchesGolden(t *testing.T) {
	resp := route([]byte("GET /dcap HTTP/1.1\r\nHost: x\r\n\r\n"))

	parts := strings.SplitN(string(resp), "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("response missing header/body separator")
	}
	body := []byte(parts[1])

	goldenPath := filepath.Join("testdata", "golden", "dcap.xml")

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(goldenPath, body, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v\n(run `make test-update-golden` to create)", err)
	}

	if string(body) != string(want) {
		t.Errorf("DCAP body diverged from golden\n--- want ---\n%s\n--- got ---\n%s", want, body)
	}
}

func TestRoute_UnknownPath(t *testing.T) {
	resp := route([]byte("GET /nonexistent HTTP/1.1\r\nHost: x\r\n\r\n"))
	if !strings.Contains(string(resp), "404 Not Found") {
		t.Errorf("expected 404, got: %s", resp)
	}
}

func TestRoute_Malformed(t *testing.T) {
	resp := route([]byte("GARBAGE\r\n"))
	if !strings.Contains(string(resp), "400 Bad Request") {
		t.Errorf("expected 400, got: %s", resp)
	}
}

func TestRoute_DcapHeaders(t *testing.T) {
	resp := string(route([]byte("GET /dcap HTTP/1.1\r\n\r\n")))
	for _, want := range []string{
		"HTTP/1.1 200 OK",
		"Content-Type: application/sep+xml",
		"Content-Length: ",
	} {
		if !strings.Contains(resp, want) {
			t.Errorf("DCAP response missing %q", want)
		}
	}
}
