//go:build keylog && integration

package csipnotify

// keylog_test.go is the acceptance test for the claim this package makes about
// evidence: that a capture of the SERVER-DIALLED notification leg decrypts like
// every other bench flow.
//
// Without it the export path could compile, run, emit nothing, and leave the
// conformance suite reporting "the notification leg is present but not readable"
// on every aggregator row — with the cause three packages away and looking, from
// the bundle, exactly like a bench that was never built with the tag. So the
// assertion is on the CONTENT of the key log, not on its existence.
//
//	CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64-keylog/include" \
//	CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64-keylog/lib -lwolfssl -lm" \
//	go test -tags "keylog integration" ./internal/csipnotify/

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/wolfssl"
)

func TestNotificationLegExportsItsSessionSecrets(t *testing.T) {
	out := filepath.Join(t.TempDir(), "notify.keylog")
	if err := wolfssl.OpenKeylog(out); err != nil {
		t.Fatalf("OpenKeylog(%s): %v — this test requires the keylog sysroot "+
			"(scripts/build-wolfssl-keylog-sysroot.sh)", out, err)
	}
	defer wolfssl.CloseKeylog()

	addr, count, _ := fakeDUTListener(t, http.StatusCreated)
	status, err := notifierUnderTest().Notify(context.Background(),
		"https://"+addr+"/notif", []byte(`<Notification xmlns="urn:ieee:std:2030.5:ns"/>`))
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	if status != http.StatusCreated || *count != 1 {
		t.Fatalf("delivery reported %d after %d listener hit(s)", status, *count)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read key log: %v", err)
	}
	body := string(b)
	// TLS 1.2 is the version CSIP mandates, so CLIENT_RANDOM is the line that
	// matters; the 1.3 labels are accepted so this does not become a version
	// assertion in disguise.
	for _, label := range []string{"CLIENT_RANDOM", "CLIENT_TRAFFIC_SECRET_0"} {
		if strings.Contains(body, label) {
			return
		}
	}
	t.Fatalf("the key log holds no secret for the notification session, so a capture of the leg the "+
		"SERVER dialled would be undecryptable and every criterion that cites it would SKIP. Contents:\n%s",
		body)
}
