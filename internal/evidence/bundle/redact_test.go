package bundle

// redact_test.go holds the redactor to both halves of its promise. Recording an
// invocation is only useful if the recording is faithful, and only safe if it
// is not faithful about credentials — so the tests that matter are the ones
// proving each side does not eat the other: a secret that survives, or a
// harmless argument that vanishes, is a bug of the same size.

import (
	"strings"
	"testing"
)

func TestRedactCommandWithholdsCredentialsAndKeepsEverythingElse(t *testing.T) {
	argv := []string{
		"certify",
		"-doc", "SSM-CONF-v0.8",
		"-gateway", "69.0.0.2:802",
		"-gateway-ssh", "cc93",
		"-iface", "enp1s0",
		"-bpf", "tcp port 802 or tcp port 11113",
		"-keylog", "/tmp/bench-shared.keylog",
		"-api-token", "hunter2",
		"-password=swordfish",
		"--secret", "s3kr1t",
		"-param", "pki.identity_wait=3s",
		"-param", "report.api_key=abcdef",
		"-param=ssm.token=zzz",
		"-require-citation",
	}
	got := strings.Join(RedactCommand(argv), " ")

	for _, want := range []string{
		"-doc SSM-CONF-v0.8",
		"-gateway 69.0.0.2:802",
		// A host alias is provenance, not a credential: blanking it costs the
		// reader "which device was introspected?" and protects nothing.
		"-gateway-ssh cc93",
		"-iface enp1s0",
		"tcp port 802 or tcp port 11113",
		// The key log's SECRET is the file, which the bundle ships knowingly
		// and warns about. Hiding its path while shipping its contents would
		// be theatre.
		"-keylog /tmp/bench-shared.keylog",
		"-param pki.identity_wait=3s",
		"-require-citation",
		// The flag NAMES all survive: that a token was passed is itself a fact
		// about the run, and only its value is withheld.
		"-api-token", "-password=", "--secret", "report.api_key=", "ssm.token=",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the recorded line lost %q:\n%s", want, got)
		}
	}
	for _, leak := range []string{"hunter2", "swordfish", "s3kr1t", "abcdef", "zzz"} {
		if strings.Contains(got, leak) {
			t.Errorf("the recorded line carries the secret %q:\n%s", leak, got)
		}
	}
	if n := strings.Count(got, Redacted); n != 5 {
		t.Errorf("%d values redacted, want 5:\n%s", n, got)
	}
}

// A boolean flag whose name happens to look credential-shaped must not swallow
// the argument after it: `-no-ssh -doc X` recording `-no-ssh [redacted]` would
// erase a selection and misreport the run.
func TestRedactCommandDoesNotEatTheNextFlag(t *testing.T) {
	got := RedactCommand([]string{"certify", "-no-ssh", "-doc", "SSM-CONF-v0.8"})
	want := []string{"certify", "-no-ssh", "-doc", "SSM-CONF-v0.8"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRedactCommandLeavesTheCallersSliceAlone(t *testing.T) {
	argv := []string{"certify", "-token", "hunter2"}
	_ = RedactCommand(argv)
	if argv[2] != "hunter2" {
		t.Errorf("RedactCommand mutated its input: %v", argv)
	}
	if RedactCommand(nil) != nil {
		t.Error("an empty invocation should stay empty rather than become a one-element line")
	}
}

// The hook is the documented escape for a binary with credential flags this
// package cannot know about. If it stops being reachable, the documentation is
// a lie and the next such flag leaks.
func TestSecretFlagHookIsHonoured(t *testing.T) {
	prev := SecretFlag
	t.Cleanup(func() { SecretFlag = prev })
	SecretFlag = func(name string) bool { return name == "hsm-pin" || prev(name) }

	got := strings.Join(RedactCommand([]string{"certify", "-hsm-pin", "1234", "-doc", "X"}), " ")
	if strings.Contains(got, "1234") {
		t.Errorf("the widened rule was ignored: %s", got)
	}
	if !strings.Contains(got, "-doc X") {
		t.Errorf("the widened rule took an unrelated flag with it: %s", got)
	}
}

func TestShellLineIsPasteable(t *testing.T) {
	got := shellLine([]string{"certify", "-bpf", "tcp port 802", "-note", "it's fine", "-x", ""})
	want := `certify -bpf 'tcp port 802' -note 'it'\''s fine' -x ''`
	if got != want {
		t.Errorf("shellLine =\n%s\nwant\n%s", got, want)
	}
}
