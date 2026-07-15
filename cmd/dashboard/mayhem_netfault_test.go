package main

import (
	"strings"
	"testing"
)

// Pure command-builder tests (no SSH) — mirror TestNetemApplyCommand. They pin
// the load-bearing properties of the remote scripts the netfault/certrot
// scenarios run over the hub's SSH, so a refactor cannot silently drop the
// both-directions block, the self-heal, the no-op guard, or the sudo -n.

func TestPartitionApplyCommand(t *testing.T) {
	cmd := partitionApplyCommand("69.0.0.20", 11111, 90)

	// Both directions must be dropped (a one-way block leaks return traffic).
	if !strings.Contains(cmd, "-I OUTPUT -d 69.0.0.20 -p tcp --dport 11111 -j DROP") {
		t.Errorf("missing OUTPUT DROP rule: %s", cmd)
	}
	if !strings.Contains(cmd, "-I INPUT -s 69.0.0.20 -p tcp --sport 11111 -j DROP") {
		t.Errorf("missing INPUT DROP rule: %s", cmd)
	}
	// Port-scoped, never a whole-IP block (that would blind the /status probe).
	if strings.Contains(cmd, "-d 69.0.0.20 -j DROP") && !strings.Contains(cmd, "--dport") {
		t.Errorf("whole-IP DROP would blind the dashboard's hub probe: %s", cmd)
	}
	// No-op guard: -C verifies the rule landed (GAP-11 false-PASS protection).
	if !strings.Contains(cmd, "iptables -C OUTPUT") {
		t.Errorf("missing -C verification (no-op guard): %s", cmd)
	}
	// Self-heal + sudo -n.
	if !strings.Contains(cmd, "sleep 90") || !strings.Contains(cmd, "iptables -D OUTPUT") {
		t.Errorf("missing self-healing delete: %s", cmd)
	}
	if !strings.Contains(cmd, "sudo -n") {
		t.Errorf("missing sudo -n (must never hang on a prompt): %s", cmd)
	}
}

func TestPartitionResetCommand(t *testing.T) {
	cmd := partitionResetCommand("69.0.0.20", 11111)
	if !strings.Contains(cmd, "-D OUTPUT -d 69.0.0.20 -p tcp --dport 11111 -j DROP") {
		t.Errorf("reset must delete the OUTPUT rule: %s", cmd)
	}
	if !strings.Contains(cmd, "-D INPUT -s 69.0.0.20 -p tcp --sport 11111 -j DROP") {
		t.Errorf("reset must delete the INPUT rule: %s", cmd)
	}
	// Idempotent: a missing rule must not error the reset.
	if !strings.Contains(cmd, "2>/dev/null") || !strings.HasSuffix(strings.TrimSpace(cmd), "true") {
		t.Errorf("reset must be idempotent (|| true / 2>/dev/null): %s", cmd)
	}
}

func TestDNSFailApplyCommand(t *testing.T) {
	cmd := dnsFailApplyCommand(80)
	if !strings.Contains(cmd, "cp /etc/resolv.conf") {
		t.Errorf("must back up resolv.conf before overwriting: %s", cmd)
	}
	if !strings.Contains(cmd, "192.0.2.1") {
		t.Errorf("must point at the unroutable TEST-NET blackhole: %s", cmd)
	}
	if !strings.Contains(cmd, "grep -q 192.0.2.1 /etc/resolv.conf") {
		t.Errorf("missing no-op guard (verify the swap landed): %s", cmd)
	}
	if !strings.Contains(cmd, "sleep 80") || !strings.Contains(cmd, "mv") {
		t.Errorf("missing self-healing restore: %s", cmd)
	}
}

func TestWriteRotationSentinelCommand(t *testing.T) {
	cmd := writeRotationSentinelCommand("/etc/lexa/certs/rotate.request", "/etc/lexa/certs/bad.pem")
	if !strings.Contains(cmd, "/etc/lexa/certs/rotate.request") {
		t.Errorf("must write the sentinel path rotate.go watches: %s", cmd)
	}
	// The sentinel body must carry the staged cert path rotate.go parses.
	if !strings.Contains(cmd, "client_cert") || !strings.Contains(cmd, "/etc/lexa/certs/bad.pem") {
		t.Errorf("sentinel body must reference the staged cert: %s", cmd)
	}
	if !strings.Contains(cmd, "sudo -n") {
		t.Errorf("writing under /etc/lexa needs sudo -n: %s", cmd)
	}
}
