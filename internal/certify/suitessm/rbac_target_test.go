package suitessm

// rbac_target_test.go covers the two RBAC-002 defects that turned a correct
// five-role authorization matrix into a FAIL in run 20260726T225512:
//
//	the ANSWER  — exception 3 was read as an authorization denial. On this
//	              product 0x01 is the denial (SunSpecTCP-40); 0x03 is emitted
//	              only after authorization has already succeeded;
//	the PROBE   — the write value was 0xFFFF, the point's not-implemented
//	              sentinel, so exception 3 was the only answer the DUT could
//	              give and the check had made its own denial.
//
// Both bytes below are lifted from that run: the request the probe sent and the
// three responses the DUT gave.

import (
	"fmt"
	"strings"
	"testing"
)

// readRsp builds the FC 3 response an ReadHolding would have read back.
func readRsp(vals []uint16) Exchange {
	pdu := []byte{0x03, byte(len(vals) * 2)}
	for _, v := range vals {
		pdu = append(pdu, byte(v>>8), byte(v))
	}
	return Exchange{Response: mbapADU(1, 1, pdu...)}
}

// fakeReader answers a read at a known address with a fixed register block, and
// anything else with a transport error.
type fakeReader map[uint16][]uint16

func (f fakeReader) ReadHolding(_ uint8, addr, count uint16, _ string) Exchange {
	block, ok := f[addr]
	if !ok {
		return Exchange{Err: fmt.Errorf("no register at %d", addr)}
	}
	out := make([]uint16, 0, count)
	for i := 0; i < int(count); i++ {
		if i < len(block) {
			out = append(out, block[i])
		} else {
			out = append(out, 0xFFFF)
		}
	}
	return readRsp(out)
}

// anyReader answers every read with a real (non-sentinel) value.
type anyReader struct{}

func (anyReader) ReadHolding(_ uint8, _, count uint16, _ string) Exchange {
	vals := make([]uint16, count)
	for i := range vals {
		vals[i] = 0x2710
	}
	return readRsp(vals)
}

// mbapADU wraps a PDU in an MBAP header, as the recovered plaintext carries it.
func mbapADU(txn uint16, unit byte, pdu ...byte) []byte {
	n := len(pdu) + 1
	out := []byte{byte(txn >> 8), byte(txn), 0, 0, byte(n >> 8), byte(n), unit}
	return append(out, pdu...)
}

func TestAuthorizationVerdictReadsExceptionOneAsTheOnlyDenial(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rsp     []byte
		want    authOutcome
		wantSay string
	}{
		{
			// GridServiceSunSpec and SuperAdministratorSunSpec, frames 6184 and
			// 6255 of run 20260726T225512. Authorization PASSED; the value the
			// probe sent was rejected.
			name:    "exception 3 is authorization SUCCESS",
			rsp:     mbapADU(0x0009, 1, 0x90, 0x03),
			want:    authCleared,
			wantSay: "AUTHORIZED",
		},
		{
			// NetworkAdministratorSunSpec and ReadOnlySunSpec, frames 6219 and
			// 6291. This is the real denial.
			name:    "exception 1 is the denial",
			rsp:     mbapADU(0x0009, 1, 0x90, 0x01),
			want:    authDenied,
			wantSay: "DENIED by authorization",
		},
		{
			name:    "exception 2 is authorization success too",
			rsp:     mbapADU(0x0009, 1, 0x90, 0x02),
			want:    authCleared,
			wantSay: "AUTHORIZED",
		},
		{
			name:    "a normal response is a performed write",
			rsp:     mbapADU(0x0009, 1, 0x10, 0x9d, 0x47, 0x00, 0x01),
			want:    authGranted,
			wantSay: "AUTHORIZED and performed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, obs := authorizationVerdict(tc.rsp)
			if got != tc.want {
				t.Fatalf("authorizationVerdict = %v, want %v (%s)", got, tc.want, obs)
			}
			if !strings.Contains(obs, tc.wantSay) {
				t.Errorf("observation = %q, want it to contain %q", obs, tc.wantSay)
			}
		})
	}
	// The consequence, stated directly: on run 20260726T225512's four answers,
	// two roles were authorized and two were denied — three distinct outcomes
	// where the check reported "none of the three privileged roles was granted
	// a write".
	authorized := 0
	for _, rsp := range [][]byte{
		mbapADU(9, 1, 0x90, 0x03), // GridServiceSunSpec
		mbapADU(9, 1, 0x90, 0x01), // NetworkAdministratorSunSpec
		mbapADU(9, 1, 0x90, 0x03), // SuperAdministratorSunSpec
	} {
		if o, _ := authorizationVerdict(rsp); o.authorized() {
			authorized++
		}
	}
	if authorized != 2 {
		t.Fatalf("%d of the three privileged roles read as authorized, want 2", authorized)
	}
}

// TestWriteTargetRefusesTheNotImplementedSentinel is the probe half. A register
// reading 0xFFFF (or 0x8000, for the signed types) is not implemented; writing
// that value back can only ever be refused on the VALUE, so it can never
// evidence an authorization decision. The scan must walk past it.
func TestWriteTargetRefusesTheNotImplementedSentinel(t *testing.T) {
	ch := &Chain{Unit: 1, Models: []ModelBlock{
		{ID: 1, Length: 66, Addr: 40002, First: 40004},
		{ID: 704, Length: 65, Addr: 40261, First: 40263},
	}}
	// Model 704 as the live gateway serves it: PFWInjEna and the next points
	// read their sentinels, then a real value.
	s := fakeReader{40263: {0xFFFF, 0x8000, 0xFFFF, 0x2710, 0x0000}}

	got, err := pickWriteTargetOfKind(s, 1, ch, controlPoint)
	if err != nil {
		t.Fatalf("pickWriteTargetOfKind: %v", err)
	}
	if got.Addr != 40266 {
		t.Errorf("target address = %d, want 40266: 40263/40264/40265 all read their not-implemented "+
			"sentinel and cannot carry a legal read-back write", got.Addr)
	}
	if notImplemented16[got.Value] {
		t.Errorf("target value = 0x%04X, which is a not-implemented sentinel — the write could only ever "+
			"be answered with exception 3, which is exactly the defect", got.Value)
	}
	if !strings.Contains(got.Why, "real value") {
		t.Errorf("Why = %q, want it to record why this register was chosen", got.Why)
	}
}

// TestNetworkAdminTargetsANetworkConfigurationPoint pins §2.7.2.1 step 4: the
// NetworkAdministrator write goes at a NETWORK CONFIGURATION point, and the
// step is conditioned on "if one exists". A DUT serving [1 701 702 704] has
// none, so the step is NOT PERFORMED — expecting a network administrator to be
// granted a write to a DER control model is an over-read of the procedure.
func TestNetworkAdminTargetsANetworkConfigurationPoint(t *testing.T) {
	derOnly := &Chain{Unit: 1, Models: []ModelBlock{
		{ID: 1, Length: 66, Addr: 40002, First: 40004},
		{ID: 701, Length: 137, Addr: 40070, First: 40072},
		{ID: 702, Length: 50, Addr: 40209, First: 40211},
		{ID: 704, Length: 65, Addr: 40261, First: 40263},
	}}
	s := anyReader{}

	if _, err := pickWriteTargetOfKind(s, 1, derOnly, networkConfigPoint); err == nil {
		t.Fatal("a chain of [1 701 702 704] holds no network configuration model; the step must not be performed")
	} else if !strings.Contains(err.Error(), "if one exists") {
		t.Errorf("error = %q, want it to name the procedure's condition", err)
	}

	// The same role on a DUT that DOES serve one must be aimed at it.
	withNet := &Chain{Unit: 1, Models: []ModelBlock{
		{ID: 1, Length: 66, Addr: 40002, First: 40004},
		{ID: 12, Length: 98, Addr: 40070, First: 40072},
		{ID: 704, Length: 65, Addr: 40261, First: 40263},
	}}
	got, err := pickWriteTargetOfKind(s, 1, withNet, networkConfigPoint)
	if err != nil {
		t.Fatalf("pickWriteTargetOfKind: %v", err)
	}
	if got.Model != 12 {
		t.Errorf("target model = %d, want 12 (IPv4): the procedure names a network configuration point, "+
			"not a DER control model", got.Model)
	}
}

// TestControlPointStillPrefers704 guards the other side: nothing above may move
// GridService off the model the procedure names.
func TestControlPointStillPrefers704(t *testing.T) {
	ch := &Chain{Unit: 1, Models: []ModelBlock{
		{ID: 1, Length: 66, Addr: 40002, First: 40004},
		{ID: 701, Length: 137, Addr: 40070, First: 40072},
		{ID: 704, Length: 65, Addr: 40261, First: 40263},
	}}
	got, err := pickWriteTargetOfKind(anyReader{}, 1, ch, controlPoint)
	if err != nil {
		t.Fatalf("pickWriteTargetOfKind: %v", err)
	}
	if got.Model != 704 {
		t.Errorf("target model = %d, want 704", got.Model)
	}
}

// TestRulesCandidatesNameTheProductsRealPath pins the path that made RBAC-004
// unevidenceable. /etc/lexa/rbac/rules.json is where the file lives; the old,
// wrong path is kept only as a fallback for older images.
func TestRulesCandidatesNameTheProductsRealPath(t *testing.T) {
	if len(rulesCandidates) == 0 || rulesCandidates[0] != "/etc/lexa/rbac/rules.json" {
		t.Fatalf("rulesCandidates = %v, want the product's real path first", rulesCandidates)
	}
	found := false
	for _, p := range rulesCandidates {
		if p == "/etc/lexa/configs/rbac/rules.json" {
			found = true
		}
	}
	if !found {
		t.Error("the previously-used path should stay in the list, so an older image still evidences RBAC-004")
	}
}
