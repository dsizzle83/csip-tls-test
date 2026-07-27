package report

import (
	"strings"
	"testing"
)

// The §4.1.2 worked example, decoded in the catalog's own note:
//
//	request  00000000000601039F880001  TxID 0, Proto 0, Len 6, Unit 1, FC 3, addr 0x9F88, qty 1
//	response 00000000000501030202C6    Len 5, Unit 1, FC 3, byte count 2, data 0x02C6
const (
	exampleReq  = "00000000000601039F880001"
	exampleResp = "00000000000501030202C6"
)

func TestDecodeMBAPAgainstTheWorkedExample(t *testing.T) {
	raw, err := DecodeHexMsg(exampleReq)
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeMBAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.TransactionID != 0 || m.ProtocolID != 0 || m.Length != 6 || m.UnitID != 1 || m.FunctionCode != 3 {
		t.Fatalf("decoded %+v", m)
	}
	if m.Exception {
		t.Error("a plain read was decoded as an exception")
	}
	if HexMsg(raw) != exampleReq {
		t.Errorf("re-encoding is not the identity: %s", HexMsg(raw))
	}
}

func TestDecodeMBAPRejectsAnInconsistentLength(t *testing.T) {
	raw, _ := DecodeHexMsg("00000000000901039F880001") // Length says 9, frame carries 6
	if _, err := DecodeMBAP(raw); err == nil {
		t.Fatal("an MBAP frame whose Length disagrees with its own size was accepted")
	}
}

func TestExceptionResponseIsRecognised(t *testing.T) {
	// FC 0x83 = exception to FC 3; exception code 2 (illegal data address).
	raw, err := DecodeHexMsg("000100000003018302")
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeMBAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Exception {
		t.Fatal("0x83 was not recognised as an exception function code")
	}
	if !strings.Contains(m.String(), "exception code 2") {
		t.Errorf("String() = %q", m.String())
	}
}

func TestDecodeRTUVerifiesTheCRC(t *testing.T) {
	body := []byte{0x01, 0x03, 0x02, 0x02, 0xC6}
	crc := crc16Modbus(body)
	frame := append(append([]byte{}, body...), byte(crc), byte(crc>>8))
	unit, fc, data, err := DecodeRTU(frame)
	if err != nil {
		t.Fatal(err)
	}
	if unit != 1 || fc != 3 || len(data) != 3 {
		t.Fatalf("unit %d fc %d data %x", unit, fc, data)
	}
	frame[len(frame)-1] ^= 0xFF
	if _, _, _, err := DecodeRTU(frame); err == nil {
		t.Fatal("a corrupt CRC was accepted; the log would claim a frame the device never accepted")
	}
}

func goodModbusLogs() *ModbusTestLogs {
	return &ModbusTestLogs{Logs: []ModbusTestLog{{
		Tests: []string{"MOD-1"},
		Entries: []ModbusLogEntry{
			{Time: 1539663163.977, Type: EntryConn, IPAddr: "192.168.0.10", IPPort: 502},
			{Time: 1539663164.152, Type: EntryReq, Msg: exampleReq},
			{Time: 1539663164.347, Type: EntryResp, Msg: exampleResp},
			{Time: 1539663169.214, Type: EntryDisc},
		},
	}}}
}

func TestValidateModbusTestLogsAcceptsTheWorkedExample(t *testing.T) {
	if f := ValidateModbusTestLogs(goodModbusLogs(), TransportTCP); len(f) != 0 {
		t.Fatalf("the specification's own worked example was rejected: %v", f)
	}
}

// TestValidateModbusTestLogsHasTeeth walks every rule §4.1 states and proves a
// document violating it FAILS. A validator that only accepts is decoration.
func TestValidateModbusTestLogsHasTeeth(t *testing.T) {
	cases := map[string]struct {
		mutate func(*ModbusTestLogs)
		want   string
	}{
		"no tests":            {func(l *ModbusTestLogs) { l.Logs[0].Tests = nil }, "`tests` is empty"},
		"no entries":          {func(l *ModbusTestLogs) { l.Logs[0].Entries = nil }, "`entries` is empty"},
		"missing time":        {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Time = 0 }, "`time` is absent"},
		"missing type":        {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Type = "" }, "`type` is absent"},
		"unknown type":        {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Type = "REQ" }, "not one of"},
		"req without msg":     {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Msg = "" }, "no `msg`"},
		"conn without ipaddr": {func(l *ModbusTestLogs) { l.Logs[0].Entries[0].IPAddr = "" }, "no `ipaddr`"},
		"conn without ipport": {func(l *ModbusTestLogs) { l.Logs[0].Entries[0].IPPort = 0 }, "no `ipport`"},
		"odd hex":             {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Msg = "000" }, "not a whole number of bytes"},
		"non hex":             {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Msg = "ZZ00" }, "not ascii hex"},
		"0x prefix":           {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Msg = "0x" + exampleReq }, "not ascii hex"},
		"bad MBAP length":     {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].Msg = "00000000000F01039F880001" }, "Length field is"},
		"message with ipaddr": {func(l *ModbusTestLogs) { l.Logs[0].Entries[1].IPAddr = "10.0.0.1" }, "connection fields"},
		"conn with msg":       {func(l *ModbusTestLogs) { l.Logs[0].Entries[0].Msg = exampleReq }, "conn entry carries a `msg`"},
	}
	for name, tc := range cases {
		logs := goodModbusLogs()
		tc.mutate(logs)
		findings := ValidateModbusTestLogs(logs, TransportTCP)
		if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
			t.Errorf("%s: no finding containing %q; got %v", name, tc.want, findings)
		}
	}
}

// TestRTUFramingIsValidatedSeparately proves the Transport switch is real: an
// MBAP frame is not a conformant RTU message, and vice versa.
func TestRTUFramingIsValidatedSeparately(t *testing.T) {
	logs := goodModbusLogs()
	if f := ValidateModbusTestLogs(logs, TransportRTU); len(f) == 0 {
		t.Fatal("MBAP-framed messages were accepted as RTU; RTU carries no MBAP header and ends in a CRC")
	}
}

func TestPairTransactionsFindsAnUnansweredRequest(t *testing.T) {
	logs := goodModbusLogs()
	paired, unmatched := PairTransactions(logs.Logs[0].Entries)
	if paired != 1 || len(unmatched) != 0 {
		t.Fatalf("paired %d unmatched %v", paired, unmatched)
	}
	logs.Logs[0].Entries = logs.Logs[0].Entries[:2] // conn + req, response dropped
	if _, unmatched = PairTransactions(logs.Logs[0].Entries); len(unmatched) != 1 {
		t.Fatalf("a request with no response went unreported: %v", unmatched)
	}
}

func TestModbusTestLogsRoundTripRejectsUnknownFields(t *testing.T) {
	data, err := goodModbusLogs().JSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseModbusTestLogs(data); err != nil {
		t.Fatalf("the emitted document does not round-trip: %v", err)
	}
	if strings.Contains(string(data), `"cid"`) {
		t.Error("a cid was emitted; v1.2's revision history records \"Removed cid.\"")
	}
	if !strings.Contains(string(data), `"ipport": 502`) {
		t.Errorf("ipport was not emitted as a JSON number, which is what the §4.1.2 example shows:\n%s", data)
	}
	bad := strings.Replace(string(data), `"tests"`, `"testz"`, 1)
	if _, err := ParseModbusTestLogs([]byte(bad)); err == nil {
		t.Error("an unknown field parsed silently")
	}
}

func goodCSIPLogs() *CSIPTestLogs {
	return &CSIPTestLogs{CID: "campaign-1", Logs: []CSIPTestLog{{
		Tests: []string{"CORE-001"},
		CID:   "campaign-1",
		Messages: []CSIPMessage{
			{Time: 1539663163.6476057, Type: MsgReq, Method: "GET", URI: "/sep2/dcap", Vers: "HTTP/1.1",
				Headers: map[string]string{"Accept": "application/sep+xml"}, Body: ""},
			{Time: 1539663163.9776247, Type: MsgResp, Vers: "HTTP/1.1", Code: "200", Reason: "OK\r\n",
				Headers: map[string]string{"Content-Type": "application/sep+xml; charset=utf-8"},
				Body:    `<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/sep2/dcap"/>`},
		},
	}}}
}

func TestValidateCSIPTestLogsAcceptsTheWorkedExample(t *testing.T) {
	if f := ValidateCSIPTestLogs(goodCSIPLogs()); len(f) != 0 {
		t.Fatalf("the §4.1.2 worked example was rejected: %v", f)
	}
}

func TestValidateCSIPTestLogsHasTeeth(t *testing.T) {
	cases := map[string]struct {
		mutate func(*CSIPTestLogs)
		want   string
	}{
		"no tests":     {func(l *CSIPTestLogs) { l.Logs[0].Tests = nil }, "`tests` is empty"},
		"no messages":  {func(l *CSIPTestLogs) { l.Logs[0].Messages = nil }, "`messages` is empty"},
		"no time":      {func(l *CSIPTestLogs) { l.Logs[0].Messages[0].Time = 0 }, "`time` is absent"},
		"no method":    {func(l *CSIPTestLogs) { l.Logs[0].Messages[0].Method = "" }, "no `method`"},
		"no uri":       {func(l *CSIPTestLogs) { l.Logs[0].Messages[0].URI = "" }, "no `uri`"},
		"no vers":      {func(l *CSIPTestLogs) { l.Logs[0].Messages[0].Vers = "" }, "`vers` is absent"},
		"no headers":   {func(l *CSIPTestLogs) { l.Logs[0].Messages[0].Headers = nil }, "`headers` is absent"},
		"no code":      {func(l *CSIPTestLogs) { l.Logs[0].Messages[1].Code = "" }, "no `code`"},
		"numeric code": {func(l *CSIPTestLogs) { l.Logs[0].Messages[1].Code = "2000" }, "three-digit HTTP status"},
		"no reason":    {func(l *CSIPTestLogs) { l.Logs[0].Messages[1].Reason = "" }, "no `reason`"},
		"bad type":     {func(l *CSIPTestLogs) { l.Logs[0].Messages[0].Type = "request" }, `not "req" or "resp"`},
		"ciphertext":   {func(l *CSIPTestLogs) { l.Logs[0].Messages[1].Body = "\x17\x03\x03\x00\x40junk" }, "logged as ciphertext"},
	}
	for name, tc := range cases {
		logs := goodCSIPLogs()
		tc.mutate(logs)
		findings := ValidateCSIPTestLogs(logs)
		if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
			t.Errorf("%s: no finding containing %q; got %v", name, tc.want, findings)
		}
	}
}

// TestCSIPResponseKeepsTheExampleShape covers the two fields §4.1.2's contents
// table omits and its worked example requires. A generator matching only the
// table would emit logs an ingest written against the example rejects.
func TestCSIPResponseKeepsTheExampleShape(t *testing.T) {
	data, err := goodCSIPLogs().JSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"code": "200"`) {
		t.Errorf("code is not a string:\n%s", text)
	}
	if !strings.Contains(text, `"reason": "OK\r\n"`) {
		t.Errorf("reason lost its trailing CRLF:\n%s", text)
	}
	if !strings.Contains(text, `"body": ""`) {
		t.Errorf("an absent body is not the empty string:\n%s", text)
	}
	if !BodyHasNoJSONNull(data) {
		t.Error("a body was emitted as JSON null")
	}
}
