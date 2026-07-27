package suitecsip

// sepdata_test.go holds the synthetic 2030.5 payloads the tests drive the
// checks with: a conformant tree, and the deliberately broken variants that
// prove each criterion has teeth.

import (
	"fmt"
	"net/http"
)

const sepCT = "application/sep+xml"

func dcapXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap" pollRate="60">
  <TimeLink href="/tm"/>
  <EndDeviceListLink href="/edev" all="3"/>
  <MirrorUsagePointListLink href="/mup" all="0"/>
  <ResponseSetListLink href="/rsps" all="1"/>
</DeviceCapability>`
}

func edevXML(lfdi string, sfdi uint64) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EndDeviceList xmlns="urn:ieee:std:2030.5:ns" href="/edev" all="3" results="3">
  <EndDevice href="/edev/0"><lFDI>%040x</lFDI><sFDI>1</sFDI><changedTime>1</changedTime></EndDevice>
  <EndDevice href="/edev/1"><lFDI>%040x</lFDI><sFDI>2</sFDI><changedTime>2</changedTime></EndDevice>
  <EndDevice href="/edev/2">
    <lFDI>%s</lFDI><sFDI>%d</sFDI><changedTime>3</changedTime>
    <RegistrationLink href="/edev/2/reg"/>
    <DERListLink href="/edev/2/der" all="1"/>
    <LogEventListLink href="/edev/2/lev" all="0"/>
    <FunctionSetAssignmentsListLink href="/edev/2/fsa" all="1"/>
  </EndDevice>
</EndDeviceList>`, 0xaa, 0xbb, lfdi, sfdi)
}

func regXML(pin uint64) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Registration xmlns="urn:ieee:std:2030.5:ns" href="/edev/2/reg"><pIN>%d</pIN><dateTimeRegistered>1</dateTimeRegistered></Registration>`, pin)
}

func fsaXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<FunctionSetAssignmentsList xmlns="urn:ieee:std:2030.5:ns" href="/edev/2/fsa" all="1" results="1">
  <FunctionSetAssignments href="/edev/2/fsa/0">
    <mRID>FSA0</mRID>
    <DERProgramListLink href="/edev/2/fsa/0/derp" all="3"/>
    <TimeLink href="/tm"/>
  </FunctionSetAssignments>
</FunctionSetAssignmentsList>`
}

func derpXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<DERProgramList xmlns="urn:ieee:std:2030.5:ns" href="/edev/2/fsa/0/derp" all="3" results="3">
  <DERProgram href="/derp/0"><mRID>DERP-SP-001</mRID><primacy>1</primacy>
    <DefaultDERControlLink href="/derp/0/dderc"/>
    <DERControlListLink href="/derp/0/derc" all="1"/>
    <DERCurveListLink href="/derp/0/dc" all="1"/></DERProgram>
  <DERProgram href="/derp/1"><mRID>DERP-SITE-001</mRID><primacy>5</primacy></DERProgram>
  <DERProgram href="/derp/2"><mRID>DERP-SYS-001</mRID><primacy>10</primacy></DERProgram>
</DERProgramList>`
}

func dercXML(mrid, mode, value string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<DERControlList xmlns="urn:ieee:std:2030.5:ns" href="/derp/0/derc" all="1" results="1">
  <DERControl href="/derp/0/derc/0" replyTo="/rsps/0/r" responseRequired="03">
    <mRID>%s</mRID><description>test</description><creationTime>100</creationTime>
    <EventStatus><currentStatus>1</currentStatus><dateTime>100</dateTime></EventStatus>
    <interval><duration>120</duration><start>200</start></interval>
    <randomizeStart>30</randomizeStart>
    <DERControlBase><%s>%s</%s></DERControlBase>
  </DERControl>
</DERControlList>`, mrid, mode, value, mode)
}

func ddercXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<DefaultDERControl xmlns="urn:ieee:std:2030.5:ns" href="/derp/0/dderc">
  <mRID>DDERC0</mRID>
  <DERControlBase><opModMaxLimW><multiplier>0</multiplier><value>10000</value></opModMaxLimW></DERControlBase>
</DefaultDERControl>`
}

func timeXML(now int64, quality int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Time xmlns="urn:ieee:std:2030.5:ns" href="/tm"><currentTime>%d</currentTime><quality>%d</quality><tzOffset>0</tzOffset></Time>`, now, quality)
}

// walkHandler serves the conformant tree above over the fixture's TLS session.
func walkHandler(lfdi string, sfdi, pin uint64, now int64) http.Handler {
	body := map[string]string{
		"/dcap":              dcapXML(),
		"/edev":              edevXML(lfdi, sfdi),
		"/edev/2/reg":        regXML(pin),
		"/edev/2/fsa":        fsaXML(),
		"/edev/2/fsa/0/derp": derpXML(),
		"/derp/0/derc":       dercXML("CERT-TEST", "opModMaxLimW", "6000"),
		"/derp/0/dderc":      ddercXML(),
		"/tm":                timeXML(now, 7),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
			w.Header().Set("Location", "/rsps/0/r/1")
			w.WriteHeader(http.StatusCreated)
			return
		}
		b, ok := body[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", sepCT)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b))
	})
}
