// Package suitemodbusserver implements the SunSpec Modbus Conformance Test
// Procedures v1.4 (catalog doc SS-MODBUS-CONF-v1.4) and the two server-side
// procedures of SunSpec Modbus for IEEE 1547 Test Procedures (catalog doc
// SS-1547-TEST-v1.1) against the LEXA gateway acting as a SunSpec Modbus
// SERVER.
//
// # What this suite proves, and what it deliberately cannot
//
// These two documents are device-model procedures: they ask whether a SunSpec
// server's register map is discoverable, correctly shaped, correctly typed,
// correctly writable, and correctly refusing. They say almost nothing about
// transport — which is the whole reason they can be run here at all, because
// the transport under them is not the one the documents assume.
//
// # The transport deviation, stated once and honoured everywhere
//
// Both documents were written for plain Modbus/TCP on port 502 (and, in the
// v1.4 document's §2.7.1-§2.7.5, for Modbus RTU on a serial line). The DUT has
// NO plain northbound Modbus listener at all: its northbound Modbus is
// mbaps-only — Secure SunSpec Modbus, mTLS on :802 — because the product
// forbids a plaintext fallback (lexa-gw CODING_PRINCIPLES §4). So every
// procedure in this suite is executed INSIDE the TLS tunnel.
//
// That is sound rather than a fudge. Secure SunSpec Modbus (SunSpecTCP-9)
// requires no change to the MBAP protocol inside the tunnel: the ADUs this
// suite sends and the ADUs the DUT answers with are byte-for-byte the ADUs the
// v1.4 procedures describe. What changes is the evidence path. A pcap of :802
// is ciphertext, so a claim about a Modbus PDU is only as good as the
// decryption behind it — which is exactly why internal/wolfssl/keylog.go and
// internal/evidence/tlsdecrypt exist. This suite reconstructs each session's
// application-layer byte stream from the capture using the run's NSS key log,
// keeps every recovered plaintext byte's provenance back to the capture frames
// it arrived in (see appstream.go), and cites THOSE frames. When the key log is
// absent or a record fails to decrypt, the affected assertion is a SKIP naming
// the reason — never a PASS resting on "we saw some TLS records go by".
//
// # The rows this transport kills, and why they are NOT-APPLICABLE, not PASS
//
// Six catalog rows in SS-MODBUS-CONF-v1.4 are dead against this DUT's
// TRANSPORT and are left unregistered so the coverage report prints them with
// the catalog's own reason rather than a verdict this suite invented:
//
//	TCP-1  "TCP Interface"    — asserts a Modbus/TCP interface on port 502.
//	                            There is none; :802 is a different, secured
//	                            interface, and passing TCP-1 on it would be a
//	                            claim about a port that is closed.
//	RTU-1  "RTU Interface"    — no northbound serial interface exists.
//	RTU-2  "Baud Rate"        — likewise.
//	RTU-3  "Partial Request"  — likewise (its TCP twin, TCP-2, IS implemented).
//	RTU-4  "Broadcast Test"   — likewise; MBAP has no broadcast.
//	RTU-5  "Device Address Write" — likewise; the Model 1 DA point addresses a
//	                            serial slave, and the gateway's unit identifiers
//	                            are allocated by the gateway, not written by a
//	                            client.
//
// Two more (CRV-2, CRV-3) are dead for a different reason: both need a WRITABLE
// second curve, and the DUT serves the staging curve wholly not-implemented —
// every Crv2./Ctl2. field reads the sentinel and every write to one is refused
// before ACK — so the 1547 profile's item G3 is not met and the adopt-curve
// handshake has nothing to run against. The write path is design Stage 5 in
// lexa-gw and is not built.
//
// CRV-1 is NOT one of them, and the reason it used to be is worth recording.
// All three were excluded until 2026-07-28 on the claim that the gateway's
// chain builder rejects models 705-712 northbound. It does not: 703 and 705-712
// are chained DEVICE-CONDITIONALLY, a unit carrying one if and only if its own
// DER serves it southbound, so a curve model is reachable and CRV-1 — which
// tests that curve 1 exists and is READ-ONLY, the posture the gateway does
// implement — has a subject. checks_crv.go says what it can assert today and
// what it cannot.
//
// # The honest shape of a write test against this DUT
//
// Six of the fifteen applicable v1.4 rows (MB-1, MOD-3, EXC-1, REV-1, REV-2,
// REV-3) require WRITING to the DUT. Three independent product policies can
// refuse a northbound write before the procedure's own criterion is reached:
//
//   - the control-authority overlay (a gateway in CSIP authority denies writes
//     to the commanded points of models 704-712, exception 0x01);
//   - the SUN-002 honesty gate (a point that is writable per RBAC but has no
//     executor is refused with exception 0x02 BEFORE the ack, rather than
//     acknowledged and dropped);
//   - defence in depth in the write decoder (no scale factor, rating,
//     remaining-time readback, model header or Model 1 point is ever writable,
//     whatever the client's role).
//
// A suite that reported "EXC-1 PASS" because a write was refused would be
// reporting the overlay, not the exception ladder. So every write-dependent
// check first performs a CONTROL write — a valid, in-range value to the same
// point — and only grades the procedure's criterion when the control write is
// accepted. When it is refused, the check returns SKIP with the refusing
// exception code cited from the wire, which says precisely "this procedure was
// not exercised, and here is the frame that shows why". That is a different
// statement from PASS and from FAIL, and the distinction is the point.
//
// Writes also restore what they changed: every check that writes captures the
// point's pre-write value and writes it back before returning, so a run leaves
// the DUT's commanded state as it found it. Setpoint writes are ordered so that
// no enable is turned on with a setpoint the operator did not ask for; the
// enumeration sweep of MOD-3 step 3, which necessarily toggles an enable, can
// be disabled with -param modbus.no-enum-writes=1 and then reports SKIP.
//
// # Referee independence
//
// This package shares exactly one thing with the product: lexa-proto/mbap, the
// MBAP framing codec (the wire format is the wire format — a divergent framing
// codec would be a bug, not independent verification). Everything above it is
// this suite's own:
//
//   - the Modbus PDUs are built and parsed here (pdu.go), not by mbap's
//     helpers, so a PDU-shaping bug shared with the DUT cannot hide;
//   - the SunSpec discovery walk is re-derived from the SunSpec Device
//     Information Model Specification (walk.go), not imported from
//     lexa-proto/sunspec;
//   - the model point tables are transcribed here from the SunSpec DER
//     Information Model Specification (models.go), NOT imported from
//     lexa-proto/sunspec/derlayout.go, which is the same table the DUT encodes
//     with. A wrong offset in that table would otherwise be invisible: the DUT
//     would put a point in the wrong place and this suite would look for it
//     there and find it.
//
// # Parameters
//
// All optional; every one has a documented default.
//
//	modbus.transport      "mbaps" (default) or "plain". "plain" speaks Modbus/TCP
//	                      with no TLS, which is what the loopback tests use and
//	                      what a future plain-502 DUT would need.
//	modbus.role           PKI role fixture to present, default "super-admin".
//	modbus.unit           Modbus unit identifier, default: discovered by probing.
//	modbus.unit-scan-max  highest unit id the probe tries, default 16.
//	modbus.reversion-s    reversion time for REV-1/2/3, default 20 (seconds).
//	modbus.no-enum-writes "1" makes MOD-3 step 3 (the enumeration sweep) SKIP.
//	pics.mn / pics.md / pics.sn
//	                      Model 1 identity from the device PICS workbook. When
//	                      supplied, DEV-2 compares them; when absent, DEV-2 says
//	                      so rather than pretending the comparison happened.
//	pics.models           comma-separated model ids the PICS declares. DEV-1
//	                      compares the discovered chain against them; without it
//	                      DEV-1 says a chain cannot be checked against itself.
//	pics.reversion-timer  "1" declares that the PICS claims a reversion timer.
//	                      §2.6 does not perform the reversion tests at all when
//	                      the functionality is not implemented, so an incomplete
//	                      reversion group is N/A by default; with this set, the
//	                      same observation is REV-1 step 1's FAIL.
//	1547.require-models   comma-separated model ids overriding the IEEE 1547
//	                      profile's required-model list for MOD-4. Use only to
//	                      record a PICS-scoped claim, and know that the bundle
//	                      prints the override.
package suitemodbusserver
