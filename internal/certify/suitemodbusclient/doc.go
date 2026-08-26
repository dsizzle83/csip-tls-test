// Package suitemodbusclient implements the SunSpec Modbus Client Conformance
// Test Procedures v1.1 (catalog document SS-MODBUS-CLIENT-CONF-v1.1) against
// the LEXA gateway's southbound Modbus client.
//
// # The one surface that needs no decryption
//
// Every other conformance surface on this bench is inside TLS. This one is not:
// the gateway polls the desktop's plain-text SunSpec sim over Modbus/TCP, in
// cleartext, on a link the bench captures. A reviewer with the bundle's pcap and
// Wireshark can open any assertion's frame and read the ADU for themselves,
// with no key material, no decryption step and no trust in this tool's crypto.
// That makes this the suite whose evidence is easiest for a third party to
// re-derive — and it raises the bar for what counts as an honest verdict here,
// because there is no technical excuse for an uncited claim.
//
// # The DUT is the client, which inverts everything
//
// In every other suite the bench drives the DUT by connecting to it. Here the
// DUT is the CLIENT under test and the bench sims are the servers it polls. The
// bench therefore never opens a socket, never learns the DUT's ephemeral source
// port, and cannot make the DUT issue a particular request. It has two levers
// and no others:
//
//   - the sims' published simapi control plane, which can make a server behave
//     the way a procedure's setup step calls for (return exceptions, serve
//     not-implemented sentinels, re-home its register map, re-address its unit
//     id, drop or truncate or delay one named response, sever the connection);
//     and
//   - the same control plane's BARRIERS, which say when the DUT has met any of
//     that — a poll-cycle barrier and a transaction ledger, both fenced on a
//     control-plane epoch the sim hands back with every change.
//
// The second used to be "time, waiting for the DUT's ten-second poll loop to
// come round", and every row's reliability rested on that guess. It does not
// any more: nothing in this suite sleeps for a poll interval, and no verdict is
// decided by elapsed time. See deterministic.go.
//
// Three consequences run through the whole package. Frame attribution rests on
// an endpoint claim rather than a 4-tuple, and the citation phase re-derives
// that claim's soundness from the capture rather than assuming it (see
// observer.claimServer and assertAttributionSound). A client that has been
// connected since long before the capture began never repeats its discovery
// sequence, so the discovery rows sever its connection through the sim to make
// it reconnect, and say in the assertion that they did. And several procedures
// written for an operator console — write this value to that point, read that
// point on its own — describe a mode of operation this DUT simply does not
// have, which is a capability gap in the device, not a gap in the bench.
//
// # What a verdict means here
//
// The suite follows the framework's vocabulary and adds one rule of its own, so
// that a partially-exercised procedure cannot round up to PASS:
//
//   - A criterion that was exercised and held is a PASS assertion, cited.
//   - A criterion that was exercised and did not hold is a FAIL assertion.
//   - A criterion that could not be exercised is a SKIP assertion whose text
//     names the missing capability precisely enough to be actioned — usually a
//     sim verb that does not exist yet, occasionally a DUT diagnostic mode.
//   - An OBSERVATION that is adjacent to a criterion but is not that criterion
//     is cited with the SKIP verdict, never PASS. Assertion verdicts roll up to
//     the test case's verdict, so a cited observation carrying PASS would
//     silently promote a row nobody demonstrated. Several checks here cite real
//     wire facts under SKIP for exactly that reason, and say so in the text.
//   - A row whose procedure was only partly run declares WARN as a floor, with
//     the unexercised part named in the notes.
//
// The three dishonesty modes the framework's own doc.go warns about all have a
// specific shape in this suite, and each has a specific defence:
//
//   - Claiming another test case's frames. The DUT's southbound connection is
//     long-lived and shared by every row in this document, so an ADU is this
//     check's evidence only if every frame delivering its bytes is this check's
//     frame; loadConversation enforces that and reports what it dropped.
//   - Decoding the DUT's bytes with the DUT's own framing code. The MBAP parser
//     in modbuswire.go is written from the specification, in this package, and
//     shares nothing with the product — not even lexa-proto/mbap.
//   - Passing a criterion the bench never exercised. Every SKIP here carries
//     the reason and the missing capability, and the report section lists them.
//
// # Layout
//
//	modbuswire.go    independent Modbus/TCP ADU parser over a reassembled
//	                 direction: MBAP fields verbatim, byte ranges, frame
//	                 provenance, request/response pairing by transaction id
//	sunspec.go       the SunSpec layer: the "SunS" identifier, the standard
//	                 bases, model-chain reconstruction from observed registers,
//	                 the not-implemented sentinel table
//	conversation.go  frames → messages, plus the finding/emit vocabulary that
//	                 keeps decision logic pure and testable
//	observe.go       the live phase's identity half: endpoint claims, what was
//	                 done to the bench, DUT journal reads
//	deterministic.go the live phase's timing half: arm at an epoch, wait on the
//	                 simulator's barrier, grade its transaction ledger
//	ledger.go        this suite's independent reader for that ledger
//	common.go        the assertions every wire row shares: attribution
//	                 soundness, MBAP framing, transaction discipline, the
//	                 125-register ceiling
//	checks_*.go      the sixteen catalog rows, grouped by the document's own
//	                 sections (§2.4 discovery, §2.5 read, §2.6 write,
//	                 §2.7 information, §2.8 protocol, §2.9 error)
//	register.go      uid bindings and run order
//	report.go        the suite's own coverage-and-gaps section for the bundle
//
// # Parameters
//
//	modbus-client.inject            "off" disables all fault injection
//	modbus-client.device            the DUT's device name for the plain server
//	                                (default "inv-plain"), for journal correlation
//	modbus-client.unit-id           the server's expected unit id, if the operator
//	                                wants it asserted rather than merely reported
//	modbus-client.dercontrol        "on" allows WR-1/WR-2 to post a bounded
//	                                northbound DERControl to provoke a southbound
//	                                write. Off by default: it makes the DUT do
//	                                something it was not doing.
package suitemodbusclient
