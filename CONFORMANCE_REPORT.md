# CSIP Conformance Report — DER Hub (northbound client)

**DUT:** `lexa-hub` — the IEEE 2030.5 / CSIP **DER client** (`lexa-northbound`
walker, scheduler, response + telemetry posters, wolfSSL mTLS transport).
`csip-tls-test` here is the **stand-in test server** (replaced by the lab Test
Server at conformance time).
**Reference:** SunSpec CSIP Conformance Test Procedures **v1.3** (Approved, 2023-10-24).
**Test server:** `sim/gridsim` driven over httptest (logic) and over wolfSSL mTLS
(`sim/server` + `sim/tlsserver`) for the security layers.

Run, from `csip-tls-test/` (self-contained, one CA, both ends on this host):

```bash
scripts/run-conformance.sh            # layers 1-3 (logic + TLS + full stack)
scripts/run-conformance.sh --capture  # + live pcap proving 0xC0AE on the wire
```

Run, from `lexa-hub/` (air-gapped: real DUT vs sim server, certs in separate repos):

```bash
scripts/devkit-mtls-check.sh          # lexa-northbound ↔ sim/server over mTLS
```

Last run: **4/4 layers pass, 42/42 logic tests pass, 0 vet findings; both repos
green; air-gapped DUT run negotiates CCM-8 and POSTs CORE-022 responses.**

### Audit resolution status (2026-06-08)

| # | Finding | Status |
|---|---|---|
| C-1 | randomizeDuration ignored | ✅ Fixed in `lexa-hub` scheduler + tests |
| C-2 | No Cancelled(6)/Superseded(7) responses | ✅ Fixed in `lexa-hub` responseTracker + tests |
| C-3 | Cross-program superseding | ✅ Documented as deliberate absolute-primacy design |
| C-4 | OS clock stepping | ✅ N/A — `lexa-hub` is already offset-only (no `Settimeofday`) |
| C-5 | COMM-004 chain-depth fixtures | ⬜ Open — generate 3/4-deep + invalid-MICA certs at the lab |
| S-1 | `X-Peer-LFDI` header trust | ✅ Fixed in `tlsserver` (strip client header) + regression test |
| S-2 | Telemetry readings lacked ReadingType | ✅ Fixed — one MMR per quantity with uom + powerOfTenMultiplier |
| Q-1 | gridsim method handling | ✅ Fixed — 501 for unknown methods, `Allow` on 405, fixture note |
| Q-2 | `AddResource` data race | ✅ Fixed — guarded by `s.mu` |
| Q-4 | Test-cert churn | ✅ Air-gapped layout: client certs in `lexa-hub/`, server in `csip-tls-test/` |

---

## 1. Evidence matrix (CSIP test ID → how it's proven)

| CSIP test | Applies to client | Evidence | Result |
|---|---|---|---|
| COMM-002 Out-of-band discovery | ✓ | `TestCSIP_COMM002` + live walk from `-server host:port` | PASS |
| COMM-003 Basic security (TLS1.2 + CCM-8) | ✓ | `TestClient_CipherIsCSIPCompliant`; **0xC0AE seen on the wire** (layer 4); server log `cipher=ECDHE-ECDSA-AES128-CCM-8` | PASS |
| COMM-004 Advanced security (cert validation) | ✓ | `TestClient_RejectsServerWithWrongCA` (wolfSSL err -188, no signer), `TestClient_RejectsWrongCipher` (err -313, no shared cipher); handshake shows server **CertificateRequest** → mutual TLS | PASS¹ |
| CORE-003 Polling | ✓ | `TestCSIP_CORE003`; hub re-walks `/dcap` every `discovery_interval_s` | PASS |
| CORE-005 Basic time (quality=7) | ✓ | `TestCSIP_CORE005`; walker computes `ClockOffset` from `/tm` | PASS |
| CORE-009 Advanced end device | ✓ | `TestCSIP_CORE009` | PASS |
| CORE-010 / 011 Function Set Assignments | ✓ | `TestCSIP_CORE010/011`; walker follows FSA→DERProgramList | PASS |
| CORE-012 / 013 DER program/control | ✓ | `TestCSIP_CORE012/013` | PASS |
| CORE-014 Basic DER settings | ✓ | `TestCSIP_CORE014` | PASS |
| CORE-021 Randomized events | ✓ | `TestCSIP_CORE021`, `BASIC019/020` | PARTIAL² |
| CORE-022 Responses | ✓ | `TestCSIP_CORE022`, `BASIC021/022/023` (Received/Started/Completed) | PARTIAL³ |
| BASIC-001 DER identification (SFDI/LFDI/PIN) | ✓ | `TestCSIP_BASIC001`; SFDI checksum matches IEEE 2030.5 §6.3.3 worked example | PASS |
| BASIC-002…029 (groups, controls, supersede, MUP) | ✓ | `TestCSIP_BASIC002`–`029` | PASS⁴ |
| ERR-001 Error scenario | ✓ | `TestCSIP_ERR001` | PASS |

¹ COMM-004 in the procedures has sub-tests A–G (chain length 2/3/4, invalid MICA
  ext/name/policy, self-signed). We prove the **rejection path** (wrong-CA,
  self-signed-equivalent, wrong-cipher). The 3- and 4-deep MICA/MCA chain fixtures
  are **not yet generated** — see finding C-5.
² Randomization handles `randomizeStart` only; `randomizeDuration` is ignored — finding C-1.
³ Responses cover the happy path (1→2→3). **Cancelled(6)** and **Superseded(7)**
  responses are not emitted — finding C-2.
⁴ Cross-program superseding (BASIC-021…026 "System DERC vs Service Point DERC")
  is exercised only within a single program by the suite — finding C-3.

---

## 2. Audit findings

Severity: **C** = CSIP-correctness, **S** = security, **Q** = code quality.
Each is something to fix *before* a paid lab run, not a blocker for bring-up.

### CSIP correctness

**C-1 — Scheduler ignores `randomizeDuration`.**
`internal/csip/scheduler/scheduler.go:175` (`randomizedStart`) applies only
`RandomizeStart`; event end is always `start + Interval.Duration`. The model
parses `randomizeDuration` (`model/resources.go:291`) but nothing consumes it.
CORE-021 sets `randomizeDuration` on DERControl#2/#3. → Apply a cached
per-MRID duration offset the same way `randomizeStart` is cached.

**C-2 — No Cancelled / Superseded responses (CORE-022 / CORE-023).**
`cmd/hub/response.go:40` skips any event with `CurrentStatus == 6` *before*
the response stage, so the hub never POSTs **status=6 (cancelled)** — which
CORE-022 step 7 explicitly requires. The model only defines
`ResponseEventReceived/Started/Completed` (`model/resources.go:433`); there is
no `=6` or `=7`. → Add Cancelled(6) and Superseded(7) constants; in the tracker,
when a previously-Received MRID transitions to cancelled/superseded, emit the
matching response instead of silently dropping it. **Untested** — no test
touches `responseTracker`; add one.

**C-3 — Superseding is single-program only.**
`Evaluate` (`scheduler.go:94`) considers only the highest-priority program, and
`isSuperseded` (`scheduler.go:200`) scans that program's own control list. The
BASIC-021…026 matrix overlaps controls *across* DERPrograms (System vs Service
Point). → Decide explicitly whether the hub merges events across programs; if
so, supersede across the merged set; if not, document the limitation.

**C-4 — Hub steps the OS clock from a quality=7 (intentionally uncoordinated) time.**
`cmd/hub/main.go:333` (`syncSystemClock`) calls `syscall.Settimeofday` to step
the system clock to server time on every walk — while *also* keeping
`clockOffset` for scheduling. Per CORE-005 the `/tm` quality is 7
("intentionally uncoordinated"); that source must not be treated as
authoritative wall-clock truth, and stepping the OS clock fights NTP. → Use the
offset-only path you already have (the `clockOffset` atomic) for event timing
and drop `Settimeofday`, or gate it behind an explicit "no NTP" config flag.

**C-5 — COMM-004 chain-depth fixtures missing.** Only a 2-deep chain
(CA→device) and a wrong-CA chain exist. The procedures require 3-deep
(SERCA→MICA→device) and 4-deep (SERCA→MCA→MICA→device) plus invalid-MICA and
self-signed certs. → Extend `scripts/gen-test-certs.sh` with these fixtures and
add COMM-004A–G negative cases.

### Security

**S-1 — `X-Peer-LFDI` header is trusted for access control (test-server path).**
`sim/gridsim/server.go:131,147` gates `/edev/*` on a client-supplied
`X-Peer-LFDI` header. Over real mTLS the client doesn't send it and the server
correctly derives identity from the peer cert (`SetClientCertDER`), so this is
*currently* a convenience for the plaintext/httptest path only. But a
header-asserted identity must **never** reach a production server. → Make the
mTLS server ignore `X-Peer-LFDI` entirely and key access solely off the
handshake-derived LFDI; keep the header strictly in `sim/httpsim` if needed.

**S-2 — Telemetry readings carry implicit scaling.** `cmd/hub/telemetry.go`
posts V×100 and Hz×100 as bare integers with no `ReadingType`
powerOfTenMultiplier/UOM, so a real server can't interpret units. The sim drains
the body unparsed, hiding this. → Send a `ReadingType` (or per-reading
multiplier) so MUP readings are self-describing.

### Code quality

**Q-1 — gridsim is a fixture, not a conformant server.** The 2030.5 handler
(`sim/gridsim/server.go`) ignores list query params `s`/`l`/`a` (CORE-004 paging
returns the full list regardless), returns 405 for unknown methods instead of
501, sets no `Allow` header on 405 (GEN.045), and never returns 400 for a
missing Host header. Fine for driving *client* tests; do **not** present it as a
server EUT. Document this in `sim/gridsim/server.go`'s header comment.

**Q-2 — `Server.AddResource` writes the resource map without `s.mu`.**
`sim/gridsim/server.go:835` mutates `s.resources` lock-free while handlers read
it under `RLock` — a data race if called after `Serve`. → Take `s.mu.Lock()`
(or document "build-time only, before Serve").

**Q-3 — `request.go` Host comment vs behavior.** The comment says it strips the
port; the code passes `host` (with port) verbatim. Harmless, but fix the comment
or the code so the next reader isn't misled.

**Q-4 — Regenerating test certs churns tracked fixtures.** `make gen-test-certs`
rewrites the committed public `*-cert.pem` files (LFDI changes with each new
keypair). Consider committing a *stable* fixture set, or `.gitignore` the
public certs too and generate them in CI, so a conformance run doesn't produce a
spurious diff.

---

## 3. What is solid

- **Transport is genuinely CSIP-correct.** Only `ECDHE-ECDSA-AES128-CCM-8` is
  offered (single cipher in the ClientHello — verified in the pcap), TLS 1.2 is
  pinned, mutual TLS is enforced (server CertificateRequest + client cert), and
  wrong-CA / wrong-cipher peers are rejected with TLS alerts.
- **Discovery is link-driven**, never hardcoded past `/dcap` (GEN.004/GEN.025).
- **Content-Type is strictly enforced** (`application/sep+xml`, GEN.003) on every
  GET, and every XML root carries `urn:ieee:std:2030.5:ns` (GEN.009).
- **SFDI/LFDI derivation matches IEEE 2030.5 §6.3** including the sum-of-digits
  check digit.
- **Scheduler fundamentals are right**: cancelled events skipped, primacy
  ordering, latest-creationTime wins with MRID tiebreak, randomization cached
  per-MRID for stability, DefaultDERControl fallback.
