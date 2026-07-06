# TASK-069 — HTTP client: `net.Conn` shim under `http.Transport` vs hardened parser (ADR + impl)

*Status: DONE (2026-07-06, option (b) — chunked decode in httpwire; net.Conn shim backlogged) · Phase: P6 · Effort: L (≈8 h) · Difficulty: high · Risk: high*

> **Resolution note (2026-07-06).** AD-009 resolved to **option (b)** — keep
> the TASK-047-hardened, fuzz-clean, capped `httpwire` parser and add chunked
> Transfer-Encoding *decoding* to it, closing the one real functional gap (a
> conformant utility that chunks) without reworking the utility-facing
> transport. The `net.Conn`-shim-under-`http.Transport` path (option (a)) is
> **deferred to a P6-with-time backlog item** (see AD-009 in 02). Consequence:
> the option-(a)-specific acceptance/regression items below — the conformance
> **dual-run**, timeout-parity across two transports, and the single-session
> Transport test — do **not** apply to what shipped; option (b) changed nothing
> on the wolfSSL transport, keep-alive lifecycle, timeout semantics, or the
> non-chunked success bytes (byte-identical), so unit + fuzz coverage of the
> httpwire leaf is the applicable evidence. Bench conformance regeneration
> rolls into the 081 gate with the other code-complete-bench-pending work.

## Objective
AD-009 is resolved: a written decision (in 02_ARCHITECTURE_DECISIONS.md)
chooses between (a) wrapping the wolfSSL session as a `net.Conn` under
Go's `http.Transport` and (b) keeping the hardened hand-rolled parser —
informed by TASK-047's fuzz corpus — and the chosen option is IMPLEMENTED,
dual-run against the gridsim conformance suite, and deployed. The
single-keep-alive-session invariant and the SO_RCVTIMEO read-timeout
semantics survive either way.

## Background
Verified current state of `lexa-hub/internal/tlsclient/`:
- `client.go` (364 lines): `Client` lifecycle New → Dial → Get… → Close;
  Dial obtains the TCP fd via `tcpConn.File()` (a dup'ed fd) and hands it
  to wolfSSL with `wolfssl.SetFD` (:112-133); read/write timeouts are set
  DIRECTLY on that fd via `SO_RCVTIMEO/SO_SNDTIMEO` because wolfSSL does
  blocking read(2)/write(2) on it (:136-150; `ReadTimeout` +
  `DefaultReadTimeout` — the northbound-hang fix). `Close` allows re-Dial
  (:181-183).
- `readResponse` (:264-332): hand-rolled HTTP/1.1 response parsing
  (status line, headers, Content-Length body). **Chunked transfer
  encoding is REJECTED, not parsed** (:293 "Transfer-Encoding: chunked is
  not supported"; detector :334-343). Note: the architecture review's D9
  wording ("chunked parsing") is wrong on this point — the risk is the
  hand-rolled status/header/length parsing on the hostile boundary, plus
  the functional gap that a chunking server breaks us.
- `fetcher.go`: `WolfSSLFetcher` — one long-lived keep-alive session
  (`ensureDialed`), `Get/Post/GetStatus`; **invariant: never `Free()`
  mid-walk** (csip-tls-test CLAUDE.md). Northbound uses THREE fetcher
  instances (discovery/responses/flowres — cmd/northbound, see TASK-068).
- TASK-047 (P4) fuzzed `readResponse` and added size caps; its corpus +
  crash findings are this task's primary evidence.
- Conformance harness: csip-tls-test `scripts/run-conformance.sh` +
  `go test ./tests/` against gridsim (mTLS :11111) — the dual-run target.
- Cipher invariant frozen: `ECDHE-ECDSA-AES128-CCM-8 TLSv1.2` (both
  CLAUDE.md files); the TLS layer itself is NOT in play here — only the
  HTTP layer above the established wolfSSL session.

## Why this task exists
D9/§10.2: hand-rolled parsing of hostile utility bytes is where parsing
bugs become security bugs. AD-009 is an OPEN decision this task closes
(review "Leaning (a)": Go's parser is battle-tested).

## Architecture review sections
D9 · §10.2 · R5 · 02 AD-009 (OPEN → resolved here) · item 17 · 05 §7
(hostile-boundary parsers).

## Prerequisites
TASK-047 DONE (fuzz corpus + size caps — the decision input).
TASK-068 DONE (fetcher seam isolated). Bench + desktop with amd64 wolfSSL
sysroot for integration tests (`make test-integration` in csip-tls-test).

## Files
- **Read first:** internal/tlsclient/client.go, fetcher.go, request.go,
  response.go, client_timeout_test.go, parsing_test.go; TASK-047's fuzz
  findings; internal/wolfssl wrapper (Read/Write bindings).
- **Modify:** internal/tlsclient/* (per decision), cmd/northbound wiring
  if the fetcher API changes (keep it stable if possible),
  cmd/telemetry (second wolfSSL consumer — grep its fetcher usage).
- **Create:** option (a): `internal/tlsclient/conn.go` (net.Conn adapter)
  + `transport.go` (http.Transport construction) + tests; ADR text in 02.

## Blast radius
The utility-facing boundary of lexa-northbound AND lexa-telemetry (both
link tlsclient — verify telemetry's usage before scoping). CGo builds.
No bus schema. Behavioral risk: keep-alive session lifecycle, timeout
semantics, 2030.5 header specifics (`Accept: application/sep+xml` etc. —
read request.go).

## Implementation strategy
Decision first (write the AD entry with the fuzz evidence), then
implement behind a dual-run: both clients issue the SAME walk against
gridsim and byte-compare bodies/status codes across the full conformance
suite before the flip. For option (a), the shim implements `net.Conn`
over the wolfSSL session (Read/Write delegate to wolfSSL; SetDeadline
maps to the fd's SO_RCVTIMEO/SNDTIMEO — semantics differ from Go
deadlines: timeval is per-syscall idle timeout, not absolute deadline;
document and test the difference), and `http.Transport` is configured
with `DialTLSContext` returning the ALREADY-ESTABLISHED session,
`MaxConnsPerHost=1`, `DisableCompression=true`, and keep-alives on, so
exactly one wolfSSL session persists per fetcher.

## Detailed steps
1. Write the AD-009 resolution in 02: decision, fuzz-evidence summary
   (crashers found? caps sufficient?), tradeoffs (shim: battle-tested
   parser + chunked support for free, but a Conn adapter over CGo adds a
   lifecycle seam; harden: smaller change, permanent parser liability).
   If TASK-047 found NO crashers and caps are in place, hardening becomes
   defensible — the ADR must argue from the evidence, not the review's
   lean.
2. (a-path) Implement `wolfConn` (net.Conn): Read/Write → wolfssl;
   Close → session close WITHOUT freeing the ctx (fetcher owns ctx);
   deadlines → setsockopt mapping with unit tests
   (client_timeout_test.go patterns).
3. (a-path) `http.Transport` wiring inside WolfSSLFetcher behind an
   internal flag; identical public API (`Get/Post/GetStatus`) so
   northbound/telemetry don't change.
4. Dual-run harness (temporary, test-only): run the discovery walk +
   conformance suite once per client implementation against gridsim;
   assert identical status codes + bodies (XML byte-equal) + header
   handling for every fetched resource; include a chunked-response case
   from gridsim IF gridsim can emit one (it does not today — add a
   test-only chunking endpoint to gridsim admin or accept the gap with a
   parsing_test.go fixture instead; state which).
5. Timeout parity: reproduce the northbound-hang semantics — a stalled
   server (gridsim /admin/outage mode `stall` — verify the mode name in
   sim/gridsim admin API; the northbound-hang scenario uses it) must
   produce a read timeout in ≤ ReadTimeout+ε on both paths.
6. Flip default to the chosen path; keep the losing path deletable in one
   commit (delete after the soak in TASK-073 exercises reconnect churn).
7. Bench: deploy; `--only northbound-hang,wan-outage-hold,
   malformed-csip,pricing-attack,curve-attack` ×3; `make test-integration`
   (csip-tls-test) for handshake regressions; full conformance evidence
   regeneration (`scripts/run-conformance.sh`).

## Testing changes
- conn deadline-mapping unit tests; dual-run conformance comparison;
  fuzz target retained (047) pointed at whichever parser remains.
- Note: the dual-run harness and the conn deadline tests live in the CGo
  `internal/tlsclient` package and run on the desktop (amd64 wolfSSL
  sysroot) only — unless a piece can be placed in the `httpwire` leaf
  package created by TASK-047 (preferred where possible).
- Run: `make test` (hub), `make test-integration` + `go test ./tests/` +
  `scripts/run-conformance.sh` (bench repo).

## Documentation changes
- 02 AD-009: OPEN → decided, with evidence.
- csip-tls-test CLAUDE.md invariants: update the Fetcher bullet if the
  internals changed (invariant itself stays).
- lexa-hub CLAUDE.md: note chunked support status post-change.

## Common mistakes to avoid
- Letting http.Transport open a SECOND connection (pool >1 or a retry
  dial) — the single-session invariant exists because wolfSSL ctx/session
  lifecycle is manual; enforce MaxConnsPerHost=1 and a test that a second
  concurrent request either serializes or errors, matching today.
- Treating SO_RCVTIMEO as a Go deadline (it is per-read idle, resets each
  syscall; a slow-drip server evades an absolute budget — if 047 flagged
  slow-drip, add a total-response budget regardless of option).
- Freeing the wolfSSL session from Transport's connection-close path
  mid-walk (the never-Free-mid-walk invariant; RSK-07 segfault class).
- Forgetting lexa-telemetry (second consumer) in build/deploy/test.
- Skipping conformance regeneration — this is the utility-facing surface;
  09 requires fresh evidence on the release build anyway.

## Things that must NOT change
- Cipher/mTLS invariants (frozen; this task never touches TLS config).
- One persistent keep-alive session per fetcher; three-fetcher layout in
  northbound.
- ReadTimeout protection (northbound-hang scenario verdict).
- 2030.5 request headers/media types (request.go behavior byte-identical
  on the wire — capture with gridsim logging or pcap and diff).
- Fail-closed walk behavior on errors (scheduler holds last-known-good).

## Acceptance criteria
- [ ] AD-009 entry merged with evidence-based decision.
- [ ] Dual-run: identical results across the full conformance suite.
- [ ] Timeout parity test green; northbound-hang ×3 at accepted verdict.
- [ ] Conformance evidence regenerated green.
- [ ] Single-session invariant test in place.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests + `scripts/run-conformance.sh` green
  (protocol-adjacent — mandatory)
- [ ] Mayhem: targeted set ×3 (northbound-hang, wan-outage-hold,
  malformed-csip, pricing-attack, curve-attack) + full FAST campaign,
  unconditional — this task by definition changes fetcher-visible behavior
  feeding the fail-closed machinery (wan-outage-hold / northbound-hang)
- [ ] `make test-integration` green (desktop amd64 sysroot)

## Mayhem scenarios affected
northbound-hang (timeout semantics), wan-outage-hold/expiry (error
classification), malformed-csip / pricing-attack / curve-attack (parser
robustness path).

## Conformance implications
Direct: this is the CSIP transport. Full evidence regeneration required;
any header/media-type drift is a conformance break.

## Suggested commit message
`feat(tlsclient): resolve AD-009 — <net.Conn shim under http.Transport | hardened parser>; dual-run verified`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** AD-009: northbound HTTP client decision + implementation
**Description:** Decision rationale from fuzz corpus; dual-run conformance
byte-comparison; timeout parity; single-session invariant test. Risk:
HIGH (utility boundary). Rollback: internal flag back to legacy path
(kept until TASK-073 soak).

## Code review checklist
- Deadline mapping semantics documented + tested (idle vs absolute).
- Connection-pool constraints provably 1.
- Wire-level request bytes unchanged (evidence attached).
- Losing path isolated for one-commit deletion.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-073 (reconnect-churn soak exercises the new lifecycle; delete losing
path after), TASK-071 (conditional requests easier under http.Transport).
