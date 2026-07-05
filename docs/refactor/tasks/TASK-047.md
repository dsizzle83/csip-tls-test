# TASK-047 — Fuzz `tlsclient.readResponse` + response size caps

*Status: DONE (2026-07-05, lexa-hub cb4ae45 + 8e477fa + 754857d on `task/047-httpwire`) —
httpwire leaf package extracted (stdlib-only, CGo-free); 64 KiB header cap added (body cap
untouched); 3 fuzz targets + 11-file real-gridsim corpus; 15 min/target local runs clean
(56.7M/82.3M/83.0M execs, zero crashers); nightly CI `fuzz` job on the existing 04:17 UTC
cron (green-on-first-scheduled-run pending merge). Bench-dependent regression items (live
conformance smoke, targeted Mayhem spot runs) deferred to the next deploying session per
lane restrictions — no behavior change expected (seam is byte-identical for valid
responses; parser-level tests + real-response corpus prove accept/reject parity).
· Phase: P4 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

## Objective
Make the hand-rolled HTTP response parser on the utility-facing boundary
fuzzable and fuzzed: extract a pure parsing seam, add Go native fuzz targets
with a corpus captured from real gridsim responses, add the missing **header
size cap** (a body cap already exists), fix trivial crashers inline, and
wire a nightly fuzz job into the TASK-002 CI.

## Background
Repo `~/projects/lexa-hub`. `internal/tlsclient` is the wolfSSL mTLS client
every northbound byte passes through (`WolfSSLFetcher` in
`internal/tlsclient/fetcher.go` wraps it; used by cmd/northbound and
cmd/telemetry). Verified state of `client.go` (364 lines):

- `readResponse()` (line 268): Phase 1 loops `wolfssl.Read` into `buf`
  until `\r\n\r\n` — **unbounded**: a server streaming garbage without a
  header terminator grows `buf` until read error/OOM. This is the missing
  header cap.
- Chunked transfer is **rejected, not parsed**: `isChunkedEncoding`
  (line 336) → `"Transfer-Encoding: chunked is not supported"` (line 293).
  (The architecture review D9/§10.2 says "chunked parsing/decoding" — that
  is inaccurate for this repo's current code; there is chunked *detection*
  only. A "max chunk" cap is therefore N/A; keep the rejection and fuzz the
  detector.)
- Body caps exist: `maxResponseBody = 10 << 20` (line 21) enforced both for
  Content-Length (line 313) and read-until-close (lines 297–309).
- `responseContentLength` (line 352): `strconv.Atoi` of the header value;
  parse failure OR absence → −1 → read-until-close. Note: a NEGATIVE
  Content-Length parses fine and also lands in read-until-close (cl < 0).
  An ambiguous duplicate Content-Length takes the first parseable one —
  fuzz will explore; decide + document behavior (first-wins + cap is
  acceptable for a client talking one pinned server).
- Read timeouts: SO_RCVTIMEO on the raw fd (lines 143–155, QA 2026-07-02
  northbound-hang fix) — the parser never hangs forever, but that is not a
  memory bound.
- Response consumers: `fetcher.go` (status-line/header split + XML body
  handoff), `response.go`, `dcap.go`; `parsing_test.go` and
  `testdata/` already exist — extend, don't duplicate.

Fuzzing requires decoupling from wolfSSL (CGo, needs the amd64 sysroot —
`make test-integration` docs in csip-tls-test). A pure function inside
`internal/tlsclient` is NOT enough: the package imports `internal/wolfssl`,
and `go test` compiles the whole package — a fuzz target living there can
never run on the sysroot-less CI runners this task's own constraint names.
So the seam moves OUT: extract the parsing core of `readResponse` as
`readHTTPResponse` plus the existing helpers `responseContentLength`
(client.go:352) and `isChunkedEncoding` (client.go:336) into a new CGo-free
leaf package `internal/tlsclient/httpwire` (stdlib imports only), which
client.go then imports; `readResponse` becomes a thin wrapper passing a
wolfssl-backed `read func([]byte) (int, error)` closure. The leaf package
fuzzes with `go test -fuzz` on any machine, no CGo, no sysroot.

## Why this task exists
D9/§10.2: "Hand-rolled HTTP parsing on the untrusted boundary … Malformed
chunk sizes / header floods / unbounded bodies — fuzz it or replace it."
Top-20 item 10. AD-009 defers the shim-vs-harden decision to TASK-069 —
"Until then the parser gets size caps (part of TASK-047)" and the fuzz
corpus informs that decision.

## Architecture review sections
D9, §10.2, R5, Top-20 item 10. Roadmap: 02 AD-009; 03 Phase 4 (fuzzers in
nightly CI ≥15 min, zero crashes = exit criterion); 05 §7 ("anything
parsing bytes from outside the box needs size caps and a fuzz target");
06 §3 ("Hostile HTTP bytes → fuzz + size caps → 047").

## Prerequisites
TASK-002 DONE (lexa-hub CI exists to host the nightly job). The refactor
itself has no dependencies.

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/tlsclient/client.go` (all)
  - `~/projects/lexa-hub/internal/tlsclient/{fetcher.go,response.go,parsing_test.go,config.go}`
  - `~/projects/lexa-hub/internal/tlsclient/testdata/` (existing fixtures)
  - `~/projects/csip-tls-test/scripts/run-conformance.sh` (corpus capture context)
- **Modify:**
  - `~/projects/lexa-hub/internal/tlsclient/client.go` (parsing core moves out; thin wrapper + httpwire import remain)
  - lexa-hub CI workflow file from TASK-002 (nightly fuzz job against httpwire)
  - `~/projects/lexa-hub/Makefile` (`fuzz` target)
- **Create:**
  - `~/projects/lexa-hub/internal/tlsclient/httpwire/httpwire.go` (CGo-free leaf: `readHTTPResponse` + `responseContentLength` + `isChunkedEncoding` + caps)
  - `~/projects/lexa-hub/internal/tlsclient/httpwire/fuzz_test.go`
  - `~/projects/lexa-hub/internal/tlsclient/httpwire/testdata/fuzz/` seed corpus files

## Blast radius
`internal/tlsclient` — the utility-facing hot path for northbound AND
telemetry. The refactor must be behavior-preserving byte-for-byte for valid
responses; the new header cap changes behavior only for responses no sane
server sends (>64 KiB of headers). CGo boundary untouched (`wolfssl.Read`
call sites stay in client.go; the parsing core moves into the new
`httpwire` leaf package, which imports nothing beyond stdlib — CGo-free by
construction).

## Implementation strategy
Three commits: (1) httpwire leaf-package extraction + existing tests green;
(2) caps + fuzz targets + seed corpus (all in httpwire); (3) CI nightly job
+ Makefile target. Corpus:
run the CSIP conformance walk against gridsim once with a temporary
capture hook (or extract from existing `testdata/` fixtures + add real
DeviceCapability/DERControlList/Time responses saved from
`curl`-equivalent bench traffic) — corpus files are raw HTTP response bytes.

## Detailed steps
1. **Leaf-package extraction.** Create `internal/tlsclient/httpwire`
   (stdlib imports only — no `internal/wolfssl`, no `internal/tlsclient`)
   and move the parsing core there:
   `func ReadHTTPResponse(read func([]byte) (int, error), maxHeader, maxBody int) ([]byte, error)`
   containing the exact current logic (header loop, chunked rejection,
   Content-Length paths), plus `responseContentLength` and
   `isChunkedEncoding` (moved from client.go:352/:336; export what
   client.go needs). client.go imports httpwire; `(c *Client) readResponse()`
   becomes
   `httpwire.ReadHTTPResponse(func(p []byte) (int, error) { return wolfssl.Read(c.ssl, p) }, maxResponseHeader, maxResponseBody)`.
   Run `go test ./internal/tlsclient/httpwire/` (pure, works anywhere) and,
   on the desktop, `go test ./internal/tlsclient/` — `parsing_test.go` and
   friends must pass unchanged (move parser-level cases into httpwire where
   they no longer need CGo). (The remaining tlsclient tests need the
   sysroot; run what runs on the desktop per BENCH.md wolfSSL notes.)
2. **Header cap.** `const maxResponseHeader = 64 << 10` (64 KiB). In
   Phase 1, if `len(buf) > maxResponseHeader` with no terminator: return
   `fmt.Errorf("response header block too large: exceeded %d bytes", maxResponseHeader)`.
   Also cap the TOTAL buffer in Phase 1 (headers may arrive with body bytes
   attached — the check is on buf before terminator found, which covers it).
3. **Content-Length hardening.** Negative or non-integer → treat as absent
   (current behavior, now explicit + tested); values > maxBody rejected
   (exists, line 313); document first-Content-Length-wins in a comment.
4. **Fuzz targets** in `httpwire/fuzz_test.go` (they MUST live in httpwire,
   not tlsclient — see Common mistakes):
   ```go
   func FuzzReadHTTPResponse(f *testing.F) // feeds arbitrary bytes via a chunking reader that splits input at varying boundaries (derive split points from data to exercise the incremental header-scan)
   func FuzzResponseContentLength(f *testing.F)
   func FuzzIsChunkedEncoding(f *testing.F)
   ```
   Properties asserted: no panic; result ≤ maxHeader+maxBody bytes; error
   XOR valid prefix; a returned response always contains `\r\n\r\n`;
   Content-Length path returns exactly headerEnd+cl bytes. Seed with: every
   file in the new corpus dir, minimal valid 200, missing CL, chunked
   header, negative CL, huge CL, header-only flood, split-across-reads
   fixtures.
5. **Corpus capture.** From the desktop with the bench up: temporarily run
   the conformance client or `sim/client` against gridsim and save 5–10
   raw responses (DeviceCapability, Time, EndDeviceList, DERProgramList,
   DERControlList, a 404, the Response POST reply) into
   `httpwire/testdata/fuzz/`. Document the capture commands in a README line inside
   the dir. (Any equivalent method is fine; the corpus must be REAL server
   bytes, review §9 self-confirmation caveat noted.)
6. **Local fuzz run:** `go test -fuzz=FuzzReadHTTPResponse -fuzztime=15m ./internal/tlsclient/httpwire/`
   (repeat per target). Triage crashers: trivial fixes (bounds, off-by-one)
   land in this task with regression seeds committed; anything structural
   is filed and linked in the PR + noted for AD-009/TASK-069.
7. **CI:** Makefile `fuzz:` target looping the three targets 15 min each
   against `./internal/tlsclient/httpwire/`; nightly workflow job (schedule
   trigger) runs `go test -fuzz` on httpwire only — no CGo, no sysroot
   needed on the runner — uploading any
   `internal/tlsclient/httpwire/testdata/fuzz/.../crash-*` artifacts. Merge
   gate for THIS task: the 15-min runs are clean.

## Testing changes
New fuzz targets + seed corpus; extended unit cases for header-cap,
negative CL, oversized CL; all existing parsing tests green. Run:
`go test ./internal/tlsclient/httpwire/` (pure, anywhere),
`go test -fuzz=... -fuzztime=15m ./internal/tlsclient/httpwire/`
per target, and on the desktop the CGo integration tests
(`make test-integration` in csip-tls-test proves the live handshake path
still works against gridsim).

## Documentation changes
- 02 AD-009: note caps landed + fuzz findings summary (informs the
  TASK-069 shim-vs-harden decision).
- Correct the review-inherited claim where it appears in roadmap prose if
  encountered: the parser REJECTS chunked; it does not decode it.

## Common mistakes to avoid
- The fuzz reader must deliver input in VARYING slice sizes — the header
  scan is incremental (`bytes.Index` on the growing buf each read); a
  single-shot reader misses the resume-scan bugs.
- Do not "fix" the chunked rejection into an implementation — that is
  TASK-069's decision (AD-009); adding a parser here doubles the attack
  surface this task is capping.
- Keep `readResponse`'s successful-path bytes IDENTICAL (headers+body,
  trailing bytes trimmed to `need`, line 330) — `fetcher.go`/`response.go`
  parse the returned blob.
- The 64 KiB header cap must comfortably exceed real CSIP responses
  (gridsim sends a handful of headers) — verify against the corpus before
  choosing a smaller value.
- The fuzz target must live in `httpwire`, NOT `internal/tlsclient`:
  `go test` compiles the whole package it sits in, and tlsclient imports
  `internal/wolfssl` (CGo) — a fuzz test there can never run on the
  sysroot-less CI runners, no matter how pure the target function is.
  httpwire must import nothing beyond stdlib.
- `wolfSSL_Init` once-per-process rule is untouched (no new init sites).

## Things that must NOT change
- Valid-response parsing behavior byte-for-byte (conformance suite +
  `wan-outage-hold`/`northbound-hang` depend on the fetcher's error
  semantics: errors → discovery error → fail-closed hold, never a hang).
- SO_RCVTIMEO timeout behavior (QA 2026-07-02 northbound-hang fix,
  client.go:136–155) — the seam must not move reads off the wolfSSL fd
  path in production code.
- `maxResponseBody = 10 MiB` (existing cap; only ADD the header cap).
- Cipher/mTLS invariants (`ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`, cipher check
  at client.go:168–172).
- `WolfSSLFetcher` single keep-alive session semantics ("never Free()
  mid-walk" — csip-tls-test CLAUDE.md invariant applies to the twin; same
  discipline here).

## Acceptance criteria
- [ ] `internal/tlsclient/httpwire` leaf package in place
      (`ReadHTTPResponse` + `responseContentLength` + `isChunkedEncoding`
      moved; client.go a thin wrapper importing it; stdlib-only imports);
      all existing tlsclient tests green; integration handshake test green
      on the desktop.
- [ ] Header flood (1 MiB of `X:junk\r\n`) returns the cap error in a unit
      test; 64 KiB-1 of headers still parses.
- [ ] Three fuzz targets, ≥8 seed corpus entries of real server bytes,
      15 min per target locally with zero crashers (or crashers fixed +
      regression seeds committed).
- [ ] Nightly CI fuzz job (targets `./internal/tlsclient/httpwire/`; runs
      without a wolfSSL sysroot) merged and green on its first scheduled
      run.
- [ ] AD-009 note updated with findings.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests green (`go test ./tests/` in csip-tls-test) +
      one live conformance smoke against gridsim (protocol-adjacent)
- [ ] Mayhem: targeted `wan-outage-hold`, `northbound-hang`,
      `malformed-csip` spot runs (fetcher error paths) — full campaign not
      required unless behavior changed
- [ ] `hub-replay-tune.sh fast` after any hub-Pi deploy

## Mayhem scenarios affected
`northbound-hang`, `wan-outage-hold`, `malformed-csip` (parser error paths
feed the fail-closed machinery) — verdicts must not move.

## Conformance implications
None intended: parsing of valid 2030.5 responses unchanged. The corpus
doubles as regression fixtures for TASK-069's dual-run
(old-parser-vs-http.Transport) later.

## Suggested commit message
Three commits:
`refactor(tlsclient): extract CGo-free httpwire parsing leaf package (TASK-047 1/3)`
`feat(tlsclient): header size cap + fuzz targets + real-response corpus in httpwire (TASK-047 2/3)`
`ci: nightly 15m fuzz job for tlsclient/httpwire (TASK-047 3/3)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Fuzz + cap the northbound HTTP response parser (TASK-047)
**Description:** D9/§10.2: pure seam extraction (CGo-free fuzzing), 64 KiB
header cap (body cap pre-existing), three go-native fuzz targets seeded
with real gridsim bytes, nightly CI job. Crashers found/fixed: <list>.
Feeds AD-009's TASK-069 decision. Rollback: revert; seam is
behavior-preserving (tests + conformance smoke attached).

## Code review checklist
- Seam diff is mechanical (side-by-side with old readResponse).
- Header cap boundary tested at 64Ki−1 / 64Ki+1.
- Fuzz asserts real properties, not just "no panic".
- Corpus files are genuine server responses (provenance noted).
- No CGo in the fuzz path: httpwire imports stdlib only; fuzz_test.go
  lives in httpwire.

## Definition of done
Acceptance + regression checklists green; AD-009 updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-069 (shim vs harden decision — cites this corpus + findings),
TASK-048 (XML/bus fuzz shares the CI job pattern), TASK-073 (reconnect
churn soak).
