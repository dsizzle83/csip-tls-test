# Handoff — CSIP conformance, 2026-07-28

Written at the end of a long session. Everything below was verified against the
live bench unless explicitly marked as inference.

---

## 1. One-paragraph summary

The CSIP conformance suite produced no usable verdicts for most of this session.
Six defects were found and fixed — **all six were in the bench harness, none in
the gateway**. The gateway's CSIP client has been behaving correctly throughout.
With the harness fixed, the suite now produces real wire-cited verdicts (6 PASS
including the whole COMM-004 certificate-chain family), and it has surfaced one
genuine product finding that **needs an owner decision**: the gateway never
posts IEEE 2030.5 Response `status=2` (Event started).

**Nothing has been committed.** All work is uncommitted in the working trees.

---

## 2. State of the trees

| repo | branch | HEAD | state |
|---|---|---|---|
| `csip-tls-test` | `qa/conformance-evidence` | `85048d8` | **14 modified, 2 new — all of today's work, UNCOMMITTED** |
| `lexa-gw` | `qa/adversarial-and-conformance` | `3744465` | 1 modified (`scripts/bench-pki-bootstrap.sh`) |
| `lexa-platform` | `fix/bio-eintr` | `1284c98` | clean |
| `lexa-proto` | `main` | `67cadfe` | clean, **2 unpushed commits** that all four repos depend on |

Modified in `csip-tls-test`:
```
Makefile
internal/certify/clients.go
internal/certify/evidence.go
internal/certify/suitecsip/comm.go
internal/certify/suitecsip/observe.go
internal/certify/suitecsip/session.go
internal/certify/window.go
internal/wolfssl/keylog.go
internal/wolfssl/keylog_stub.go
scripts/bench-sims-up.sh
sim/gridsim/admin.go
sim/gridsim/server.go
sim/server/main.go
sim/simapi/logs.go
```
New (untracked):
```
internal/certify/consolidate_test.go
sim/simapi/logs_wrap_test.go
```

All tests pass under `-race`. The wolfSSL-linked packages need the sysroot flags
(`make` exports them; a bare `go test ./...` fails to build those two packages —
that is not a regression):

```
CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64/include" \
CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64/lib -lwolfssl -lm" \
  go test -race ./internal/certify/suitemodbusserver/ ./internal/certify/suites/
```

---

## 3. THE PRODUCT FINDING — needs an owner decision, do not "fix" unilaterally

**The gateway never posts Response `status=2` (Event started).**

Evidence, from the board's own journal for 2026-07-28 (163 Responses):

```
status=1  (Received)    75
status=3  (Completed)   22
status=7  (Superseded)  42
status=8                13
status=10               11
status=2  (Started)      0     <-- never
```

This is deliberate, not a bug. In `lexa-gw/internal/northbound/responses/tracker.go`:

- `beginGoverning()` posts `ResponseEventStarted` **only when `confirmWindow == 0`**.
- Otherwise it arms the S7 actuation-confirm latch (CSIP-004(c), owner decision
  D3) and holds the control at `Received(1)`.
- `evalConfirmLocked()` posts Started(2) only when the derived fan-out set is
  non-empty **and every member has a matching terminal-applied report**. On
  timeout it escalates **CannotComply** — the comment says explicitly "never a
  silent Started". There were **29** such escalations on the bench today.
- `cmd/northbound/config.go`: `actuation_confirm_window_s` **absent/0 ⇒ 60s
  default**. The board config has no such key, so **the gate is ON by default in
  the shipping product**.

This causes 12 of the current CSIP failures ("gridsim received no Response POST
from the DUT in this window") plus `CORE-022` ("2 Responses but none with
status=2") and `CORE-023`.

**It is a conformance-versus-safety conflict.** CSIP V1.3 expects `status=2` when
an event begins; the product deliberately withholds it until it can prove the
inverter actually actuated. Both positions are defensible. Options discussed but
NOT actioned:

1. Post `Started(2)` at adopt, add a separate signal for confirmed actuation.
2. Keep the gate, shorten the window so confirmation lands inside the test window.
3. Take it to the working group: Started-before-actuation is arguably a false
   claim of compliance.

**Do not change this without the owner.** It is the DER control-authority path;
altering when the gateway claims an event started has field consequences.

---

## 4. The six harness fixes (all in `csip-tls-test`)

Each was verified on the live bench, not just in unit tests.

### 4.1 Bounded-ring delta — the big one (22 false FAILs)
`sim/simapi/logs.go`, `internal/certify/suitecsip/observe.go`, `sim/gridsim/admin.go`, `internal/certify/clients.go`

gridsim's request log is a **bounded ring**. `ServerView.Since()` computed its
delta by prefix length, which is valid only for an append-only list. Once the
ring filled — ~10 min into any run, since one discovery walk is ~28 logged GETs —
`len()` pinned at the cap and stopped growing while events kept arriving, so the
delta was permanently empty. An empty delta is indistinguishable from silence, so
the harness reported **"the DUT did nothing in this window"** about a gateway
polling perfectly on time. It failed as false FAILs, not as an error.

Fix: monotonic `firstSeq` on the ring; `Since(cursor) -> {lines, next, dropped}`;
new `GET /admin/logs.json?since=N` (SSE stream retained for the dashboard);
`AdminClient.Logs()`. `ServerView.Since` now has four explicit cases —
synthetic / exact / approximate (no cursor endpoint, says so) / unobservable
(baseline evicted, reports how many lines were lost). `maxLogLines` 400 → 4000,
but that alone would only have delayed the failure.

Tests: `sim/simapi/logs_wrap_test.go`.

### 4.2 RecoverSession demanded one conversation per port
`internal/certify/evidence.go`, `internal/certify/suitecsip/session.go`

`StreamOn` refused with "cite one explicitly" whenever a window held >1
conversation — which is always, because the gateway's **telemetry role POSTs to
`/mup` on the same host:port** as the discovery walk. Added `StreamsOn` (plural);
`RecoverSession` now identifies the discovery session by what it *contains* (a
GET of the discovery root) and records rejected candidates in `Transcript.Problems`.

### 4.3 Service-discovery attributed to the wrong host
`internal/certify/suitecsip/comm.go`

COMM-002 scanned the whole capture for SSDP/mDNS and WARNed on any hit, with a
comment claiming a connectionless datagram couldn't be attributed. It carries a
source IP. It reported `SSDP×4` against the gateway when all four came from the
**bench workstation**. Now counted per source address via `dutAddr(t)`.

### 4.4 Bench server never exported TLS secrets
`sim/tlsserver/server.go`, `sim/server/main.go`, `Makefile` (`server-keylog` target)

`keylog.go`'s own doc says the bench is both the mbaps client *and* the 2030.5
server and that exporting the bench side suffices — but only the client half was
ever wired. Gateway→gridsim sessions stayed ciphertext, so every criterion about
a response body or status line reported "no secret for this session's client
random". Now wired behind the same `keylog` build tag.

### 4.5 POISONED KEY LOG — worst bug of the day (112 assertions)
`internal/wolfssl/keylog.go`

`lexa_write_tls12_keylog` checked `mlen <= 0` but **never checked for an all-zero
buffer**. wolfSSL hands a *server* back an all-zero master secret for most
sessions while still returning a positive length. **79 of 119 exported lines were
zeros.** The line is well-formed, so every analyser accepts the key log, derives
garbage keys, and reports `AEAD authentication failed` — which reads as a corrupt
capture or a broken DUT, not a missing key.

Fix: refuse all-zero secrets, **and** register wolfSSL's OpenSSL-compatible
`wolfSSL_CTX_set_keylog_callback` (told the secret as the key schedule produces
it, works server-side where the session lookup does not). New
`wolfssl.EnableCtxKeylog(ctx)` + stub. Verified: 0 zero-secrets.

> Note for whoever edits `keylog.go`: the cgo preamble is one big `/* */` block.
> **Use `//` comments inside it** — a nested `/* */` closes the preamble early.

### 4.6 Frame-level attribution split TLS sessions
`internal/certify/window.go`

A conversation straddling two windows was split at frame granularity. Neither
check could then cite it (the runner correctly refuses to let a check cite frames
another owns), so decryptable evidence sat in the capture **unusable by anybody**
and both checks reported it missing. This blocked 126 assertions.

`consolidateStreams()` post-pass: a conversation owned by >1 check is given whole
to its **majority owner**, ties broken by uid for determinism. Yielded frames
counted in a new `FrameSet.Consolidated`. It only ever repairs an already-split
conversation; never invents an owner, never touches a wholly-owned one.

Tests: `internal/certify/consolidate_test.go` (positive + negative).

---

## 5. Current results — CSIP suite, 79 cases

Latest bundle: `runs/csip-20260728T152503/`

```
PASS  6      COMM-002, COMM-004, COMM-004A, COMM-004B, COMM-004C, ERR-001
FAIL 18      12 = the status=2 gate (§3); 2 = server-authenticated session
             (likely resumed sessions omitting certificates — UNVERIFIED);
             rest = DER* PUT / MUP POST not seen in window
SKIP 37      28 of these are catalog "not applicable to this DUT"
WARN 18
```

Trend across the session: `0 PASS / 26 FAIL` → `3/6` → `6 PASS / 18 FAIL`. FAIL
rising is *expected* — cases that previously could not cite anything now produce
real verdicts.

---

## 6. How to run it

Bench is **currently up**: gridsim (keylog build) on `:11113`/`:11114`, board
northbound active.

```bash
cd ~/projects/csip-tls-test

# gridsim must be the keylog build, and BOTH ports must be one process
make server-keylog
setsid nohup ./bin/server-keylog -listen 0.0.0.0:11113 -admin 0.0.0.0:11114 \
  -ca certs/mbaps/ca-cert.pem -cert-chain certs/mbaps/dev-server-cert.pem \
  -key certs/mbaps/dev-server-key.pem \
  -poll-rate-s 60 -idle-timeout-s 10 -keylog /tmp/bench-shared.keylog \
  > /tmp/gridsim2.log 2>&1 < /dev/null &

ssh cc93 'sudo systemctl restart lexa-northbound'   # pick up the new pollRate

make certify-keylog
setsid nohup ./bin/certify-keylog -suite csip \
  -target 69.0.0.2:802 -iface enp1s0 -pki certs/mbaps -gateway-ssh cc93 \
  -gridsim 69.0.0.20:11113 -gridsim-admin http://127.0.0.1:11114 \
  -keylog /tmp/bench-shared.keylog -out runs/csip-$(date -u +%Y%m%dT%H%M%S)/ \
  > /tmp/certify-csip.log 2>&1 < /dev/null &
```

Two flags are **required** and both are non-obvious:

- **`-gridsim 69.0.0.20:11113`, NOT `127.0.0.1:11113`.** The check claims its
  capture endpoint from this value. Loopback never appears on `enp1s0`, so
  `127.0.0.1` silently yields **0 attributed frames**. This cost real time.
- **`-poll-rate-s 60`** on gridsim. Stock `/tm` advertises 900s; a DUT in
  `poll_rate_mode: honor` (the product default) then correctly walks every 15
  minutes, and the harness's ~90s wait misses it ~94% of the time.
- **`-idle-timeout-s 10`** gives one observable TLS session per walk. Without it
  the gateway keeps ONE persistent session, which (correctly) never re-handshakes.

Suite takes ~50–60 min for 79 cases. Verify a bundle:
`./bin/certify -verify runs/<dir>/`

---

## 7. Hard constraints — do not violate

- **wolfSSL must never ship.** It exists only in `csip-tls-test`. The product's
  TLS is mbed TLS (`lexa-platform/mbedtls`).
- **Never add key export to the product's TLS stack.** Only the bench exports
  secrets — the device measured must be the device that ships.
- `runs/` is gitignored: bundles contain `keys.log` with real session secrets.
- **`csip-tls-test` and `lexa-hub` are PUBLIC** — no self-hosted CI runners
  there; a PR could execute code on the workstation holding bench SSH keys and
  the gateway trust-domain CA.
- **Never run `make gen-mbaps-certs`** — it does `RemoveAll` + new root and would
  lock the bench out of the DUT. Use `-reuse-ca`.
- Never disable `session_cache` on the gateway to make a test pass.
- The user's instruction for this work: **"no cheating the tests, pervasive
  idiomatic fixes."** Nothing here loosened an assertion; the checks are
  unchanged and can now see what the device did.

---

## 8. Landmines (each cost real time today)

1. **`pgrep -f <pattern>` matches your own shell.** A waiter looping
   `until ! pgrep -f certify-keylog` waited on itself forever. `pkill -f 'bin/server -listen'`
   killed the invoking shell. Use `[b]in/...` bracket form, or a recorded PID + `kill -0`.
2. **`setsid nohup ... &` — `$!` is the wrapper, not the process.** Re-read the
   real PID with `ps -eo pid,args | grep '[c]ertify-keylog -suite csip'`.
   A monitor armed on the wrong PID declared a running job finished.
3. **Orphaned sims answer on the ports.** An 8-hour-old gridsim held `:11114`
   while a new one held `:11113`; the DUT talked to one, the harness read
   server-side observations from the other. gridsim now binds admin eagerly
   (fatal on clash) and exits on SIGTERM with a 5s backstop — but **check
   `ss -ltnp` shows ONE pid for both ports** before trusting a run.
4. **The board clock is UTC-4.** I twice computed elapsed times wrong from it.
5. **Provisional vs reconciled verdicts.** The live `[p/f/s/w]` counters are
   provisional; the citation phase re-derives everything and can only lower a
   verdict. Only the CONFORMANCE RUN SUMMARY is real. A run showing `[0/0/79/0]`
   ended as `6/18/37/18`.

---

## 9. Methodological warning — the recurring error

Nearly every wrong turn today had the same shape: **"I didn't observe X"
concluded as "X didn't happen," when the observation itself was broken.**

- Declared the northbound discovery walk "stopped" and called it a significant
  defect. It was walking perfectly. My three checks (5s `ss` sampling for a 35ms
  event; two identical metric reads 70s apart; journal silence) could not have
  detected it even if running. I SIGQUIT'd a healthy process to prove it healthy.
- Measured straddling at "2 of 79" from an artifact of the old code and reported
  that as the reason not to do the deeper fix. It was actually the norm.
- Read a stale key log from a dead process and briefly concluded a fix hadn't worked.
- Declared "CSIP is fixed" on one passing case; the 79-case suite disagreed.

The harness's error messages are phrased as accusations of the DUT ("records no
GET /dcap **from the DUT**", "no ClientHello **from the gateway**"). That phrasing
is why a broken observation reads as a broken device. **Treat every such message
as a claim about the harness until proven otherwise.**

---

## 10. Open tasks

Recorded in the session task list; the durable ones:

| # | Item |
|---|---|
| 12 | `ObservationWait` reads `discovery_interval_s` (a floor) instead of the honored pollRate — currently papered over by `-poll-rate-s 60` |
| 14 | Board has **no build stamp** — no `/etc/lexa/build-id`, no embedded version, `provision.json` is `{}`. Runs are stamped with binary SHA-256 prefixes as a stopgap (`mbaps:856bc322 nb:ba8d13dd modbus:dcfc6b4b`). An evidence bundle that cannot name its firmware is weak for a submission. |
| 15 | Bundle does not record its own invocation — two runs cannot be compared after the fact; this hid the `-gridsim 127.0.0.1` mistake |
| 16 | `lexa-gw/internal/northbound/run/pollrate.go` — `PollRateOverride` doc claims the bench ships `"override"` via `deploy-hub-pi.sh`. Both configs say `"honor"` and that script is lexa-hub's. Stale comment carried over by the port from `lexa-hub@0d3481c`. **It nearly caused me to certify a non-default mode.** |
| 17 | No preflight asserting `-gridsim` and `-gridsim-admin` belong to the same live process (see landmine 3) |
| 7 | Purge wolfSSL from product docs (harness only) |
| 8 | Local GitHub Actions runners exist and are online; workflows still say `runs-on: ubuntu-latest` |
| 10 | mbed TLS does not bound *handshake* records by MFL (documented in patch 0003, not fixed) |

Also outstanding from earlier in the session: `MOD-4` remains an accepted scope
gap (models 703, 705–712 absent; 713 absent), and `ss-test-pki::PKI-6` is a real
finding — the DUT's leaf carries no `hwType`, so there is no manufacturer model
OID rooted at an IANA PEN.

---

## 11. Suggested next steps

1. **Get the owner decision on §3 (status=2).** It gates ~13 CSIP cases and is
   the only remaining item that is genuinely about the product.
2. **Commit today's work.** Six independent fixes; they should be six commits,
   not one. Nothing is pushed anywhere.
3. Investigate the 2 × "server-authenticated session" failures — hypothesis
   (UNVERIFIED) is resumed sessions omitting certificates, which would be a
   seventh observation artifact and is worth ruling out before anyone reads it
   as an mTLS finding.
4. Re-run the **full** 159-case suite (`-suite ssm,modbus-server,csip,modbus-client,pki`)
   once §3 is settled; today's fixes touch `internal/certify/window.go`, which is
   shared by every suite, and only CSIP has been re-run against it.
