# TASK-072 — Cert expiry monitoring + alerting

*Status: TODO · Phase: P6 · Effort: M (≈4–6 h) · Difficulty: low · Risk: low*

## Objective
lexa-northbound parses the client certificate and CA `NotAfter` at startup
and daily, exposes days-to-expiry as a metric and a retained bus status,
logs a WARN alert when ≤30 days remain (ERROR when expired), and lexa-api's
`/status` carries the cert-expiry field for dashboards/harness. Verified
on the bench with a deliberately short-lived cert.

## Background
Verified:
- Cert material: northbound.json (`configs/northbound.json`) carries
  `ca_cert`, `client_cert`, `client_key` paths (deployed to
  `/etc/lexa/certs/` — ca.pem, client.pem; lexa-hub CLAUDE.md config
  table). LFDI is already derived from the client cert at startup
  (`lfdiFromCert`, cmd/northbound/main.go:640-660) — so PEM parsing
  precedent exists (crypto/x509, pure Go; no wolfSSL involvement needed
  for INSPECTION).
- lexa-telemetry uses the same client cert (telemetry.json) — cover it
  or explicitly scope to northbound-only with a note (northbound is the
  control path; telemetry shares the cert file so ONE monitor on the
  file's content suffices; decide: monitor in northbound, report for the
  cert file, note that telemetry shares it).
- Metric surface: TASK-044 (Prometheus /metrics on all six services) is a
  P4 dependency per the graph — this task registers
  `lexa_cert_expiry_seconds{cert="client|ca"}` gauges on it.
- Bus/status path: lexa-api aggregates retained/live topics into
  `GET /status` (cmd/api/main.go:106, handlers.go). Pattern to follow:
  publish a small retained JSON (`lexa/northbound/certstatus`) that
  cmd/api folds into the status snapshot.
- Bench cert tooling: csip-tls-test `make gen-client-cert CN=csip-pi-002`
  (Makefile:298-299) generates client certs; scripts/gen-client-cert.sh,
  gen-test-certs.sh exist. Verify whether the target supports a custom
  lifetime flag; if not, the bench test uses `openssl req/x509` directly
  with `-days 1` against the same CA material (keys stay gitignored —
  `*-key.pem` rule).
- Review context: "cert lifecycle absent … a CSIP deployment WILL hit
  cert expiry; today that's a silent discovery-error loop (at least it
  fails closed now)" (§10.5).

## Why this task exists
§10.5 / 09 checklist hard gate "Expiry monitoring + alert ≥30 days out."
An expiring cert today looks like a WAN outage — the operator learns from
a compliance breach letter, not a warning.

## Architecture review sections
§10.5 · item — Top-20 #6-adjacent · 08 RSK-07 context (rotation is
TASK-073; this is detection) · 09 Certificates · 02 AD-008.

## Prerequisites
TASK-044 DONE (metrics endpoint — hard for the metric; the log+bus
fallback keeps the task shippable if 044 slipped, note which). Bench
access for the short-lived-cert test.

## Files
- **Read first:** cmd/northbound/main.go (lfdiFromCert, startup order),
  configs/northbound.json, cmd/api/handlers.go (+store/state assembly,
  stale_test.go pattern), internal/bus/topics.go + messages.go
  (topic/message conventions, envelope rules from TASK-017),
  csip-tls-test Makefile gen-client-cert + scripts/gen-client-cert.sh.
- **Modify:** cmd/northbound (monitor goroutine + publish),
  internal/bus (new `CertStatus` message + topic const),
  cmd/api (fold into /status), lexa-hub CLAUDE.md topic table.
- **Create:** `cmd/northbound/certmon.go` (+`certmon_test.go`).

## Blast radius
lexa-northbound (additive goroutine), one new retained bus topic +
message type (born versioned per AD-006), lexa-api /status JSON gains a
field (additive — dashboards tolerate unknown fields; verify the
csip-tls-test dashboard's /status decoding is tolerant before shipping).

## Implementation strategy
Pure-Go x509 inspection of the configured PEM files (client + CA), run at
startup and every 24 h on an owned goroutine with ctx shutdown (05 §4).
Publish retained `lexa/northbound/certstatus` {v, client_not_after,
ca_not_after, days_left, ts}; register gauges; log with level by
threshold. cmd/api merges the retained message into its snapshot like the
other topics it consumes.

## Detailed steps
1. `certmon.go`: `inspect(paths) (CertInfo, error)` — parse PEM chain,
   take the LEAF for client (file may contain a chain), NotAfter/NotBefore;
   handle unreadable/expired/not-yet-valid distinctly. Table tests with
   generated fixtures (create test certs in-code via crypto/x509 —
   no checked-in keys).
2. Monitor loop: at start + 24 h ticker (and on SIGHUP if trivially
   available — optional): inspect, publish retained CertStatus (QoS 1),
   set gauges, log: `days_left > 30` info once at startup; `≤30` WARN
   daily; `≤0` ERROR daily. Never crash on inspection failure — WARN and
   publish the error state (fail-closed reporting).
3. Bus: add `TopicNorthboundCertStatus = "lexa/northbound/certstatus"` +
   `CertStatus` struct (with `V` per envelope policy) in internal/bus.
4. cmd/api: subscribe, hold latest, expose as `"cert_status": {...}` in
   /status; add a unit test beside stale_test.go.
5. Metrics: `lexa_cert_expiry_seconds{cert=…}` gauge via the 044
   scaffolding (or TODO-tagged fallback if 044 absent — then the
   acceptance metric line converts to the bus field).
6. Bench validation: generate a 1-day cert signed by the bench CA (reuse
   gen-client-cert.sh mechanics; do NOT commit keys), deploy it to a
   staging path, point a spare northbound config at it (or briefly swap
   on the hub Pi outside demo hours), confirm: WARN fires, /status shows
   days_left=0-1, dashboard still renders. Restore the real cert and
   confirm recovery. Record the procedure — it becomes part of the
   TASK-073 runbook.
7. Update lexa-hub CLAUDE.md topic table (+QoS/retained flags).

## Testing changes
- certmon table tests (valid/expiring/expired/garbage/missing file/chain).
- cmd/api merge test.
- Run: `make test` (lexa-hub). Bench procedure per step 6 with journal
  evidence.

## Documentation changes
- lexa-hub CLAUDE.md topic map + config notes.
- Runbook stub: "reading cert status" (extended by TASK-073's rotation
  runbook).
- 09 checklist: link evidence when done.

## Common mistakes to avoid
- Parsing with wolfSSL/CGo — unnecessary; crypto/x509 reads PEM fine and
  keeps the monitor testable everywhere.
- Alerting once at startup only (a service that runs for months crosses
  the threshold silently — the daily re-check is the point).
- Publishing non-retained (api restart would lose it; retained + QoS 1
  matches lexa/csip/control conventions).
- Committing test keys or the short-lived bench cert (gitignore `*-key.pem`
  invariant; generate fixtures in-memory in tests).
- Swapping certs on the live hub during a QA campaign window.

## Things that must NOT change
- TLS behavior itself: the monitor only READS files; wolfSSL context
  loading, cipher pinning, LFDI derivation untouched.
- /status existing fields and their staleness semantics
  (csipReportGraceS logic in cmd/api/handlers.go:88-131 untouched).
- The discovery walk cadence/goroutine (monitor is a separate goroutine
  with its own shutdown).

## Acceptance criteria
- [ ] Retained certstatus on the bus; /status shows it; metric (or noted
  fallback) exposed.
- [ ] WARN at ≤30 d, ERROR at expired, verified with the 1-day bench cert
  (journal evidence attached).
- [ ] Recovery after restoring the real cert verified.
- [ ] All unit tests green; no keys committed.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none (no protocol behavior change)
- [ ] Mayhem: none required (additive); optional smoke wan-outage-hold to
  confirm no walk interference
- [ ] Dashboard renders /status with the new field

## Mayhem scenarios affected
None (additive observation). Future scenario "cert-expiry" is a natural
follow-up once TASK-073's rotation lands.

## Conformance implications
None directly; supports the 09 Certificates gates.

## Suggested commit message
`feat(northbound): cert expiry monitor — retained certstatus, /status field, ≥30d alerting`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Certificate expiry monitoring (§10.5)
**Description:** Daily x509 inspection of client/CA PEMs; retained bus
status + lexa-api field + gauge; bench-verified with a 1-day cert.
Risk: low, additive. Rollback: revert; topic is retained-only additive.

## Code review checklist
- Leaf-vs-chain parsing correct; error states published not swallowed.
- Goroutine owner/shutdown per 05 §4.
- Envelope/versioning per AD-006 on the new message.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-073 (rotation uses this monitor as its verification signal); Mayhem
cert-expiry scenario (backlog); alert routing once 045 alerting lands.
