# TASK-013 — Mosquitto per-service credentials + ACLs

*Status: TODO · Phase: P0 · Effort: L (≈6–8 h + campaign) · Difficulty: med · Risk: med*

## Objective
The hub Pi's broker no longer accepts anonymous clients: each of the six lexa services
plus the QA `mqttproxy` authenticates with its own credentials, a topic ACL mirroring
`internal/bus/topics.go` enforces least privilege (publishers write only their topics,
subscribers read only theirs), and a full Mayhem campaign proves no control path was
silently dropped (RSK-09).

## Background
Verified state:
- Broker config source: `lexa-hub/systemd/mosquitto-lexa.conf` — `listener 1883
  localhost`, `allow_anonymous true`, with a comment that already sketches the upgrade:
  "switch to per-service credentials + an ACL file (hub: write lexa/control/# and
  lexa/evse/+/command, read elsewhere; modbus and ocpp: the inverse)".
- **The deployed config differs from the repo file**: `deploy-hub-pi.sh` writes a
  *slimmed* drop-in to `/etc/mosquitto/conf.d/lexa.conf` (listener + anonymous + queue
  bounds only; the distro's mosquitto.conf owns persistence/log settings — re-declaring
  them in conf.d is a fatal duplicate in mosquitto 2.x). Your changes must go into the
  deploy script's heredoc AND the repo file, kept consistent.
- The review's W7 justification for "localhost-only ⇒ anonymous OK" is already violated
  in QA sessions: `cmd/mqttproxy` (csip-tls-test) is a third-party process deployed onto
  the hub Pi by `scripts/mqtt-chaos.sh` — a TCP proxy (`-listen 127.0.0.1:1882
  -upstream 127.0.0.1:1883`, control API on `69.0.0.1:11882`) that the lexa services are
  re-pointed through during MQTT-fault QA. Its `/inject` endpoint publishes with a
  hand-rolled MQTT 3.1.1 CONNECT (`cmd/mqttproxy/inject.go`, `connectPacket()`) that
  sends **no username/password** — it breaks the moment anonymous is off.
- MQTT client wiring: `lexa-hub/internal/mqttutil/mqttutil.go` `Connect(broker,
  clientID)` sets no credentials; every service config
  (`configs/{hub,northbound,modbus,ocpp,telemetry,api}.json`) has `mqtt_broker` +
  `mqtt_client_id` fields only.
- Topic map (authoritative: `internal/bus/topics.go`; QoS/table in lexa-hub CLAUDE.md):
  measurements + battery metrics + evse state (device planes), `lexa/csip/control`
  (retained), pricing/billing/flowreservation status (retained), flowreservation request,
  compliance alert, northbound schedule (retained), control/battery/+, control/solar/+,
  evse/+/command, `lexa/hub/plan` (retained).

Per-service access matrix (derived from verified pub/sub sites; re-derive when
implementing):

| user | write | read |
|---|---|---|
| lexa-modbus | `lexa/measurements/+`, `lexa/battery/+/metrics` | `lexa/control/battery/+`, `lexa/control/solar/+` |
| lexa-northbound | `lexa/csip/control`, `lexa/csip/pricing`, `lexa/csip/billing`, `lexa/csip/flowreservation/status`, `lexa/northbound/schedule` | `lexa/csip/compliance/alert`, `lexa/csip/flowreservation/request` |
| lexa-hub | `lexa/control/battery/+`, `lexa/control/solar/+`, `lexa/evse/+/command`, `lexa/hub/plan`, `lexa/csip/compliance/alert`, `lexa/csip/flowreservation/request` | `lexa/measurements/+`, `lexa/battery/+/metrics`, `lexa/csip/control`, `lexa/evse/+/state`, `lexa/northbound/schedule`, `lexa/csip/pricing` |
| lexa-ocpp | `lexa/evse/+/state` | `lexa/evse/+/command` |
| lexa-telemetry | — | `lexa/measurements/+`, `lexa/csip/control` |
| lexa-api | — | `lexa/measurements/+`, `lexa/battery/+/metrics`, `lexa/csip/control`, `lexa/evse/+/state`, `lexa/northbound/schedule`, `lexa/hub/plan` |
| qa-inject (mqttproxy) | `lexa/#` (QA needs to forge anything — that's its job; bench-only user, commented as such) | `lexa/#` |

## Why this task exists
Review W7/§10.1: "any local code execution = full hardware control, and the config file
itself admits it." First half of §14 item 6 (TASK-014 is the API half).

## Architecture review sections
W7, §10.1, §14 item 6; AD-008; RSK-09; 03 P0 risks ("ACL file mirrors
internal/bus/topics").

## Prerequisites
TASK-002/003 (CI). Bench access; FAST mode for the campaign. Sequence before TASK-014
(its dependency row) — same AD-008 umbrella.

## Files
- **Read first:** `lexa-hub/systemd/mosquitto-lexa.conf`,
  `lexa-hub/scripts/deploy-hub-pi.sh` (the conf.d heredoc),
  `lexa-hub/internal/mqttutil/mqttutil.go`, all six `lexa-hub/configs/*.json` + each
  service's `config.go`, `lexa-hub/internal/bus/topics.go`,
  `csip-tls-test/cmd/mqttproxy/{inject.go,control.go}` + `scripts/mqtt-chaos.sh`,
  `csip-tls-test/sim/mqttproxy.service`.
- **Modify (lexa-hub):** `internal/mqttutil` (`Connect` gains optional user/pass — new
  `ConnectAuth(broker, clientID, user, pass string)` or extra params), all six
  `cmd/*/config.go` (+ example configs: `mqtt_user`, `mqtt_pass_file` — password read
  from a root-owned 0600 file, NOT inline JSON), `systemd/mosquitto-lexa.conf`,
  `scripts/deploy-hub-pi.sh` (conf.d heredoc + passwd/ACL generation).
- **Modify (csip-tls-test):** `cmd/mqttproxy` (`-user/-passfile` flags feeding
  `connectPacket` — MQTT 3.1.1 CONNECT with username/password flags set),
  `sim/mqttproxy.service` (flags), `scripts/mqtt-chaos.sh` (pass creds through).
- **Create:** `lexa-hub/systemd/mosquitto-lexa.acl` (ACL file source).

## Blast radius
Every MQTT connection in the system. A wrong ACL line silently drops a control path
(publish denied = disconnect or silent drop depending on broker settings) — this is the
highest-consequence failure mode of P0, hence the campaign gate. Two repos change
(paired PRs, same-session deploy).

## Implementation strategy
Introduce credentials support everywhere while the broker still allows anonymous
(backward-compatible), generate passwd/ACL on the Pi via the deploy script, then flip
`allow_anonymous false` in one deploy, verify every service reconnects and every topic
flows, and gate with the full campaign plus the four mqtt scenarios (which exercise
mqttproxy's injection under the new ACLs).

## Detailed steps
1. lexa-hub: extend `mqttutil.Connect` with optional credentials
   (`opts.SetUsername/SetPassword` when non-empty). Each service config gains
   `mqtt_user` + `mqtt_pass_file` (empty ⇒ anonymous, today's behavior). Unit-test the
   option plumbing.
2. Write `systemd/mosquitto-lexa.acl` implementing the matrix above (mosquitto `user X`
   / `topic read|write|readwrite <pattern>` stanzas; `+` wildcards are valid in ACL
   topic patterns). Comment each stanza with the bus-topic constant it mirrors.
3. Update `systemd/mosquitto-lexa.conf` (repo reference file) AND the
   `deploy-hub-pi.sh` heredoc: `allow_anonymous false`, `password_file
   /etc/mosquitto/lexa-passwd`, `acl_file /etc/mosquitto/lexa-acl`.
4. Deploy-script credential generation (idempotent): create users with
   `mosquitto_passwd -b` using per-service passwords generated once on the Pi
   (`openssl rand -hex 16`), stored to `/etc/lexa/mqtt/<svc>.pass` (0600, owner lexa)
   and referenced by each service's `mqtt_pass_file`; install the ACL file. Passwords
   never enter git or the deploy artifacts.
5. csip-tls-test: mqttproxy `-user/-passfile` flags; set username/password flags in
   `connectPacket` (CONNECT flags byte 0x02 → 0xC2 with user+pass fields appended);
   `mqtt-chaos.sh` provisions a `qa-inject` broker user the same way and passes the
   flags via `sim/mqttproxy.service` ExecStart. Note: the proxy's PASSTHROUGH path needs
   nothing — proxied lexa services present their own credentials end-to-end.
6. Staged bench rollout: deploy code+configs with credentials populated but broker still
   anonymous → verify all services connected with usernames
   (`mosquitto_sub`-less check: journal lines) → flip the broker config
   (anonymous off) + restart mosquitto → `systemctl status` all six + mqttproxy;
   check journals for `not authorised` — zero expected.
7. Negative test: `mosquitto_pub -h localhost -t lexa/control/battery/battery-0 -m '{}'`
   on the Pi without credentials → rejected; with lexa-api's credentials → ACL-denied
   (api is read-only).
8. Re-run `hub-replay-tune.sh fast` (deploy reset), then gates: full FAST campaign +
   `--only mqtt-broker-restart,mqtt-broker-latency,mqtt-malformed-control,
   mqtt-stale-retained` ×10 (these use mqttproxy /fault + /inject — proves QA tooling
   survived the lockdown). Baseline: ≤ V6.
9. Paired PRs (lexa-hub + csip-tls-test) referencing each other; deployed same session.

## Testing changes
- lexa-hub: mqttutil credentials unit test (options set when fields non-empty).
- csip-tls-test: `cmd/mqttproxy` packet-encoding unit test for CONNECT-with-credentials
  (golden bytes).
- Bench: steps 6–8 evidence.

## Documentation changes
- lexa-hub CLAUDE.md: broker section — anonymous is dead; creds live in
  `/etc/lexa/mqtt/`; ACL mirrors `internal/bus/topics.go` (update BOTH repos' docs same
  session where they describe the broker).
- `docs/BENCH.md`: note the qa-inject user + where mqtt-chaos provisions it.
- 00_MASTER_INDEX status.

## Common mistakes to avoid
- Enabling the ACL before every service has credentials wired — startup loop of
  `Connection Refused: not authorised`. Follow the stage order (step 6).
- Forgetting `lexa/csip/compliance/alert` (hub writes, northbound reads) or
  `lexa/csip/flowreservation/request` (hub→northbound) — they're easy to miss because
  they're the only hub→northbound topics; a missed line = CannotComply silently dead
  (RSK-09's exact scenario — `reject-write-curtail`/`enable-gate-curtail` would FAIL).
- Editing only `systemd/mosquitto-lexa.conf` and not the deploy heredoc (the Pi runs the
  heredoc version — verified divergence).
- Putting passwords in configs/*.json in git — use pass-files generated on the Pi.
- Retained-message gotcha: after flipping, the retained `lexa/csip/control` is still
  delivered to authorized subscribers — but if you recreate the persistence DB while
  fiddling, the hub starts control-less until the next walk. Don't delete
  `/var/lib/mosquitto/` state.
- `pkill -f` over SSH (kills your session) — systemctl only.

## Things that must NOT change
- Topic names/retain flags/QoS (TASK-016 owns QoS; this task only wraps access).
- mqttutil reconnect/replay/publish-timeout behavior (backs `mqtt-broker-restart`
  PASS) — credentials are additive options.
- Mayhem scenario oracles — if an mqtt scenario breaks, fix the ACL/creds, never the
  scenario (06 §4.5).
- Localhost-only listener (`listener 1883 localhost`) — unchanged; ACLs are
  defense-in-depth behind it, not a LAN opening.

## Acceptance criteria
- [ ] `allow_anonymous false` live on the Pi; anonymous `mosquitto_pub` rejected.
- [ ] All six services + mqttproxy connected with per-user credentials (journal evidence).
- [ ] Cross-privilege publish denied (step 7 negative tests).
- [ ] mqtt scenario set ×10 verdict-identical; full FAST campaign ≤ V6 baseline.
- [ ] No secrets in either repo (`git grep -i` for the generated passwords → empty by construction).

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: **full campaign** + targeted mqtt set ×10 (RSK-09 gate)
- [ ] Bench restored FAST; `mqtt-chaos.sh restore` path re-tested once (configs point back to :1883 with creds intact)

## Mayhem scenarios affected
`mqtt-broker-restart`, `mqtt-broker-latency` (reconnect now includes auth),
`mqtt-malformed-control`, `mqtt-stale-retained` (mqttproxy /inject now authenticates).
All must keep their verdicts.

## Conformance implications
None (broker is internal plumbing; CSIP surface untouched).

## Suggested commit message
lexa-hub: `feat(broker): per-service credentials + topic ACLs mirroring bus/topics (W7, AD-008)`
csip-tls-test: `feat(mqttproxy): authenticated CONNECT for /inject; qa-inject broker user (W7 lockstep)`
both `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Broker lockdown: per-service credentials + ACLs (paired PR with csip-tls-test)
**Description:** Matrix in task file; staged rollout (creds-while-anonymous → flip);
campaign + mqtt-scenario evidence attached. Rollback: revert conf.d drop-in to
anonymous (documented RSK-09 recovery), services keep working since creds are additive.

## Code review checklist
- ACL matrix re-derived from actual Subscribe/Publish call sites, not from this file.
- Both repos' halves reviewed together; same-session deploy stated.
- Secret handling: pass-files 0600, generated on-device, never in git/artifacts.
- Stage order enforced in the deploy script (no anonymous-off before creds exist).

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated; RSK-09 row
annotated with the campaign evidence.

## Possible follow-up tasks
TASK-014 (lexa-api auth — AD-008's second half), TASK-018 (envelope's reject-and-alarm
counters complement ACL denials), TASK-044 (export broker-auth failure metrics),
TASK-051 (MQTT storm now also exercises per-user queue limits).
