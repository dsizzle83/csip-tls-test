# Family D board-control hooks (authority / PKI / infra)

The wave-3 **authority/PKI/infra** family (`sim/gw-mayhem/authority_pki.go`,
category `authority-pki-infra`) judges effects that only appear when the gateway is
put into a mode / a service is restarted / a cert is rotated / the trust store is
tampered — all **BOARD-MUTATING**. The `gw-mayhem` suite **never** performs those
mutations. Instead each scenario ships:

- a **board hook** (the `Board` field on the scenario, mirrored below) — the exact
  shell steps the **orchestrator** runs on the gateway host to *arm* the mutation
  and later *restore* it; and
- a Go **observe** arm that only reads the gateway's effect over `:802` / the sims'
  `/state` — no board mutation.

## The run flow (orchestrator)

```
1. ARM       run the hook's Arm command on the board (out of band).
2. OBSERVE   gw-mayhem -target 69.0.0.2:802 -pki certs/mbaps \
               -board-armed <scenario-id> -only <scenario-id>
             → the scenario's arm samples the effect; diagnoseAuthorityPKI judges it.
3. TEARDOWN  run the hook's Teardown command on the board (restore the resting state).
```

Without `-board-armed <id>`, every family-D scenario **SKIPS** as an expected
`INCONCLUSIVE` and prints its Arm/Teardown hook — so a default QA run is safe and
never touches the board. Each scenario is pinned `[PASS, INCONCLUSIVE]`: a contract
**violation** under an armed run is a `FAIL` that trips the gate; the board-only /
unarmed outcomes stay `INCONCLUSIVE`.

> Host = the ConnectCore 93 dev kit at **69.0.0.2** (`root@`, per `docs/BENCH.md`).
> The service names + config paths below are the **lexa-gw** deployment's — confirm
> them against the live board (`systemctl list-units 'lexa*' certmgr mosquitto`;
> `ls /etc/lexa-gw`) before running. `sponge` is from moreutils; substitute a
> temp-file rewrite if it is absent.

---

## authority-switch-honors-exclusive

Flip `mode.json` authority `mbaps → csip`; the newly-**non-authoritative** mbaps
interface's control must then be **refused** (the user's core exclusive-authority
decision).

- **Arm:** `ssh root@69.0.0.2 'jq ".authority=\"csip\"" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl restart lexa-mode'`
- **Observe** (Go): connect GridService over mbaps `:802`, attempt a `WMaxLimPct`
  write — **PASS** if refused (exception), **FAIL** if accepted (`Wrote`).
- **Teardown:** `ssh root@69.0.0.2 'jq ".authority=\"mbaps\"" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl restart lexa-mode'`
- **Design:** exclusive control authority — the non-authoritative interface's
  control is refused.

## privacy-switch-vendor-access

Toggle `vendor_access=false`; `LexaVoltReadOnly` must **disappear** from the RBAC
(its role deleted), effective **≤5s** (design 05 §1.2).

- **Arm:** `ssh root@69.0.0.2 'jq ".vendor_access=false" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl reload-or-restart lexa-mode'`
- **Observe** (Go): the role-denial matrix's vendor-mode auto-detect
  (`probeVendorDisabled`) — **PASS** if LexaVolt is now denied a read (role
  removed), **FAIL** if still active. The **≤5s** latency bound is timing-observable:
  the orchestrator supplies the toggle-applied timestamp vs. the detect time.
- **Teardown:** `ssh root@69.0.0.2 'jq ".vendor_access=true" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl reload-or-restart lexa-mode'`
- **Design:** design 05 §1.2 — vendor_access toggle adds/removes LexaVoltReadOnly ≤5s.

## cert-rotation-mid-session

Rotate the nb-mbaps-server leaf via certmgr `/v1/rotate` **while an aggregator
session is active**; existing sessions must survive / cleanly reconnect and new
handshakes must present the rotated leaf.

- **Arm** (with the standing aggregator running): `ssh root@69.0.0.2 'curl -fsS -XPOST http://127.0.0.1:<certmgr-port>/v1/rotate -d "{\"target\":\"nb-mbaps-server\"}"'`
- **Observe** (Go): a **fresh** mbaps handshake after rotation must succeed and
  serve a read (the rotated leaf is chain-valid) — **PASS** if so, **FAIL** if the
  handshake/read fails. Existing-session **survival** is board-observable
  (`journalctl -u lexa-mbaps` — the pre-rotation session was not torn down); the
  orchestrator supplies it.
- **Teardown:** none (rotation is forward-only). Re-run the standing aggregator to
  confirm steady state.
- **Design:** cert rotation is hitless — active sessions survive, new handshakes
  present the rotated leaf.

## trust-store-tamper-failclosed  *(board-only decisive evidence)*

Corrupt the certmgr trust-store integrity index (`index.hmac`); certmgr must latch
**fail-closed** — 503s + integrity alarm, and **no crash-loop** (T03.12).

- **Arm:** `ssh root@69.0.0.2 'printf deadbeef >> /var/lib/lexa-gw/certmgr/truststore/index.hmac && systemctl restart certmgr'`
- **Observe:** the decisive effect is **board-only** — certmgr `/health` returns
  503, an integrity alarm is raised, and `journalctl -u certmgr` shows a **single
  latched failure, NOT a restart loop**. The Go arm records a *supporting* signal
  (mbaps handshakes refused fail-closed at `:802`) but returns `INCONCLUSIVE`; the
  orchestrator supplies the certmgr evidence.
- **Teardown:** `ssh root@69.0.0.2 'systemctl stop certmgr && rm /var/lib/lexa-gw/certmgr/truststore/index.hmac && <re-seal the trust store, e.g. certmgr --reseal> && systemctl start certmgr'`
- **Design:** T03.12 — a trust-store integrity failure latches fail-closed (503 +
  integrity alarm, no crash-loop).

## service-restart-mid-cap  (mosquitto / lexa-mbaps)

Bounce `mosquitto` (or `lexa-mbaps`) **under an active cap**; the cap must hold
(retained-state re-seed) or safely revert, with **no wedge**.

- **Arm:**
  1. write an active cap first —
     `aggregator -target 69.0.0.2:802 -pki certs/mbaps -campaign qa/aggregator/curtail-solar-50.json`
     (leave it at 50% — do **not** run its release step yet); then
  2. `ssh root@69.0.0.2 'systemctl restart mosquitto'`  (or `systemctl restart lexa-mbaps`).
- **Observe** (Go): read `WMaxLimPct` post-restart — **PASS** if the gateway
  responds and the cap re-seeded to a sane value (held ≈50% or safely reverted
  ≈100%); **FAIL** on no response (wedge) or an absurd projection.
- **Teardown:** release the cap —
  `aggregator ... -campaign qa/aggregator/curtail-solar-50.json` (its final step
  releases to 100%) — then confirm the standing aggregator PASSES.
- **Design:** a service restart under an active cap re-seeds retained state; the cap
  holds or safely reverts; no wedge.
