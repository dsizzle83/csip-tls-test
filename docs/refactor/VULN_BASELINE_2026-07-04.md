# govulncheck baseline — 2026-07-04

TASK-005. First `govulncheck` run in both repos, before any dependency upgrade
(TASK-006 does the upgrade). Recorded so the refresh's before/after delta is
measurable.

## Method

- Scanner: `govulncheck` **v1.5.0** (pinned in `scripts/ci/govulncheck.sh`,
  latest tag as of 2026-07-04 per `go list -m golang.org/x/vuln@latest`).
- Go toolchain: `go1.26.4` (desktop).
- Both repos scanned with the wolfSSL amd64 sysroot on `CGO_CFLAGS`/`CGO_LDFLAGS`
  (`~/.local/wolfssl-amd64`), matching the cgo CI job's env — a scan without it
  fails to load `internal/wolfssl`/`internal/tlsclient` and silently shrinks
  the module scanned. Confirmed via the SBOM module count printed by the
  script (18 modules for csip-tls-test, 20 for lexa-hub — no cgo packages
  dropped).
- Command: `govulncheck -format json ./...` from each repo root, piped through
  the reachability filter in `scripts/ci/govulncheck.sh`.

### Reachability tiers (why the counts below aren't "0 vulnerabilities" or "89 vulnerabilities")

`govulncheck` JSON always emits a non-empty `finding.trace` — even for a
vulnerable module that's merely a transitive `go.sum` entry, never imported.
The three tiers, and how they show up in JSON:

| Tier | Meaning | JSON shape | Gates CI? |
|---|---|---|---|
| **Called** | real call path from this repo's code to the vulnerable symbol | some `trace[]` frame has a `"function"` key | **Yes** (this task) |
| Imported | package imported, vulnerable symbol not called | `trace[0].package` set, no `function` anywhere | No (informational) |
| Required | module present in `go.sum`, package not even imported | `trace[0]` has only `module`/`version` | No (informational) |

`scripts/ci/govulncheck.sh` gates only on the **Called** tier. This baseline's
"module-required-only" counts below are almost entirely the Required tier
(verified: every one of those findings' trace frames carry `module`/`version`
only, no `package`).

## csip-tls-test

```
Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 47
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

- **Called (gates CI): 0.**
- **Required-only (informational): 47**, all three from the ancient
  `golang.org/x/*` versions already known (see TASK-006 background):

  | Module | Version in go.mod | Findings | Fixed by |
  |---|---|---|---|
  | `golang.org/x/crypto` | `v0.0.0-20191011191535-87dc89f01550` (Oct 2019) | 25 | TASK-006 (x/crypto bump) |
  | `golang.org/x/net` | `v0.0.0-20200114155413-6afb5195e5aa` (Jan 2020) | 21 | TASK-006 (x/net bump) |
  | `golang.org/x/sys` | `v0.0.0-20220804214406-8e32c043e418` (Aug 2022) | 1 | TASK-006 (x/sys bump) |

  Full OSV ID list (all Required-tier, none Called): GO-2020-0012, GO-2020-0014,
  GO-2021-0078, GO-2021-0227, GO-2021-0238, GO-2021-0356, GO-2022-0192,
  GO-2022-0193, GO-2022-0197, GO-2022-0229, GO-2022-0236, GO-2022-0288,
  GO-2022-0493, GO-2022-0536, GO-2022-0968, GO-2022-0969, GO-2022-1144,
  GO-2023-1495, GO-2023-1571, GO-2023-1988, GO-2023-2102, GO-2023-2402,
  GO-2024-2687, GO-2024-2961, GO-2024-3321, GO-2024-3333, GO-2025-3487,
  GO-2025-3503, GO-2025-3595, GO-2025-4116, GO-2025-4134, GO-2025-4135,
  GO-2026-4440, GO-2026-4441, GO-2026-4918, GO-2026-5005, GO-2026-5006,
  GO-2026-5013, GO-2026-5014, GO-2026-5015, GO-2026-5016, GO-2026-5017,
  GO-2026-5018, GO-2026-5019, GO-2026-5020, GO-2026-5021, GO-2026-5023,
  GO-2026-5025, GO-2026-5026, GO-2026-5027, GO-2026-5028, GO-2026-5029,
  GO-2026-5030, GO-2026-5033.

  (Note: this repo has no `paho` dependency — `cmd/mqttproxy` is a raw TCP
  proxy, per TASK-005's background.)

### Disposition — csip-tls-test

No Called-tier findings, so nothing to allowlist and nothing blocking. All 47
Required-tier findings are **(a) fixed by TASK-006** (x/crypto, x/net, x/sys
bump) — logged here as the TASK-006 worklist input, not allowlisted per the
"don't allowlist what the refresh will fix" rule.
`scripts/ci/vuln-allowlist.txt` in this repo is empty (comment-only).

## lexa-hub

```
Your code is affected by 2 vulnerabilities from 2 modules.
This scan also found 0 vulnerabilities in packages you import and 40
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

- **Called (gates CI): 2** — both reached through the vendored
  `paho.mqtt.golang v1.4.3` client used by `internal/mqttutil` /
  `cmd/northbound`:

  | OSV ID | Module | Found | Fixed in | Example call path |
  |---|---|---|---|---|
  | `GO-2025-4173` | `github.com/eclipse/paho.mqtt.golang` | v1.4.3 | v1.5.1 | `internal/mqttutil.Connect` → `paho.client.Connect` → `packets.*Packet.{Write,Details,String}`; also `cmd/northbound/main.go` Subscribe/Disconnect paths |
  | `GO-2025-3503` | `golang.org/x/net` | v0.8.0 | v0.36.0 | `internal/mqttutil.Connect` → `paho.client.Connect` → `x/net/proxy.FromEnvironment` / `proxy.PerHost.Dial` (paho's HTTP-proxy dialer, pulled in transitively) |

- **Required-only (informational): 42**, same `x/crypto`/`x/net`/`x/sys` cluster
  as csip-tls-test plus one additional non-reachable paho finding:

  | Module | Version in go.mod | Findings |
  |---|---|---|
  | `golang.org/x/crypto` | `v0.0.0-20191011191535-87dc89f01550` | 25 |
  | `golang.org/x/net` | `v0.8.0` | 15 |
  | `golang.org/x/sys` | `v0.6.0` | 1 |
  | `github.com/eclipse/paho.mqtt.golang` | v1.4.3 | 1 |

### Disposition — lexa-hub

Both Called-tier findings are **(a) fixed by TASK-006**:
- `GO-2025-4173`: paho `v1.4.3` → `v1.5.1+` (the RSK-04-gated, campaign-tested
  bump — mqtt-broker-restart / mqtt-broker-latency Mayhem scenarios per
  TASK-006 background).
- `GO-2025-3503`: `x/net` bump (commit 2 of TASK-006, alongside `x/crypto`/`x/sys`).

Neither is allowlisted — this is exactly the debt TASK-006 exists to retire.
`scripts/ci/vulncheck` in lexa-hub is expected to report **red** (informational,
`continue-on-error: true`) until TASK-006 merges; that's intentional signal,
not a bug in this task. `scripts/ci/vuln-allowlist.txt` in lexa-hub is empty
(comment-only) for the same reason as csip-tls-test.

All 42 Required-tier findings are the same TASK-006 worklist (x/crypto, x/net,
x/sys bump); the one paho Required-tier finding will also be cleared by the
same paho bump that fixes GO-2025-4173.

## TASK-006 worklist (derived from this baseline)

1. `golang.org/x/crypto` bump (both repos) — clears 25 Required findings/repo.
2. `golang.org/x/net` bump (both repos) — clears 21 Required (csip-tls-test) /
   15 Required + 1 Called (`GO-2025-3503`, lexa-hub).
3. `golang.org/x/sys` bump (both repos) — clears 1 Required finding/repo.
4. `github.com/eclipse/paho.mqtt.golang` bump, **lexa-hub only, last, alone,
   campaign-gated** (RSK-04) — clears 1 Called (`GO-2025-4173`) + 1 Required
   finding.
5. Re-run `scripts/ci/govulncheck.sh` in both repos after each commit; the
   acceptance bar for TASK-006 is **0 Called findings** in both repos (this
   baseline already has 0 in csip-tls-test — the bar there is "stay at 0").
   Required-tier findings should also drop to ~0 once the x/* bumps land, but
   are not a hard gate.
6. Once lexa-hub's Called-tier count is confirmed 0, flip both workflows'
   `vulncheck` job from `continue-on-error: true` to required (remove the
   `TODO(TASK-006)` in each `ci.yml`).

## Acceptance criteria this baseline satisfies (TASK-005)

- [x] `bash scripts/ci/govulncheck.sh` runs in both repos locally (see
  `scripts/ci/govulncheck.sh` in each repo) and is wired into
  `.github/workflows/ci.yml`'s new `vulncheck` job.
- [x] Version pinned (`GOVULNCHECK_VERSION="v1.5.0"`); nightly schedule
  (`cron: '17 4 * * *'`) active in both workflows.
- [x] Every reachable (Called-tier) finding dispositioned: 0 in csip-tls-test
  (nothing to disposition), 2 in lexa-hub (both → TASK-006 worklist, not
  allowlisted).
- [x] This document committed.
