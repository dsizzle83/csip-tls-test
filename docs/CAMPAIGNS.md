# Campaigns, exploratory runs, and what a bundle is allowed to decide

`bin/certify` produces two kinds of evidence, and until now nothing in the tool
said which kind you were holding.

A **campaign** is a named, closed selection with a stated DUT precondition that
is *proven before case 1* and recorded in the bundle. It is the only shape whose
result may gate anything.

An **exploratory run** is everything else — `-suite`, `-doc`, `-uid`, a
whole-catalog sweep. It still runs, still bundles, still self-verifies, and it is
marked **NOT GATING** in `bundle.json`, in `REPORT.md`, and on the console.

    certify -campaign mbaps -manifest configs/candidate.json \
            -gateway-ssh cc93 -iface enp1s0 -out runs/mbaps-$(date -u +%Y%m%dT%H%M%SZ)/

---

## 1. The three campaigns

| `-campaign` | Suites | Required LIVE control authority | Subject |
|---|---|---|---|
| `csip` | `csip` | **`csip`** | the DUT as an IEEE 2030.5 / CSIP DER client |
| `mbaps` | `ssm` + `modbus-server` + `pki` | **`mbaps`** | the DUT as a Secure SunSpec Modbus northbound server, with its SunSpec server and PKI rows |
| `modbus-client` | `modbus-client` | any posture the **manifest** claims | the DUT as a southbound SunSpec Modbus client polling its DER |

Each campaign implies `-applicable`: a campaign's subject is the rows the
product *claims*. The informative rows — implemented, run, but outside the
claimed profile — are examined in exploratory runs.

`-campaign` **cannot be combined with `-suite`.** A campaign *is* a suite
selection, closed on purpose. A bundle that claims to be the mbaps campaign and
contains some other set of rows is worse than one that claims nothing.

`-campaign` **requires `-manifest`.** See §4.

A campaign **narrowed** by `-uid`, `-doc`, `-role` or `-automatable` is allowed —
re-running one row against a parked DUT is a real need, and the campaign's
preconditions still bite in full. But the bundle is marked **NOT GATING** and
says why: it contains *part of* the campaign, not the campaign, and one row
stamped `gating: true` would be read as the whole thing.

The three campaigns are **disjoint**: no catalog row belongs to two of them.
An unselected protocol therefore contributes neither a FAIL nor a SKIP to a
campaign — it contributes no row at all. `internal/certify/suites/campaign_test.go`
holds that property against the linked suites on every test run.

### Dry-run selections (catalog sha256 `f84d442e…`, 286 rows as of 2026-09-08 —
the per-campaign RUN/SKIP/N/A counts below are illustrative from an earlier
catalog snapshot and have not been re-run against the current one)

    certify -campaign csip          -manifest c.json -dry-run   →  52 to RUN ·  0 SKIP ·  0 N/A
    certify -campaign mbaps         -manifest c.json -dry-run   →  56 to RUN ·  2 SKIP ·  0 N/A
    certify -campaign modbus-client -manifest c.json -dry-run   →  15 to RUN ·  0 SKIP ·  0 N/A

`mbaps` selects **58** rows to get those 58 outcomes: 56 to run, 2 skipped for a
missing `gateway` capability, and no N/A at all. It reported **3 N/A** until
2026-08-26, when the catalog stopped marking the three Secure SunSpec
**client**-direction rows applicable — see §5's scope-conflict note. Since a
campaign implies `-applicable`, agreeing with the manifest moves those rows out
of the SELECTION rather than into an N/A verdict.

### What a campaign closed out

A campaign is a closed selection, so it prints what it closed:

    Campaign:     mbaps — …
                  suites ssm + modbus-server + pki · GATING
                  7 row(s) in those suites are OUTSIDE the claimed profile and are not
                  selected (catalog applicable=false; the reason travels in the bundle's
                  archived catalog.json): ssm-conf-v0.8::PKI-009, … and 3 more

These are **not** SKIPs and **not** N/A. Both of those are for rows a run
examined and decided about; these were never selected. Their reasons travel
anyway: every bundle archives the `catalog.json` it ran against, beside the
digest `bundle.json` records, and `applicable: false` plus its
`applicability_reason` is in there for each of them. `-trr` reads that archived
catalog for exactly this purpose.

---

## 2. The control-authority precondition, and why it fails closed

The product arbitrates control of its DER between mutually exclusive lanes, and
exactly one owns `lexa/desired/*` at a time. **The lane that is not in authority
is not idle: its writes are deliberately refused.** On the Secure SunSpec side
the refusal is an RBAC overlay that denies model 704–712 control writes to every
role including `SuperAdministratorSunSpec`
(`configs/rbac/overlays.d/10-csip-mode.json`, the "D1 lock-screen").

So a row whose subject is a control path has a precondition no published
document mentions. Run it under the other posture and it measures a refusal that
is correct product behaviour, and publishes it as the row's own verdict. That is
`RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES` in
`lexa-gw/docs/known_issues.json` — a whole cluster of "findings" that were
findings about the lock-screen.

### How the posture is read

Two channels, and they must **agree**:

| | Source | What it is |
|---|---|---|
| **LIVE** | dev API `GET /mode` → `control_authority` | the posture the running system is *in*, projected from retained `lexa/mode` |
| **CONFIGURED** | `/var/lib/lexa/mode-overlay.json` if it declares one, else `/etc/lexa/mode.json` | the posture the device is *set to hold* |

The dev API is loopback-bound and speaks HTTPS with a per-device self-signed
leaf, so it is fetched **on the DUT** through the introspection transport:
`wget -qO- --no-check-certificate --header 'Authorization: Bearer …' https://127.0.0.1:9100/mode`.
The bearer token is read from `/etc/lexa/api.token`; if it is unreadable the
fetch is retried unauthenticated (lexa-gw's `requireBearer` is staged-open) and
the bundle records which happened. Override the base URL with `-dev-api`.

A **disagreement is a failure.** Live ≠ configured means arbitration has moved
the device away from what it is set to hold — mid-flight, or left there by an
earlier run — and a campaign measured across that boundary is a campaign whose
rows saw two different devices.

### The rules

| Situation | Outcome |
|---|---|
| Posture matches | run proceeds; the reading is printed and recorded |
| Posture wrong, unknown, or live ≠ configured | **run ends before case 1**, non-zero exit |
| No introspection transport, `-campaign` given | **run ends**: a campaign proves its preconditions or it is not a campaign |
| No introspection transport, exploratory, no `-skip-preflight` | **run ends** |
| No introspection transport, exploratory, `-skip-preflight` | run proceeds, **marked NOT GATING** in the bundle with the reason |

`-skip-preflight` is **not** a way past a wrong reading. Its only effect on this
check is the last row above; its documented job remains the `-gridsim` /
`-gridsim-admin` pairing check.

**Exit codes.** A precondition that could not be met exits **1**, the same as the
`-gridsim`/`-gridsim-admin` pairing preflight it sits beside: both are facts
about the bench and the device, and a pipeline already treats a preflight
failure that way. A *bad invocation* — an unknown campaign, `-campaign` without
`-manifest`, `-campaign` with `-suite`, a selection matching zero rows, a
malformed `-gateway-exec` — exits **2**.

### Which rows arm it

`internal/certify/authority.go` carries the classification, one entry per row
with the reason it needs that lane. In outline:

* **`csip`** — `BASIC-004…015` (inverter control), `BASIC-016…026` (event
  precedence), `CORE-012/013/021/022/023`, `local-ext-v1::EXT-001…004`.
  `EXT-002`/`EXT-003`/`EXT-004` (REV0907-B1/B2) are LOCAL EXTENSION rows with
  no published CSIP-CONF-v1.3 procedure behind them at all: `EXT-002` proves a
  RESERVED `currentStatus` value (6) is never treated as Cancelled, `EXT-003`
  proves a `currentStatus=3` (Cancelled with Randomization) event is not
  withdrawn before its own end randomization, and `EXT-004` proves an event
  whose Specified End Time (§10.2.3.3 l) has already passed AT FIRST SIGHTING
  draws Response status 254 and is never Received/Started/Completed —
  regardless of the `currentStatus` (0, Scheduled) the server advertises on
  it. All three share `CORE-012/013/021/022/023`'s own reason for needing
  `csip`: their subject is the DER program/control lifecycle itself, which
  exists only while the CSIP control path owns `lexa/desired/*`.
* **`mbaps`** — every `ssm-conf-v0.8::RBAC-*`, and the northbound **write** rows
  `MB-1`, `MOD-3`, `EXC-1`, `EXC-2`, `CRV-1`, `REV-1/2/3`.

Discovery, read and transport rows measure the same thing under every posture
and are not classified. `TestAuthorityClassificationResidueIsAcknowledged` makes
that explicit: every row a campaign executes must be *either* classified *or*
listed in that test with a reason it needs no lane. **A new catalog row cannot
join a campaign without somebody deciding, in writing, which lane it needs.**

### Parking the DUT

Both levers work:

* apply an authority intent — lexa-gw subscribes `lexa/intent/authority` and
  `internal/authority/intentin.go` performs a real fail-closed transition; or
* set `"authority"` in `/etc/lexa/mode.json` and restart `lexa-mode`.

A transition to `csip` additionally needs `csip_enabled: true`; lexa-mode refuses
it otherwise, and the refusal message says so when it sees `csip_enabled=false`.
It also warns when the DUT reports `FAILSAFE ENGAGED`, which changes what the
control path will apply at all.

---

## 3. Introspection transports

    -gateway-ssh cc93                    a remote DUT, over ssh
    -gateway-exec "docker exec gw"       a DUT on THIS host, via a command prefix
    -gateway-exec "scripts/lab/lab-exec"

Mutually exclusive — they name different devices, and a run that read some facts
from one and some from the other would be evidence about neither.

**The read-only allowlist is enforced before either transport**, on the same
argument vector. Making the DUT reachable without ssh does not make anything
runnable that was not runnable before.

Either transport satisfies the `gateway` capability, so a local-exec run is a
first-class introspection channel.

*(ssh concatenates its trailing arguments and the remote shell splits them
again, so arguments are shell-quoted on that path only — and only when they need
it, so every pre-existing command goes over the wire byte-identically. The local
path passes a real argv and needs no quoting.)*

---

## 4. The candidate manifest

`-manifest <path>` loads the **candidate manifest**: the machine-readable
declaration of what the DUT claims to be. The product installs it at
`/etc/lexa/candidate.json`. It is REQUIRED with `-campaign`, optional otherwise.

```json
{
  "profile": "one-to-one-7xx-tcp",
  "topology": {"configured_der": 1, "role": "inverter", "northbound_units": [1]},
  "csip": {"role": "der-client", "end_devices": 1, "der_resources": 1},
  "secure_sunspec": {"roles": ["server"], "transport": "tls-tcp", "port": 802,
                     "frame_budget_ms": 2000},
  "modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx"},
  "authority_profiles": ["csip", "mbaps"],
  "models": [1, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712]
}
```

Every key is required **except `secure_sunspec.frame_budget_ms`** (§4.1).
Vocabularies: `topology.role` ∈ inverter|battery|meter ·
`csip.role` ∈ der-client|der-aggregator-client · `secure_sunspec.roles` ⊆
server|client · `secure_sunspec.transport` ∈ tls-tcp · `modbus_client.transport`
∈ tcp|rtu|rtuovertcp · `modbus_client.generation` ∈ 1xx|7xx|8xx ·
`authority_profiles` ⊆ csip|mbaps|local.

The reader is **strict about shape** — an unknown key is an error, on the
catalog loader's reasoning — and **tolerant about your time**: every problem is
reported at once, and an absent key is named as *missing* rather than decoding
to a zero that then reads as a declaration of "zero DERs" or "port 0". It also
refuses a manifest that contradicts itself (`configured_der` vs
`csip.der_resources` vs `modbus_client.device_count` vs the length of
`northbound_units`).

The manifest file is copied into the bundle beside its sha256, so a reader can
hash the copy in front of them and confirm the scope decisions were made against
it.

### 4.1 `secure_sunspec.frame_budget_ms` — the one optional key, and why it exists

The DUT's **MBAP frame budget**: how long its northbound listener holds a
connection open waiting for the rest of a frame whose MBAP header has already
promised a length, before it gives up and closes. On the product side it is
`limits.frame_budget_ms` in `configs/mbaps.json` (`cmd/mbaps` Config,
`internal/listener` `Server.FrameBudget`); the deployed value and the default
are both **2000**.

It is here because **SS-MODBUS-CONF v1.4 TCP-2 and TCP-3 put the same bytes on
the wire, and only the pause tells them apart.** Both send part of an MBAP frame,
pause, then send more bytes on the same connection:

| | pause | what the second write is |
|---|---|---|
| **TCP-3** §2.7.8 | 20 ms — *inside* any budget | the rest of ONE request; reassembling it is the pass criterion |
| **TCP-2** §2.7.7 | budget + margin — *past* the budget | a NEW request; splicing it onto the first is the failure |

Neither section specifies any timing at all. The harness used to pause 200 ms,
which is shorter than any deployed budget — so a conformant server still
assembling the first frame (exactly what TCP-3 *requires* it to do) spliced the
second write on and answered under the first frame's transaction id, and the
harness recorded that as a defect. The number has to come from the device, and
this is where the device states it.

`certify` adds a **≥ 500 ms margin** on top (`suitemodbusserver.TCP2Margin`).
The budget is when the DUT *decides*; the margin is the slack between that
decision and the harness observing it, and a pause of exactly the budget races
the transition it is trying to observe.

**Absent, the two run kinds answer differently, on purpose:**

* a **campaign** refuses to run TCP-2 — the row FAILs naming the key. Guessing
  the budget would publish the guess as a measurement, and the guess decides the
  verdict.
* an **exploratory** run falls back to 2000 ms + the margin and says so loudly —
  in the notes, in the assertion's note, and in the run log — because that
  assumption is about a *different* device than the one on the socket. An
  exploratory bundle is marked NOT GATING anyway.

Present, it is validated against the same `[1, 60000]` ms range `cmd/mbaps`
itself enforces, so a manifest this reader accepts is one the DUT would accept.
Strictness is unchanged elsewhere: a misspelling of the optional key is still an
unknown key, and still an error.

### 4.2 TCP-2's three outcomes

§2.7.7's criteria are that the device RECOVERS from the incomplete request — it
does not hang and does not mis-parse the following one — and that the following
complete request receives a successful response. It is silent on whether the
second request may go on the same connection and on whether the DUT may close
the connection after the partial one, and the catalog's own note directs that
the close be recorded as an **observation rather than a failure**.

| observed | verdict |
|---|---|
| the follow-up answered on the **same connection**, echoing its own transaction id | **PASS** — the server discarded the partial frame and resynchronised. Also conformant to the literal text, and the stricter reading. |
| the DUT **closed the connection** at its budget, and a complete request on a **fresh connection** was answered normally | **PASS**, with the close carried as the §2.7.7 observation. This is lexa-gw's shape, and it was previously graded WARN — a device doing exactly what the procedure permits, published as a partial result. |
| a response under the **truncated frame's** transaction id | **FAIL** — the DUT spliced the follow-up onto the partial frame: the following request was MIS-PARSED. Past the DUT's own budget this can no longer be confused with TCP-3's reassembly. |
| no answer on either connection | **FAIL** — the following complete request received no successful response. |

A stale-id answer is **not** followed by a fresh-connection attempt: the DUT has
already answered, wrongly, and opening a second connection there would only put a
successful exchange beside a failure and invite it to be read as recovery.

TCP-3 is untouched: its 20 ms split is safe under every budget by construction.

### Topology preflight

When a transport is configured, the manifest's observable claims are held
against the DUT's own report (`GET /southbound/inventory`, falling back to
`GET /status`'s `southbound.device_count`): the admitted DER count, the device
role, the southbound transport, and the northbound unit.

* A fact that **contradicts** the manifest ends the run.
* A fact the DUT **cannot report** is stated as unproven and the run continues.

The dev API publishes the *admitted* inventory, not the *configured* one, so a
count of zero is reported as unproven rather than as a contradiction. When the
product grows an explicit configured-count fact, this gains one comparison.

### Baseline precondition + gating reset (WP7-T6)

Two closely related, but different, mechanisms close
`QAGAMUT2-001-SIMULATOR-STATE-NOT-RESET-BETWEEN-RUNS`: residual bench state
carried from one run into the next silently becoming a FAIL, a false PASS, or
an unattributable SKIP.

**At campaign start**, before case 1, a GATING campaign's preflight resets
every configured southbound sim (`POST /reset` — restores the as-built
register image and disarms every fault layer) and clears gridsim's
program/event tree. A sim that cannot be *proven* reset — unreachable, or an
old build that answers `501` to `POST /reset` — refuses the run exactly like
an unprovable `-gridsim`/`-gridsim-admin` pairing does (§2's failed-closed
rule): a certification bundle may not rest on a device this run never proved
was clean. The reset epoch(s) are printed in the run's own console log.

**Inside a campaign**, before EACH oracle-graded `csip` row publishes
anything, it re-reads the DER's own actuator register(s) — the same ones its
oracle grades — and compares the baseline against the value it is about to
command. A baseline already indistinguishable from the target (a residual
control from the row before it, or from a prior campaign a reset did not
reach) is never reported as a PASS or a FAIL: the row publishes nothing and
rolls up to an explicit **SKIP** naming the register, the value, and — when
the residue came from this same campaign — which row's teardown actually left
it there. See `internal/certify/suitecsip/basic.go`'s `oracleContaminationParam`
and `internal/certify/suitecsip/teardown.go`'s post-teardown baseline note for
the mechanism; `CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION` is the finding
this closes at the row boundary, and the campaign-start reset above is the
same finding closed at the campaign boundary.

---

## 5. `N/A` — a verdict, and not one

`bundle.VerdictNotApplicable` (`"N/A"`) is **distinct from SKIP**, and the
difference is the whole point:

* **SKIP** — *this run could not measure it.* A fact about the bench. An
  evidence gap. Possibly fixable by re-running with a capture, a transport, a
  capability.
* **N/A** — *there is nothing here to measure.* A fact about the candidate's
  declared scope. No amount of re-running changes it.

Reporting the second as the first is how a campaign accumulates dozens of SKIP
lines that look like unfinished work and bury the handful that really are.

A row can become N/A two ways, and the bundle records **which**:

| `source` | Meaning |
|---|---|
| `catalog-applicability` | the catalog marks the row inapplicable to the claimed profile **and no suite implements it**. (An implemented-but-inapplicable row still runs and is reported as *informative* — that tally is unchanged.) |
| `manifest` | the candidate does not claim what the row is about. Today the one active axis is the Secure SunSpec **direction**: a `dut_role: mbaps-client` row against a manifest whose `secure_sunspec.roles` lacks `client`. |
| `pics` | reserved for a PICS-sourced declaration. |

### The same axis, one grain finer: `N/A` on an ASSERTION

The catalog's `dut_role` is one scalar per case, so it can take a whole
`mbaps-client` row out of scope and can say nothing about the row that is
*mostly* about the server and carries one client-procedure criterion inside it.
SSM-CONF-v0.8 is full of those: its Table 1 marks 20 of the rows this bench
implements **Both**, and each splits into a `2.x.y.1 Server Procedure` and a
`2.x.y.2 Client Procedure`.

Against `"secure_sunspec": {"roles": ["server"]}` those inner `[C]` criteria used
to run anyway — waiting out the gateway's southbound poll interval for a
ClientHello whose conformance the candidate never claimed, then recording a SKIP
indistinguishable from an evidence gap. CRYP-001 is the worked example: six
server assertions PASS and assertion 7 SKIPs, and the row reads as unfinished
work about a direction the device does not have.

`internal/certify/suitessm/roles.go` gives every SSM assertion an explicit
direction (`server` / `client` / `both`) in the suite's own table, transcribed
from Table 1's Role column and from which procedure subsection each assertion
implements. When `RunCtx.RoleClaimed("client")` is false:

* the client-direction assertions are reported `N/A`, source `manifest`, with a
  reason naming the unclaimed role and the candidate profile — the claim and the
  method survive so a reader sees *which* criterion was excluded, the citation
  digest does not, because nothing was measured;
* an observation the bench happened to make anyway is carried in the note rather
  than discarded;
* the check does **not** pay for the direction: no endpoint is claimed, no
  `drop_session` fault is armed on the device sim, and no poll interval is waited
  out;
* the row rolls up on its remaining server assertions, so a case whose server
  half all passes reports **PASS** rather than **WARN**.

A run with **no** `-manifest` is unchanged: `RoleClaimed` answers true for every
role, and every `[C]` half is asserted exactly as before.

The table is drift-guarded. `TestEverySSMAssertionCarriesARole` parses the
suite's own sources and fails if a claim carrying the document's `[C]:` marker
is not accounted for by a client-direction rule of the case that mints it, or if
a rule matches no claim that still exists.

Rules the verifier enforces:

* an N/A row **must** carry a reason and a recognised source — an unexplained
  N/A is indistinguishable from a row quietly dropped;
* no other verdict may carry that record — a row is either graded or out of
  scope, never both;
* the roll-up still runs, so a FAIL assertion under an N/A heading is caught;
* N/A is refused outright in a bundle declaring schema
  `lexa-evidence-bundle/1`, which predates the verdict.

N/A is neither a pass nor a failure: it is excluded from every FAIL tally, and
from the "did this run establish anything" floor — a bundle every row of which
was out of scope reports **"Nothing was measured"**, not "No failures".
`REPORT.md` and `COVERAGE.md` tally it on its own line; the TRR maps it to
`NOT SUPPORTED` carrying its reason and source.

### Scope conflict

If the manifest excludes a row the **catalog marks applicable**, the manifest
stands — it is the candidate's own statement about itself — but the
disagreement is printed prominently and recorded in the bundle note. One of the
two documents is wrong, and only the owner of the claim can say which.

`-campaign mbaps` reported exactly this for `ssm-conf-v0.8::PKI-009`,
`PROT-003` and `RBAC-011`, and **the catalog was the document that was wrong**
(LAB29-011, closed 2026-08-26). All three carry `dut_role: mbaps-client`; the
candidate claims `secure_sunspec.roles = ["server"]` under the profile
`one-to-one-7xx-tcp`, and the regenerated PICS states the negative outright —
`PICS.md`'s `pics-claims` block carries
`secure_sunspec_roles_not_claimed: ["client"]`, and `PICS_SUNSPEC_MODBUS.md`
§5.1 rev. g reads *"mbaps client … NOT CLAIMED — present in source, unreachable
under the candidate profile"*, with *"every case written against the EUT-C is
out of the claim"* as the stated consequence. Three independent layers keep the
southbound mbaps client unreachable (a fatal non-`tcp` scheme check, an empty
`devices` list, and a refusal rather than a downgrade when the TLS identity is
unwired), so this is **present in source, out of the claim** — not
unimplemented.

The three rows are now `applicable: false` with that citation as their
`applicability_reason`. Two things follow, and the second one surprises people:

* the SCOPE CONFLICT no longer fires — the two documents agree;
* the rows leave the mbaps campaign's **selection** (58 rows, not 61) instead of
  becoming N/A. A campaign implies `-applicable`, and `-applicable` is applied
  during `Catalog.Select`, before the plan is built — so `CatalogScope` never
  sees them. That is the same standing treatment the twenty-two
  DER-Aggregator-Client rows already get under `-campaign csip`, and the run
  names the rows it closed out (§1). Run them without `-applicable` and they
  execute and report as **informative**, unchanged.

### For suite authors

Case-level scope is decided before the plan runs and never reaches a check.
For the finer grain a check *can* see — an assertion that only bears on a
direction the candidate does not claim:

```go
rc.Manifest()             // *manifest.Manifest, or nil
rc.RoleClaimed("client")  // Secure SunSpec direction; TRUE when no manifest was supplied
```

**No manifest means "assert everything".** Silence is not a disclaimer, and a
run with no `-manifest` must behave exactly as it did before manifests existed.

---

## 6. Zero selection is an error

`-suite modbus-server -uid ssm-conf-v0.8::RBAC-002` selects nothing: the uid
exists, the suite exists, no case is in both. Every downstream check then passes
*vacuously* — coverage complete over an empty list, no failures, exit 0, an empty
bundle. A green CI gate over nothing.

It is refused at construction, naming each requested uid and the suite that
actually owns it:

    certify: -suite modbus-server -uid ssm-conf-v0.8::RBAC-002 selects ZERO test cases. …
      ssm-conf-v0.8::RBAC-002 is in SSM-CONF-v0.8, suite ssm

`-dry-run` prints the full plan and a three-number footer:
`N to RUN · N to SKIP (unmeasurable here) · N NOT APPLICABLE (out of scope, never run)`.

---

## 7. `-preset local`

Fills in the **host-native lab**'s addresses for every target flag you did
**not** type. Explicit flags always win — including one that happens to equal
the default, because the preset is applied from the flags the parser actually
visited.

The lab is lexa-gw's `docs/LAB_LOOP.md`: the production binaries running on this
host inside a rootless user namespace, with the simulators from
`scripts/lab/lab-sims-up.sh` beside them. The two files that OWN these addresses
are `lexa-gw scripts/lab/lib.sh` and `csip-tls-test scripts/lab/lab-sims-up.sh`;
the table below is transcribed from them and `TestPresetLocalFillsInTheLoopbackBench`
holds it there.

| Flag | Value |
|---|---|
| `-gateway` | `127.0.0.2:802` |
| `-gridsim` / `-gridsim-admin` | `127.0.0.20:21113` / `http://127.0.0.20:21114` |
| `-modsim` / `-modsim-api` | `127.0.0.20:15020` / `http://127.0.0.20:16020` |
| `-mbapsdev` / `-mbapsdev-api` | `127.0.0.20:18021` / `http://127.0.0.20:16031` |
| `-metrics-endpoint` | `http://127.0.0.1:9102/metrics` |
| `-dev-api` | `https://127.0.0.1:9100` |
| `-iface` | `lo` |

**Three addresses, on purpose.** certify decides a captured frame's direction by
comparing its source against the DUT's, so on `127.0.0.1`-for-everything every
frame reads as the DUT's. `127.0.0.2` is the product, `127.0.0.20` the
simulators, `127.0.0.1` this harness — the same mnemonic split as the bench's
`69.0.0.2` / `69.0.0.20`.

**`802`, not a lab mirror.** `cmd/mbaps` refuses to start on any port the
candidate manifest does not claim (`secure_sunspec.port = 802`,
`Config.validateCandidate`, the LAB29-004 fail-closed shape rule), and the lab
installs `configs/candidate.json` **byte-identically** because its sha256 is a
load-time fact every bundle cites — a lab manifest edited to say `8802` would be
a different product shape wearing the same name. So the lab grants the port
instead of moving the listener: the host sysctl
`net.ipv4.ip_unprivileged_port_start`, a one-time owner prerequisite that
`lab.sh preflight` checks hard. There is deliberately no high-port fallback.

**The sim ports are the lab's own block, disjoint from the bench's.**
`sim/simapi` binds the wildcard address, so a lab reusing `11113/11114`,
`5020/6020` or `8021/6031` could not be separated from the bench set by address
— it would silently attach the local loop to the simulators a live bench
campaign is grading. `TestPresetLocalDoesNotCollideWithTheBenchPorts` holds the
two blocks apart.

**`-iface lo` matters**: loopback traffic crosses `lo` and nothing else, and
leaving the bench NIC here produces a capture with zero frames and a bundle full
of PASSes downgraded "for want of a citation".

One limit the lab cannot remove, and does not pretend to: Linux sources every
outbound loopback connection from `127.0.0.1` regardless of destination, so the
DUT's OWN client sockets (CSIP → gridsim, Modbus → modsim/mbapsdev) appear as
`127.0.0.1` rather than as the DUT's address. Direction-sensitive assertions on
the DUT-as-client legs are Layer-3 (board) evidence.

---

## 7a. `-evidence` — the campaign that must produce a submission artefact

    certify -campaign csip -evidence -manifest configs/candidate.json \
            -param report.comm004=csip-conf-v1.3::COMM-004,…COMM-004A,…COMM-004B,…COMM-004C \
            -gateway-ssh cc93 -iface wlp2s0 -keylog /tmp/bench-shared.keylog \
            -out runs/csip-evidence-$(date -u +%Y%m%dT%H%M%SZ)/

`-evidence` is a **modifier on a campaign**, never a selection of its own — an
exploratory run is marked NOT GATING whatever its bench looked like, so there
would be nothing for the claim to attach to, and `-evidence` without
`-campaign` is refused (exit **2**).

It says: *this bundle will carry a submission-grade artefact.* Every bench
precondition that artefact depends on is therefore **proven before case 1**, and
the run ends there if any of them cannot be established — the same fail-closed
discipline as the `-gridsim`/`-gridsim-admin` pairing preflight and the
control-authority preflight it sits beside. A precondition that could not be met
exits **1**.

### Why it exists (LAB29-011)

SS-CSIP-RESULTS v1.1 Chapter 5 requires a raw TLS packet trace per COMM-004
certificate scenario, containing that scenario's whole handshake. `RPT-060`
exports them from the run's own capture — and it **failed**, because not one
COMM-004 scenario had an attributable fresh handshake: every session had been
resumed from a ticket.

Everything about that failure was late and indirect. The COMM-004 rows
themselves passed. Their certificate criteria correctly report *"this window's
session is a RESUMED TLS 1.2 session, so the chain cannot be read from it"* as
UNAVAILABLE rather than as a device fault — which is the right answer for a row
measuring a **device**. So the run looked clean until the last row of the last
document tried to assemble a submission out of eight windows with no certificate
exchange in them, and reported the aggregate as its own failure. By then the
bench was hours gone.

The cause was a **launch flag**. gridsim issues session tickets unless started
with `-no-tickets`, and holds a connection open forever unless started with
`-idle-timeout-s`. Neither is observable from the traffic — the absence of a
handshake in a window looks identical whether tickets were on or the DUT simply
had nothing to say.

### What it proves, before case 1

| Requirement | Refusal if unmet |
|---|---|
| a capture (`-no-capture` is refused) | the artefacts ARE the capture |
| a `-keylog` | without the secrets, every transcript-borne citation is lost |
| `-param report.comm004=<uid>[,<uid>…]` | RPT-060 traces the scenarios named here; unnamed, none is written |
| each named uid will actually RUN in this plan | a scenario that does not run produces no frames, so no trace can be cut for it |
| each named uid is a COMM-004 row | another row's conversation under a Chapter 5 filename misdescribes the artefact |
| gridsim publishes a TLS posture at all | **absent ≠ false**: an old simulator, or another server entirely — either way UNPROVEN |
| `tls.no_tickets == true` | a resumed session carries no Certificate message (RFC 5077 §3.1; RFC 8446 §2.2 for 1.3) |
| `0 < tls.idle_timeout_s` | otherwise one connection spans every poll cycle and only the first scenario's window holds a ClientHello |
| `tls.idle_timeout_s < poll_rate_s` | the timeout must fire INSIDE the poll cadence, which is the boundary between one scenario's session and the next |
| `poll_rate_s != 0` | with the built-ins (300 `/dcap`, 900 `/tm`, 60 control lists) there is no single boundary to hold the timeout against — and a `poll_rate_mode=honor` DUT paces its whole walk at 900 s |

The posture comes from gridsim's own `GET /admin/status`, which now carries:

```json
"tls": {"no_tickets": true, "idle_timeout_s": 30}
```

The key is **omitted** when the embedding binary never declared one
(`gridsim.Server.SetTLSPosture`), because "unreported" and "reported false" are
different facts and a fail-closed caller has to tell them apart. Reading it from
`/admin/status` is deliberate: the pairing preflight has already proven that
response belongs to the process serving the data plane, so the posture is *that
process's* posture and not some other gridsim's.

The preflight is **read-only**. It does not start, restart or reconfigure the
simulator: this harness must not mutate the bench it is measuring, and a
simulator restarted mid-campaign invalidates the evidence of every case before
it. An operator who sees it fail relaunches gridsim with the flags the message
names and re-runs.

### The second line: per-scenario grading

A correctly posed bench can still produce a resumption — the DUT reconnecting
inside a window, an idle timeout that did not fire in time. So under `-evidence`
each COMM-004 row (the parent and A–G) gains one criterion, **first** in its
list:

> *this COMM-004 scenario ran on a FULL TLS handshake, so the raw packet trace
> SS-CSIP-RESULTS v1.1 Chapter 5 requires for it can be cut from this window*

It **FAILS the scenario, on the scenario's own row, with the reason** — instead
of going unavailable and leaving RPT-060 to report the aggregate later. A
**rejected** handshake satisfies it: COMM-004 D/E/F/G exist to make the DUT
refuse a chain, so the handshake does not complete, and the server's Certificate
message — which is exactly what the trace must contain — is on the wire all the
same.

Outside an evidence run the criterion is not added at all. An ordinary run
measures a **device**, and "this window's session was resumed" is a fact about
the bench that must not be charged to the DUT.

The `-evidence` flag itself is recorded in the bundle: `run.command` carries the
invocation, redacted (`bundle.RedactCommand`), so a reader can see the claim was
made rather than infer it.

---

## 8. What the bundle records

`bundle.json` → `run.campaign`:

```json
{"name": "mbaps", "suites": ["ssm","modbus-server","pki"],
 "authority": "mbaps", "authority_observed": "mbaps", "gating": true}
```

`gating` is written even when false — *"this bundle is not gating"* is a fact a
CI gate must read directly, not infer from a missing key. An exploratory run also
carries `exploratory` saying why.

`run.candidate` carries `{path, sha256, profile}` and the manifest file travels
in the bundle beside it.

Bundle schema is now **`lexa-evidence-bundle/2`**. `/1` bundles still load and
still verify; a `/1` bundle carrying `/2` vocabulary is refused.
