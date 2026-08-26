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

### Dry-run selections (catalog sha256 `e1de6743…`, 283 rows)

    certify -campaign csip          -manifest c.json -dry-run   →  52 to RUN ·  0 SKIP ·  0 N/A
    certify -campaign mbaps         -manifest c.json -dry-run   →  56 to RUN ·  2 SKIP ·  3 N/A
    certify -campaign modbus-client -manifest c.json -dry-run   →  15 to RUN ·  0 SKIP ·  0 N/A

(the three N/A rows under `mbaps` are the Secure SunSpec **client**-direction
rows against a server-only manifest — see §5.)

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
  precedence), `CORE-012/013/021/022/023`, `local-ext-v1::EXT-001`.
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

With the manifest above, `-campaign mbaps` reports exactly this for
`ssm-conf-v0.8::PKI-009`, `PROT-003` and `RBAC-011`.

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
