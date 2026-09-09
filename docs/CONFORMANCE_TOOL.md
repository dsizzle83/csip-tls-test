# `certify` — the conformance evidence tool

`cmd/certify` drives the LEXA DER gateway through the published SunSpec / CSIP
conformance test procedures and emits an **evidence bundle**: a packet capture
plus a machine-checkable mapping from each test case to the exact frames and
byte ranges that demonstrate its pass criteria. A third party verifies the
bundle with one command, reading nothing but the directory we hand them.

It is built on the bench's own independent stacks. The referee never uses the
product's implementations — `internal/mbtls` rather than
`lexa-platform/securemodbus`, `internal/csipref` rather than the hub's walker —
so a profile, authorization, or scheduler bug in the device under test cannot
hide behind a shared implementation (PN-1 / C9 / AD-003(f)). Only
`lexa-proto/{mbap,modbus,sunspec,csipmodel}` is shared, because the wire format
is the wire format.

---

## 1. Coverage of the standard

The specification is `testdata/catalog/catalog.json` — 286 test cases extracted
from eight published documents, plus a ninth catalog entry, `LOCAL-EXT-v1`,
this bench's own non-certifying extension family (see "NOT CERTIFIABLE" under
`-list`'s output) — committed, and hashed into every bundle so a reader can
answer "which version of the spec was this measured against?" by hashing a
file in front of them. Table regenerated from `certify -list` on 2026-09-08
against `testdata/catalog/catalog.json` sha256
`f84d442e31d56d1e6c9ce6ab7a4715155a1998138edab77d6beac1bfe9554677` (286 cases,
9 documents).

| Document | Selected | Applicable | Implemented | …of which the extraction marks inapplicable | Unimplemented | Not applicable, no check |
|---|---:|---:|---:|---:|---:|---:|
| CSIP-CONF-v1.3 | 79 | 51 | 79 | 28 | **0** | 0 |
| LOCAL-EXT-v1 | 4 | 4 | 4 | 0 | **0** | 0 |
| SS-1547-TEST-v1.0 | 2 | 2 | 2 | 0 | **0** | 0 |
| SS-CSIP-RESULTS-v1.1 | 47 | 45 | 45 | 0 | **0** | 2 |
| SS-MODBUS-CLIENT-CONF-v1.1 | 16 | 15 | 15 | 0 | **0** | 1 |
| SS-MODBUS-CONF-v1.4 | 24 | 16 | 16 | 0 | **0** | 8 |
| SS-MODBUS-RESULTS-v1.2 | 54 | 52 | 52 | 0 | **0** | 2 |
| SS-TEST-PKI | 21 | 6 | 10 | 4 | **0** | 11 |
| SSM-CONF-v0.8 | 39 | 34 | 37 | 3 | **0** | 2 |
| **TOTAL** | **286** | **225** | **260** | **35** | **0** | **26** |

`SS-1547-TEST-v1.0` was `SS-1547-TEST-v1.1` until WP7-T8 (REV0907-E9,
2026-09-08) re-keyed the catalog's doc key and uid prefix to match the source
PDF's actual version (the prior key was a misparse of the file name
`SunSpec-Modbus-for-1547-Test-Procedures-v1_10-8-24-1.pdf`; the `doc_version`
field on both rows in `testdata/catalog/catalog.json` carries the full note).
`internal/certify/suitemodbusserver/suite.go`'s `checkMOD4` / `checkSF`
registrations were re-keyed in the same change, so both cases still show
Implemented above rather than Unimplemented/orphaned. An evidence bundle
minted before the migration still carries the old uid verbatim — that is
immutable evidence and is never rewritten — and
`testdata/catalog/uid_aliases.json` records the old-to-new mapping so a saved
`-doc SS-1547-TEST-v1.1` / `-uid ss-1547-test-v1.1::MOD-4` and a Test Results
Report generated from an old bundle both still resolve against the current
catalog (`internal/certify/aliases.go`, `internal/certify/report/trr.go`'s
`certTypeFor`/`noCertBasisFor`).

Of the 260 implemented cases, the extraction rates 147 fully automatable, 35
partially, and 78 manual — a manual case still gets a check, because recording
an operator's observation inside a timestamped frame window is worth more than
recording nothing.

**CSIP-CONF-v1.3's applicable count moved 51 → 73 → 51 on 2026-07-28.** The
owner re-scoped the certification from the **DER Client** profile to the **DER
Aggregator Client** profile that morning and revised it back the same day. The
column it settled on is **DER Client, in the Generating Facility EMS (GFEMS)
posture**: the gateway sits at one point of interconnection and presents to the
utility as a single 2030.5 client — one EndDevice, one LFDI — with the control
fan-out to the inverters happening *below* the 2030.5 boundary. §4 Profile Test
Conformance requires twenty-two rows of an aggregator client that it does not
require of a DER Client (AGG-001..012, CORE-018, CORE-019, ERR-002,
MAINT-001/003/004/005, UTIL-002/003/004), and the two client columns nest
strictly — no row is required of a DER Client that an aggregator does not also
owe — so the narrower claim drops rows without dropping a single check.

**All twenty-two of those rows remain implemented and keep running**, which is
why CSIP-CONF-v1.3's Implemented column stays at 79 while its Applicable column
drops to 51. Their verdicts are *informative*: evidence about a capability this
product does not claim, gating nothing. See
`docs/PROFILE_SCOPE_2026-07-28_der-client-gfems.md` for the decision and what
the catalog records about it, and the superseded
`docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md` §3-§4 for the row-by-row
inventory of what each one drives and the errata it honours.

**`SS-MODBUS-CONF-v1.4`'s CRV-1 became applicable the same day**, for an
unrelated and duller reason: its exclusion rested on the claim that the
gateway's chain builder rejects models 705-712 northbound, and that had stopped
being true. Those models are chained device-conditionally, per unit, and CRV-1
tests that curve 1 is present and **read-only** — the posture the gateway does
implement. CRV-2 and CRV-3 stay inapplicable on the narrower, still-true fact
that neither can run without a *writable* second curve.

Regenerate the table at any time, and gate on it:

```bash
bin/certify -list                  # the table above, plus every gap by name
bin/certify -list -details         # every one of the 286 cases, with its status
bin/certify -list -json            # certify.Coverage, for a pipeline
```

`-list` exits **1** if any applicable case has no implementation or any
registration names a uid the catalog does not contain. A coverage regression
fails a pipeline; it is not a formatting preference.

### The four columns, precisely

* **Implemented** — a suite registered a check for the uid. The check runs.
* **Unimplemented** — the case is applicable to this product and nobody wrote a
  check. **This is zero, and the tool refuses to print "ALL TEST CASES
  ADDRESSED" while it is not.**
* **Not applicable, no check** — the extraction marked the case inapplicable and
  no check is registered. These 26 are printed in the coverage report *with the
  extraction's own reason*, which is why they are deliberately left
  unregistered: registering a check that could only ever SKIP would file the row
  under "Implemented" and lose the reason. Examples: `SS-MODBUS-CONF-v1.4`'s
  TCP-1 (asserts a plaintext Modbus/TCP interface on :502; the DUT's northbound
  Modbus is mbaps-only on :802, so a PASS would be a claim about a closed port),
  RTU-1..5 (no northbound serial interface), CRV-2..3 (no writable second
  curve); `SS-TEST-PKI`'s PKI-2, PKI-9..10, PKI-12..18, PKI-21 (requirements on
  the SunSpec Alliance certificate *package* a lab ships, not on the device).
* **…of which the extraction marks inapplicable** — 35 cases carry a check even
  though the catalog rates them inapplicable, because exercising the row is
  worth more than assuming it. They count as Implemented, not as N/A. The three
  columns therefore do not sum to the total, and `-list` says so on the totals
  line rather than leaving a reviewer to reconcile it. Twenty-eight of the 35
  are in CSIP-CONF-v1.3: **twenty-two** are the aggregator-only rows the DER
  Client claim excludes and the harness runs anyway, and **six** are excluded
  for reasons no profile choice can touch — CORE-001/002/004 and UTIL-001 test a
  2030.5 *server*, MAINT-002 is made optional by Annex A seq 32, and COMM-001 is
  optional for all device types by its own Purpose. All six are blank in every
  §4 column, and those six alone are bound to the not-applicable stub. The
  remaining seven are four in `SS-TEST-PKI` (`PKI-4..7`, the device
  certificate's Subject-empty/hwType-SAN encoding, manufacturer-model-OID
  uniqueness, IANA-PEN OID hierarchy, and serial-number ASN.1 encoding rows —
  distinct from the PKI-2/9..10/12..18/21 rows above, which are unregistered
  N/A) and three in `SSM-CONF-v0.8` (`PKI-009` Self-Signed Certificate
  Support, `PROT-003` TLS Compression Method, `RBAC-011` Client Certificate
  Role Requirement) — each runs and is reported informatively; `-list
  -details` prints the extraction's reason for every one.

### SKIP is a runtime verdict, not a coverage number

A check that runs and cannot assert its criterion here reports **SKIP with the
reason**, and that is a property of the *run*, not of the tool. It depends on
what the DUT serves, which bench pieces are present, and which capabilities the
invocation has. A real run reads like this (loopback SunSpec device, 24 cases of
`SS-MODBUS-CONF-v1.4`):

```
PASS 7 · FAIL 0 · SKIP 16 · WARN 1
  SKIP  REV-1  the DUT serves no model 704, so it exposes no reversion timer
  SKIP  EXC-1  the DUT serves no model this suite knows an invalid value for
  SKIP  TCP-1  not applicable to this product: no plaintext Modbus/TCP interface
```

Every SKIP names its reason. None is silent, and none is counted as a pass.

---

## 2. Running it

### Build — two configurations, and the difference is not cosmetic

```bash
make build-certify      # bin/certify        — ordinary wolfSSL sysroot
make certify-keylog     # bin/certify-keylog — keylog sysroot + -tags keylog
```

The ordinary build runs everything but exports no TLS session secrets, so a
capture's encrypted payloads stay opaque and the affected checks say so instead
of asserting on ciphertext. The keylog build exports NSS key-log lines so the
capture decrypts and the mbaps / HTTPS payload claims become re-checkable.
**A certification campaign uses the keylog build.**

Passing `-keylog` to the ordinary build is a hard error naming both the sysroot
and the tag. It is not a warning: a run that believes its capture is decryptable
and is not produces a bundle that looks complete until someone tries to verify
it, days later.

A `CGO_ENABLED=0` build also works and is not a lie — `-list`, `-dry-run`,
`-verify` and `-report` are fully functional and every plaintext-transport check
runs; only the mbaps transport is absent, and the checks that need it say so.

**One thing the ordinary build gained a stack for.** SSM-CONF-v0.8 mandates six
cipher suites and two of them use AES-CCM — `0xC0AE`
`TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` and `0x1304` `TLS_AES_128_CCM_SHA256`. Go's
`crypto/tls` implements no CCM cipher at all, so the SSM suite could take a
CCM handshake as far as the DUT's ServerHello and no further, and CRYP-001 and
CRYP-002 each carried a standing `WARN` saying the selection was asserted and no
session was. §2.5.1.3's criterion is "the EUT-S successfully **establishes a
secure session** using each of the mandatory TLS v1.2 cipher suites", so that
was a gap on a MUST row, published on every run.

`internal/tlsprobe` closes it: a small independent wolfSSL client, pinnable to
one suite at one version, that completes the mTLS handshake with the harness's
`-pki certs/mbaps` fixtures and carries a SunSpec Model 1 read (FC 0x03 at the
SunSpec base) inside the tunnel. It reports the negotiated version and suite, the
peer leaf, and where its secrets went. CRYP-001 and CRYP-002 now assert an
ESTABLISHED session on each mandated suite, cited from the capture on the
conversation's own ServerHello and full handshake flight.

In a `CGO_ENABLED=0` build the probe is not linked in, and the two non-CCM
suites fall back to `crypto/tls` while the CCM ones report — precisely, and as a
fact about the binary rather than about the device — that no session could be
established.

The probe verifies the DUT's certificate **in the library** (wolfSSL offers no
way not to), unlike the suite's `crypto/tls` sessions, which verify in the check
so the result is an observation. So a handshake it cannot complete is classified
before it is reported: a failure whose wolfSSL reason says *this side refused the
peer's certificate* (no trust anchor, an `extendedKeyUsage` naming no
`serverAuth`, an expired leaf) is recorded as a bench-side obstacle with the
reason named, never as "the DUT refused a mandatory cipher suite". The DUT's
certificate is measured on PKI-003/004/007/008, where a defect belongs.

### The seven modes

```bash
# What does the tool cover?
bin/certify -list [-doc SSM-CONF-v0.8] [-details] [-json]

# What would this selection run, and what would it skip, and why?
bin/certify -doc SSM-CONF-v0.8 -dry-run

# A real run. NOTE the key log: it is the SIMS' SHARED file, not a per-run
# private one. -keylog is both where certify EXPORTS its own TLS secrets and the
# file the citation phase READS BACK to decrypt the capture — so on a leg where
# certify is not a party to the sessions under test (the CSIP leg: the DUT is the
# client and gridsim the server) a private file is exported-to by nobody and
# decrypts nothing. The export opens the file in APPEND mode, so sharing it adds
# certify's secrets to the sims' rather than replacing them. See the per-leg
# table in docs/PREFLIGHT_2026-08-05_flashed-image-campaign.md.
#
# This -keylog path is separate from the *-keylog SIM binaries' own default
# key log: a wolfSSL sysroot built with --enable-keylog-export also writes an
# UNSOLICITED ./sslkeylog.log into the sim's process cwd, regardless of
# -keylog above (REV0907-E5). scripts/bench-sims-up.sh and
# scripts/lab/lab-sims-up.sh run every sim from $LEXA_SIM_RUNDIR (default
# /tmp/lexa-sims), never this repo's root, so that file lands there — it
# never reaches the repo checkout.
#
# Because -keylog names a file shared across every run and every leg,
# capture/*.keylog inside the bundle is NOT a copy of it: at write time the
# bundle keeps only the lines whose client random names a TLS session
# capture/*.pcapng actually contains, and drops the rest (a malformed source
# line is dropped too, counted rather than aborting the write). A bundle
# built against 69.0.0.2:802 ships secrets for that session and no other —
# not the CSIP leg captured five minutes earlier, not another operator's run
# against the same shared file (REV0907-E5).
bin/certify-keylog \
    -target 69.0.0.2:802 -iface enp1s0 \
    -pki certs/mbaps -gridsim-admin http://69.0.0.20:11114 \
    -keylog /tmp/bench-shared.keylog \
    -out runs/2026-07-26/ \
    -operator "your name" -dut-name lexa-gw -dut-build <fw version>

# Re-verify a bundle, standalone, trusting nothing.
bin/certify -verify runs/2026-07-26/

# Turn a bundle into a SunSpec submission.
bin/certify -report runs/2026-07-26/ -config lab.json

# Extract the southbound REGISTER WRITE SET a captured leg holds. Offline and
# read-only — it reads capture/*.pcapng (+ capture/*.keylog) and nothing else,
# so it is safe to run against a bundle while a battery is still going.
bin/certify -writes runs/2026-07-26/                       # full timeline, by axis
bin/certify -writes runs/2026-07-26/ -writes-mrid DERC-SP-CURVE-1786940036

# Turn a whole campaign into the Test Results Report package: BOTH Results
# Reporting specifications, from as many bundles as it took.
bin/certify -trr runs/csip-2026-07-28=csip-conf-v1.3 \
            -trr runs/full-2026-07-28 \
            -trr-out runs/trr-2026-07-28 -config lab.json -allow-incomplete
```

Two more that matter day to day:

```bash
# Which capability tags does this invocation have, and what do they gate?
bin/certify -capabilities -target 69.0.0.2:802 -pki certs/mbaps

# Logic-only: no capture, no wire citation. For developing checks.
bin/certify -no-capture -suite modbus-server -target 127.0.0.1:5020 \
            -param modbus.transport=plain -out /tmp/dev-run
```

A `-no-capture` run prints, in as many words, that **the bundle it produced is
not evidence** and must not be submitted.

### Selection and configuration

| Flag | Purpose |
|---|---|
| `-doc` `-uid` `-suite` `-role` | select cases (repeatable, comma-separated). A typo is refused, not silently narrowed to nothing. |
| `-applicable` `-automatable full\|partial\|manual` | narrow by the extraction's judgement |
| `-target` / `-gateway` | the DUT's mbaps address. `-target` wins; the bare host is derived from it. |
| `-pki` | mbaps certificate fixtures (`make gen-mbaps-certs` → `certs/mbaps`) |
| `-gridsim` `-gridsim-admin` | the 2030.5 server the DUT's CSIP client dials, and its admin API |
| `-modsim` `-modsim-api` `-mbapsdev` `-mbapsdev-api` | southbound sims and their simapi sidecars |
| `-iface` `-bpf` | capture interface and filter. **Empty filter is the safe default**: a frame a filter excluded is not recoverable afterwards. A non-empty filter must be one the tool can re-apply to the captured frames afterwards (§3, *The capture is filtered twice*); anything else is refused before the run starts, not after it. |
| `-keylog` | NSS key-log path (keylog build only) |
| `-no-capture` | logic-only run; no wire citation is then possible |
| `-capture-settle` | pause before stopping the capture so it flushes (default 750 ms — see §5) |
| `-guard` | frame-attribution guard at each end of a check's window |
| `-param k=v` | procedure parameters, e.g. `-param modbus.transport=plain`, `-param pics.mn="Acme"`. Scope one to a single case with `-param <case>:<k>=<v>` — see below |
| `-cap TAG` | assert a capability the runner cannot detect (e.g. `root`) |
| `-timeout` | per-check timeout (default 3 m) |
| `-require-coverage` | fail the run if an applicable case has no implementation |
| `-campaign` | select a CLOSED, named certification lane (`csip`, `mbaps`, `modbus-client`) instead of `-suite`/`-doc`/`-uid`. It is the only way to produce a GATING bundle (`campaign.gating` — see `-verify` below); every other invocation is EXPLORATORY and non-gating. |
| `-require-citation` | downgrade a PASS with no re-checkable citation to WARN (default `true`). On a GATING campaign, `-require-citation=false` is **REFUSED outright** (REV0907-E3: an uncited PASS is not a claim a third party can re-check against the capture) — it is honored, and recorded in the bundle's `campaign.weakened`, only on an EXPLORATORY run. |
| `-skip-preflight` | do not verify that `-gridsim` and `-gridsim-admin` are one live process. On a GATING campaign this is **REFUSED outright** (REV0907-E3: a certification bundle may not rest on an unproven pairing) — it is honored, and recorded in `campaign.weakened`, only on an EXPLORATORY run. |
| `-allow-dirty` | let a GATING campaign run against a dirty harness worktree. When it actually waves one through, the bundle is recorded WEAKENED and written **NOT GATING** regardless of `-campaign` — a bundle may never claim both (`-verify` fails one that does). |
| `-operator` `-note` `-dut-*` | recorded in the bundle |

### `-writes`: what the gateway actually wrote

PC-001's supersession claims are of the form *"a supersession over
byte-identical curves writes ONLY the admitted axes"*. Nothing could produce the
artefact that settles one: `mbapref` is library-only and builds a deduplicated
fuzz **corpus** rather than a timeline, and the reconciler's logs are the
gateway's account of its own writes rather than the wire.

`-writes` reads the write set off the capture the bundle already carries.

```
# writeset capture=runs/…/capture/run-20260817.pcapng
# chain (derived from this capture's own header reads): M705@40072+30 M712@40106+20
# mrid=DERC-SP-CURVE-… mentions=2 window=[…12:00:01Z .. …12:00:04Z] settle=10s bound=…12:00:14Z frames=5..8
# attribution rule: a write is attributed to this mRID when its frame time is at or after the FIRST
#   frame mentioning the mRID and at or before the LAST such frame plus the settle margin.
# excluded=1 (writes in this capture outside the window)
# axes=2 writes=2
axis M705 writes=1
  write axis=M705 ts=2026-08-17T12:00:02.000000Z frame=6 addr=40072 count=3 fc=0x10 unit=1 off=0 values=1,2,3 flow=… tls=false
```

Two things are **derived from the capture**, not configured, because a tool that
had to be told them could be told them wrongly:

- **the model chain** — the gateway's own two-register header reads are in the
  capture, and the sequence of them *is* the device's chain. Candidate headers
  are rejected unless the id and length are plausible (id 0 is the high word of
  any `uint32` under 65536 — the shape of every reversion-timer poll), and any
  two blocks that **overlap** are *both* dropped, because an overlap proves one
  is a phantom and there is no honest way to choose. A write outside every
  surviving block reports `model=unknown` and its address stands alone, which is
  still a checkable claim — a confidently wrong axis is not.
- **the mRID's window** — the **union of per-mention intervals**: a write is
  attributed when it falls within the settle margin of *some* mention. Not
  "first to last": on a polled protocol a control is re-served every poll cycle
  until it expires, so first-to-last is how long it was **offered**, not how
  long it was acting. Every mention is printed with its own covering interval,
  and any inter-mention **gap** longer than the settle margin is flagged.

`-writes-settle` (default 10 s) exists because registers are written *after* the
control is fetched: a window ending at a mention would exclude the very writes
the claim is about.

#### When the tool cannot tell two controls apart — and says so

A supersession pair is normally served in **one `DERControlList` document**, so
both mRIDs appear in the same frame, get identical mention sets, and each is
credited with the other's writes. No time rule can decompose that, so the report
**incriminates itself**:

```
# confounded=YES
#
# !! CONFOUNDED ATTRIBUTION — THE WRITES BELOW MAY NOT ALL BE THIS CONTROL'S.
# !!   DERC-…-999 is in the SAME FRAME(S) as this control: [5]. One document, two controls:
# !!   they have identical mention sets, so NO time rule can tell their writes apart.
# !!   Re-run with -writes-until naming the superseding mRID to cut at the supersession boundary.
```

A clean extraction prints `# confounded=no` and carries no `!!` lines, so the
two are distinguishable at a glance rather than by comparing mention lists.

`-writes-until <mRID>` is the cut that **can** separate them: the window ends at
the first mention of the superseding control. The capture cannot know which
control supersedes which; the caller making the claim does.

```sh
bin/certify -writes runs/<dir>/ -writes-mrid <superseded> -writes-until <supersessor>
```

Every line carries **timestamp, frame number and register address** — a claim
without addresses is not a claim in this campaign — and the format is stable
across runs so a bundle manifest can cite a line by content. stdout is the
report only; the summary count goes to stderr, so a manifest quoting the tool is
quoting evidence.

An mRID that does not appear in the capture is an **error**, not an empty
report: "this control wrote nothing" is the strongest claim available and must
never be made on the strength of having looked in the wrong file.

**TLS.** Southbound legs (`:802`, `:8021`) are decrypted with the bundle's own
key log and decoded as Modbus. Northbound legs (`:443`, `:8443`, `:11113`) are
decrypted too — **the mRID lives there**, so attribution depends on it — but are
never decoded as Modbus. A northbound port that turns out to carry plaintext is
still searched; a southbound leg that cannot be decrypted has its writes
excluded and says so per stream, rather than reporting an empty write set.

### Local extensions — coverage without a conformance claim

Some behaviour matters and no published procedure covers it. Those rows live in
the **`LOCAL-EXT-v1`** family (uids `local-ext-v1::EXT-nnn`), and the family is a
posture, not a loophole:

- they **run** in the ordinary campaign, and their evidence lands in the bundle;
- `certify -verify` re-derives their citations from the capture exactly as it
  does for a conformance row — a row nobody certifies is still a row whose
  citations must hold up;
- their verdicts are **excluded from every applicable-FAIL tally and from the
  clean-run criterion**, so an extension FAIL can never turn a campaign red or
  change the process exit code;
- the failure stays fully visible: `Counts()` still reports it, the console and
  `REPORT.md` print it in the *informative* half, and the bundle row is tagged
  `local-ext`;
- they earn **no `Test <ID>` row** in any submitted Summary Test Results
  (`report.NoCertificationBasis`), because there is no certification for them to
  be a result of.

The exclusion is carried by the catalog record's `certifiable: false`, read
through `Case.BearsOnClaim()` — not by any code that inspects a uid prefix. A row
cannot opt *itself* out of a claim it was registered under, and a reader meets
the posture in the case's own record.

`certify -list` names the non-certifiable families under the document table.

This is the same posture the campaign already carried for the v0.8 TEST-status
Secure SunSpec Modbus specification, taken one step further: that document at
least *is* a specification.

### Per-case parameters

`-param <case>:<key>=<value>` applies a parameter to **one case only**; the
unscoped form is the default for every other case. `<case>` is the globally
unique uid or the bare in-document id — the same two spellings `-uid` accepts.

```sh
# The three cases that need a long wait get one; the other 76 do not pay for it.
certify -suite csip -param csip.wait=30s \
        -param BASIC-029:csip.wait=8m \
        -param CORE-022:csip.wait=8m \
        -param CORE-023:csip.wait=8m
```

This exists because a global `csip.wait` is one case's budget charged to every
case: the RC0 §9.5 battery recorded that setting it globally "turned a 2 h
campaign into 25 h", and the alternative — separate single-`-uid` invocations —
produces separate bundles and separate captures for a row whose criterion is
stated over one suite run. That battery therefore ran `BASIC-029`, `CORE-022`
and `CORE-023` without the parameter and noted that "neither verdict is the
certifiable one".

Two rules worth knowing:

- a scope **wins even when its value is empty**, which is how a parameter is
  turned off for one case (checks that require a parameter treat empty as
  absent);
- a scope naming a case the catalog does not have is **refused before the run
  starts**, like a bad `-doc`, `-uid` or `-suite`. A typo would otherwise leave
  the case on the global value while the bundle recorded a verdict the operator
  believed was measured under another.

### Exit status

| Code | Meaning |
|---|---|
| `0` | clean: every applicable selected case addressed, no FAIL, the bundle verifies |
| `1` | a negative **result**: a conformance failure, an unaddressed applicable case, a capture-integrity finding, a bundle that does not verify |
| `2` | the tool could not run: bad flags, no catalog, no capture interface |

The split matters. Exit 1 is a fact about the DUT or the evidence; exit 2 is a
fact about the invocation. A pipeline that cannot tell them apart will
eventually report a broken bench as a passing device.

---

## 3. What the evidence bundle contains

```
runs/2026-07-26/
├── bundle.json          every test case, verdict, and assertion, with citations
├── REPORT.md            the human-readable report, frames cited inline
├── COVERAGE.md          coverage of the catalog for THIS selection, gaps by name
├── MANIFEST.sha256      sha256 of every file — plain `sha256sum -c` format
├── MANIFEST.sha256.sig  detached ed25519 signature over MANIFEST.sha256 (only when
│                        the run was given -sign-key — see §4, "Signing")
├── catalog.json         the specification the run was measured against
└── capture/
    ├── run-<ts>.pcapng  the packet capture
    └── run-<ts>.keylog  NSS key log (keylog build only), FILTERED to this
                          bundle's own capture — see "The key log is filtered
                          to this bundle" below
```

`bundle.json`'s `run.keylog` field (`{lines_kept, lines_dropped}`, present only
when a key log was set) records the filtering result described below without a
reader having to re-derive it — see "The key log is filtered to this bundle".

An **assertion** is one checkable claim. It carries the claim in prose, the
method, the verdict, what was observed — and a citation:

* **frame citation** — the capture frame numbers, plus a sha256 over those
  frames' bytes; or
* **byte-range citation** — a reassembled TCP stream, a half-open byte range,
  and a sha256 over exactly those bytes.

An assertion with no citation is counted separately everywhere and is never
described as verified.

### The capture is filtered twice

`-bpf` is passed to the capture tool, and then applied **again**, in this
process, to the frames the tool actually wrote. The second pass is not
redundancy for its own sake: a multi-interface `dumpcap` can leave its kernel
filter unarmed on the first-listed interface for an entire capture while arming
it correctly on the rest (§5, *The filter that was never armed*). Every readiness
signal is genuinely true while it happens, so nothing can wait it out.

What the second pass does, at capture stop, before anything has read the file:

* every frame that **provably** does not match the requested filter is dropped,
  and the capture file is rewritten without it. The rewrite copies blocks — the
  section header, every interface description, name-resolution and
  decryption-secrets blocks, and each surviving frame — byte for byte, so a
  filtered capture is a strict subsequence of the tool's own output, not a
  re-encoding of it. When nothing is dropped the file is not touched at all;
* a frame it **cannot decide** — a header the dissector rejects, the first
  fragment of a fragmented datagram, a transport it does not dissect — is
  **kept** and counted separately. The pass can add redaction; it can never
  destroy evidence;
* the per-interface accounting is recorded in `bundle.json` under
  `capture.interfaces[]` — `{id, name, captured, kept, dropped, undecided,
  filter_unarmed_suspected}` — and printed in `REPORT.md`, with a banner naming
  the interface when `dropped > 0`. A bundle written before this accounting
  existed carries no `interfaces` key; absent means *this bundle does not say*,
  and is never rendered as "0 dropped".

Because it runs at capture stop, every frame number in the bundle already counts
over the filtered file: citations, per-case pcap slices and `capture.packets` are
all derived from it afterwards, and `-verify` re-reads the same file.

**The filter must therefore be re-appliable, and an expression this tool cannot
re-apply is refused** — at `capture.New`, before a single frame is captured,
rather than at stop after a run's worth of traffic. Refusing is the point: a
filter form nobody has thought about must not be able to silently switch the
hygiene pass off. The accepted grammar is `and`/`or`/`not`, parentheses, the
protocols `ip ip6 tcp udp icmp icmp6 arp`, and `[src|dst] host <ip>`,
`net <ip>/<bits>`, `net <ip> mask <ip>`, `port <n>`, `portrange <a>-<b>`, with a
leading protocol qualifier where libpcap allows one (`tcp port 802`). Numeric
ports and literal addresses only — service names and hostnames resolve through
the machine's `/etc/services` and DNS, which is not a re-appliable filter.
Everything every run driver in `runs/` has ever passed is inside it; byte-offset
expressions (`tcp[13] & 2 != 0`), link-layer primitives (`ether`, `vlan`) and
length tests (`greater`) are not, and say so.

### The key log is filtered to this bundle

The bench sims run with one shared, append-mode key log
(`-keylog /tmp/bench-shared.keylog`), written across every run and every leg —
the other campaign that ran an hour ago, the other leg of a split bench, a
developer poking a sim by hand. Copying that file verbatim into a bundle would
ship TLS secrets for sessions that have nothing to do with the evidence a
reviewer is looking at: a bundle that let a lab decrypt traffic outside its own
claims (REV0907-E5).

So `capture/*.keylog` inside a bundle is **not** a copy of the source key log.
At write time it keeps only the lines whose client random names a TLS session
`capture/*.pcapng` actually contains — the client random is unencrypted on the
wire in both TLS 1.2 and 1.3, so the capture alone tells the filter which
sessions belong — and drops the rest; a malformed source line is dropped too,
counted rather than aborting the write. `bundle.json`'s `run.keylog` records
how many lines survived and how many did not (`{lines_kept, lines_dropped}`),
so a reader sees the filtering result without re-deriving it, and `-verify`
independently re-derives the client-random set from the shipped capture and
refuses a bundle whose key log carries even one **orphan** — a secret for a
session the capture does not contain — naming the orphan's client random. A
properly filtered bundle has none; a non-empty result means the filter was
bypassed, failed, or the bundle was hand-edited after the fact.

### The three ways this tool could lie, and what stops each

1. **A PASS it never asserted.** After the citation phase every PASS is
   inspected. If nothing behind it carries a digest the verifier can re-derive,
   the verdict is downgraded to **WARN** and the reason is printed and recorded
   — unless the check declared the criterion off-wire *with a reason*, which is
   printed in the bundle so a reader knows the row rests on something other than
   the pcap.
2. **A quietly dropped test case.** The catalog is the specification. The runner
   emits a record for every selected case, implemented or not, and the summary
   refuses to print "ALL TEST CASES ADDRESSED" while an applicable case has no
   implementation.
3. **The wrong frames.** This bench carries continuous background traffic —
   10-second southbound Modbus polls, a CSIP client walking the server — on the
   same wire as the test. Attribution is therefore on **two** signals: a frame
   belongs to a check only if it falls inside that check's time window *and*
   matches a connection the check explicitly claimed. A frame claimed by two
   checks is attributed to neither and reported as contested.

---

## 4. How a third party verifies a bundle without trusting us

```bash
certify -verify runs/2026-07-26/
```

That reads **only** the directory. No bench, no device, no network, no catalog,
no state from the run that produced it. It re-derives, from the capture file
sitting in that directory, that

* every file is byte-for-byte what `MANIFEST.sha256` says (so the capture has
  not been edited since the report was written),
* every frame an assertion cites exists in that capture,
* the bytes at every cited stream offset hash to the value recorded in the
  assertion, and
* the key log — when the bundle carries one — names no session outside the
  capture it ships beside (the previous section).

With `-pubkey <public key PEM>` it additionally checks `MANIFEST.sha256`'s
ed25519 signature against that key ("Signing", below) — the one check that
survives a rewrite of the whole bundle, not just of one file in it.

Someone who does not want to run our binary at all can do most of it with
standard tools:

```bash
cd runs/2026-07-26 && sha256sum -c MANIFEST.sha256   # the manifest is plain sha256sum format
wireshark capture/run-*.pcapng                        # go to the cited frame numbers
# For encrypted payloads: Preferences → Protocols → TLS → (Pre)-Master-Secret log
# and point it at capture/run-*.keylog. The plaintext Wireshark then shows is
# what the assertions quote.
# To check the signature (needs openssl 3.x, which speaks ed25519 natively):
openssl pkeyutl -verify -pubin -inkey sign-ed25519.pub -rawin \
  -in MANIFEST.sha256 -sigfile <(python3 -c "import json,base64,sys; \
  sys.stdout.buffer.write(base64.b64decode(json.load(open('MANIFEST.sha256.sig'))['sig']))")
```

Or rebuild the verifier from source with nothing but a Go toolchain — the
evidence engine is pure Go, no cgo, no third-party dependencies:

```bash
CGO_ENABLED=0 go build ./internal/evidence/...
```

### What verification deliberately does NOT claim, without a public key

**A hash-only `-verify` establishes internal consistency, not who produced the
bundle.** It detects corruption and piecemeal tampering — change a byte in the
capture and the hashes stop agreeing with the report — but somebody who
rewrites the *whole* bundle can rewrite the manifest to agree with the
rewrite, and every check above still passes: internal consistency is all a
hash ever claimed to establish. A `-verify` run with no `-pubkey` reports this
plainly, as `Unsigned: true`, printed right under the header — a reader must
never mistake a hash-only pass for a signed one, and this field (JSON and
text output both) is the only thing that tells them apart.

### Signing

```bash
# Once, outside any repository:
certify -gen-sign-key ~/keys/lexa-cert
#   private key (mode 0600, PKCS#8 PEM): ~/keys/lexa-cert/sign-ed25519.key
#   public key  (hand this to a lab):    ~/keys/lexa-cert/sign-ed25519.pub

# Every GATING campaign (REQUIRED — see below):
certify -campaign csip -manifest configs/candidate.json -sign-key ~/keys/lexa-cert/sign-ed25519.key ...

# A lab, or anyone else, checking a bundle against the public key they were given:
certify -verify runs/2026-07-26/ -pubkey sign-ed25519.pub
```

`-sign-key` signs `MANIFEST.sha256` with a detached ed25519 signature,
`MANIFEST.sha256.sig` — a small JSON object (`{"alg":"ed25519","key_id":"…",
"sig":"…"}`; `key_id` is the first 8 bytes of `sha256(public key)`, hex, so a
report can name which key without printing it; `sig` is the raw 64-byte
signature, base64) written over `MANIFEST.sha256`'s exact bytes, nothing else.
It closes exactly the gap the paragraph above names: rewriting the capture and
rehashing the manifest to agree no longer produces a manifest the *original*
signature covers, because the attacker does not have the private key — which
lives on the operator's own machine and this tool never writes anywhere but
there.

**A GATING campaign refuses to run with no `-sign-key`.** An unsigned
`MANIFEST.sha256` is not a weaker version of a certification bundle, it is
missing the one thing that makes a rewrite detectable after the fact, so
`-campaign` treats a missing signing key the same way it treats
`-skip-preflight` or `-require-citation=false` on a gating run: refused
outright, before a single frame is captured. (Unlike those switches, an
unsigned gating run has no legitimate *disclosed* shape — it is refused, full
stop, so `"unsigned"` never appears in a written bundle's
`campaign.weakened`.) It is honored, unsigned, only on an EXPLORATORY run (no
`-campaign`).

A signature says WHO held the key that signed this manifest, not who ran the
test or whether the DUT behaved as recorded — it is not a certificate chain,
and a lab still has to receive the operator's public key through a channel it
trusts (out of band; this tool has no opinion on how). What it adds over the
hash-only baseline is narrow and load-bearing: non-repudiation of the manifest
bytes.

A bundle recording a **FAIL** still verifies, signed or not, and must.
Verification is about whether the cited bytes are in the capture and, when
checked, who signed the manifest that says so — not about whether the device
behaved. Conflating those would make a failing run uncitable, precisely when
the evidence matters most.

---

## 5. Proving the tool without the bench

```bash
make test-certify
```

Five steps, each load-bearing:

1. `go vet` over the CLI and the framework.
2. `go test -race` over the framework, all six suites, and the CLI. Every
   check's decision logic is proven against synthetic inputs, and each suite
   also stands up a **deliberately non-conformant** in-process peer and proves
   the check FAILs it. A check that always returns PASS passes against a good
   device too.
3. A `CGO_ENABLED=0` build and test run, so the no-TLS-stack configuration stays
   usable rather than merely hoped for.
4. A **keylog-configuration** build and vet, which is the only way to catch a
   break in the key-export path.
5. The loopback acceptance run (`internal/certify/suites`): a **real dumpcap
   capture on `lo`** against a **real SunSpec Modbus device** (`sim/southbound`),
   driven by the **real runner and the real registry with all six suites
   linked**, producing a **real bundle**, which is then handed to
   `bundle.Verify`. It runs the same two checks twice — once against a
   conformant device (must PASS, with citations) and once against a device whose
   Common Model manufacturer string reads its not-implemented value (must FAIL,
   with citations) — and separately proves that flipping one byte of the capture
   breaks verification.

That last step is what proves the *assembly*, which no per-suite test can reach:
all six suites link into one binary without a duplicate catalog uid, the catalog
the binary finds is the one the suites were written against, a real capture on a
real interface attributes to the right check, and what comes out the far end
verifies.

### Findings this work produced, recorded because every one of them was silent

**The capture settle.** The runner used to stop the capture the instant the last
check returned. `dumpcap` reads from a kernel ring and writes in batches, so the
frames still in that ring were never written. Measured on loopback: a run whose
whole exchange took 200 ms produced a **400-byte pcapng — the file header and
nothing else, ten frames lost**. Nothing about it was loud; the bundle was
written, the citations silently found no frames, and every PASS was downgraded
to WARN for "want of a citation", which reads like sloppy checks rather than
discarded evidence. There is now a settle interval (`-capture-settle`, default
750 ms), and a capture that records zero frames while checks executed is
recorded as a capture-integrity finding that makes the run unclean.

**The filter that was never armed.** `dumpcap -i A -i B -f '<bpf>'` can leave its
kernel filter off the FIRST-listed interface for the whole capture — reproduced
here with plain `dumpcap -i lo -i lo -f 'tcp port N'` (2446 unfiltered frames on
tap 1, none on tap 2), and 4 times out of 4 with two real NICs. Both signals the
runner waits on are genuinely true when it happens, the tool announces itself
normally, writes a valid file and reports zero drops, and the pcapng header is
there — so there is no signal to wait for and nothing in the capture's own
output to notice. The damage is not lost evidence but lost **redaction**: a
bundle handed to a laboratory containing thousands of frames of somebody's mDNS,
DNS-SD and HTTP, from a run that asked for `tcp port 802`. The filter is now
re-applied in-process at capture stop and the non-matching frames are dropped
from the artefact, with the per-interface counts recorded in `bundle.json` and
`REPORT.md` so the race is a disclosed fact rather than an invisible one (§3,
*The capture is filtered twice*).

**The bundle that ate its own capture.** The natural invocation is
`-out runs/<ts>/`, and the runner writes its capture to
`<out>/capture/run-<ts>.pcapng` — exactly where the bundle then copies it.
`os.Create` truncates first, source and destination were the same file, and the
run's entire capture became zero bytes. `bundle.copyFile` now detects the
same-file case (`os.SameFile`) and leaves the file alone; a regression test
fails without the fix.

**The DUT host that was never derived.** `Targets.GatewayHost` — the DUT's
address without a port — is what `suitessm` compares a frame's source against to
tell its direction. Nothing on the command line set it, so a run against any
address but the compiled-in bench default (`-target 127.0.0.1:9502`) left it at
`69.0.0.2` and every direction test silently compared against a device that was
not under test. `Targets.Normalise` now derives it from `-target`/`-gateway` in
the runner's constructor.

**`-suite` that selected nothing and everything.** `-suite` was applied at
dispatch rather than at selection, so `-suite ssm` selected all 282 cases,
executed 34, and skipped 248 with "suite csip not selected" — and the
`COVERAGE.md` sealed into that bundle described the whole catalog instead of the
campaign that ran. It is now part of the catalog filter, exactly as `-doc` is,
and a `-suite` name nobody registered is refused by name rather than quietly
selecting zero cases.

**A sim bug the referee caught.** `sim/southbound.Populate` (the static
inverter behind `NewServer`) writes the Model 1 serial with
`setStr8(m1Base+32)`, and offset 32 is `Opt`, not `SN` — the canonical layout is
Mn(0,16) / Md(16,16) / Opt(32,8) / Vr(40,8) / SN(48,16). That device serves an
empty serial, a mandatory Common Model point reading its not-implemented value,
and DEV-2 fails it. `populateSolarCore` was fixed for exactly this bug (its
comment records the bench finding: two sims collapsing into one `nb_unit`
because both serials were empty); `Populate` was not. **This is reported, not
patched** — it is outside this work's package — and the loopback acceptance test
uses the corrected solar sim, with the reason written down where the choice is
made.

---

## 6. Producing a SunSpec submission

```bash
bin/certify -report runs/2026-07-26/ -config lab.json
```

This is a separate mode on purpose: the evidence is fixed at capture time, the
covering document is not, so the paperwork can be revised and the report
regenerated **without re-running the device**. It writes

```
runs/2026-07-26-submission/          a SIBLING of the bundle, never inside it
├── public/SUMMARY.csv               the §3.1 Summary Test Results
├── archive/DETAILED-TEST-LOGS.json  the §4 Detailed Test Logs
├── SUBMISSION-READINESS.md          per-requirement self-assessment
└── MANIFEST.sha256
```

The submission is written **beside** the bundle, not inside it, and a
`-report-out` pointing inside is refused. A bundle verifies partly by checking
that every file in the directory is listed in its manifest — that is what stops
somebody slipping an extra artefact in beside the evidence — so a submission
written into the bundle would make the evidence itself stop verifying, and the
failure would surface later, on a `-verify`, looking exactly like tampering.

Three refusals are built in:

* **No invented metadata.** Roughly thirty keys are facts only a SunSpec
  Authorized Test Laboratory or the submitter can supply — the certificate
  number, the legal company name, which of the thirteen authorized labs
  supervised the run. A key nobody supplied is not emitted; it is named as
  missing, and the CSV is written as `SUMMARY-INCOMPLETE.csv` (a filename nobody
  forwards to a lab by accident) and only with `-allow-incomplete`.
* **No manufactured verdicts.** §3.1.1 enumerates exactly PASS, FAIL and NOT
  SUPPORTED. A bench SKIP is none of them — it means "addressed but not asserted
  here" — so SKIP and WARN rows are **omitted from the CSV and named in the
  console output**. Mapping them to PASS would forge a result; mapping them to
  NOT SUPPORTED would misreport the product's capabilities.
* **No log that disagrees with the capture.** The §4 detailed logs are *derived
  from the bundle's own pcap*, not from what a client library believed it sent:
  each entry is a rendering of captured bytes, so the log and the capture cannot
  drift. Only cleartext conversations can be rendered; conversations carrying
  TLS records are counted and reported as not rendered, so a short log is
  explained rather than mistaken for an idle bench.

The mode also **refuses to build a submission from a bundle that does not
verify**.

### The whole package: `-trr`

`-report` covers one bundle and one certificate type. A real campaign covers six
documents governed by TWO Results Reporting specifications, and often takes more
than one bench run. `-trr` is that shape:

```bash
bin/certify -trr runs/csip-2026-07-28=csip-conf-v1.3 \
            -trr runs/full-2026-07-28 \
            -trr-out runs/trr-2026-07-28 -config lab.json -allow-incomplete
```

It routes every case by its document, maps each bench verdict by a rule stated
in the emitted report, derives BOTH §4 logs from the bundles' captures — the
mbaps and CSIP sessions included, by decrypting them with the run's own key log —
and writes one package with a README naming everything it does not carry. The
`=<doc-key>` suffix narrows a source, which is how two campaigns covering the
same document are kept from silently overwriting one another; without it, a
disagreement about one procedure's verdict stops the run.

Beyond `-report`'s three refusals it adds two:

* **`NOT SUPPORTED` needs a catalog behind it.** Only a case the bundle's own
  archived `catalog.json` marks inapplicable earns that verdict, and the row
  carries the catalog's reason. Every other SKIP and every WARN is omitted with
  the gap recorded — in the README, in the readiness report, and counted in
  Additional Test Comments.
* **One image behind the whole campaign.** Two bundles whose DUT build stamps
  disagree are refused: §2.1 requires the software unaltered across the
  campaign, so no single `Software Checksum` covers two builds.

The full key reference, the verdict-mapping derivation and the self-check
invocation are in [TRR_SUBMISSION_CONFIG.md](TRR_SUBMISSION_CONFIG.md).

`lab.json` uses the flat key space of `internal/certify/report`'s
`SubmissionConfig` (unknown keys are an error — a misspelled key would otherwise
silently omit the value it meant to supply):

```json
{
  "certificate_type": "SunSpec Modbus",
  "company_name": "…", "company_address": "…", "company_city": "…",
  "company_state": "…", "company_country": "…", "company_postal_code": "…",
  "test_laboratory": "<one of the thirteen authorized labs>",
  "supervising_test_engineer": "…",
  "software_operating_environment": "Hardware Device",
  "product_manufacturer": ["…"], "product_model": ["…"],
  "hardware_manufacturer": ["…"], "hardware_model": ["…"],
  "test_completion_date": "MM/DD/YYYY",
  "pics_url": "https://…"
}
```

---

## 7. Layout

```
cmd/certify/                  the CLI: modes, flags, exit codes, keylog shims
internal/certify/             the framework — catalog, registry, runner, frame
                              attribution, evidence citation, coverage report
internal/certify/suites/      links all six suites; the loopback acceptance test
internal/certify/report/      SS-CSIP-RESULTS-v1.1 + SS-MODBUS-RESULTS-v1.2 and
                              the submission generator
internal/certify/suitecsip/          CSIP-CONF-v1.3
internal/certify/suitemodbusclient/  SS-MODBUS-CLIENT-CONF-v1.1
internal/certify/suitemodbusserver/  SS-MODBUS-CONF-v1.4 + SS-1547-TEST-v1.0
internal/certify/suitepki/           SS-TEST-PKI
internal/certify/suitessm/           SSM-CONF-v0.8
internal/evidence/            the evidence engine: capture, pcapng, dissection,
                              TLS dissection/decryption, bundles (pure Go)
testdata/catalog/catalog.json the specification: 286 extracted test cases
```

A new suite is added by registering its checks against catalog uids from an
`init`, and adding one blank import to `internal/certify/suites`. The registry
panics at process start on a duplicate uid, and the runner refuses to run at all
if any registration names a uid the catalog does not contain — both are
coordination bugs whose only honest outcome is a loud failure before any
evidence exists.

---

## 8. Bench discipline

A live campaign holds the whole bench: it drives the gateway, perturbs the sims,
and captures the wire. **Serialize it.** Two concurrent runs interfere and
produce evidence that describes neither. Development happens against loopback
and in-process sims (`-no-capture`, or a private port with `-iface lo`), which
is what `make test-certify` does and what every suite's own tests do.
