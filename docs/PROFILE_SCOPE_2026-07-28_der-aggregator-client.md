# Profile scope: DER Aggregator Client (owner decision, 2026-07-28)

The CSIP conformance catalog's applicability column now tracks §4's **DER
Aggregator Client** profile. It used to track the **DER Client** profile.

This document is the citation trail. Every `applicability_reason` in
`testdata/catalog/catalog.json` for a `CSIP-CONF-v1.3` row points here, and the
point of pointing here is that a reviewer can disagree with the decision without
having to reverse-engineer it from a JSON diff.

---

## 1. The decision

**The DUT is certified as a DER Aggregator Client.** The gateway fans controls
out to multiple inverters and matches the CTP's aggregator-client EUT
definition, so the aggregator column is the honest one to be measured against.

The decision is the owner's. It is recorded here as a decision, not derived: no
amount of reading the standard tells you which profile a vendor chooses to
certify. What the standard tells you is what follows from the choice, and §4 is
where that is written down.

## 2. What §4 says

CSIP Conformance Test Procedures V1.3, §4 *Profile Test Conformance* (pp. 19-20)
is a three-column table: Server, DER Client, DER Aggregator Client. "Tests marked
with an X in the following table are required for a conforming implementation for
each profile."

Twenty-two rows carry an X in the **DER Aggregator Client** column and no X in
the **DER Client** column. Those twenty-two are the whole of this change:

| Group | Rows |
|---|---|
| Aggregator operations | AGG-001, AGG-002, AGG-003, AGG-004, AGG-005, AGG-006, AGG-007, AGG-008, AGG-009, AGG-010, AGG-011, AGG-012 |
| Subscription / notification | CORE-018, CORE-019 |
| Error handling | ERR-002 |
| Model maintenance | MAINT-001, MAINT-003, MAINT-004, MAINT-005 |
| Utility-server aggregator model | UTIL-002, UTIL-003, UTIL-004 |

Six rows stay **not applicable**, and not one of them stays out because of the
profile scope alone:

| Row | Why it stays out |
|---|---|
| CORE-001 | Blank in all three §4 columns. Tests the utility **server's** HTTP method handling. |
| CORE-002 | Blank in all three columns. Tests the **server's** non-TLS→TLS 301 redirect of `/dcap`. The client half of that behaviour is ERR-001, which is required and implemented. |
| CORE-004 | Blank in all three columns. Tests the **server's** list pagination and query-string handling. |
| UTIL-001 | Blank in all three columns; `[S]` in its printed title. Its steps are performed by the `[TC]` test client against the server. Kept in the catalog because UTIL-002, UTIL-003 and AGG-001 all say "perform the test setup from UTIL-001". |
| MAINT-002 | Blank in all three columns. Annex A Errata I seq 32: *"Test not required as it is unlikely for utilities to utilize the tested behavior. Make the test optional/remove entirely from the spec."* It is the one MAINT row the re-scope did **not** pull in. |
| COMM-001 | Blank in all three columns; its own Purpose says *"This test is optional for all device types."* The DUT has no xmDNS/DNS-SD client and is provisioned out of band, which COMM-002 certifies. |

Three rows are **applicable but required of nobody**. They are optional
evidence this bench can produce, and conformance is not gated on them:

| Row | Status |
|---|---|
| BASIC-013 | Blank in all three §4 columns. `opModFixedW` (hundredths of a percent) is implemented and the check produces a real verdict. |
| BASIC-014 | Blank in all three columns. `opModTargetW` (absolute watts) likewise. |
| CORE-023 | **Absent from the §4 table entirely.** Annex A seq 33 adds it, and the entry reads in full "Adding a new test (Optional)". `profile_conformance` is `null` for this row rather than all-false, because the printed matrix has no row for it to record. |

"Applicable" and "required" are different questions and the catalog keeps them
apart. `applicable` records whether the case can be exercised against this
product; `profile_conformance` records what §4 demands. A row can be applicable
and optional (the three above), or inapplicable and optional (MAINT-002,
COMM-001), and a reader who conflates them will mis-read the coverage table.

### Verification

The catalog's `profile_conformance` objects were re-read against the §4 table in
`SunSpecCSIPConformanceTestProceduresV1.3-1.txt` (pp. 19-20) at the time of the
change, and the two agreed exactly — no row of the table was missing from the
catalog and no row of the catalog was absent from the table. `certify`'s own
guard on this lives in `TestProfileScopeIsTheAggregatorColumn`
(`internal/certify/suitecsip/register_test.go`), which fails if applicability
ever drifts from the aggregator column again.

## 3. What each new row can demonstrate on today's bench

Every one of the twenty-two rows was written against a fixture this bench does
not build:

* **The Figure-15 topology** — an aggregator EndDevice plus EDA1/EDA2 under
  SPA1/SPA2 and EDB1/EDB2 under SPB1/SPB2. `sim/gridsim` serves a fixed tree
  with **one** EndDevice for the DUT.
* **Subscription and notification** — the server POSTs a Notification to the
  client's `notificationURI` and the client answers it. `sim/gridsim` implements
  no Subscription resource and originates no Notification.

The checks respond to that by driving everything the bench *can* drive, and
reporting **SKIP with the specific missing capability named** for everything it
cannot. They never report PASS for a criterion that was not exercised, and they
never report FAIL for a fixture the bench did not build — the second mistake is
the more dangerous one, because a false FAIL looks like diligence.

| Row | What runs for real today | What SKIPs, pending bench work |
|---|---|---|
| AGG-001 | Subscription advertisement and Subscription POST, if the server offers the function set | Notification push and answer; EDA1X fan-out |
| AGG-002 | DefaultDERControl acquisition | Activation — **the document itself** says there is no 2030.5 acknowledgment and it "must be done out-of-band" |
| AGG-003 | TFA event published (+2 min, 1 min) and Response lifecycle 1/2/3 asserted | Per-device fan-out; the EDB1/EDB2 negative assertion |
| AGG-004 | Same, with the default→event→default sequence | Default-in-force halves (out-of-band); fan-out |
| AGG-005 | Both non-overlapping TFA events published and asserted | Fan-out (12 Response POSTs across 2 devices) |
| AGG-006 | Both events published on SY and TFA, per Annex A seq 26's corrected setup | Fan-out |
| AGG-007 | Overlapping pair published on SY/TFA; **supersession status 14** asserted (Annex A seq 5) | Fan-out |
| AGG-008 | Mirror pair; **status 14** asserted (Annex A seq 6) | Fan-out |
| AGG-009 | SY published, then TFA published *after* SY starts; **status 7** asserted | Fan-out |
| AGG-010/011/012 | Two **independent**-mode controls published; the absence of any status 7 or 14 asserted | Fan-out; concurrent setpoint application |
| CORE-018 | Subscription advertisement; Subscription POST | Notification push, the 201-only answer (Annex A seq 44), GET-and-compare |
| CORE-019 | Subscription advertisement; two Subscription POSTs | Notification push; the one-notification rule (seq 42); cancellation |
| ERR-002 | Subscription advertisement; Subscription POST | Power-reset persistence; 201/204 answer; HTTP 400 on an invalid Notification |
| MAINT-001 | EndDeviceList walk | EndDevice deletion and the 404; notification |
| MAINT-003 | FSA acquisition | Topology re-parenting; notification |
| MAINT-004 | **The added DERControl is published for real** (+15 min, 5 min, no randomization) and its acquisition asserted | Change notification; per-device fan-out |
| MAINT-005 | DERProgramList acquisition and primacy ordering | The primacy swap (no gridsim lever); DER.005 setpoint effect |
| UTIL-002 | **The whole commissioning walk**: `/dcap` → EndDeviceList → own-LFDI match → RegistrationLink pIN → PUT DERCapability/DERSettings | The "all other EndDevice instances" fan-out |
| UTIL-003 | FSA and DERProgramList walk | Per-device fan-out; Subscription POSTs |
| UTIL-004 | DERControl published (+2 min, 2 min) and the Response 1/2/3 loop asserted | The SPA1/FDA/SY scope fan-out; notification |

## 4. Errata that change an observable, and where they are enforced

The catalog's `steps` and `expected` are a verbatim extraction of the
**unamended** printed procedure, which is correct — an extraction that silently
applied Annex A would stop being checkable against the document a reviewer
holds. The corrections live beside them in `errata`, and the implementations
honour them. Both halves are pinned by tests.

| Erratum | Effect | Enforced in |
|---|---|---|
| seq 5 / seq 6 | AGG-007 and AGG-008 expect Response status **14**, not the printed 7 | `aggScenarios()`; `TestLiveErrataAreImplemented` |
| (none) | AGG-009 keeps status **7** — its event had already started | same |
| seq 26 | AGG-006's corrected setup: SY at +4 min, TFA at +2 min | same |
| seq 44 | CORE-018 / CORE-019 must **not** accept HTTP 204 for a Notification | `core018Criteria`, `core019Criteria` |
| seq 23 | CORE-014 **does** require 204 on PUT — the counterweight to seq 44 | `critDERPut` |
| seq 42 | CORE-019: one Notification per subordinate change, not two | `core019Criteria` |
| seq 38 | ERR-002: printed step 6 removed; no re-POSTed Subscription may be demanded | `err002Criteria` — asserted by its **absence** |
| seq 32 | MAINT-002 optional / removed | `TestMaint002IsOptional` |
| seq 34 | MAINT-005 subscribes to the DERProgram**List** | `maintPrograms` |
| seq 3 | UTIL-002 PUTs the DER field resources, not the DERListLink | `utilCommissioning`, `critDERPut` |
| seq 12 | UTIL-003 / UTIL-004 subscribe to the DERProgram**List** | `utilGroupRetrieval`, `utilDERRetrieval` |
| seq 1 | AGG-001: the follow-up GET is a `[CT]` test-client step, not a DUT demand | `aggSubscription` |
| seq 33 | CORE-023 added as optional | catalog `applicability_reason` |

## 5. Bench work this decision creates

Two capabilities close most of the SKIPs above. Neither is in `csip-tls-test`
alone — the first needs a southbound fleet as well as a northbound one.

1. **A four-EndDevice `gridsim` tree.** `sim/gridsim` must serve the Figure-15
   topology: an aggregator EndDevice plus EDA1/EDA2/EDB1/EDB2, each with a
   `FunctionSetAssignmentsListLink` and a `DERListLink`, and DERPrograms bound to
   the SPA1/SPA2/SPB1/SPB2 and TFA/TFB/SY nodes with the primacy values of
   Figure 16. The southbound half — four inverters for the gateway to fan out to
   — is `scripts/bench-sims-up.sh`'s four-sim mode; see that script's header for
   the board-side configuration it needs.
2. **A Subscription / Notification function set in `gridsim`**, plus a capture
   claim on the DUT's inbound listener so `RecoverSession` can reconstruct the
   server-dialled conversation a Notification arrives on.

## 6. A note on `facts-dut-capability.md`

Many `applicability_reason` strings written before this change cite
`facts-dut-capability.md` by section. **That document is not committed in this
repository** and is not present in `lexa-gw` either; it was an artefact of the
catalog extraction pass, as was the `CATALOG-CRITIQUE.md` that
`internal/certify/catalog.go`'s header references. Those citations are therefore
currently unresolvable, which is a documentation debt worth recording rather
than papering over: a reviewer following one of them has nowhere to go.

The reasons written by this change cite **this document** and the CTP §4 table
instead, both of which are reachable — this file is in the repository, and the
table is reproduced in §2 above. Rewriting the older citations is a separate job
and was not done here, because it would have meant re-asserting DUT capability
claims from a source nobody can currently read.
