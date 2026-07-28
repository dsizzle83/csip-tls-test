# The submission configuration, and what `certify -trr` does with it

`certify -trr` turns one or more completed evidence bundles into the artefact
SunSpec actually receives: a **Test Results Report package**. Everything in that
package that describes the DEVICE comes from the bundles. Everything that
describes the SUBMITTER comes from the file this document specifies. Nothing
comes from a default — there are none.

    certify -trr runs/csip-20260728T152503=csip-conf-v1.3 \
            -trr runs/full-20260728T041500 \
            -trr-out runs/trr-20260728 \
            -config testdata/submission/example-submission.json \
            -allow-incomplete

A worked example lives at `testdata/submission/example-submission.json`. Every
value in it is a placeholder.

## What comes out

```
<trr-out>/
  TEST-RESULTS-REPORT.md          the package README: which bundles, the verdict
                                  mapping rule with its citations, every omitted
                                  procedure, every conversation that could not be
                                  read
  MANIFEST.sha256                 a digest of everything below
  ieee-2030.5-csip/
    public/SUMMARY.csv            §3.1 Summary Test Results — the half SunSpec
      (or SUMMARY-INCOMPLETE.csv)   posts publicly
    archive/DETAILED-TEST-LOGS.json  §4 Detailed Test Logs — archived, never public
    SUBMISSION-READINESS.md       per-requirement self-assessment
    MANIFEST.sha256
  sunspec-modbus/
    …the same four
```

Which certificate type a campaign document lands under is `report.DocCertType`:

| Catalog document | Certificate type |
|---|---|
| `csip-conf-v1.3` | IEEE 2030.5/CSIP |
| `ss-modbus-conf-v1.4` | SunSpec Modbus |
| `ss-modbus-client-conf-v1.1` | SunSpec Modbus |
| `ss-1547-test-v1.1` | SunSpec Modbus |
| `ssm-conf-v0.8` | SunSpec Modbus |
| `ss-test-pki` | SunSpec Modbus |

`ss-csip-results-v1.1` and `ss-modbus-results-v1.2` are excluded: those rows are
requirements on the report, and putting them in one would be the report grading
itself.

## The file

JSON (`.json`) or the small flat-YAML subset (`.yaml`/`.yml`) described in
`internal/certify/report/config.go`. **Unknown keys are an error** — a
misspelled key would otherwise silently omit a value from a certification
submission. Use `_comment` for a remark about the file itself;
`additional_test_comments` for a remark that should reach the report.

### Keys the submitter supplies — a missing one is a hard error

| Key | §3.1.1 key | Notes |
|---|---|---|
| `company_name` | Company Name | the legal name the certificate is issued to |
| `company_address` | Company Address | |
| `company_city` | Company City | |
| `company_state` / `company_province` | Company State / Company Province | supplying one marks the other `Not Applicable`, which is the specification's own rule |
| `company_country` | Company Country | the example uses `USA`; neither document prints the enumeration it references |
| `company_postal_code` | Company Postal Code | a **String**: `02123` must not become `2123` |
| `software[]` | Software Name/Version/Checksum `<n>` | see below |
| `operating_systems[]` | Operating System/Version `<n>` | documented as `X.X`, exemplified as `18.04`; emitted verbatim and the contradiction flagged |
| `software_operating_environment` | Software Operating Environment | `Hardware Device` or `Cloud` (§3.1.1); both §3.1.2 examples print `Device`, and the normative token is what is emitted |
| `pics_url` | Protocol Implementation Conformance Statement | a properly formed URL. It is what justifies every `NOT SUPPORTED` row |
| `hardware_manufacturer[]`, `hardware_model[]` | Hardware Manufacturer/Model `<n>` | |
| `product_manufacturer[]`, `product_model[]` | Product Manufacturer/Model `<n>` | optional |
| `cloud_provider`, `cloud_provider_version` | Cloud Provider / Version | auto-filled with `Not Applicable` for a hardware-hosted submission |
| `test_completion_date` | Test Completion Date | `MM/DD/YYYY`, zero-padded. Not derived from a clock: which day the campaign is complete is a statement, not a reading |
| `test_description` | Test Description | for SunSpec Modbus it must be one of Appendix A2's three offerings; the CSIP document references an Appendix A it does not contain, so any string is accepted there |
| `additional_test_comments` | Additional Test Comments | free text; the generator APPENDS its own statements, never overwrites |

### Keys only SunSpec or an Authorized Test Laboratory can supply

`certificate_number`, `date_issued`, `certificate_signer_name`,
`test_laboratory`, `supervising_test_engineer`.

These are **required by §3.1.1 and are not an operator error when absent.** A
package missing them needs `-allow-incomplete`, and then:

- the key is **omitted**, not written blank. An empty `Test Laboratory` would be
  a value outside the Appendix A1 enumeration — a document that fails its own
  validation is worse than one that visibly omits a row.
- `Additional Test Comments` carries the **SELF-TEST declaration** naming all
  five and saying why they are absent.
- the summary is written as `SUMMARY-INCOMPLETE.csv`, a name nobody forwards to
  a laboratory by accident.

The thirteen laboratories Appendix A1 enumerates are in `report.AuthorizedLabs`.
An in-house bench is not among them, and the tool will not pretend otherwise.

### Software Checksum: derived, not typed

```json
"software": [
  { "name": "mbapsd", "version": "0.9.0", "element": "mbaps" }
]
```

`element` has no key in either §3.1.1 table and is never emitted. It names one
of the deployed binaries in the evidence bundle's DUT build stamp — the
`mbaps:856bc322 nb:ba8d13dd modbus:dcfc6b4b` string a campaign records — and
`Software Checksum <n>` is filled from that digest. A record with a `checksum`
already set is left alone.

Two bundles whose build stamps disagree about one element are a **hard error**:
§2.1 requires the software to be unaltered across the whole campaign, so no
single `Software Checksum` can cover two images.

The format defines no key for the checksum ALGORITHM. When a value is derived,
`Additional Test Comments` states what those digits are.

### Per-certificate-type overrides

SunSpec issues one certificate per type, so a gateway that is both a SunSpec
Modbus device and an IEEE 2030.5 client has two certificate numbers, two PICS
documents and two Test Descriptions. One flat file would put the Modbus
certificate number on the CSIP report.

```json
"per_certificate_type": {
  "IEEE 2030.5/CSIP": {
    "test_description": "IEEE 2030.5 / CSIP conformance, direct DER client profile",
    "pics_url": "https://…/pics-csip.xlsx",
    "context_id": "lexa-csip-2026-07"
  },
  "SunSpec Modbus": {
    "test_description": "SunSpec Modbus Conformance Certification",
    "pics_url": "https://…/pics-modbus.xlsx"
  }
}
```

Overridable: `certificate_number`, `certificate_type_version`, `date_issued`,
`certificate_signer_name`, `pics_url`, `test_description`,
`test_completion_date`, `additional_test_comments`, `context_id`.
`Certificate Type` is always pinned to the report being written.

## The verdict mapping

Both §3.1.1 tables enumerate exactly three values for a `Test <Test ID>` row:
`PASS`, `FAIL`, `NOT SUPPORTED`. This bench records four.

| Bench verdict | Reported as | Why |
|---|---|---|
| PASS | `PASS` | direct |
| FAIL | `FAIL` | direct |
| SKIP, case marked inapplicable by the archived catalog | `NOT SUPPORTED` | `applicable: false` plus its `applicability_reason` is a statement about what the product implements — the same thing the PICS records |
| SKIP, any other reason | *(no row, recorded gap)* | the reason is a fact about the RUN, not the device |
| WARN | *(no row, recorded gap)* | "asserted, with a caveat" has no member in a three-value enumeration |

Every omission is named — with its bench verdict and reason — in the package
README and in that part's `SUBMISSION-READINESS.md`. **An omitted row is not a
pass.** The full derivation, with the exact spec text, is the file comment of
`internal/certify/report/trr.go`.

Two bundles that disagree about one procedure's verdict stop the run: which
campaign is the submitted one is the operator's decision. Narrow a source with
`-trr <dir>=<doc-key>[,<doc-key>…]`.

## Checking the package

The `results-report` suite is the executable form of both Results Reporting
specifications, and it can be pointed at an already-emitted package instead of
at a report it generates itself:

    certify -no-capture -suite results-report -out runs/trr-selfcheck \
            -param report.trr=runs/trr-20260728 \
            -param report.config=testdata/submission/example-submission.json

With `report.trr` set, the §3.1 document rows parse the bytes on disk — the file
that will actually be sent. Without it they validate a summary the run builds
from the configuration, which only proves the generator agrees with itself.

The §4 rows and the Chapter 5 trace row require the `capture` capability: they
prove their claims by conducting a real exchange and citing the captured bytes,
so they SKIP on a run with no bench. The emitted logs are still validated
against §4.1 — see the `RPT-050`…`RPT-055` and `RPT-LOG-*` rows of each part's
`SUBMISSION-READINESS.md`.
