# SOURCES

Independently fetched copy of the SunSpec Alliance model definitions
(https://github.com/sunspec/models), used ONLY as the source for
`internal/certify/sunspecgolden`'s golden point tables — WP4-T5/T6
(REV0907-E8). This copy is fetched straight from GitHub; it is NOT copied
from, generated from, or cross-checked against lexa-proto's vendored
`sunspec` package (`vendor/lexa-proto/sunspec`) or lexa-gw's copy of the same
models. Referee independence for register semantics (`docs/CODING_PRINCIPLES.md`,
`docs/ADVERSARIAL_QA_STRATEGY.md` §5 rule PN-1/C9/AD-003(f)) requires an
oracle that does not consume the product's own parser or constant tables —
an oracle built from lexa-proto's own `sunspec` package could not find a bug
lexa-proto's `sunspec` package shares with the thing testing it.

## Pinned commit

    repo:   https://github.com/sunspec/models
    commit: 90b4a331dcca1d6eac69c1bead952fddcc5852e0
    fetched: 2026-09-08 via `curl` against
      https://raw.githubusercontent.com/sunspec/models/<commit>/json/model_<id>.json

## Files and checksums (sha256)

    04af1c080d2fe21cb620233c5d20308d3386170deec035694c8c1f13720ad31d  model_1.json
    5b5dd26a9cb8058e32c1f70f5c3a9681d326cbb37068d1f3b9765b5188fe7455  model_103.json
    9fef637dfe8ba3974abf776642360df5d1ecc8ed6ff8b6ffc72fd6d94c7b6c02  model_120.json
    fb85cfcad89093ff5175347a28eb5739bc55e81510b8388347710cc2257300cb  model_121.json
    f2b45a4a2ceb3de6734bdc279744b7f06445c5f44101ba922cf73dd34f250554  model_122.json
    bceda31f15c184034c2c8c2bb80c54e4e45c6bacd54b4fccab837b3651e6364a  model_123.json
    0ef1c1968241e9ac3d7e4a1ed0da2c63c420a37d7f71bfe300e8da8ce31b34dd  model_701.json
    30aee97da4ae71a92cdb13d7c04e99d649fd89459be95294511c7a57862954ee  model_702.json
    96c01118a8fc262947c7f45f6aea0ff99ac113eefe46e1885b7135d8132bb881  model_703.json
    3600babfeec08fa17349012281a80e992e404229127b3f27f62528d3f4522cb9  model_704.json
    407f01cac4d8fb38f1ff40381cff8f3056306dd610ad04b1cb2d9d3483422526  model_705.json
    1c34043e21cbf11ce2c95a32e7a82e3b561251be6c2ec7641d08c8a7d0b4bb81  model_706.json
    45e4ac69e847ef67c09fb8461c722bd294809b33064c0b4d3309c186a9e65a75  model_707.json
    e362e6b9f68b530131743a6fd290e9f80e0f91af3c58a4b9a19ef50796015b33  model_708.json
    1a9c78b17197263113700fde3a56a476fb58192b0040d49caeb0b0b1e831489f  model_709.json
    c71ae5fd67d5a7e69ae9e9337d177138bf04a80637e4c0c02c5b3b78ea5e9949  model_710.json
    0b7c476837eb2f14de15224f0d4c862658ac10b318faf07776d3833a9aca191e  model_711.json
    6a9f32180165386597412333022e3d3ef96155f5f0f474eae2e75e189e56c530  model_712.json
    e0e216bc2abf14214a1ade537ba5ae1a5addd2ff86d0b5d83275b35550152ead  model_802.json

Verify with (from this directory):

    sha256sum model_*.json | sort -k2 | \
      diff - <(sed -n 's/^    \([0-9a-f]\{64\}  model_[0-9]*\.json\)$/\1/p' SOURCES.md | sort -k2)

## Regenerating

    ./gen/gen.sh   # or: go generate ./...  (from this package directory)

Do NOT hand-edit `golden_gen.go` — it is produced by `gen/main.go` from the
JSON files above. Do NOT replace these JSON files with a copy pulled from
`vendor/lexa-proto/sunspec` or from lexa-gw's own SunSpec model docs — the
whole point of this table is that it was never touched by the product's own
transcription of the spec.
