# TASK-0XX — <Title>

*Status: TODO | IN PROGRESS | DONE (date, commit) · Phase: PX · Effort: S/M/L (≈hours) · Difficulty: low/med/high · Risk: low/med/high*

## Objective
One paragraph: the outcome, stated so completion is checkable.

## Background
Everything a coding model needs without reading the whole codebase: what
the relevant subsystem does, how it does it today, and the vocabulary
(topics, types, services, ports) the steps use.

## Why this task exists
The failure mode / debt / review finding it addresses.

## Architecture review sections
W#/D#/R#/§# references + roadmap docs (02 AD-#, 07 GAP-#).

## Prerequisites
Task IDs that must be DONE; bench/tooling preconditions.

## Files
- **Read first:** …
- **Modify:** …
- **Create:** …

## Blast radius
Packages / interfaces / public APIs / internal APIs / config /
data structures affected. State "none" explicitly where true.

## Implementation strategy
The approach in 3–6 sentences, including the migration pattern if any
(introduce → dual-run → flip → delete).

## Detailed steps
Numbered, concrete, in order, each independently verifiable.
(Implementer note: symbol names are authoritative, line numbers are hints —
re-verify `file:line` references by grep before editing.)

## Testing changes
Tests to add/modify; how to run them (`exact commands`).

## Documentation changes
Which docs/CLAUDE.md/runbooks to update.

## Common mistakes to avoid
Task-specific traps (deploy gotchas, invariant violations, known
foot-guns).

## Things that must NOT change
Protected behavior, named. For guard replacements: the preservation-ledger
entries (guard → originating QA scenario) this task touches.

## Acceptance criteria
Checkable list. Include exact test/command outputs where possible.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./...` (lexa-hub) green
- [ ] Conformance logic tests green if protocol-adjacent
- [ ] Mayhem: <none | targeted scenarios | full campaign> (per 05 §12)
- [ ] Task-specific items…

## Mayhem scenarios affected
Scenario IDs whose behavior/verdict this task may change, and how.

## Conformance implications
CSIP/SunSpec/OCPP implications, or "none".

## Suggested commit message
`type(scope): summary` (+ trailer per repo convention)

## Suggested PR title & description
Title; description with summary, risk, testing evidence, rollback note.

## Code review checklist
What the reviewer must verify beyond CI.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
IDs or backlog items this unblocks or suggests.
