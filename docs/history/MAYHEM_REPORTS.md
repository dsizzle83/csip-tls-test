# Mayhem QA reports archive

313 untracked `qa-mayhem-*.md` run reports and 5 stale root-level build
binaries (`certify`, `dashboard`, `evsim`, `mbapsdev`, `modsim-conformance`)
were moved out of the repo by WP7-T9a (finding REV0907-E10, hygiene half) on
2026-09-08. They were never tracked by git (`qa-mayhem-*.md` is
`.gitignore`d) and are per-run artifacts, not fixture material, so they were
moved rather than committed anywhere.

Archive path: `/home/dmitri/projects/archives/csip-mayhem-reports-2026-06..07/`

Date range: `qa-mayhem-20260620-214336.md` (2026-06-20 21:43) through
`qa-mayhem-20260710-163857.md` (2026-07-10 16:38).

The 4 qa-mayhem reports that WERE tracked in git (`qa-mayhem-20260620-131403.md`,
`qa-mayhem-20260620-210206.md`, `qa-mayhem-20260706-160549.md`,
`qa-mayhem-20260706-171022.md`) are not in this archive — they were `git mv`d
into this directory (`docs/history/`) instead, since removing tracked history
is a different operation than sweeping untracked run output.
