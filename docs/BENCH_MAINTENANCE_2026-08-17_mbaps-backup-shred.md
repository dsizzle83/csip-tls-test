# Bench maintenance — 2026-08-17: the stale mbaps PKI backup was shredded

`certs/mbaps.bak-ethsplit-20260807/` held **16 private-key files** on disk. It was
the pre-rotation backup of the bench mbaps PKI, taken when the bench moved to the
WAN/LAN ethernet split on 2026-08-07, and it had been flagged rotate-or-shred
since that day. It is now gone.

These are **bench-only simulator keys** — the fixture PKI
`scripts/gen-mbaps-certs.sh` regenerates and `make gen-mbaps-certs` rebuilds.
Nothing in this record, and nothing in the commit that accompanies it, contains
or reproduces key material: **filenames only**.

## What was verified BEFORE anything was destroyed

Every one of these was checked, and any single failure was to stop the operation
on that file:

| check | result |
|---|---|
| Referenced by any live config, script, Makefile target or source file? | **No** — zero references to `mbaps.bak` / `bak-ethsplit` anywhere in the tree |
| Tracked in git at HEAD? | **No** — `git ls-files` returns nothing under that path |
| Any private key ever committed there, on any branch? | **No** — `git log --all --name-only` over that path yields **zero** `*-key.pem` entries |
| Ignored? | Yes — `.gitignore:134` `certs/*.bak-*/` |
| Is it clearly the backup set of the live tree? | Yes — its file list is **identical** to `certs/mbaps/`'s, name for name |
| Does anything fall back to it if it is absent? | **No** — `certs/mbaps/` carries its own complete 16-key set; every live consumer points at `certs/mbaps` (`Makefile`, `cmd/gw-campaign`, `mbapsdev` flag defaults) |

Two further facts, recorded because they change what the shred means rather than
whether it was safe:

- **The public halves WERE in git history** (commits `2d8b627`, `2a9752b` list
  the `*-cert.pem`, `dev-ca.pem`, `manifest.json` and `README.md` under this
  path; they are no longer tracked). No key material is in history, so shredding
  the working copies removes the private material from this machine completely.
- `ca-key.pem` and `intermediate-key.pem` in the backup were **byte-identical to
  the live ones**, i.e. they were duplicate copies of key material that is still
  in use — which is the strongest reason to have removed them.
  `dev-server-key.pem` differed, confirming the directory is genuinely
  superseded material from before the 2026-08-07 rotation.

## What was shredded

`shred -u` (overwrite, then unlink) on each file, then the directories removed.
All 34 files went; the 16 private keys are listed separately because they are the
reason the operation exists.

### Private keys (16)

```
ca-key.pem
dev-server-key.pem
intermediate-key.pem
wrong-ca-key.pem
clients/grid-service-key.pem
clients/lexavolt-read-only-key.pem
clients/net-admin-key.pem
clients/read-only-key.pem
clients/super-admin-key.pem
negative/bad-encoding-key.pem
negative/empty-role-key.pem
negative/expired-key.pem
negative/no-role-key.pem
negative/oversize-role-key.pem
negative/two-role-key.pem
negative/wrong-ca-key.pem
```

### Public/other material in the same directory (18)

```
ca-cert.pem                      dev-ca.pem
dev-server-cert.pem              intermediate-cert.pem
wrong-ca-cert.pem                manifest.json
README.md
clients/grid-service-cert.pem    clients/lexavolt-read-only-cert.pem
clients/net-admin-cert.pem       clients/read-only-cert.pem
clients/super-admin-cert.pem
negative/bad-encoding-cert.pem   negative/empty-role-cert.pem
negative/expired-cert.pem        negative/no-role-cert.pem
negative/oversize-role-cert.pem  negative/two-role-cert.pem
negative/wrong-ca-cert.pem
```

## If this backup is ever wanted again

It is not recoverable, by design. Regenerate the fixture PKI instead:

```sh
make gen-mbaps-certs      # scripts/gen-mbaps-certs.sh -> certs/mbaps/
```

A backup of a bench fixture PKI has no evidentiary value — the certificates it
holds are not the ones any bundle was captured against once the tree has rotated,
and keeping one only multiplies the copies of live CA key material on disk.
