# app: the Spatial app, whole

The AUKORA spatial frontend on the DeepSeek harness, exactly as Peter uses it. Imported from aukora-prime at the commit
the Nebius pilot runs, with nothing hidden or dropped (bricks #1-#17, #98 in [NORTH-STAR.md](../NORTH-STAR.md)).

- `APP-LOCK.json`: Peter's app and System entries. `checks/` makes main red if one is missing; the M1 test fails if
  one is hidden or 404s on the node.
- `PROVENANCE.json` (written by the import): source repository, commit, and sha256 of every imported file. Nothing
  here may point back into another repository.
- The harness itself is built from the pinned `vendor/dsh-source.tar.gz` and `upstream-dsh.json` on the node and is
  never committed (its install is about 1.7 GB).
