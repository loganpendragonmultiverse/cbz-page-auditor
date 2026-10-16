# Changelog

## 1.3.0 - 2026-10-16

- Bound resume checkpoints to the engine, decoder versions, schema and audit limits.
- Re-audit stale or malformed records and detect archive changes before advancing state.
- Added configurable CLI audit limits and checkpoint regression fixtures.

## 1.2.0 - 2026-09-07

- Repair formatting and add local finding contact sheets, decoder diagnostics and resumable per-archive checkpoints.
- Added regression coverage for the audited behavior and invalid inputs.

## 1.1.0 - 2026-07-18

- Added read-only 7Z/CB7 auditing with automatically deleted temporary extraction.
- Added RAR/CBR auditing through an installed UnRAR, 7-Zip, `unar`, or `bsdtar` backend.
- Expanded directory scans, package metadata, safety checks, tests, and documentation for all six accepted extensions.

## 1.0.0 - 2026-07-18

- Added read-only CBZ integrity and image decoding audits.
- Added exact duplicate, numbering-gap, dimension, blank-page, and possible-spread findings.
- Added batch terminal, JSON, and static HTML reports.
- Added archive entry and uncompressed-size safety limits.
