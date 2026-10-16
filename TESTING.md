# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, and `python -m build`. CI also audits dependencies and runs the supported OS/Python matrix.

## 1.2.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Repair formatting and add local finding contact sheets, decoder diagnostics and resumable per-archive checkpoints.

## Checkpoint identity (1.3.0)

Resume requires schema 2 checkpoints and checks the auditor version, installed decoder
versions, audit limits, and full archive SHA-256 before reusing results. Changing
`--max-pages` or `--max-uncompressed-mb` re-audits the batch. Legacy checkpoints need
a new state filename. Malformed records are re-audited; invalid JSON or unsupported
schemas fail without replacing the checkpoint. Completed records survive interruption
because each archive advances the state atomically. Checkpoints remain trusted local data.
