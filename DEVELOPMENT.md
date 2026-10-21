# Development handoff

## 1.1.0 archive-format expansion

- Added ZIP/CBZ, 7Z/CB7, and RAR/CBR as the supported archive families.
- 7Z uses `py7zr` and an automatically deleted temporary directory; RAR uses `rarfile` and requires a compatible local decompression backend.
- Every format expansion must update package metadata, README support and limitations, tests, changelog, GitHub release copy, repository description/topics, and the Forge catalog together.

The release contract is audit-only: never rewrite a user's archive or retain extracted page files. Temporary decoding is allowed only inside an automatically deleted private workspace. Treat every archive and image as untrusted input, retain resource limits, and add malformed-input tests with any parser change.

## 1.2.0 improvement session

Repair formatting and add local finding contact sheets, decoder diagnostics and resumable per-archive checkpoints.

HTML contact sheets include up to 200 page thumbnails per archive, whole-page finding labels and navigation to previewed pages. Labels do not claim precise pixel localization. --doctor reports installed Python decoders and RAR-related executables on PATH; discovery does not prove a decoder works for every archive. --state writes an atomic per-archive checkpoint; --resume explicitly reuses it after checking full archive SHA-256 hashes. Changed archives are re-audited, and damaged archives retain their own failed results while other archives continue. Checkpoints are trusted local review data, not tamper-proof attestations. Reports must be new files. Original archives are not changed, and thumbnails remain local unless you share the report.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.

## Checkpoint identity (1.3.0)

Resume requires schema 2 checkpoints and checks the auditor version, installed decoder
versions, audit limits, and full archive SHA-256 before reusing results. Changing
`--max-pages` or `--max-uncompressed-mb` re-audits the batch. Legacy checkpoints need
a new state filename. Malformed records are re-audited; invalid JSON or unsupported
schemas fail without replacing the checkpoint. Completed records survive interruption
because each archive advances the state atomically. Checkpoints remain trusted local data.

HTML thumbnails use the same effective archive entry and expanded-size limits as
the audit and checkpoint identity. Raising limits is explicit; the defaults remain
10,000 entries and 2,000 MB, with at most 200 thumbnail previews.


## Version 2.0 compatibility and bounded auditing

Version 2.0.0 requires Python 3.11+ and Pillow 13; Python 3.10 is no longer
supported. The six native CI combinations remain Linux, Windows and macOS,
with Python 3.11 and 3.13. The aggregate `verify` check also requires dependency
audit success. Formatting, lint, type checks, source tests and builds run in CI.

Archive payloads are consumed one member at a time. Image members are limited
to 64 MiB expanded bytes and 40 million decoded pixels before full image decode.
The configurable archive entry and expanded-byte limits still apply; 7Z enforces
its expanded-byte budget during extraction. ZIP streams are checked through their
complete compressed span for actual size, CRC and codec completion, including
metadata and directory records. ZIP LZMA dictionaries are limited to 64 MiB.
Corrupt image/member findings retain other readable pages where the archive decoder
can continue. Damaged solid 7Z streams can stop the archive.

Only safe image targets are temporarily extracted from 7Z. Unselected directory
records are not materialized. RAR requires a separately installed supported backend;
`--doctor` reports discovery rather than successful codec verification. Actual
native acceptance on Linux uses official 7-Zip 26.04 with real compressed RAR3/RAR5
and a CBR with an owned PNG. Other backend/platform combinations require their own
installed-tool checks. No OCR or pixel-level finding localization is claimed.

Checkpoints reject links/nonregular files, bind engine/library/configuration and
native RAR executable hashes, and refuse an observed concurrent state change.
New reports are created exclusively; existing or dangling destinations are refused.
These guards address ordinary accidental collisions, not hostile concurrent
filesystem mutation. Failed or missing archives do not erase later batch evidence.
Changed page bytes are refused before preview rendering.

The wheel and sdist install all four authority documents and an owned sample
archive generator under `share/doc/cbz-page-auditor`. Run the installed generator
with an unused output path, then `cbz-audit sample.cbz --format html --output review.html`.

Pillow 13 has an upstream conditional Arrow-export advisory with no fixed release
listed at this assessment. This CLI does not export Arrow data; final source-specific
applicability is independently reviewed. Dependency-audit output is not a claim of
zero known vulnerabilities in every upstream operation.

Archive entry budgets count every header, including directories and metadata; directory
payload declarations must be empty. `--max-entries` is an alias for the retained
`--max-pages` option. Selected member paths reject Windows device names (including
superscript COM/LPT forms), nested ADS/colons, control characters, ambiguous Unicode
aliases and trailing dots/spaces before any extraction.
