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
