# Development handoff

## 1.1.0 archive-format expansion

- Added ZIP/CBZ, 7Z/CB7, and RAR/CBR as the supported archive families.
- 7Z uses `py7zr` and an automatically deleted temporary directory; RAR uses `rarfile` and requires a compatible local decompression backend.
- Every format expansion must update package metadata, README support and limitations, tests, changelog, GitHub release copy, repository description/topics, and the Forge catalog together.

The release contract is audit-only: never rewrite a user's archive or retain extracted page files. Temporary decoding is allowed only inside an automatically deleted private workspace. Treat every archive and image as untrusted input, retain resource limits, and add malformed-input tests with any parser change.
