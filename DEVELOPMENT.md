# Development handoff

The v1 contract is audit-only: never rewrite or extract a user's archive as part of an audit. Treat every archive and image as untrusted input, retain resource limits, and add malformed-input tests with any parser change.
