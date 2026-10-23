# Changelog

All notable changes to Howdah are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-10-23

### Added
- Layer 2 input inspection: content inspection of decoded GET, POST, cookie and
  path values for SQL injection, path traversal and command/code injection.
- Detects and logs; **does not block by default.** Layer 2 is governed by its
  own `inspect.mode`, independent of `howdah.mode`: a global
  `howdah.mode = block` does not arm it.
- The matched value is never logged; log lines carry the variable name, the
  rule class and the source only.
- Linear-time scanning with per-value and per-request budgets, so inspection
  cannot be turned into a denial-of-service vector.
- Configured under `[inspect]`; see [docs/config.md](docs/config.md).
- Signature inspection is best-effort and can be bypassed, which is why it logs
  by default.

## [1.0.0]

### Added
- Layer 1 request parsing limits: multipart/form-data upload floods, input
  variable count and shape, and request headers.
