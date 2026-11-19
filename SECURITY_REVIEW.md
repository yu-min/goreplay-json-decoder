# Security review — GoReplay JSON Decoder 1.1.0

Date: 2026-11-19. Scope: standalone Python decoder, Colab notebook, CLI output handling, synthetic unit tests, and GitHub Actions configuration.

## Review approach

Manual source inspection, targeted negative tests, deterministic malformed-input tests, CLI safety checks, Python syntax validation, notebook-to-module source comparison, and output integrity verification. No real customer traffic was used. This was not an independent penetration test, full fuzzing campaign, or third-party dependency audit.

| Area | Previous concern | Remediation / verification |
| --- | --- | --- |
| Input size | Entire files read without a cap | 128 MiB input cap; 96 MiB maximum encoded field size |
| Expansion bombs | Brotli decompressed in one unbounded operation | Incremental Brotli processing; strict 64 MiB expanded body cap; zstd bounded output/window; existing gzip/deflate/Snappy caps tested |
| Memory/CPU abuse | Malformed Snappy and HTTP headers/chunks | Tag count limit, HTTP header size/line limit, chunk-size and CRLF checks |
| Sensitive data in reports | Raw `Authorization`, `Cookie`, and API key header values in diagnostic JSON | Header-name-based redaction, suppression of raw payload preview in decode errors |
| Filesystem overwrite | Existing JSON or binary output might be overwritten | Exclusive create, symlink rejection, default no overwrite, atomic replacement on explicit `--overwrite`, input/output path collision refusal |
| Terminal output | Field names could inject control characters into CLI logs | Escape control characters in all variable CLI output; tested with ANSI escape sequence |
| Notebook divergence | Embedded code did not necessarily track module fixes | Notebook regenerated from current source and source-parity test |
| CI permissions | Workflow default token permissions unspecified | Explicit `contents: read`, disabled persisted checkout credentials, 10-minute timeout |

## Tests

33 synthetic unit tests passed on the local Python runtime, including tests for UTF-8, Traditional Chinese, Simplified Chinese, GB18030, Big5, Snappy Protobuf, malformed HTTP chunks, expansion limits, output overwrites, symlinks, and diagnostic redaction. GitHub Actions additionally tests Python 3.10, 3.11, 3.12, and 3.13 when workflows execute.

## Remaining risk and security assumptions

- **No absolute assurance:** A code review and finite test suite cannot prove absence of all vulnerabilities.
- Memory can exceed size limits due to parser object overhead, double buffering, and native codec allocations. Use OS resource limits for malicious traffic.
- The payloads and binary outputs can include personal data and secrets; header redaction only applies to the diagnostic copy of recognized HTTP headers.
- Optional Brotli/Zstandard dependency vulnerabilities may change over time; users should install patched versions from trusted sources and periodically audit dependencies.
- Generic Protobuf schema detection and text encoding inference are best-effort; decoding correctness requires the appropriate schema and source metadata.
- A limited manual review does not cover supply-chain compromises, runtime vulnerabilities, all platform-specific symlink/race conditions, or exhaustive grammar fuzzing.

## Guidance

For untrusted capture processing, use a dedicated, non-privileged, resource-limited container or VM without network egress, and avoid cloud notebook uploads of sensitive traffic. Keep local workspaces private. Review `SECURITY.md` for responsible reporting and limitations.
