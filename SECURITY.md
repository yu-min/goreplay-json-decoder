# Security policy

## Intended use and trust boundary

GoReplay JSON Decoder is an **offline parser for untrusted JSON/JSONL traffic captures**. It is not a sandbox or a credential-redaction utility. Run it with a non-privileged account in a controlled environment, preferably with OS-level CPU, RAM and disk quotas when analyzing traffic from unknown sources.

## Implemented safeguards

- Input file size cap: 128 MiB; maximum field encoded input: 96 MiB; maximum expanded body: 64 MiB.
- Bounded decompression for gzip/deflate, Snappy raw block, Brotli (incremental), and Zstandard (bounded reader and window).
- HTTP chunk length and terminator validation; HTTP header size and line limits.
- Maximum nesting depth for recursive JSON field discovery and Protobuf wire inference.
- Binary outputs use deterministic sanitized names and exclusive file creation.
- Existing output files are not overwritten by default. Use `--overwrite` only intentionally. Output symlinks are refused, and the input cannot be used as an output path.
- Exported diagnostics redact common credential-bearing HTTP header names. Decoder error previews do not repeat captured body values. Untrusted field paths are escaped in CLI output.

## Residual risks

- Memory usage may exceed individual limits due to in-memory JSON parsing, intermediate copies, or native compression libraries. A resource-constrained process/container is recommended.
- Decoded payloads and saved binary files may **still contain secrets or personal data**; diagnostic redaction does not sanitize full output. Never publish real capture artifacts.
- Generic Protobuf interpretation is heuristic without an authoritative schema. Some charsets cannot be distinguished reliably when source metadata is missing.
- Brotli versions older than 1.2.1 are rejected at runtime due to CVE-2026-111497. Optional Brotli and Zstandard packages still have their own dependency and native-code attack surfaces. Update them as security releases become available.
- Local filesystem permissions and symlink behavior differ by platform; control access to the working directory.

## Reporting a vulnerability

Please report a suspected security issue privately through the repository owner's private contact channel rather than opening a public issue containing exploit payloads or customer traffic. Avoid uploading sensitive evidence to the issue tracker.

## Security testing scope

Synthetic tests cover malformed HTTP chunk framing, excessive compressed size declarations, decompression output caps, symlink writes, accidental overwrites, raw-header redaction and error-preview suppression.

No source review or test suite can establish that a parser is free of all vulnerabilities. This project has not undergone a formal independent penetration test or memory-safety audit of optional third-party libraries.
