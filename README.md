# GoReplay JSON Decoder

**English** | [繁體中文](README.zh-TW.md) | [简体中文](README.zh-CN.md)

A Python utility for turning encoded HTTP traffic fields in JSON/JSONL exports into readable, inspectable data. Run it locally or in Google Colab.

## About

GoReplay JSON Decoder helps inspect HTTP capture exports from GoReplay and other collectors. It recursively detects `reqBody`, `resBody`, and `rawPayload` fields, unwraps supported encodings and compression, and produces readable text or structured representations where possible. It also generates a per-field diagnostic report and preserves unrecognized binary payloads.

**Scope:** This is a general-purpose decoding and troubleshooting tool, not a traffic-capture agent, vulnerability scanner, or universal Protocol Buffers parser. Different exporters may use different JSON schemas.

## Features

- **Input:** JSON objects, arrays, or newline-delimited JSON (JSONL); recursive field discovery.
- **Field encoding:** validated Base64, explicit hexadecimal, plain text, and byte arrays.
- **HTTP compression:** Snappy raw blocks, gzip, deflate; optional Brotli and Zstandard.
- **Text and internationalization:** BOM and HTTP `charset` handling, UTF-8, UTF-16, GB18030, and Big5. Decoded JSON retains readable Unicode characters.
- **Content interpretation:** JSON, URL-encoded forms, selected raw HTTP messages, generic Protobuf wire fields, and recognized Prometheus Remote Write v1 messages.
- **Diagnostics:** per-field transformation details, warnings, SHA-256 of decoded bodies, and separate files for binary content.

## Quick start

Requires **Python 3.10+**. Core features use the Python standard library.

```bash
python goreplay_decoder.py traffic.json
python goreplay_decoder.py traffic.jsonl --body-encoding auto
python goreplay_decoder.py traffic.json -o decoded.json
```

When the export format is known to encode every body in Base64, you can explicitly enable it:

```bash
python goreplay_decoder.py traffic.json --body-encoding base64
```

For optional Brotli and Zstandard support (Brotli **1.2.1 or later** is required for security):

```bash
python -m pip install -r requirements-optional.txt
```

Alternatively, after installing the package locally with `python -m pip install .`, use `goreplay-json-decoder traffic.json`.

### Google Colab

[Open the notebook in Google Colab](https://colab.research.google.com/github/yu-min/goreplay-json-decoder/blob/main/GoReplay_JSON_Decoder_Colab.ipynb), then run the cells and upload an authorized JSON/JSONL file. The notebook packages results into a ZIP file.

> **Sensitive data:** HTTP captures may contain credentials, cookies, access tokens, or personal information. Do not upload such data to Colab or commit it to GitHub without authorization. Use a local, controlled environment for confidential datasets.

## Decoding pipeline

1. Read the source JSON/JSONL and locate supported fields, including nested objects.
2. Identify the field encoding; decode Base64 when recognized or explicitly requested.
3. For raw HTTP messages, separate headers from the message body when possible.
4. Decompress according to `Content-Encoding`, or cautiously identify well-known compression formats.
5. Interpret structured content using its type; otherwise apply declared text charset or strict text fallbacks.
6. Save unknown binary data without lossy character substitution; record results and limitations in the diagnostic report.

`Accept-Encoding` describes response encodings a client accepts. Actual body decompression follows `Content-Encoding`.

## Output

For `traffic.json`, the default outputs are:

| Path | Description |
| --- | --- |
| `traffic_decoded.json` | Decoded values in JSON with readable Unicode text |
| `traffic_decoded_report.json` | Per-field encoding, decompression, format, charset, and warning information |
| `traffic_decoded_files/` | Extracted Protobuf or other binary payloads, when applicable |

The original input is not modified. Inspect the report when automatic detection cannot confidently identify a format.

## Tests

All fixtures are synthetic and include **English**, **Traditional Chinese**, and **Simplified Chinese** text, with coverage for UTF-8, GB18030, Big5, gzip, deflate, Snappy/Protobuf, nested Base64, HTTP messages, and JSONL.

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the test suite on supported Python versions.

## Limitations

- Base64 auto-detection is heuristic to avoid corrupting plain text; use `--body-encoding base64` only when you know the export convention.
- Snappy support targets **raw blocks** (including Remote Write), not the framed Snappy stream format.
- Without an accurate `.proto` schema, generic Protobuf output uses field numbers and wire types rather than semantic field names. Protocol inference may be uncertain.
- When the source does not declare a charset, legacy Chinese encodings can be ambiguous. Check diagnostic warnings and verify against the original source.
- Only selected HTTP message layouts are supported; multipart, streaming protocols, and arbitrary custom exporter schemas may need adapters.
- Decoded bodies are limited to **64 MiB per field** and the input file to **128 MiB** by default. Input is loaded into memory rather than streamed; use an isolated environment with sufficient memory.

## Safety and security

- Treat all capture files as untrusted. Large or malformed payloads can consume CPU and memory even when limits are enabled.
- The decoder enforces input and expanded-body limits, checks Snappy and HTTP Chunk framing, and avoids overwriting existing outputs unless `--overwrite` is explicitly supplied.
- Diagnostic reports redact common credential-bearing HTTP headers, and decode errors do not echo original payload previews. **Decoded content and binary exports can still contain secrets.**
- Generated files use restricted permissions on systems that support POSIX file modes. Store captures and outputs only on trusted storage; the program does not anonymize sensitive content.
- Optional Brotli and Zstandard decompression use third-party packages. Keep dependencies patched; a bounded result is not equivalent to a complete sandbox.
- Review [SECURITY.md](SECURITY.md) before processing sensitive or hostile traffic.

To intentionally replace previously generated results, append `--overwrite` to the command. The original input file cannot be used as an output path.

## License

[Apache License 2.0](LICENSE).
