#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GoReplay JSON/JSONL decoder for structured HTTP payload inspection.

Recursively replaces encoded reqBody/resBody/rawPayload with decoded content.
Reports transformations; does not silently preserve the original Base64 field.
Snappy raw-block decoding is built in (no python-snappy requirement).

Usage:
  python goreplay_decoder.py traffic.json
  python goreplay_decoder.py traffic.json --body-encoding base64
"""
import argparse
import base64
import binascii
import codecs
import copy
import gzip
import hashlib
import json
import math
import os
import re
import struct
import zlib
from pathlib import Path
from urllib.parse import parse_qs

__version__ = "1.1.0"
MAX_BODY = 64 * 1024 * 1024
MAX_INPUT_FILE = 128 * 1024 * 1024
MAX_FIELD_INPUT = 96 * 1024 * 1024
MAX_HTTP_HEADERS = 64 * 1024
MAX_SNAPPY_TAGS = 1_000_000
SENSITIVE_HEADER_RE = re.compile(
    r'(?:authorization|cookie|token|secret|password|credential|api[-_]?key|session|jwt|set-cookie)',
    re.I,
)
TARGETS = {'reqbody': 'request', 'resbody': 'response', 'rawpayload': 'raw'}
HEADER_NAMES = {
    'request': ('reqheaders', 'requestheaders', 'reqheader', 'requestheader'),
    'response': ('resheaders', 'responseheaders', 'resheader', 'responseheader'),
    'raw': ('reqheaders', 'requestheaders', 'reqheader', 'requestheader', 'resheaders', 'responseheaders'),
}


def norm(s):
    return re.sub(r'[^a-z0-9]', '', str(s).lower())


def maybe_header_obj(x):
    if not isinstance(x, dict):
        return None
    vals = {}
    for k, v in x.items():
        if isinstance(v, list):
            v = ', '.join(str(it) for it in v)
        vals[str(k).strip().lower()] = str(v)
    if any(k in vals for k in ('content-type', 'content-encoding', 'accept', 'transfer-encoding', 'user-agent', 'host')):
        return vals
    return None


def find_headers(containers, direction):
    names = HEADER_NAMES[direction]
    for holder in reversed(containers):
        if not isinstance(holder, dict):
            continue
        nk = {norm(k): k for k in holder}
        # Prefer explicit request/response header objects.
        for alias in names:
            if alias in nk:
                v = maybe_header_obj(holder[nk[alias]])
                if v is not None:
                    return v
        if direction != 'raw':
            part = direction
            for alias in (part, 'req' if direction == 'request' else 'res'):
                if alias in nk and isinstance(holder[nk[alias]], dict):
                    nested = holder[nk[alias]]
                    for hk, hv in nested.items():
                        if norm(hk) in ('headers', 'header'):
                            v = maybe_header_obj(hv)
                            if v:
                                return v
        # Plain headers only when adjacent to this field.
        for alias in ('headers', 'header'):
            if alias in nk:
                v = maybe_header_obj(holder[nk[alias]])
                if v:
                    return v
    return {}


def b64_decode(s, forced=False, binary_hint=False):
    """Decode a complete Base64 value; in auto mode require plausible payload.

    Complete Base64 values are checked before decoding; auto mode uses heuristics.
    """
    if len(s) > MAX_FIELD_INPUT:
        raise ValueError('Encoded field exceeds input size limit')
    s = re.sub(r'\s+', '', s)
    prefixed = s.lower().startswith(('base64:', 'data:application/octet-stream;base64,'))
    if prefixed:
        s = s.split(':', 1)[-1]
        if ';base64,' in s:
            s = s.split(';base64,', 1)[1]
        forced = True
    if len(s) < 4 or len(s) % 4 == 1 or not re.fullmatch(r'[A-Za-z0-9+/_-]+={0,2}', s):
        return None
    try:
        std = s.replace('-', '+').replace('_', '/')
        result = base64.b64decode(std + '=' * (-len(std) % 4), validate=True)
        if base64.b64encode(result).decode('ascii').rstrip('=') != std.rstrip('='):
            return None
    except (ValueError, binascii.Error):
        return None
    if forced:
        return result
    recognised = result.startswith((
        b'{', b'[', b'GET ', b'POST ', b'PUT ', b'HTTP/', b'\x1f\x8b',
        b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff'))
    if recognised or binary_hint:
        return result
    # GoReplay can store Snappy blocks without a corresponding header object.
    try:
        expanded = snappy_block_decompress(result)
        if expanded.startswith((b'{', b'[', b'GET ', b'POST ')) or proto_generic(expanded) is not None:
            return result
    except (ValueError, OverflowError):
        pass
    try:
        if proto_generic(result) is not None:
            return result
    except (ValueError, OverflowError):
        pass
    # Base64 plain text, including Chinese UTF-8, may contain only letters/digits.
    for charset in ('utf-8', 'gb18030'):
        try:
            decoded = result.decode(charset)
            if decoded and len(decoded) >= 2 and all(
                (ch.isprintable() or ch in '\r\n\t') for ch in decoded
            ) and (any(ord(ch) > 127 for ch in decoded) or
                   any(ch in s for ch in '+/_=') or
                   (len(s) >= 24 and ' ' in decoded)):
                return result
        except UnicodeError:
            pass
    return None


def body_bytes(value, mode, headers):
    # Bound materialization before Base64, Hex, or JSON transformations.
    if isinstance(value, str) and len(value) > MAX_FIELD_INPUT:
        raise ValueError('Field exceeds input size limit')
    if isinstance(value, list) and len(value) > MAX_FIELD_INPUT:
        raise ValueError('Byte-array field exceeds input size limit')
    if isinstance(value, list) and all(isinstance(v, int) and 0 <= v < 256 for v in value):
        return bytes(value), 'byte-array'
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False).encode(), 'JSON value'
    if value is None:
        return b'', 'empty'
    if not isinstance(value, str):
        value = str(value)
    if mode == 'hex' or (mode == 'auto' and value.lower().startswith(('0x', 'hex:'))):
        txt = value[4:] if value.lower().startswith('hex:') else value[2:] if value.lower().startswith('0x') else value
        return bytes.fromhex(re.sub(r'\s+', '', txt)), 'hex'
    if mode in ('base64', 'auto'):
        ct = headers.get('content-type', '').lower()
        ce = headers.get('content-encoding', '').lower()
        hint = bool(ce) or any(t in ct for t in ('protobuf', 'octet-stream', 'grpc'))
        raw = b64_decode(value, forced=(mode == 'base64'), binary_hint=hint)
        if raw is None and mode == 'auto':
            # Explicit charset provides useful evidence for encoded CJK text.
            charset_match = re.search(r'charset\s*=\s*[\x22\x27]?([^;\s\x22\x27]+)', ct, re.I)
            if charset_match and len(value) >= 12:
                candidate = b64_decode(value, forced=True)
                if candidate is not None:
                    try:
                        decoded = candidate.decode(charset_match.group(1), errors='strict')
                        printable = decoded and all(c.isprintable() or c in '\r\n\t' for c in decoded)
                        if printable and (any(ord(c) > 127 for c in decoded) or ' ' in decoded):
                            raw = candidate
                    except (UnicodeError, LookupError):
                        pass
        if raw is not None:
            return raw, 'base64'
        if mode == 'base64':
            raise ValueError('Invalid/incomplete Base64; provide the FULL value, without ellipsis')
    return value.encode('utf-8'), 'plain string'


def read_varint(b, p):
    val = 0
    for n in range(10):
        if p >= len(b):
            raise ValueError('Truncated varint')
        x = b[p]
        p += 1
        val |= (x & 127) << (n * 7)
        if not x & 128:
            return val, p
    raise ValueError('Invalid varint')


def snappy_block_decompress(b):
    """Snappy raw block (Prometheus Remote Write), not Snappy framed stream."""
    target, p = read_varint(b, 0)
    if target > MAX_BODY:
        raise ValueError('Snappy output exceeds size limit')
    out = bytearray()
    tags = 0
    while p < len(b):
        tags += 1
        if tags > MAX_SNAPPY_TAGS:
            raise ValueError('Snappy block contains excessive tags')
        tag = b[p]
        p += 1
        ty = tag & 3
        if ty == 0:
            n = tag >> 2
            if n < 60:
                length = n + 1
            else:
                extras = n - 59
                if p + extras > len(b):
                    raise ValueError('Truncated Snappy literal length')
                length = int.from_bytes(b[p:p+extras], 'little') + 1
                p += extras
            if length > target - len(out) or p + length > len(b):
                raise ValueError('Invalid or truncated Snappy literal')
            out.extend(b[p:p+length])
            p += length
        else:
            if ty == 1:
                length = 4 + ((tag >> 2) & 7)
                if p >= len(b):
                    raise ValueError('Truncated Snappy offset')
                offset = ((tag & 0xe0) << 3) | b[p]
                p += 1
            else:
                length = 1 + (tag >> 2)
                width = 2 if ty == 2 else 4
                if p + width > len(b):
                    raise ValueError('Truncated Snappy offset')
                offset = int.from_bytes(b[p:p+width], 'little')
                p += width
            if not offset or offset > len(out) or length > target - len(out):
                raise ValueError('Invalid Snappy copy')
            # Copies can overlap (common in Snappy).
            for _ in range(length):
                out.append(out[-offset])
    if len(out) != target:
        raise ValueError(f'Snappy output size mismatch: {len(out)} != {target}')
    return bytes(out)


def bounded_inflate(b, wbits):
    z = zlib.decompressobj(wbits)
    result = z.decompress(b, MAX_BODY+1)
    if len(result) > MAX_BODY or z.unconsumed_tail:
        raise ValueError('Expanded HTTP body is too large')
    result += z.flush(MAX_BODY+1-len(result))
    if len(result) > MAX_BODY or not z.eof:
        raise ValueError('Truncated/oversized compressed data')
    return result


def inflate(b, name):
    name = name.lower().strip()
    if name in ('', 'identity'):
        return b
    if name in ('gzip', 'x-gzip'):
        return bounded_inflate(b, zlib.MAX_WBITS | 16)
    if name == 'deflate':
        try:
            return bounded_inflate(b, zlib.MAX_WBITS)
        except zlib.error:
            return bounded_inflate(b, -zlib.MAX_WBITS)
    if name == 'snappy':
        # The built-in raw-block decoder enforces the output size limit.
        return snappy_block_decompress(b)
    if name in ('br', 'brotli'):
        # Brotli 1.2.0 and older are affected by CVE-2026-111497.
        # Refuse vulnerable versions even if a caller installed them outside
        # the project's optional dependency constraints.
        from importlib.metadata import PackageNotFoundError, version
        try:
            installed = version('Brotli')
        except PackageNotFoundError as exc:
            raise ValueError('Install patched Brotli>=1.2.1 for Brotli decoding') from exc
        numbers = re.match(r'^(\d+)\.(\d+)\.(\d+)', installed)
        if not numbers or tuple(map(int, numbers.groups())) < (1, 2, 1):
            raise ValueError('Brotli>=1.2.1 is required due to a decoder security advisory')
        import brotli
        # Stream instead of the unbounded one-shot decompressor.
        # Native decoders may still transiently allocate memory.
        decoder = brotli.Decompressor()
        out = bytearray()
        for pos in range(0, len(b), 256):
            chunk = decoder.process(b[pos:pos + 256])
            if len(chunk) > MAX_BODY - len(out):
                raise ValueError('Brotli output too large')
            out.extend(chunk)
        if not decoder.is_finished():
            raise ValueError('Truncated Brotli body')
        return bytes(out)
    if name in ('zstd', 'zstandard'):
        import io
        import zstandard
        with zstandard.ZstdDecompressor(max_window_size=MAX_BODY).stream_reader(io.BytesIO(b)) as r:
            out = r.read(MAX_BODY+1)
        if len(out) > MAX_BODY:
            raise ValueError('Zstd output too large')
        return out
    raise ValueError('Unsupported Content-Encoding')


def unpack_body(b, headers, log):
    methods = [x.strip() for x in headers.get('content-encoding', '').split(',') if x.strip()]
    if not methods and b.startswith(b'\x1f\x8b'):
        methods = ['gzip (sniffed)']
    if not methods:
        # Try Snappy raw block only when it decompresses completely and the
        # resulting data looks like protobuf, HTTP or reasonable text.
        try:
            candidate = snappy_block_decompress(b)
            valid = bool(list(proto_fields(candidate, limit=200))) or candidate.startswith((b'{', b'[', b'GET ', b'POST '))
            if valid:
                log.append('snappy (sniffed; header missing)')
                return candidate
        except (ValueError, UnicodeError):
            pass
        return b
    out = b
    for name in reversed(methods):
        actual = name.replace(' (sniffed)', '')
        out = inflate(out, actual)
        log.append(name)
        if len(out) > MAX_BODY:
            raise ValueError('Decompressed body exceeds size limit')
    return out


def proto_fields(b, limit=3000):
    p = 0
    n = 0
    while p < len(b):
        n += 1
        if n > limit:
            raise ValueError('Too many Protobuf fields')
        tag, p = read_varint(b, p)
        no, wire = tag >> 3, tag & 7
        if not no or wire not in (0, 1, 2, 5):
            raise ValueError('Invalid protobuf wire tag')
        if wire == 0:
            val, p = read_varint(b, p)
        elif wire == 1:
            if p+8 > len(b):
                raise ValueError('Truncated fixed64')
            val, p = b[p:p+8], p+8
        elif wire == 5:
            if p+4 > len(b):
                raise ValueError('Truncated fixed32')
            val, p = b[p:p+4], p+4
        else:
            ln, p = read_varint(b, p)
            if ln > len(b)-p:
                raise ValueError('Truncated length-delimited field')
            val, p = b[p:p+ln], p+ln
        yield no, wire, val


def display_utf8(b):
    try:
        txt = b.decode('utf-8', 'strict')
        if txt and sum(c.isprintable() or c in '\r\n\t' for c in txt) / len(txt) > .97:
            return txt
    except UnicodeError:
        pass
    return None


def proto_generic(b, depth=0):
    if depth > 5:
        return None
    try:
        raw = list(proto_fields(b, limit=300))
        if not raw:
            return None
    except ValueError:
        return None
    output = []
    for fno, wire, v in raw:
        if wire == 0:
            decoded = v
        elif wire in (1, 5):
            decoded = {'hex': v.hex()}
        else:
            t = display_utf8(v)
            if t is not None:
                decoded = t
            else:
                sub = proto_generic(v, depth+1) if depth < 5 else None
                decoded = sub if sub is not None else {'hex': v[:48].hex(), 'bytes': len(v)}
        output.append({'field': fno, 'wire_type': wire, 'value': decoded})
    return output


def prometheus_v1(b):
    series = []
    raw = list(proto_fields(b))
    # Remote Write v1 may include additional metadata fields alongside TimeSeries.
    series_fields = [(fno, wire, value) for fno, wire, value in raw if fno == 1 and wire == 2]
    if not series_fields:
        return None
    for fno, wire, time_series in series_fields:
        labels = {}
        samples = []
        try:
            for sf, sw, val in proto_fields(time_series):
                if sf == 1 and sw == 2:
                    name = value = None
                    for lf, lw, lv in proto_fields(val):
                        if lf == 1 and lw == 2:
                            name = lv.decode('utf-8')
                        elif lf == 2 and lw == 2:
                            value = lv.decode('utf-8')
                    if name is not None:
                        labels[name] = value
                if sf == 2 and sw == 2:
                    value, ts = None, None
                    for jf, jw, jv in proto_fields(val):
                        if jf == 1 and jw == 1:
                            value = struct.unpack('<d', jv)[0]
                            if not math.isfinite(value):
                                value = str(value)
                        if jf == 2 and jw == 0:
                            ts = jv - (1 << 64) if jv >= (1 << 63) else jv
                    samples.append({'value': value, 'timestamp_ms': ts})
        except (UnicodeError, ValueError, struct.error):
            return None
        if not labels and not samples:
            return None
        series.append({'labels': labels, 'samples': samples})
    return series if series else None


def parse_http(b):
    # Some GoReplay records begin with a metadata line: '1 <uuid> <timestamp>'.
    if not re.match(rb'^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s|^HTTP/', b):
        p = b.find(b'\n')
        if 0 < p < 160 and re.match(rb'^[123]\s+\S+\s+\d+', b[:p]):
            b = b[p+1:]
    for sep in (b'\r\n\r\n', b'\n\n'):
        if sep not in b:
            continue
        head, body = b.split(sep, 1)
        if len(head) > MAX_HTTP_HEADERS:
            raise ValueError('HTTP headers exceed safe size limit')
        lines = head.decode('latin-1', 'replace').splitlines()
        if len(lines) > 1024:
            raise ValueError('Excessive HTTP header lines')
        if not lines or not re.match(r'^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s|^HTTP/', lines[0]):
            continue
        hs = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                hs[k.strip().lower()] = v.strip()
        # Files made with GoReplay sometimes end in its record separator.
        for marker in ('🐵🙈🙉\n'.encode(), '🐵🙈🙉'.encode()):
            if body.endswith(marker):
                body = body[:-len(marker)]
        if 'chunked' in hs.get('transfer-encoding', '').lower():
            try:
                body = dechunk(body)
            except ValueError as exc:
                raise ValueError('Invalid chunked HTTP body') from exc
        return lines[0], hs, body
    return None


def dechunk(data):
    result, p = bytearray(), 0
    while True:
        nl = data.find(b'\r\n', p)
        if nl < 0:
            raise ValueError('Truncated chunk')
        line = data[p:nl].split(b';', 1)[0].strip()
        if not line or len(line) > 16 or not re.fullmatch(rb'[0-9a-fA-F]+', line):
            raise ValueError('Invalid HTTP chunk length')
        n = int(line, 16)
        p = nl + 2
        if n == 0:
            return bytes(result)
        if n > MAX_BODY - len(result) or p + n + 2 > len(data):
            raise ValueError('Chunk is truncated or too big')
        result.extend(data[p:p+n])
        p += n
        if data[p:p+2] != b'\r\n':
            raise ValueError('HTTP chunk is missing CRLF')
        p += 2


def decode_text(b, headers):
    ct = headers.get('content-type', '')
    m = re.search(r'charset\s*=\s*[\x22\x27]?([^;\s\x22\x27]+)', ct, re.I)
    declared = m.group(1) if m else ''
    choices = []
    if b.startswith(codecs.BOM_UTF8):
        choices.append('utf-8-sig')
    elif b.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        choices.append('utf-16')
    if declared:
        choices.append(declared)
    choices += ['utf-8', 'gb18030', 'big5']
    for enc in dict.fromkeys(choices):
        try:
            txt = b.decode(enc, errors='strict')
            if not txt or sum(c.isprintable() or c in '\r\n\t' for c in txt) / len(txt) >= .97:
                return txt, enc
        except (LookupError, UnicodeError):
            pass
    return None, None


def secure_write(path, payload, *, overwrite=False):
    """Write derived bytes with owner-only permissions and no symlink following."""
    path = Path(path)
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError('Refusing symlinked output directory')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError('Refusing to overwrite a symlink')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    if overwrite and path.exists():
        # Atomic replacement; never follow the existing destination for writing.
        import tempfile
        fd, temp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    else:
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
        except BaseException:
            path.unlink(missing_ok=True)
            raise


def emit_binary(b, folder, name, ext):
    folder = Path(folder)
    if folder.is_symlink():
        raise ValueError('Refusing symlinked binary output directory')
    folder.mkdir(exist_ok=True, parents=True, mode=0o700)
    # Include both path and payload digests to prevent filename collisions.
    safe = re.sub(r'[^a-zA-Z0-9_-]+', '_', name)[:90]
    identity = hashlib.sha256(name.encode('utf-8') + b'\0' + b).hexdigest()[:16]
    f = folder / (safe + '_' + identity + ext)
    if not f.exists():
        secure_write(f, b)
    elif f.is_symlink() or f.read_bytes() != b:
        raise ValueError('Refusing to overwrite existing binary output')
    return str(f)


def redact_headers(headers):
    """Do not duplicate credential-bearing headers in diagnostic reports."""
    return {k: '[REDACTED]' if SENSITIVE_HEADER_RE.search(k) else v
            for k, v in headers.items()}


def decode_value(value, headers, role, mode, folder, stem):
    info = {'field': stem, 'content_type': headers.get('content-type', ''),
            'content_encoding': headers.get('content-encoding', ''), 'warnings': []}
    info['original_string_length'] = len(value) if isinstance(value, str) else None
    try:
        blob, enc = body_bytes(value, mode, headers)
        info['input_encoding'] = enc
        if enc == 'plain string' and isinstance(value, str) and len(value) > 10 and re.fullmatch(r'[A-Za-z0-9+/_=-]+', value):
            info['warnings'].append('String resembles Base64 but failed confidence check; retry with --body-encoding base64 if source is known Base64')
        info['raw_byte_length'] = len(blob)
        if len(blob) > MAX_BODY:
            raise ValueError('Input field >64MiB')
        # Some collectors Base64-wrap a body twice. Unwrap only when the
        # first decoded layer itself looks like another valid Base64 value.
        layers = 1 if enc == 'base64' else 0
        while layers and layers < 3:
            try:
                inner_str = blob.decode('ascii')
                more = b64_decode(inner_str, forced=False,
                                  binary_hint=False)
            except UnicodeDecodeError:
                more = None
            if more is None or more == blob:
                break
            blob = more
            layers += 1
        info['base64_layers'] = layers
        if role == 'raw':
            http = parse_http(blob)
            if http:
                first, parsed_headers, blob = http
                headers = parsed_headers
                info['http_start_line'] = first
                info['http_headers'] = redact_headers(parsed_headers)
                info['content_type'] = headers.get('content-type', '')
                info['content_encoding'] = headers.get('content-encoding', '')
        methods = []
        body = unpack_body(blob, headers, methods)
        info['decompressions'] = methods
        info['decoded_byte_length'] = len(body)
        info['sha256_decoded_body'] = hashlib.sha256(body).hexdigest()
        ct = headers.get('content-type', '').lower()
        # A Snappy block can carry Prometheus Remote Write even when
        # the collector omitted Content-Type. Infer this schema only when
        # a standard __name__ metric label is actually present.
        if not ct and any('snappy' in name for name in methods):
            guessed = prometheus_v1(body)
            if guessed and any('__name__' in item['labels'] for item in guessed):
                info['result_kind'] = 'prometheus_remote_write_v1'
                info['warnings'].append('Remote Write schema inferred from Snappy and __name__ label; original HTTP Content-Type missing')
                path = emit_binary(body, folder, stem, '.pb')
                info['binary_file'] = path
                return {'format': 'prometheus_remote_write_v1', 'timeseries': guessed}, info
        # Protobuf content is structured binary; never decode entire stream as GBK/UTF-8.
        if 'protobuf' in ct or 'grpc' in ct:
            v1 = prometheus_v1(body)
            # Do not mislabel an arbitrary protobuf message as Remote Write.
            # Generic wire-level decoding is the safe fallback without schema.
            remote_hint = 'x-prometheus-remote-write-version' in headers
            if v1 is not None and (remote_hint or any('__name__' in item['labels'] for item in v1)):
                info['result_kind'] = 'prometheus_remote_write_v1'
                path = emit_binary(body, folder, stem, '.pb')
                info['binary_file'] = path
                return {'format': 'prometheus_remote_write_v1', 'timeseries': v1}, info
            generic = proto_generic(body)
            info['result_kind'] = 'protobuf_generic' if generic is not None else 'protobuf_binary'
            path = emit_binary(body, folder, stem, '.pb')
            info['binary_file'] = path
            if generic is not None:
                info['warnings'].append('Generic Protobuf wire decode; field numbers need a .proto schema for semantic names')
                return {'format': 'protobuf_generic', 'fields': generic}, info
            return {'format': 'protobuf_unrecognized', 'saved_file': path,
                    'hex_preview': body[:48].hex(' ')}, info
        txt, charset = decode_text(body, headers)
        if txt is not None:
            info['charset'] = charset
            if charset in ('gb18030', 'big5') and 'charset' not in ct:
                info['warnings'].append('Fallback CJK charset guessed; verify against original source')
            info['result_kind'] = 'text'
            if 'application/x-www-form-urlencoded' in ct:
                # parse_qs decodes percent-encoding using declared/assumed charset.
                parsed = parse_qs(txt, keep_blank_values=True, encoding=charset, errors='replace')
                info['result_kind'] = 'form'
                return {'text': txt, 'form': parsed}, info
            if 'json' in ct or txt.lstrip().startswith(('{', '[')):
                try:
                    data = json.loads(txt)
                    info['result_kind'] = 'json'
                    return data, info
                except json.JSONDecodeError:
                    info['warnings'].append('Body looked like JSON but JSON parsing failed; returned readable text')
            return txt, info
        # If no/misreported content-type, a valid protobuf wire-format may still be present.
        generic = proto_generic(body)
        if generic is not None:
            path = emit_binary(body, folder, stem, '.pb')
            info['result_kind'] = 'protobuf_generic'
            info['binary_file'] = path
            info['warnings'].append('Protobuf guessed from wire format; verify with schema')
            return {'format': 'protobuf_generic', 'fields': generic}, info
        path = emit_binary(body, folder, stem, '.bin')
        info['result_kind'] = 'binary_unrecognized'
        info['binary_file'] = path
        info['warnings'].append('Not safely interpretable as text; exact bytes saved')
        return {'format': 'binary_unrecognized', 'saved_file': path,
                'hex_preview': body[:48].hex(' ')}, info
    except Exception as exc:
        info['result_kind'] = 'error'
        info['warnings'].append(f'{type(exc).__name__}: {exc}')
        return {'decode_error': f'{type(exc).__name__}: {exc}',
                'original_preview': '[omitted: potentially sensitive input]'}, info


def recursive_process(node, ancestors, path, opts, folder, report, record_no, depth=0):
    if depth > 30:
        return node
    if isinstance(node, str) and node.lstrip().startswith(('{', '[')):
        # A frequent export layout puts a JSON object INSIDE a JSON string.
        # Open it only if it contains one of the fields of interest.
        if re.search(r'"(?:reqBody|resBody|rawPayload)"\s*:', node, re.I):
            try:
                obj = json.loads(node)
                if isinstance(obj, (dict, list)):
                    return recursive_process(obj, ancestors, path,
                                             opts, folder, report, record_no, depth+1)
            except json.JSONDecodeError:
                pass
    if isinstance(node, list):
        return [recursive_process(it, ancestors, path + f'[{i}]',
                                  opts, folder, report, record_no, depth+1)
                for i, it in enumerate(node)]
    if not isinstance(node, dict):
        return node
    result = {}
    for name, val in node.items():
        nkey = norm(name)
        dest = f'{path}.{name}' if path else str(name)
        if nkey in TARGETS:
            role = TARGETS[nkey]
            headers = find_headers(ancestors + [node], role)
            safe_path = f'{record_no:06d}_{dest}'
            decoded, info = decode_value(val, headers, role,
                                         opts.body_encoding, folder, safe_path)
            report.append(info)
            # Recurse into nested request/response fields exposed by decoding.
            # Do not re-run the SAME field, only its decoded children.
            result[name] = recursive_process(decoded, ancestors + [node], dest,
                                             opts, folder, report, record_no, depth+1)
        else:
            result[name] = recursive_process(val, ancestors + [node], dest,
                                             opts, folder, report, record_no, depth+1)
    return result


def load_records(src):
    if src.stat().st_size > MAX_INPUT_FILE:
        raise ValueError(f'Input file exceeds {MAX_INPUT_FILE // (1024 * 1024)} MiB limit')
    with src.open('rb') as stream:
        blob = stream.read(MAX_INPUT_FILE + 1)
    if len(blob) > MAX_INPUT_FILE:
        raise ValueError('Input file grew beyond size limit while reading')
    if blob.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = blob.decode('utf-16')
    else:
        try:
            text = blob.decode('utf-8-sig')
        except UnicodeError:
            text = blob.decode('gb18030')
    try:
        value = json.loads(text)
        return value
    except json.JSONDecodeError:
        values = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                values.append({'_line': n, '_parse_error': str(exc)})
        return values


def cli_safe(value):
    """Escape control characters from untrusted field names and paths in logs."""
    return str(value).encode('unicode_escape').decode('ascii')[:400]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input', type=Path)
    ap.add_argument('--body-encoding', choices=('auto', 'base64', 'plain', 'hex'), default='auto')
    ap.add_argument('-o', '--output', type=Path)
    ap.add_argument('--overwrite', action='store_true', help='Replace existing outputs, but never the input')
    opts = ap.parse_args()
    output = opts.output or opts.input.with_name(opts.input.stem + '_decoded.json')
    folder = output.parent / (output.stem + '_files')
    rpt = output.with_name(output.stem + '_report.json')
    input_path = opts.input.resolve()
    if input_path in (output.resolve(), rpt.resolve()):
        ap.error('Refusing to overwrite source input with output or report')
    if any(p.is_symlink() for p in (output, rpt, folder)):
        ap.error('Output paths must not be symlinks')
    if not opts.overwrite and (output.exists() or rpt.exists()):
        ap.error('Output exists; choose a new path or use --overwrite')
    source = load_records(opts.input)
    report = []
    if isinstance(source, list):
        parsed = [recursive_process(x, [], f'[{n}]', opts, folder, report, n) for n, x in enumerate(source, 1)]
    else:
        parsed = recursive_process(source, [], '', opts, folder, report, 1)
    secure_write(output, json.dumps(parsed, ensure_ascii=False, indent=2).encode('utf-8'), overwrite=opts.overwrite)
    secure_write(rpt, json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8'), overwrite=opts.overwrite)
    from collections import Counter
    stats = Counter(d['result_kind'] for d in report)
    print(f'Decoded fields: {len(report)}; result types: {dict(stats)}')
    print('Output JSON:', cli_safe(output))
    print('Diagnostic report:', cli_safe(rpt))
    print('Saved binary:', cli_safe(folder))
    print('For a particular field, inspect decoded report for input_encoding, result_kind, and warnings.')
    if not report:
        print('WARNING: No reqBody/resBody/rawPayload keys found (check actual field names)')
    for r in report[:20]:
        print(f"  {cli_safe(r['field'])} : {cli_safe(r['result_kind'])} / {cli_safe(r.get('input_encoding'))} / {cli_safe(r.get('decompressions', []))}")
        for w in r.get('warnings', []):
            print('    WARNING:', cli_safe(w))


if __name__ == '__main__':
    main()
