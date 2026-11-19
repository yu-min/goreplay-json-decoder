"""Synthetic test vectors in English, Traditional Chinese, and Simplified Chinese."""
import base64
import gzip
import json
import struct
import tempfile
import unittest
import zlib
import os
import sys
import subprocess
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

from goreplay_decoder import (
    __version__, b64_decode, decode_value, load_records, prometheus_v1,
    recursive_process, snappy_block_decompress, dechunk, secure_write, parse_http,
)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def encode_json(data, charset='utf-8') -> str:
    return b64(json.dumps(data, ensure_ascii=False).encode(charset))


def varint(n):
    data = bytearray()
    while n > 127:
        data.append((n & 127) | 128)
        n >>= 7
    data.append(n)
    return bytes(data)


def pb_field(index, payload: bytes):
    return varint((index << 3) | 2) + varint(len(payload)) + payload


def snappy_literal(plain: bytes) -> bytes:
    if len(plain) < 61:
        tag = bytes([(len(plain) - 1) << 2])
    elif len(plain) <= 256:
        tag = bytes([60 << 2, len(plain) - 1])
    else:
        tag = bytes([61 << 2]) + (len(plain) - 1).to_bytes(2, 'little')
    return varint(len(plain)) + tag + plain


class GoReplayDecoderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def decode(self, value, content_type='', content_encoding='', field='reqBody', mode='auto'):
        headers = {'content-type': content_type, 'content-encoding': content_encoding}
        return decode_value(value, headers, 'request', mode, self.folder, field)

    def test_notebook_uses_identical_decoder_source(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'goreplay_decoder.py').read_text(encoding='utf-8')
        notebook = json.loads((root / 'GoReplay_JSON_Decoder_Colab.ipynb').read_text(encoding='utf-8'))
        expected = source.rsplit("\n\nif __name__ == '__main__':\n    main()", 1)[0].rstrip() + "\n"
        self.assertEqual(''.join(notebook['cells'][1]['source']), expected)

    def test_version(self):
        self.assertEqual(__version__, '1.1.0')

    def test_english_utf8_json(self):
        data = {'status': 'Ready', 'message': 'Operation completed'}
        decoded, info = self.decode(encode_json(data), 'application/json; charset=utf-8')
        self.assertEqual(decoded, data)
        self.assertEqual(info['result_kind'], 'json')

    def test_traditional_chinese_utf8_json(self):
        data = {'訊息': '訂單已完成', '地點': '測試環境', '服務': '使用者設定'}
        decoded, info = self.decode(encode_json(data), 'application/json')
        self.assertEqual(decoded, data)
        self.assertEqual(info['charset'], 'utf-8')

    def test_simplified_chinese_utf8_json(self):
        data = {'消息': '订单已完成', '地点': '测试环境', '服务': '用户设置'}
        decoded, info = self.decode(encode_json(data), 'application/json')
        self.assertEqual(decoded, data)
        self.assertEqual(info['charset'], 'utf-8')

    def test_nested_encoded_json_all_three_languages(self):
        nested = {'reqBody': encode_json({'English': 'Success', '繁體': '測試成功', '简体': '测试成功'})}
        payload = {'response': {'resBody': encode_json(nested)}}
        reports = []
        processed = recursive_process(payload, [], '', SimpleNamespace(body_encoding='auto'), self.folder, reports, 1)
        result = processed['response']['resBody']['reqBody']
        self.assertEqual(result['English'], 'Success')
        self.assertEqual(result['繁體'], '測試成功')
        self.assertEqual(result['简体'], '测试成功')
        self.assertEqual(len(reports), 2)

    def test_gzip_gb18030_simplified_chinese(self):
        original = '简体中文：网络访问记录'
        val = b64(gzip.compress(original.encode('gb18030')))
        decoded, info = self.decode(val, 'text/plain; charset=gb18030', 'gzip')
        self.assertEqual(decoded, original)
        self.assertIn('gzip', info['decompressions'])

    def test_big5_traditional_chinese(self):
        original = '繁體中文：網路存取紀錄'
        # Charset must come from source; GB18030 and Big5 are not always distinguishable.
        decoded, info = self.decode(b64(original.encode('big5')), 'text/plain; charset=big5')
        self.assertEqual(decoded, original)
        self.assertEqual(info['charset'], 'big5')

    def test_deflate_english(self):
        original = 'Compression test with a few English words'
        decoded, info = self.decode(b64(zlib.compress(original.encode())), 'text/plain', 'deflate')
        self.assertEqual(decoded, original)
        self.assertIn('deflate', info['decompressions'])

    def test_utf16_with_bom(self):
        original = 'Hello 繁體中文 Sample'
        decoded, info = self.decode(b64(original.encode('utf-16')), 'text/plain')
        self.assertEqual(decoded, original)
        self.assertEqual(info['charset'], 'utf-16')

    def test_raw_http_payload_with_chinese(self):
        plain = json.dumps({'language': '繁體中文', 'status': '成功'}, ensure_ascii=False).encode('utf-8')
        raw = b'HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n' + plain
        decoded, info = decode_value(b64(raw), {}, 'raw', 'auto', self.folder, 'rawPayload')
        self.assertEqual(decoded['language'], '繁體中文')
        self.assertEqual(info['http_start_line'], 'HTTP/1.1 200 OK')

    def test_snappy_prometheus_labels_three_languages(self):
        def label(k, v):
            return pb_field(1, k.encode('utf-8')) + pb_field(2, v.encode('utf-8'))
        labels = [label('__name__', 'requests_total'), label('en', 'Request volume'),
                  label('zh_TW', '請求數量'), label('zh_CN', '请求数量')]
        sample = b'\x09' + struct.pack('<d', 2.0) + b'\x10' + varint(1000)
        ts = b''.join(pb_field(1, l) for l in labels) + pb_field(2, sample)
        plain = pb_field(1, ts)
        compressed = snappy_literal(plain)
        self.assertEqual(snappy_block_decompress(compressed), plain)
        decoded, info = self.decode(b64(compressed), 'application/x-protobuf', 'snappy')
        self.assertEqual(info['result_kind'], 'prometheus_remote_write_v1')
        out = decoded['timeseries'][0]['labels']
        self.assertEqual((out['en'], out['zh_TW'], out['zh_CN']), ('Request volume', '請求數量', '请求数量'))

    def test_unknown_protobuf_not_misidentified_as_prometheus(self):
        # Nested label-like data alone does not establish protocol identity.
        fake = pb_field(1, pb_field(1, pb_field(1, b'key') + pb_field(2, b'value')))
        decoded, info = self.decode(b64(fake), 'application/x-protobuf')
        self.assertNotEqual(info['result_kind'], 'prometheus_remote_write_v1')
        self.assertEqual(info['result_kind'], 'protobuf_generic')

    def test_invalid_base64_auto_does_not_alter_plain_text(self):
        original = 'Short plain text'
        decoded, info = self.decode(original, 'text/plain')
        self.assertEqual(decoded, original)
        self.assertEqual(info['input_encoding'], 'plain string')

    def test_jsonl_english_traditional_simplified(self):
        src = self.folder / 'records.jsonl'
        rows = [{'reqBody': encode_json({'text':'Hello'})},
                {'reqBody': encode_json({'text':'你好，繁體中文测试'})},
                {'reqBody': encode_json({'text':'你好，简体中文测试'})}]
        src.write_text('\n'.join(json.dumps(r, ensure_ascii=False) for r in rows), encoding='utf-8')
        self.assertEqual(load_records(src), rows)

    def test_unknown_binary_saved_without_collision(self):
        byte_seq = b'\xff\x01\xff\x02\x00\xf0'
        result1, info1 = self.decode(b64(byte_seq), 'application/octet-stream', field='x?')
        result2, info2 = self.decode(b64(byte_seq+b'\x03'), 'application/octet-stream', field='x/')
        self.assertNotEqual(info1['binary_file'], info2['binary_file'])
        self.assertTrue(Path(result1['saved_file']).is_file())
        self.assertTrue(Path(result2['saved_file']).is_file())


    def test_gzip_decompression_bomb_is_bounded(self):
        payload = b64(gzip.compress(b'Z' * 8192))
        with patch('goreplay_decoder.MAX_BODY', 1024):
            decoded, info = self.decode(payload, 'text/plain', 'gzip')
        self.assertEqual(info['result_kind'], 'error')
        self.assertNotIn('Z' * 20, str(decoded))

    def test_snappy_claimed_size_over_limit_is_rejected(self):
        block = varint(1024 * 1024 * 1024) + b'\x00'
        with self.assertRaises(ValueError):
            snappy_block_decompress(block)

    def test_brotli_decompression_bomb_is_bounded(self):
        try:
            import brotli
        except ImportError:
            self.skipTest('Brotli is optional')
        payload = b64(brotli.compress(b'B' * 8192))
        with patch('goreplay_decoder.MAX_BODY', 1024), patch('importlib.metadata.version', return_value='1.2.1'):
            decoded, info = self.decode(payload, 'text/plain', 'br')
        self.assertEqual(info['result_kind'], 'error')

    def test_vulnerable_brotli_refused_before_decompression(self):
        with patch('importlib.metadata.version', return_value='1.2.0'):
            decoded, info = self.decode(b64(b'unsafe-codec'), 'text/plain', 'br')
        self.assertEqual(info['result_kind'], 'error')
        self.assertIn('Brotli', json.dumps(info))

    def test_invalid_chunk_size_rejected(self):
        for candidate in (b'-1\r\nx\r\n', b'XYZ\r\n', b'1\r\nx?', b'fffffffffffffffff\r\n'):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    dechunk(candidate)

    def test_valid_chunked_http(self):
        raw = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n'
        parsed = parse_http(raw)
        self.assertEqual(parsed[2], b'Hello')

    def test_malformed_http_header_limit(self):
        raw = b'HTTP/1.1 200 OK\r\nX-Test: ' + b'X' * 70000 + b'\r\n\r\nbody'
        with self.assertRaises(ValueError):
            parse_http(raw)

    def test_credentials_redacted_in_diagnostics(self):
        raw = (b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
               b'Authorization: Bearer confidential-secret\r\n'
               b'Cookie: session=private\r\nX-API-Key: secret-value\r\n\r\nHello')
        # rawPayload uses the HTTP header extraction path.
        decoded, info = decode_value(b64(raw), {}, 'raw', 'auto', self.folder, 'rawPayload')
        self.assertEqual(decoded, 'Hello')
        self.assertEqual(info['http_headers']['authorization'], '[REDACTED]')
        self.assertEqual(info['http_headers']['cookie'], '[REDACTED]')
        self.assertEqual(info['http_headers']['x-api-key'], '[REDACTED]')
        self.assertNotIn('confidential-secret', json.dumps(info))
        self.assertNotIn('secret-value', json.dumps(info))

    def test_error_never_echoes_raw_sensitive_payload(self):
        sensitive = 'PRIVATE-SECRET-$$$' * 8
        decoded, info = self.decode(sensitive, 'text/plain', mode='base64')
        self.assertEqual(info['result_kind'], 'error')
        self.assertNotIn('PRIVATE-SECRET', json.dumps(decoded))

    def test_secure_write_refuses_existing_file(self):
        path = self.folder / 'output.json'
        secure_write(path, b'first')
        with self.assertRaises(FileExistsError):
            secure_write(path, b'second')
        self.assertEqual(path.read_bytes(), b'first')
        if os.name == 'posix':
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink unsupported')
    def test_secure_write_refuses_symlink_output(self):
        victim = self.folder / 'victim.txt'
        victim.write_text('unchanged')
        path = self.folder / 'redirect.json'
        path.symlink_to(victim)
        with self.assertRaises(ValueError):
            secure_write(path, b'leak', overwrite=True)
        self.assertEqual(victim.read_text(), 'unchanged')

    def test_input_size_limit(self):
        src = self.folder / 'large.json'
        src.write_bytes(b'0' * 256)
        with patch('goreplay_decoder.MAX_INPUT_FILE', 128):
            with self.assertRaises(ValueError):
                load_records(src)

    def test_cli_refuses_input_overwrite(self):
        src = self.folder / 'source.json'
        src.write_text('{"reqBody":"text"}')
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'goreplay_decoder.py'),
             str(src), '-o', str(src)], capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(src.read_text(), '{"reqBody":"text"}')

    def test_cli_does_not_emit_terminal_escape_sequences(self):
        src = self.folder / 'unsafe.json'
        src.write_text(json.dumps({'\x1b[31m': {'reqBody': encode_json({'message': 'okay'})}}))
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'goreplay_decoder.py'), str(src)],
            capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0)
        self.assertNotIn('\x1b', completed.stdout)

    def test_cli_refuses_existing_output(self):
        src = self.folder / 'source.json'
        src.write_text('{"reqBody":"text"}')
        target = self.folder / 'result.json'
        target.write_text('important')
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'goreplay_decoder.py'),
             str(src), '-o', str(target)], capture_output=True, text=True
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(target.read_text(), 'important')

    def test_encoded_field_input_limit(self):
        with patch('goreplay_decoder.MAX_FIELD_INPUT', 32):
            decoded, info = self.decode('A' * 40, 'text/plain', mode='base64')
        self.assertEqual(info['result_kind'], 'error')

    def test_unicode_roundtrip_neutral_examples(self):
        rows = ['Hello, English test', '你好，繁體中文测试', '你好，简体中文测试']
        for line in rows:
            with self.subTest(language=line):
                result, info = self.decode(b64(line.encode('utf-8')), 'text/plain; charset=utf-8')
                self.assertEqual(result, line)


if __name__ == '__main__':
    unittest.main()
