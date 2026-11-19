# GoReplay JSON Decoder

[English](README.md) | [繁體中文](README.zh-TW.md) | **简体中文**

将 JSON／JSONL HTTP 流量记录中的编码内容还原为可阅读、可检查的数据。支持本地 Python 和 Google Colab。

## 关于（About）

GoReplay JSON Decoder 用于分析 GoReplay 或其他采集工具导出的 HTTP 记录。程序递归定位 `reqBody`、`resBody`、`rawPayload` 字段，依据有效信息处理编码和压缩，再输出文本或结构化结果。不能可靠识别的二进制内容将保存为单独文件，同时生成逐字段诊断报告。

**定位：** 通用解码与排查辅助工具，不是抓包代理、漏洞扫描器，也无法在没有 Schema 的情况下理解任意 Protobuf 协议。不同导出器可能采用不同 JSON 结构。

## 功能

- **输入：** JSON 对象、数组和 JSONL，支持递归识别字段。
- **字段编码：** Base64、显式 Hex、普通文本和字节数组。
- **HTTP 压缩：** Snappy raw block、gzip、deflate；Brotli、Zstandard 为可选依赖。
- **中文与字符集：** 支持 BOM、HTTP `charset`、UTF-8、UTF-16、GB18030、Big5；输出可直接阅读的 Unicode。
- **内容解析：** JSON、URL 表单、部分原始 HTTP 报文、Protobuf wire format，以及可识别的 Prometheus Remote Write v1。
- **诊断：** 记录编码、解压缩、字符集、告警和 SHA-256；必要时另存二进制内容。

## 快速开始

需要 **Python 3.10+**。基础能力仅依赖 Python 标准库。

```bash
python goreplay_decoder.py traffic.json
python goreplay_decoder.py traffic.jsonl --body-encoding auto
python goreplay_decoder.py traffic.json -o decoded.json
```

如果已确认所有 Body 都使用 Base64，可显式指定：

```bash
python goreplay_decoder.py traffic.json --body-encoding base64
```

安装可选 Brotli 与 Zstandard 依赖：

```bash
python -m pip install -r requirements-optional.txt
```

也可执行 `python -m pip install .`，然后运行 `goreplay-json-decoder traffic.json`。

### Google Colab

[在 Colab 中打开 Notebook](https://colab.research.google.com/github/yu-min/goreplay-json-decoder/blob/main/GoReplay_JSON_Decoder_Colab.ipynb)，运行单元格并上传获准处理的 JSON／JSONL，结果会打包下载。

> **隐私提示：** HTTP 记录可能包含 Cookie、访问凭证、Token 和个人信息。未经授权，请勿上传至 Colab 或提交公开 GitHub；敏感数据应在受控环境中处理。

## 解码流程

1. 读取 JSON／JSONL，递归定位目标字段。
2. 验证字段编码，并在可识别或明确指定时还原 Base64。
3. 尝试从原始 HTTP 报文拆分 Header 和 Body。
4. 根据 `Content-Encoding` 解压缩，或谨慎识别已知压缩格式。
5. 根据内容类型解析结构，文本优先使用明确声明的字符集。
6. 对未知二进制保留精确字节，并生成诊断记录。

`Accept-Encoding` 表示客户端可接受的响应压缩格式，实际 Body 解压应依据 `Content-Encoding`。

## 输出

以 `traffic.json` 为例：

| 路径 | 内容 |
| --- | --- |
| `traffic_decoded.json` | 解码后的 JSON，中文保持可读 |
| `traffic_decoded_report.json` | 各字段编码、解压缩、类型、字符集和警告 |
| `traffic_decoded_files/` | 按需保存 Protobuf 或其他二进制文件 |

原始输入不会被覆盖。自动检测失败时，请检查诊断报告。

## 测试

使用合成数据覆盖**英文、繁体中文、简体中文**，以及 UTF-8、GB18030、Big5、gzip、deflate、Snappy/Protobuf、嵌套 Base64、HTTP 和 JSONL。

```bash
python -m unittest discover -s tests -v
```

GitHub Actions 同样会运行测试。

## 局限性

- Base64 自动判断采用启发式规则，避免误改普通文本；仅在确认编码方式后使用强制模式。
- Snappy 支持 raw block，并不覆盖所有 framed stream 格式。
- 缺少 `.proto` Schema 时，未知 Protobuf 只能输出字段编号和 wire type，不能保证协议推断准确。
- 来源没有声明字符集时，部分繁简中文编码可能存在歧义，请核对诊断告警。
- 仅支持部分 HTTP 报文布局；multipart、流式协议以及自定义导出 Schema 可能需要适配。
- 单字段解压上限为 **64 MiB**；输入文件整体载入内存，超大文件需考虑内存占用。

## 安全注意事项

输入文件默认限制为 128 MiB，解压后单字段限制为 64 MiB。除非显式使用 `--overwrite`，程序不会覆盖现有输出。诊断报告会遮蔽常见凭证、Cookie 和 API Key 请求头，但**解码结果仍可能包含敏感信息**。处理不可信流量请使用隔离环境，参见 [SECURITY.md](SECURITY.md)。

## 许可证

[Apache License 2.0](LICENSE)。

**依赖安全：** Brotli 解码必须使用 `Brotli>=1.2.1`。本工具会拒绝旧版本（CVE-2026-111497）。
