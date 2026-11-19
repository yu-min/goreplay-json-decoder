# GoReplay JSON Decoder

[English](README.md) | **繁體中文** | [简体中文](README.zh-CN.md)

將 JSON／JSONL HTTP 流量紀錄中的編碼內容還原成可閱讀、可檢查資料的 Python 工具，可在本機或 Google Colab 執行。

## 關於（About）

GoReplay JSON Decoder 用於分析 GoReplay 或其他流量收集工具匯出的 HTTP 紀錄。程式會遞迴尋找 `reqBody`、`resBody`、`rawPayload`，依據可用資訊還原編碼與壓縮，再輸出文字或結構化資料；無法確定格式的二進位資料會獨立保存，並產生逐欄位診斷報告。

**定位：** 通用解碼及疑難排除輔助工具，並非封包擷取代理程式、弱點掃描器，也不是能理解所有 Protobuf Schema 的解碼器。不同匯出器可能採用不同 JSON 格式。

## 功能

- **輸入：** JSON 物件、陣列及 JSONL，遞迴尋找欄位。
- **欄位編碼：** Base64、明確標記的 Hex、純文字及位元組陣列。
- **HTTP 壓縮：** Snappy raw block、gzip、deflate；Brotli、Zstandard 為選用功能。
- **中文與字元集：** 支援 BOM、HTTP `charset`、UTF-8、UTF-16、GB18030、Big5；輸出可直接閱讀的 Unicode 字元。
- **內容解析：** JSON、URL 表單、部分原始 HTTP 訊息、Protobuf wire format，以及可辨識的 Prometheus Remote Write v1。
- **診斷：** 記錄編碼、解壓縮、字元集、警告與 SHA-256；必要時另存二進位內容。

## 快速開始

需要 **Python 3.10 以上**。基本功能僅使用標準函式庫。

```bash
python goreplay_decoder.py traffic.json
python goreplay_decoder.py traffic.jsonl --body-encoding auto
python goreplay_decoder.py traffic.json -o decoded.json
```

若已確認所有 Body 均使用 Base64，可指定：

```bash
python goreplay_decoder.py traffic.json --body-encoding base64
```

選用 Brotli 與 Zstandard：

```bash
python -m pip install -r requirements-optional.txt
```

也可執行 `python -m pip install .`，再使用 `goreplay-json-decoder traffic.json`。

### Google Colab

[在 Colab 開啟 Notebook](https://colab.research.google.com/github/yu-min/goreplay-json-decoder/blob/main/GoReplay_JSON_Decoder_Colab.ipynb)，執行儲存格並上傳獲准處理的 JSON／JSONL，完成後自動打包解析結果。

> **隱私提醒：** HTTP 紀錄可能包含 Cookie、存取憑證、Token、個人資料。未經授權，不應上傳至 Colab 或提交到公開 GitHub；機密資料請在受控環境中處理。

## 解碼流程

1. 讀取 JSON／JSONL，找出含巢狀結構的目標欄位。
2. 驗證並辨識欄位編碼，依需要還原 Base64。
3. 嘗試從原始 HTTP 訊息分離標頭與 Body。
4. 根據 `Content-Encoding` 解壓縮，或謹慎辨識常見壓縮格式。
5. 依內容型態解析結構；文字優先採用明確宣告的字元集。
6. 不強制轉碼未知二進位，保留原始資料並輸出診斷結果。

`Accept-Encoding` 表示客戶端願意接受的回應壓縮格式；Body 應依 `Content-Encoding` 處理。

## 輸出

以 `traffic.json` 為例：

| 路徑 | 用途 |
| --- | --- |
| `traffic_decoded.json` | 解碼後的 JSON，中文維持可閱讀形式 |
| `traffic_decoded_report.json` | 各欄位編碼、解壓縮、格式、字元集及警告 |
| `traffic_decoded_files/` | 按需儲存 Protobuf 或其他二進位資料 |

不會覆寫原始輸入。自動辨識失敗時，請檢查診斷報告。

## 測試

所有測試資料均為合成資料，涵蓋**英文、繁體中文及簡體中文**，並測試 UTF-8、GB18030、Big5、gzip、deflate、Snappy/Protobuf、巢狀 Base64、HTTP 及 JSONL。

```bash
python -m unittest discover -s tests -v
```

GitHub Actions 亦會執行測試。

## 限制

- Base64 自動辨識採啟發式規則，以避免誤改純文字；請只在確認格式後使用強制 Base64 模式。
- Snappy 支援 raw block，不支援所有 framed stream 格式。
- 未提供 `.proto` Schema 時，未知 Protobuf 只能以欄位編號及 wire type 展示，不保證協定推斷正確。
- 若來源未宣告字元集，部分繁簡中文編碼可能無法可靠區分，請依警告核對原始資料。
- 只支援部分 HTTP 訊息格式；multipart、串流協定及特製匯出 Schema 可能需要擴充。
- 單欄位解壓上限 **64 MiB**；輸入檔案會載入記憶體，超大型檔案需留意記憶體使用量。

## 安全注意事項

解析器對輸入檔案（預設 128 MiB）和解壓後的單欄位資料（64 MiB）設定大小限制，並避免在未指定 `--overwrite` 時覆蓋既有輸出。診斷報告會遮蔽常見的 Cookie、授權與 API Key 標頭，但**解析結果本身仍可能包含敏感資訊**。請在受控環境處理未受信任的流量，詳見 [SECURITY.md](SECURITY.md)。

## 授權

[Apache License 2.0](LICENSE)。

**相依套件安全：** Brotli 解碼必須使用 `Brotli>=1.2.1`。本工具會拒絕較舊版本（CVE-2026-111497）。
