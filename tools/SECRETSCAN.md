# SecretScan 1.0.0 — Secret Scanner

`secretscan.py` quét mã nguồn tìm các **bí mật bị lộ** (khóa API, token, mật khẩu, private key) kiểu gitleaks/trufflehog. Sản phẩm của **Digital Core team**, viết bằng Python thuần (stdlib), không cần cài thêm gì.

```
python secretscan.py [tùy chọn] file-hoặc-thư-mục...
```

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Cách hoạt động](#2-cách-hoạt-động)
3. [Bí mật được phát hiện](#3-bí-mật-được-phát-hiện)
4. [Giảm nhiễu (false positive)](#4-giảm-nhiễu-false-positive)
5. [Tham số](#5-tham-số)
6. [Định dạng output](#6-định-dạng-output)
7. [Exit codes](#7-exit-codes)
8. [Ví dụ](#8-ví-dụ)
9. [Sử dụng trong CI](#9-sử-dụng-trong-ci)
10. [Lưu ý](#10-lưu-ý)

---

## 1. Cài đặt

Yêu cầu: **Python ≥ 3.10**. Không cần cài thêm gì:

```powershell
python secretscan.py C:\projects\myapp
python secretscan.py .env config.js
```

---

## 2. Cách hoạt động

1. Duyệt đệ quy thư mục; tự **bỏ qua** `.git`, `node_modules`, `__pycache__`, `.venv`, `dist`, `build`, file nhị phân (phát hiện qua byte NUL / tỷ lệ ký tự in được), file lớn (> 10 MB mặc định), và các đuôi tài liệu/ảnh/nén (`*.png`, `*.pdf`, `*.zip`, `*.min.js`, `*.lock`...).
2. Với mỗi dòng, áp dụng danh sách quy tắc regex (đã biên dịch sẵn, có flag case-insensitive khi cần).
3. Lọc nhiễu: từ khóa giả (`example`, `your`, `changeme`...), kiểm tra **entropy** Shannon với các quy tắc chung, bộ allowlist.
4. Báo cáo từng kết quả với **file:dòng:cột**, mức độ nghiêm trọng, giá trị bí mật (ẩn mặc định trong output text) và dòng ngữ cảnh.

---

## 3. Bí mật được phát hiện

| Rule | Mức độ |
|---|---|
| AWS Access Key ID (`AKIA...`) | HIGH |
| AWS Secret Access Key | HIGH |
| GitHub Token (`ghp_/gho_/ghu_/ghs_/ghr_`) | HIGH |
| GitHub Fine-grained PAT (`github_pat_...`) | HIGH |
| Slack Token (`xoxb-/xoxp-/xoxa-...`) | HIGH |
| Slack Webhook | HIGH |
| Google API Key (`AIza...`) | HIGH |
| Google OAuth Token (`1//0...`) | HIGH |
| GCP Service Account | HIGH |
| Stripe Live Secret Key (`sk_live_/rk_live_`) | HIGH |
| Stripe Test Secret Key (`sk_test_/rk_test_`) | MEDIUM |
| Twilio API Key (`SK...32 hex`) | HIGH |
| SendGrid API Key (`SG....`) | HIGH |
| npm Token (`npm_...`) | HIGH |
| Telegram Bot Token (`123456789:AAA...`) | HIGH |
| Private Key (`-----BEGIN ... PRIVATE KEY-----`) | HIGH |
| JWT Token (`eyJ...`) | MEDIUM |
| API Key Assignment (`api_key = "..."`, entropy ≥ 3.5) | MEDIUM |
| Password Assignment (`password = "..."`, entropy ≥ 3.0) | MEDIUM |
| Database Connection String (`mongodb://admin:pass@db.example.com`) | MEDIUM |

Xem danh sách đầy đủ khi chạy:

```powershell
python secretscan.py --rules
```

---

## 4. Giảm nhiễu (false positive)

Mặc định bật 3 lớp lọc để tránh báo nhầm:

1. **Từ khóa giả** — giá trị bí mật chứa `example`, `sample`, `your`, `changeme`, `placeholder`, `replace`, `todo`, `dummy`, `fake`, `public`, `default`, `password`... sẽ bị bỏ qua; đồng thời nếu dòng chứa từ chỉ dấu placeholder (`example`, `sample`, `your`, `demo`...) như `mongodb://admin:pass@db.example.com` thì cũng bỏ qua.
2. **Entropy Shannon** — các rule chung (API Key/Password Assignment) chỉ báo khi chuỗi đủ ngẫu nhiên (ngưỡng 3.0–3.5). Ví dụ `password = "postgres"` hay `api_key = "your-key"` không bị bắt.
3. **Allowlist** — tắt bằng cách cấu hình riêng:

```powershell
# Bỏ qua mọi thứ khớp regex (dùng nhiều lần)
python secretscan.py . --allow "1234567890" --allow "sandbox"

# File allowlist: 1 regex/dòng, '#' là ghi chú
python secretscan.py . --allowlist allow.txt
```

> Khi cần báo cáo thô hơn (bỏ entropy check): `--no-entropy`.

---

## 5. Tham số

| Tham số | Ý nghĩa |
|---|---|
| `files...` | File hoặc thư mục cần quét |
| `-f, --file FILE` | Thêm 1 file quét (dùng nhiều lần) |
| `--ext EXTS` | Chỉ quét đuôi mở rộng: `--ext py,js,env` |
| `--exclude GLOB` | Bỏ qua file/thư mục khớp glob (dùng nhiều lần) |
| `--min-severity S` | Chỉ báo từ mức `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` (mặc định `LOW`) |
| `--allow REGEX` | Bỏ qua kết quả khớp regex (dùng nhiều lần) |
| `--allowlist FILE` | File chứa các regex bỏ qua (1 regex/dòng) |
| `--no-entropy` | Tắt kiểm tra entropy |
| `--max-size MB` | Bỏ qua file lớn hơn N MB (mặc định 10) |
| `--no-mask` | Hiện đầy đủ bí mật trong output text (mặc định ẩn giữa) |
| `--rules` | Liệt kê các quy tắc phát hiện rồi thoát |
| `--json` / `--csv` | Xuất JSON / CSV (chứa giá trị bí mật đầy đủ) |
| `--short` | 1 dòng tổng kết cho mỗi file có bí mật |
| `-o, --output FILE` | Ghi kết quả ra file |
| `-v, --verbose` | In từng file đang quét ra stderr |
| `--no-color` | Tắt màu ANSI |

---

## 6. Định dạng output

### Output text (mặc định)

```
;; SecretScan 1.0.0 <<>> Digital Core team
;; 3 file, 11 bí mật (C0/H7/M4/L0) trong 0.1s

[HIGH  ] AWS Access Key ID    config.js:1:26
    ! AKIA***********LMNOP          <- bí mật bị ẩn giữa
    @ export AWS_ACCESS_KEY_ID=AKIA...  <- dòng ngữ cảnh
```

### Output JSON (`--json`)

```json
{
  "tool": "SecretScan", "version": "1.0.0", "team": "Digital Core team",
  "queried_at": "...",
  "summary": { "files": 3, "bytes": 967, "secrets": 11,
               "critical": 0, "high": 7, "medium": 4, "low": 0 },
  "secrets": [
    { "rule": "AWS Access Key ID", "severity": "HIGH",
      "file": "config.js", "line": 1, "column": 26,
      "secret": "AKIA...", "context": "export AWS_ACCESS_KEY_ID=..." }
  ]
}
```

### Output CSV (`--csv`)

Header: `severity,rule,file,line,column,secret`

---

## 7. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Quét xong, **không** phát hiện bí mật nào (từ mức `--min-severity`) |
| `1` | Có bí mật được phát hiện |
| `2` | Không quét được file nào (đường dẫn sai / không có file hợp lệ / toàn binary) |
| `3` | Lỗi đầu vào (không có path, regex `--allow`/`--allowlist` sai, không đọc được allowlist) |

---

## 8. Ví dụ

```powershell
# Quét toàn bộ repo, bỏ các thư mục quen thuộc
python secretscan.py C:\projects\myapp

# Quét vài file cụ thể
python secretscan.py .env config.js id_rsa

# Chỉ file mã nguồn
python secretscan.py C:\projects\myapp --ext py,js,go,rs

# Chỉ quan tâm mức HIGH trở lên (exit 1 khi có)
python secretscan.py C:\projects\myapp --min-severity HIGH --short

# Bỏ qua kết quả giả quen thuộc
python secretscan.py C:\projects\myapp --allow "mycompany" --allow "1234567890"

# Xuất JSON/CSV cho tooling
python secretscan.py C:\projects\myapp --json -o scan.json
python secretscan.py C:\projects\myapp --csv -o scan.csv

# Xem danh sách quy tắc
python secretscan.py --rules
```

---

## 9. Sử dụng trong CI

```powershell
# PowerShell — dừng pipeline khi phát hiện bí mật
python secretscan.py . --min-severity HIGH
if ($LASTEXITCODE -eq 1) { throw "Phat hien bi mat trong source!" }
```

```bash
# Git Bash / Linux
python secretscan.py . --short
```

> Nên lưu file `.secretscan-allowlist` trong repo để dùng chung: `--allowlist .secretscan-allowlist`.

---

## 10. Lưu ý

- SecretScan quét **file trên đĩa hiện tại** — không truy vết lịch sử git. Bí mật đã bị xóa nhưng còn trong commit cũ vẫn tồn tại (cần xoay vòng/revoke và xem lại `git log`).
- Quy tắc khóa nổi tiếng (AWS, GitHub, Stripe...) có format riêng ít nhiễu; các rule "Assignment" chung dùng entropy để chặn nhiễu — có thể bỏ sót chuỗi ký tự nhỏ hoặc thông dụng.
- Dùng cho **hệ thống bạn sở hữu hoặc được ủy quyền kiểm tra**.
- Khi phát hiện bí mật thật: **revoke/rotate ngay** (không xóa file là đủ).
