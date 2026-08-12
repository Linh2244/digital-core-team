# DepCheck 1.0.0

Dependency Vulnerability Checker — quét các package trong dự án, đối chiếu
với cơ sở dữ liệu CVE và xuất báo cáo **text / JSON / Markdown**.

Thuộc bộ công cụ bảo mật **Digital Core team** (cùng nhóm với `tlscheck.py`,
`httpsec.py`, `secretscan.py`, ...). Viết bằng Python chuẩn, **không cần thư
viện ngoài**.

## Tính năng

- Hỗ trợ nhiều loại file lockfile / manifest:
  - Python: `requirements.txt`, `Pipfile`, `poetry.lock`
  - Node.js: `package.json`, `package-lock.json`
  - Java: `pom.xml`
  - Go: `go.mod`
  - Rust: `Cargo.lock`
- Hoặc quét trực tiếp từ dòng lệnh: `requests==2.31.0`
- Nhiều ecosystem (PyPI, npm, Maven, Go, crates.io, ...)
- Cơ sở dữ liệu CVE: **OSV.dev** (miễn phí, không cần API key)
- Cache local tại `~/.depcheck/cache` — chạy được **offline** sau khi `--update`
- Khớp phiên bản chính xác (`==2.31.0`) và khớp khoảng (`>=2.0,<3.0`,
  `^4.18.0`, `~1.2.3`)
- Điểm an toàn (0–100) + grade A–F
- Exit code chuẩn để dùng trong CI
- Output: text màu / JSON / Markdown, ghi ra file bằng `-o`

## Cài đặt

Không cần cài thêm gì ngoài Python 3.10+:

```powershell
python D:\tools\depcheck.py --version
```

## Cách dùng

### Quét file requirements

```powershell
python depcheck.py requirements.txt
```

### Quét nhiều file cùng lúc

```powershell
python depcheck.py requirements.txt package.json pom.xml go.mod
```

### Quét package trực tiếp

```powershell
python depcheck.py requests==2.31.0 urllib3==1.26.17
python depcheck.py -e npm axios==1.6.0
```

### Xuất báo cáo Markdown

```powershell
python depcheck.py requirements.txt --md -o report.md
```

### Xuất JSON

```powershell
python depcheck.py requirements.txt --json -o report.json
```

### Cập nhật cache CVE

```powershell
python depcheck.py requirements.txt --update
```

### Chạy offline (dùng cache có sẵn)

```powershell
python depcheck.py requirements.txt --offline
```

## Cơ sở dữ liệu CVE

- Nguồn: **OSV.dev API** (`https://api.osv.dev/v1/query`) — tổng hợp từ
  NVD, GitHub Advisory, PyPA, Go vuln database, RustSec, ...
- Cache local: `~/.depcheck/cache/<Ecosystem>__<package>.json`, TTL 1 ngày.
- `--update`: bỏ qua TTL, tải lại từ OSV.dev.
- `--offline`: chỉ đọc cache; báo lỗi (exit 3) nếu chưa có cache.

## Exit codes

| Code | Ý nghĩa |
|------|---------|
| 0    | Không có lỗ hổng nào (>= `--min-severity`) |
| 1    | Có lỗ hổng bảo mật |
| 2    | Input sai (file không hỗ trợ, target sai) |
| 3    | Lỗi mạng / không lấy được CVE database |

## Tuỳ chọn

```
usage: depcheck [-h] [-e ECO] [--update] [--offline] [-T TIMEOUT]
                [--threads THREADS] [--min-severity {CRITICAL,HIGH,MEDIUM,LOW}]
                [--json] [--md] [-o FILE] [--no-color] [--version]
                [targets ...]

  targets             file lockfile hoặc 'name==version'
  -e, --ecosystem     ecosystem cho target name==version (mặc định PyPI)
  --update            buộc cập nhật cache CVE từ OSV.dev
  --offline           chỉ dùng cache local, không gọi mạng
  -T, --timeout       timeout gọi API OSV (mặc định 10s)
  --threads           số query song song (mặc định 8)
  --min-severity      ngưỡng báo lỗi / exit 1 (mặc định LOW)
  --json              output JSON
  --md                output Markdown
  -o, --output FILE   ghi kết quả ra file (kèm in ra màn hình)
  --no-color          tắt màu ANSI
  --version           in phiên bản
```

## Ví dụ kết quả

```
;; DepCheck 1.0.0 <<>> Digital Core team

requests 2.31.0  (PyPI)  [requirements.txt]
  FAIL  MEDIUM   CVE-2024-35195: MEDIUM - fix: 2.32.0 - Requests `Session`
                  object does not verify requests after making first request
                  with verify=False
  FAIL  MEDIUM   CVE-2024-47081: MEDIUM - fix: 2.32.4 - Requests vulnerable
                  to .netrc credentials leak via malicious URLs
  FAIL  MEDIUM   CVE-2026-25645: MEDIUM - fix: 2.33.0 - Requests has
                  Insecure Temp File Reuse ...

  VERDICT: Score 70/100 (C) | 1 goi, 1 bi anh huong, 3 CVE
```

## Lưu ý

- Với khai báo dạng khoảng (ví dụ `flask>=2.0,<3.0`), DepCheck báo
  `[khoang phien ban]` và đánh dấu nếu khoảng đó **cắt** khoảng bị ảnh
  hưởng — có thể báo hơi rộng. Nên dùng lockfile (có phiên bản chính xác)
  khi có thể.
- Package giống nhau khai báo nhiều lần chỉ query CVE một lần.
- Các lỗ hổng trùng (CVE = alias của GHSA/PYSEC) được gộp lại một dòng.
