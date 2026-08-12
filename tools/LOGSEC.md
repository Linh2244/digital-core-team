# LogSec 1.0.0 — Log Security Analyzer

`logsec.py` phân tích file log (web server, SSH, JSONL) để phát hiện mối đe dọa và tấn công. Sản phẩm của **Digital Core team**, viết bằng Python thuần (stdlib), không cần cài thêm thư viện.

```
python logsec.py [tùy chọn] file-log...
```

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Định dạng log được hỗ trợ](#2-định-dạng-log-được-hỗ-trợ)
3. [Mối đe dọa được phát hiện](#3-mối-đe-dọa-được-phát-hiện)
4. [Tham số](#4-tham-số)
5. [Ví dụ](#5-ví-dụ)
6. [Định dạng output](#6-định-dạng-output)
7. [Exit codes](#7-exit-codes)
8. [Sử dụng trong script / CI](#8-sử-dụng-trong-script--ci)
9. [Giới hạn và lưu ý](#9-giới-hạn-và-lưu-ý)

---

## 1. Cài đặt

Yêu cầu: **Python ≥ 3.10** (máy đã có sẵn trong bộ Digital Core Toolkit).

Không cần cài thêm gì — chạy trực tiếp:

```powershell
python logsec.py access.log
```

---

## 2. Định dạng log được hỗ trợ

Mặc định `--format auto` sẽ tự nhận dạng từ 50 dòng đầu tiên. Có thể ép bằng `--format`.

| Format | Nhận dạng | Ví dụ dòng |
|---|---|---|
| `apache` / `clf` | `IP - - [ngày] "METHOD path" status bytes` | `192.0.2.5 - - [10/Oct/2026:08:15:01 +0700] "GET /index.html HTTP/1.1" 200 512` |
| `combined` | Như CLF + referer + user-agent | `... 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"` |
| `auth` | Syslog SSH (Debian/Ubuntu, `auth.log`/`secure`) | `Jan  5 01:12:31 server sshd[1234]: Failed password for root from 203.0.113.9 port 54321 ssh2` |
| `jsonl` | 1 JSON object / dòng | `{"ts": "2026-07-01T10:00:00Z", "src_ip": "198.51.100.9", "method": "GET", "uri": "/login.php", "status": 200}` |
| `generic` | Dòng phổ thông, tự đoán | `2026-07-01 10:00:00 198.51.100.5 POST /api/data 200` |

**Khóa JSONL được nhận dạng** (không phân biệt hoa thường):

| Trường | Khóa chấp nhận |
|---|---|
| IP | `ip`, `src_ip`, `client_ip`, `remote_addr`, `source_ip` |
| Thời gian | `timestamp`, `time`, `@timestamp`, `ts`, `datetime` |
| Method | `method`, `http_method`, `req_method` |
| Đường dẫn | `path`, `uri`, `request`, `url`, `full_request` |
| Status | `status`, `status_code`, `http_status`, `response` |
| User-Agent | `user_agent`, `ua`, `agent` |
| Referer | `referer`, `referrer` |

> Lưu ý: dòng bắt đầu bằng ký tự BOM (UTF-8 with BOM) được xử lý tự động, không tính là lỗi.

---

## 3. Mối đe dọa được phát hiện

### 3.1. Web (apache/clf/combined/jsonl/generic)

| Rule | Tên | Mức độ | Điều kiện |
|---|---|---|---|
| LFI | Local file inclusion | **CRITICAL** | Path chứa `/etc/passwd`, `file=`, `file://` hoặc pattern LFI |
| SQLi | SQL injection payload | HIGH | Path/query chứa `' OR 1=1`, `UNION SELECT`, `'--`, v.v. |
| XSS | XSS payload | HIGH | Path/query chứa `<script`, `alert(`, `javascript:` |
| TRAV | Path traversal | HIGH | Path chứa chuỗi `../` |
| BRUTE | Web brute force (401/403) | HIGH | ≥ 20 lần HTTP 401/403 từ cùng 1 IP |
| SCAN | Path scan | MEDIUM | ≥ 30 đường dẫn trả về 4xx riêng biệt từ cùng 1 IP |
| SENS | Sensitive path probe | MEDIUM | Path trỏ tới `.git`, `.env`, `config.php.bak`, file backup `.zip`/`.sql`, `phpinfo`, v.v. |
| UA | Scanner user-agent | LOW | User-Agent của công cụ quét (sqlmap, nikto, nmap, masscan, gobuster, wpscan...) |

### 3.2. SSH (auth)

| Rule | Tên | Mức độ | Điều kiện |
|---|---|---|---|
| SSHBF | SSH brute force | **HIGH** | ≥ 5 lần `Failed password` từ cùng 1 IP |
| SSHE | SSH user enumeration | MEDIUM | ≥ 10 user không tồn tại (`Invalid user`) từ cùng 1 IP |

Các sự kiện SSH được phân loại: `Failed password` (sai mật khẩu), `Invalid user` (user không tồn tại), `Accepted` (thành công — hiển thị trong phần "login thành công"). User thành công khi đã có `Accepted` trước đó trong log.

---

## 4. Tham số

| Tham số | Ý nghĩa |
|---|---|
| `files...` | File log cần phân tích (nhiều file cùng lúc) |
| `-f, --file FILE` | Thêm 1 file log (dùng nhiều lần) |
| `--format` | Ép định dạng: `auto` (mặc định), `apache`, `clf`, `combined`, `auth`, `jsonl`, `generic` |
| `--top N` | Số mục trong mỗi bảng top (mặc định 10) |
| `--ip IP` | Chỉ phân tích dòng có IP này |
| `--path SUB` | Chỉ giữ dòng có đường dẫn chứa chuỗi SUB |
| `--since TS` | Chỉ giữ dòng từ mốc thời gian này (ISO, VD `2026-08-01T00:00`) |
| `--until TS` | Chỉ giữ dòng trước mốc thời gian này |
| `--last-hours N` | Chỉ giữ dòng trong N giờ gần nhất |
| `--threats-only` | Chỉ in phần THREATS |
| `--min-severity S` | Mức tối thiểu để **hiển thị** (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`, mặc định `LOW`) |
| `--exit-on S` | Exit code `1` khi có mối đe dọa từ mức này trở lên (mặc định `HIGH`) |
| `--json` | Output JSON |
| `--csv` | Output CSV danh sách mối đe dọa |
| `--short` | Output gọn 1 dòng/file |
| `-o, --output FILE` | Ghi kết quả ra file (vẫn in ra màn hình) |
| `-v, --verbose` | Thêm bảng Top User-Agent / Top Referrer |
| `--no-color` | Tắt màu ANSI |

> `--since`/`--until` chấp nhận cả dạng có offset múi giờ (`2026-07-01T10:00:02Z`) và không có; so sánh tự chuẩn hóa giữa thời gian có/không có múi giờ.

---

## 5. Ví dụ

### Báo cáo đầy đủ

```powershell
python logsec.py access.log
python logsec.py access.log auth.log
```

### Chỉ xem mối đe dọa

```powershell
python logsec.py access.log --threats-only
python logsec.py auth.log --threats-only
```

### Output gọn cho CI

```powershell
python logsec.py access.log --short
# access.log: 37 dòng, 37 parse, 0 lỗi
# TOTAL: 37 dòng, 7 threats (C1/H4/M1/L1)
```

### Lọc theo IP / đường dẫn / thời gian

```powershell
python logsec.py access.log --ip 192.0.2.99
python logsec.py access.log --path "/login"
python logsec.py access.log --since 2026-10-10T14:00:00 --until 2026-10-11T00:00:00
python logsec.py access.log --last-hours 24
python logsec.py -f secure --format auth --ip 203.0.113.9
```

### Xuất JSON / CSV

```powershell
python logsec.py access.log --json -o report.json
python logsec.py access.log --csv -o threats.csv
```

### Kiểm tra mức nghiêm trọng

```powershell
python logsec.py access.log --min-severity HIGH --threats-only
```

---

## 6. Định dạng output

### Output text (mặc định)

Gồm: dòng header (file, format, số dòng parse/lỗi), tổng kết, và với mỗi file: HTTP status, top paths, top sources (kèm dung lượng bytes), timeline theo giờ, phần SSH (nếu là log auth), và danh sách THREATS.

Với `-v` thêm 2 bảng: Top User-Agent và Top Referrer.

### Output JSON (`--json`)

```json
{
  "tool": "LogSec", "version": "1.0.0", "team": "Digital Core team",
  "queried_at": "...",
  "files": [ { "source": "...", "format": "...", "lines": 37, "parsed": 37,
               "errors": 0, "period": "..." } ],
  "totals": { "lines": 37, "parsed": 37, "threats": 7,
              "critical": 1, "high": 4, "medium": 1, "low": 0 },
  "web": { "top_ips": [...], "status": {...}, "top_paths": [...],
           "top_ua": [...], "timeline": [...] },
  "auth": { "top_failed_ips": [...], "top_failed_users": [...], "accepted": 0 },
  "threats": [ { "rule": "LFI", "name": "Local file inclusion",
                 "severity": "CRITICAL", "ip": "...", "count": 2,
                 "sample": "..." } ]
}
```

### Output CSV (`--csv`)

Header: `severity,rule,name,ip,count,sample` — mỗi dòng 1 mối đe dọa.

### Output gọn (`--short`)

1 dòng/file + 1 dòng tổng kết, không màu ANSI — tiện cho CI.

---

## 7. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Không có mối đe dọa nào từ mức `--exit-on` trở lên |
| `1` | Có mối đe dọa từ mức `--exit-on` trở lên (mặc định `HIGH`) |
| `2` | Không đọc được / không phân tích được file nào |
| `3` | Lỗi đầu vào: không có file, `--since`/`--until` sai định dạng |

> `--exit-on` độc lập với `--min-severity`: `--min-severity` chỉ lọc phần hiển thị, còn exit code luôn tính trên toàn bộ mối đe dọa phát hiện được.

---

## 8. Sử dụng trong script / CI

```powershell
# PowerShell — dừng nếu có tấn công HIGH trở lên
python logsec.py access.log --exit-on HIGH
if ($LASTEXITCODE -ne 0) { Write-Warning "Phat hien tan cong!" }

# Git Bash / Linux
python logsec.py /var/log/auth.log --threats-only --exit-on MEDIUM
```

```bash
# Kiểm tra trong CI, exit 1 khi phát hiện SQLi/LFI/XSS/brute-force
python logsec.py access.log --min-severity HIGH --short
```

---

## 9. Giới hạn và lưu ý

- Chỉ phân tích **log đã ghi** — không chặn tấn công theo thời gian thực (khác WAF/IDS).
- Threshold (số lần 401/403, số đường dẫn 4xx...) là giá trị mặc định; môi trường cao tải có thể cần điều chỉnh.
- Log có cấu trúc khác lạ (nginx JSON, Windows Event Log...) có thể cần chuyển về JSONL hoặc generic trước khi dùng.
- Dùng cho **hệ thống bạn sở hữu hoặc được ủy quyền kiểm tra**.
