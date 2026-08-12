# Digital Core Security Toolkit

Bộ công cụ viết bằng Python thuần (stdlib), chạy trên Windows/macOS/Linux, gồm tám công cụ:

| Công cụ | Mô tả |
|---|---|
| **`pyscan.py`** | Port scanner nâng cao (giống nmap + JSON, lịch sử diff, SSL/TLS chi tiết) |
| **`httpsec.py`** | HTTP security scanner (TLS, headers, cookies, methods, paths, CORS, redirect) |
| **`dnslookup.py`** | DNS lookup đầy đủ kiểu dig (mọi loại bản ghi, DNSSEC, trace, TCP/EDNS, JSON) |
| **`subfind.py`** | Subdomain finder (crt.sh, brute-force DNS, zone transfer/AXFR, wildcard filter, JSON) |
| **`logsec.py`** | Log security analyzer (apache/CLF/combined, auth SSH, JSONL, generic; phát hiện SQLi/XSS/LFI/brute-force; output text/JSON/CSV) |
| **`pwgen.py`** | Password generator (secrets, mật khẩu/passphrase, kiểm tra độ mạnh, JSON) |
| **`secretscan.py`** | Secret scanner (quét mã nguồn tìm khóa API, token, private key; entropy + allowlist chống nhiễu; output text/JSON/CSV) |
| **`pwcheck.py`** | Password strength checker (phân tích zxcvbn-like: top phổ biến, từ thông dụng/leetspeak, mẫu bàn phím/tuần tự/lặp, năm; batch + `--stdin`; JSON) |

**Sản phẩm của Digital Core team.**

---

## Mục lục

1. [Cài đặt và yêu cầu](#1-cài-đặt-và-yêu-cầu)
2. [PyScan — port scanner (`pyscan.py`)](#2-pyscan--port-scanner-pyscanpy)
3. [HttpSec — HTTP security scanner (`httpsec.py`)](#3-httpsec--http-security-scanner-httpsecpy)
4. [DnsLookup — DNS lookup (`dnslookup.py`)](#4-dnslookup--dns-lookup-dnslookuppy)
5. [SubFind — subdomain finder (`subfind.py`)](#5-subfind--subdomain-finder-subfindpy)
6. [LogSec — log security analyzer (`logsec.py`)](#6-logsec--log-security-analyzer-logsecpy)
7. [PassGen — password generator (`pwgen.py`)](#7-passgen--password-generator-pwgenpy)
8. [SecretScan — secret scanner (`secretscan.py`)](#8-secretscan--secret-scanner-secretscanpy)
9. [PWCheck — password strength checker (`pwcheck.py`)](#9-pwcheck--password-strength-checker-pwcheckpy)
10. [Exit codes](#10-exit-codes)
11. [Ví dụ kết hợp các công cụ](#11-ví-dụ-kết-hợp-các-công-cụ)
12. [Lưu ý pháp lý](#12-lưu-ý-pháp-lý)

---

## 1. Cài đặt và yêu cầu

Cả tám công cụ chỉ dùng thư viện chuẩn (`socket`, `ssl`, `argparse`, `json`, `urllib`, `re`, `secrets`, `fnmatch`...), **không cần cài thêm gì** cho các chức năng cơ bản.

| Thành phần | Bắt buộc? | Dùng cho |
|---|---|---|
| Python ≥ 3.10 | Bắt buộc | Tất cả công cụ |
| `scapy` | Tùy chọn (chỉ PyScan) | Scan raw: `-sS -sU -sN -sF -sX -sA -sW` |
| `cryptography` | Tùy chọn (chỉ PyScan) | Giải mã chi tiết chứng chỉ SSL |
| Npcap (Windows) | Tùy chọn (chỉ PyScan) | Raw socket / SYN scan trên Windows |

Cài đặt thêm (tùy chọn, cho PyScan):

```powershell
pip install scapy
pip install cryptography
```

> Thiếu `scapy`/quyền admin, PyScan **tự hạ về TCP connect scan** kèm cảnh báo — không bị lỗi giữa chừng.

---

## 2. PyScan — port scanner (`pyscan.py`)

```
python pyscan.py [tùy chọn] targets...
```

### Ví dụ nhanh

```bash
# Scan TCP phổ biến
python pyscan.py -sT -p 1-1000 example.com

# SYN scan toàn bộ cổng, nhanh (cần scapy/admin)
python pyscan.py -sS -p- -T4 192.168.1.10

# Phát hiện dịch vụ + banner + đoán OS
python pyscan.py -sS -sV -O -T4 -p- 192.168.1.10

# Kiểm tra chứng chỉ SSL/TLS chi tiết
python pyscan.py -sT -p 443,8443 --ssl-detail example.com

# Giám sát thay đổi so với lần scan trước (dùng cho CI)
python pyscan.py --diff -p- example.com

# Chỉ dò host đang sống
python pyscan.py -sn 10.0.0.1-50
```

### Tóm tắt tham số

| Tham số | Ý nghĩa |
|---|---|
| `-sS` | SYN scan (raw, bán tàng hình) |
| `-sT` | TCP connect scan (mặc định, an toàn nhất) |
| `-sU` | UDP scan |
| `-sN` / `-sF` / `-sX` / `-sA` / `-sW` | NULL / FIN / XMAS / ACK / Window scan (raw) |
| `-p, --ports` | Danh sách cổng: `22,80-100,443`; `-p-` = toàn bộ |
| `--top-ports N` | Scan N cổng phổ biến nhất |
| `-T, --timing 0-5` | Tốc độ (0 = paranoid, chậm; 5 = insane, nhanh) |
| `-sV, --service-version` | Phát hiện dịch vụ + phiên bản |
| `-sC, --banner` | Bí danh của `-sV` |
| `-sn, --ping-scan` | Chỉ dò host, không scan cổng |
| `-O, --os-guess` | Đoán OS từ TTL/window |
| `--ssl-detail` | Kiểm tra SSL/TLS sâu trên các cổng TLS |
| `--diff` | So sánh với lần scan trước, thoát code `1` nếu có thay đổi |
| `--history-dir DIR` | Thư mục lịch sử (mặc định `.pyscan_history`) |
| `-oN / -oX / -oG / -oJ` | Xuất output text / XML / grepable / JSON |
| `-v, --verbose` | Tăng chi tiết (`-vv` = đầy đủ) |
| `--no-color` | Tắt màu ANSI |

> Tài liệu đầy đủ từng tham số: xem [PYSCAN.md](./PYSCAN.md).

### Định dạng target

| Dạng | Ví dụ |
|---|---|
| Hostname | `example.com` |
| IPv4 | `192.168.1.10` |
| IPv6 | `::1` |
| CIDR | `192.168.1.0/24` |
| Range | `192.168.1.1-20` |

---

## 3. HttpSec — HTTP security scanner (`httpsec.py`)

```
python httpsec.py [tùy chọn] URL
```

Quét lần lượt: reachability → TLS → headers → cookies → methods → sensitive paths → CORS → redirect → ứng dụng. Kết quả chấm điểm **0–100** kèm xếp hạng **A–F**.

### Ví dụ nhanh

```bash
# Quét passive cơ bản
python httpsec.py https://example.com

# Quét IP bằng HTTP (mặc định http nếu thiếu scheme)
python httpsec.py http://10.0.0.5

# Bật kiểm tra active (PUT/DELETE, XSS reflection, open redirect)
python httpsec.py -u http://192.168.1.10 --active

# Kèm header tùy chỉnh (auth, cookie...)
python httpsec.py https://example.com -H "Authorization: Bearer xyz"

# Server tự ký (self-signed): bỏ qua lỗi xác minh, vẫn báo cáo
python httpsec.py https://10.0.0.5 --insecure

# Xuất báo cáo nhiều định dạng
python httpsec.py https://example.com -oJ report.json -oH report.html -oT report.txt

# Xem chi tiết đầy đủ (kể cả các mục PASS)
python httpsec.py https://example.com -v

# Danh sách mục kiểm tra
python httpsec.py --list-checks
```

### Tham số

| Tham số | Ý nghĩa |
|---|---|
| `url` (vị trí) hoặc `-u` | URL mục tiêu; mặc định scheme `http` |
| `-T, --timeout SEC` | Timeout mỗi request (mặc định 10s) |
| `-H HEADER` | Header tùy chỉnh, dùng nhiều lần |
| `-A, --user-agent UA` | Đổi User-Agent |
| `--active` | Bật kiểm tra active: PUT/DELETE/PATCH, XSS reflection, open redirect |
| `--insecure` | Bỏ qua xác minh TLS (kết quả vẫn được ghi nhận) |
| `--list-checks` | In danh sách các mục kiểm tra rồi thoát |
| `-oJ / -oH / -oT FILE` | Xuất JSON / HTML / text |
| `-v, --verbose` | Hiện chi tiết PASS/detail |
| `--no-color` | Tắt màu ANSI |

### Nhóm kiểm tra

| Nhóm | Kiểm tra | Chế độ |
|---|---|---|
| **TLS** | Phiên bản TLS (1.0/1.1 yếu), cipher yếu, chứng chỉ hết hạn, chuỗi trust, HTTP/2 | chỉ khi scan `https://` |
| **Headers** | HSTS, CSP, X-Frame-Options (clickjacking), nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, lộ thông tin (Server, X-Powered-By, X-AspNet-Version) | passive |
| **Cookies** | Thuộc tính Secure, HttpOnly, SameSite của từng cookie | passive |
| **Methods** | OPTIONS/Allow, TRACE (XST), PUT/DELETE/PATCH không xác thực | active cho phần write-test |
| **Paths** | `.git`, `.env`, backup (`.zip`/`.sql`), admin, phpMyAdmin, phpinfo, robots.txt, sitemap... | passive |
| **CORS** | Phản chiếu origin tùy ý, wildcard + credentials | passive |
| **Redirect** | Có ép HTTP → HTTPS không | passive |
| **App** | Phản chiếu input (XSS), open redirect | active |

### Cách đọc kết quả

Mỗi mục có: **trạng thái** (`PASS` / `FAIL` / `WARN` / `INFO`), **mức độ** (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`), mô tả chi tiết và gợi ý khắc phục (`fix:`).

```
[ HEADERS ]
  FAIL MEDIUM   Missing clickjacking protection
        no X-Frame-Options and no CSP frame-ancestors
        fix: set X-Frame-Options: DENY or CSP frame-ancestors 'self'
```

Điểm số tính theo mức độ và số mục FAIL/WARN; **PASS/INFO** được cộng điểm tốt.

> Mẹo: quét server trả về redirect (HTTP → HTTPS) sẽ hiện mục "HTTP → HTTPS redirect"; quét thẳng địa chỉ `https://` để phân tích header đầy đủ.

---

## 4. DnsLookup — DNS lookup (`dnslookup.py`)

```
python dnslookup.py [tùy chọn] tên-miền
```

Tra cứu DNS kiểu `dig` viết bằng Python thuần: tự dựng/giải mã gói tin DNS qua UDP (tự chuyển TCP khi truncated), hỗ trợ A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV/NAPTR/CAA/DS/DNSKEY/RRSIG/NSEC/NSEC3/TLSA/HTTPS, tra ngược IPv4/IPv6, EDNS0, DNSSEC (DO bit), truy vết root→TLD→authoritative và xuất JSON.

### Ví dụ nhanh

```bash
# Bản ghi cơ bản
python dnslookup.py example.com
python dnslookup.py gmail.com --mx
python dnslookup.py google.com --ns --txt --soa --caa

# DNSSEC: DNSKEY + bằng chứng NXDOMAIN
python dnslookup.py cloudflare.com -t DNSKEY --dnssec
python dnslookup.py nonexist12345.cloudflare.com --dnssec -v

# Tra ngược IPv4 / IPv6
python dnslookup.py -x 8.8.8.8
python dnslookup.py -x 2606:4700::1111

# Truy vết đường phân giải + ép TCP
python dnslookup.py example.com --trace
python dnslookup.py example.com --tcp

# Output gọn / JSON cho script
python dnslookup.py gmail.com --mx --short
python dnslookup.py --file domains.txt -t A --json -o out.json

# Chỉ định server
python dnslookup.py example.com -s 8.8.8.8 -s 1.1.1.1
```

> Tài liệu đầy đủ: xem [DNSLOOKUP.md](./DNSLOOKUP.md).

---

## 5. SubFind — subdomain finder (`subfind.py`)

```
python subfind.py [tùy chọn] tên-miền
```

Tìm tên miền con từ **ba nguồn**: Certificate Transparency (crt.sh, thụ động), brute-force DNS bằng wordlist (có tự phát hiện/lọc wildcard), và zone transfer **AXFR** qua TCP. Tự dựng gói DNS thô như `dnslookup.py`, hỗ trợ resolve A/AAAA, xuất JSON.

### Ví dụ nhanh

```bash
# Chỉ crt.sh (thụ động, mặc định)
python subfind.py example.com

# Nhanh với ~N tên phổ biến tích hợp sẵn
python subfind.py example.com --top 100

# Brute-force wordlist + resolve IP
python subfind.py cloudflare.com -w subdomains.txt --resolve

# Thử zone transfer (AXFR)
python subfind.py zonetransfer.me --axfr

# Tất cả nguồn, output JSON
python subfind.py example.com --top 200 -w big.txt --axfr --json -o out.json
```

### Tóm tắt tham số

| Tham số | Ý nghĩa |
|---|---|
| `-w, --wordlist FILE` | Wordlist brute-force |
| `--top N` | N tên phổ biến tích hợp sẵn |
| `--no-crt` | Tắt nguồn crt.sh |
| `--axfr` | Thử zone transfer (AXFR) qua TCP |
| `--resolve` | Phân giải A/AAAA và hiển thị IP |
| `-s, --server` | DNS server, dùng nhiều lần |
| `-T, --threads N` | Số luồng brute-force song song (40) |
| `--short` | Chỉ in tên, 1 dòng/1 tên |
| `--json` | Xuất JSON |
| `-o FILE` | Ghi kết quả ra file |

> Tài liệu đầy đủ: xem [SUBFIND.md](./SUBFIND.md).

---

## 6. LogSec — log security analyzer (`logsec.py`)

```
python logsec.py [tùy chọn] file-log...
```

Phân tích file log phát hiện mối đe dọa. Tự nhận dạng format (apache/CLF, combined, auth SSH, JSONL, generic — hoặc ép bằng `--format`). Gán mức độ CRITICAL/HIGH/MEDIUM/LOW, hỗ trợ output text/JSON/CSV/gọn, lọc theo IP/path/thời gian, và trả exit code để dùng trong script/CI.

### Ví dụ nhanh

```bash
# Báo cáo đầy đủ (mặc định)
python logsec.py access.log auth.log

# Chỉ xem mối đe dọa
python logsec.py access.log --threats-only

# 1 dòng gọn cho mỗi file (dùng trong CI)
python logsec.py access.log --short

# Lọc theo IP / đường dẫn / thời gian
python logsec.py access.log --ip 192.0.2.99 --path "/login"
python logsec.py access.log --since 2026-10-10T14:00:00 --until 2026-10-11T00:00:00

# Chỉ quan tâm mối đe dọa HIGH trở lên, thoát code 1 nếu có
python logsec.py access.log --min-severity HIGH --short

# Xuất JSON / CSV cho tooling
python logsec.py access.log --json -o report.json
python logsec.py access.log --csv
```

### Tham số

| Tham số | Ý nghĩa |
|---|---|
| `-f, --format` | Ép format: `auto`, `apache`, `clf`, `combined`, `auth`, `jsonl`, `generic` (mặc định `auto`) |
| `--top N` | Số dòng trong bảng top (mặc định 10) |
| `--ip IP` | Chỉ phân tích IP này |
| `--path SUB` | Chỉ phân tích đường dẫn chứa chuỗi SUB |
| `--since / --until TS` | Lọc theo thời gian (ISO: `2026-10-10T14:00:00`) |
| `--last-hours N` | Chỉ N giờ gần nhất |
| `--threats-only` | Chỉ in mối đe dọa |
| `--min-severity S` | Chỉ hiển thị từ mức S (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) |
| `--exit-on S` | Exit code 1 nếu có mối đe dọa từ mức S (mặc định `HIGH`) |
| `--json` / `--csv` | Xuất JSON / CSV |
| `--short` | 1 dòng tổng kết mỗi file |
| `-o FILE` | Ghi kết quả ra file |
| `-v, --verbose` | Thêm bảng User-Agent/Referrer |
| `--no-color` | Tắt màu ANSI |

### Mối đe dọa được phát hiện

| Rule | Mức độ | Điều kiện |
|---|---|---|
| LFI (local file inclusion) | CRITICAL | `/etc/passwd`, `file=`, `../`... |
| SQLi (SQL injection) | HIGH | payload `OR 1=1`, `UNION SELECT`, `'--`... |
| XSS | HIGH | payload `<script>`, `alert(`... |
| TRAV (path traversal) | HIGH | chuỗi `../` |
| BRUTE (web brute force) | HIGH | ≥ 20 lần 401/403 từ 1 IP |
| SCAN (path scan) | MEDIUM | ≥ 30 đường dẫn 4xx lạ từ 1 IP |
| SSHBF (SSH brute force) | HIGH | ≥ 5 lần sai mật khẩu |
| SSHE (SSH user enum) | MEDIUM | ≥ 10 user không tồn tại |
| SENS (sensitive path) | MEDIUM | `.git`, `.env`, backup... |
| UA (scanner agent) | LOW | User-Agent công cụ quét (sqlmap, nikto...) |

> Tài liệu đầy đủ: xem [LOGSEC.md](./LOGSEC.md).

---

## 7. PassGen — password generator (`pwgen.py`)

```
python pwgen.py [tùy chọn]
python pwgen.py --strength "mật-khẩu"
```

Sinh mật khẩu/passphrase ngẫu nhiên bằng mô-đun `secrets` (an toàn mật mã), kiểm tra độ mạnh (`--strength`) với entropy + thời gian bẻ khóa ước tính. Wordlist 349 từ cho passphrase.

### Ví dụ nhanh

```bash
# 10 mật khẩu 16 ký tự (mặc định)
python pwgen.py

# 5 mật khẩu dài 20, loại ký tự dễ nhầm lẫn
python pwgen.py -c 5 -l 20 --no-ambig

# Passphrase 10 từ
python pwgen.py --passphrase -w 10

# Kiểm tra độ mạnh
python pwgen.py --strength "Tr0ub4dor&3"

# Xuất JSON
python pwgen.py -c 20 -l 20 --json -o passwords.json
```

### Tóm tắt tham số

| Tham số | Ý nghĩa |
|---|---|
| `-c, --count N` | Số lượng (mặc định 10) |
| `-l, --length N` | Độ dài mật khẩu, ≥ 4 (mặc định 16) |
| `--no-lower/--no-upper/--no-digit/--no-symbol` | Tắt nhóm ký tự |
| `--no-ambig` | Loại ký tự dễ nhầm `0O1lI` |
| `-p, --passphrase` | Chế độ passphrase |
| `-w, --words N` | Số từ (mặc định 8) |
| `--sep CHUỖI` / `--cap` | Ký tự nối / viết hoa đầu từ |
| `--strength PASSWORD` | Kiểm tra độ mạnh mật khẩu cho sẵn |
| `--json` | Xuất JSON |
| `-o FILE` | Ghi ra file |
| `-v, --verbose` | Hiện entropy từng mật khẩu |
| `--no-color` | Tắt màu ANSI |

> Tài liệu đầy đủ: xem [PWGEN.md](./PWGEN.md).

---

## 8. SecretScan — secret scanner (`secretscan.py`)

```
python secretscan.py [tùy chọn] file-hoặc-thư-mục...
```

Quét mã nguồn tìm bí mật bị lộ: khóa API (AWS, Google, Stripe, Twilio, SendGrid...), token (GitHub, Slack, npm, Telegram...), JWT, private key, mật khẩu, connection string. Tự bỏ qua `.git`/`node_modules`/file nhị phân, lọc nhiễu bằng entropy Shannon + allowlist.

### Ví dụ nhanh

```bash
# Quét toàn bộ repo
python secretscan.py C:\projects\myapp

# Quét file cụ thể
python secretscan.py .env config.js

# Chỉ quan tâm mức HIGH, output gọn (CI)
python secretscan.py . --min-severity HIGH --short

# Bỏ qua kết quả giả
python secretscan.py . --allow "mycompany"

# Xuất JSON / CSV
python secretscan.py . --json -o scan.json
python secretscan.py . --csv -o scan.csv

# Danh sách quy tắc
python secretscan.py --rules
```

### Tóm tắt tham số

| Tham số | Ý nghĩa |
|---|---|
| `--ext EXTS` | Chỉ quét đuôi: `--ext py,js,env` |
| `--exclude GLOB` | Bỏ qua file/thư mục khớp glob |
| `--min-severity S` | Chỉ báo từ mức S (mặc định `LOW`) |
| `--allow REGEX` / `--allowlist FILE` | Bỏ qua kết quả khớp regex |
| `--no-entropy` | Tắt kiểm tra entropy |
| `--max-size MB` | Bỏ qua file lớn hơn N MB (mặc định 10) |
| `--no-mask` | Hiện đầy đủ bí mật trong text |
| `--rules` | Liệt kê quy tắc phát hiện |
| `--json` / `--csv` | Xuất JSON / CSV |
| `--short` | 1 dòng/file có bí mật |
| `-o FILE` | Ghi ra file |
| `-v, --verbose` / `--no-color` | Chi tiết / tắt màu |

> Tài liệu đầy đủ: xem [SECRETSCAN.md](./SECRETSCAN.md).

---

## 9. PWCheck — password strength checker (`pwcheck.py`)

```
python pwcheck.py mật-khẩu [mật-khẩu...]
python pwcheck.py --stdin
```

Phân tích độ mạnh mật khẩu theo **mô hình zxcvbn-like**: entropy brute-force + phát hiện mẫu yếu thực tế — trùng top mật khẩu phổ biến, chứa từ thông dụng (kể cả leetspeak `p@ssw0rd`, từ đảo ngược, từ tiếng Việt), chuỗi tuần tự, mẫu bàn phím, ký tự lặp, năm. Báo cáo: thành phần ký tự, entropy trước/sau, mẫu phát hiện, xếp hạng YẾU–RẤT MẠNH, thời gian bẻ khóa.

### Ví dụ nhanh

```bash
# Kiểm tra 1 mật khẩu
python pwcheck.py "Tr0ub4dor&3"

# Một loạt từ yếu đến mạnh
python pwcheck.py 123456 "P@ssw0rd" "correcthorsebatterystaple"

# Đọc hàng loạt từ file (1 dòng 1 mật khẩu) — CI thoát 1 khi có YẾU
Get-Content C:\sec\pwd.txt | python pwcheck.py --stdin

# Pipe từ PassGen (tự bỏ dòng tiêu đề/số thứ tự)
python pwgen.py -c 5 -l 12 | python pwcheck.py --stdin

# Bỏ qua từ điển / leetspeak
python pwcheck.py --no-blacklist "P@ssw0rd"

# Xuất JSON
python pwcheck.py "Passw0rd" "xK9$fP2mQz@vB4wR" --json -o report.json
```

### Tóm tắt tham số

| Tham số | Ý nghĩa |
|---|---|
| `password...` (vị trí) | Mật khẩu cần kiểm tra (dùng nhiều lần) |
| `--stdin` | Đọc mật khẩu từ stdin, 1 dòng/cái; bỏ dòng `;;` và `N. ` |
| `--no-leet` | Không giải mã leetspeak khi khớp từ |
| `--no-blacklist` | Bỏ qua danh sách mật khẩu/từ thông dụng |
| `--json` | Xuất JSON |
| `-o FILE` | Ghi ra file |
| `--no-color` | Tắt màu ANSI |

> Tài liệu đầy đủ: xem [PWCHECK.md](./PWCHECK.md).

---

## 10. Exit codes

| Code | PyScan | HttpSec | DnsLookup | SubFind | LogSec | PassGen | SecretScan | PWCheck |
|---|---|---|---|---|---|---|---|---|
| `0` | Thành công (không đổi với `--diff`) | Quét xong | NOERROR | Tìm thấy ≥ 1 subdomain | Không có mối đe dọa từ mức `--exit-on` | Thành công | Không phát hiện bí mật | Không có mật khẩu YẾU |
| `1` | Có thay đổi khi dùng `--diff` | Không tới được target | NXDOMAIN | Không tìm thấy subdomain | Có mối đe dọa từ mức `--exit-on` | — | Có bí mật được phát hiện | Có ≥ 1 mật khẩu YẾU |
| `2` | Lỗi đầu vào (target/CIDR không hợp lệ) | Thiếu URL mục tiêu | Lỗi mạng/timeout với mọi server | (dành cho lỗi mạng mọi nguồn) | Không đọc được file nào | Lỗi đầu vào (`--count`/`--length`/`--words` sai, hết charset) | Không quét được file nào | Lỗi đầu vào (không có mật khẩu) |
| `3` | — | — | Lỗi đầu vào (type/domain/IP/file) | Lỗi đầu vào (domain/wordlist) | Lỗi đầu vào / không có file / `--since` sai | — | Lỗi đầu vào (không có path, regex sai) | — |

---

## 11. Ví dụ kết hợp các công cụ

```powershell
# 1) Tìm cổng mở + dịch vụ trong subnet
python pyscan.py -sT -sV -p 22,80,443,3306,6379,8080,8443 -oJ C:\scans\subnet.json 192.168.1.0/24

# 2) Với cổng web tìm được, quét bảo mật HTTP sâu (cả active test)
python httpsec.py http://192.168.1.5 --active -oJ C:\scans\site.json -oH C:\scans\site.html

# 3) Kiểm tra chứng chỉ TLS của dịch vụ HTTPS
python pyscan.py -sT -p 443 --ssl-detail -v example.com

# 4) Giám sát drift cổng + chạy HTTP scan định kỳ (CI)
python pyscan.py --diff --history-dir C:\scans\history -sT -p- 192.168.1.10
python httpsec.py https://example.com -oJ C:\scans\site.json

# 5) Xác định IP của domain, rồi scan + quét HTTP chính IP đó
python dnslookup.py example.com --short
python pyscan.py -sT -sV -p 443,8443 <IP-trả-về>
python httpsec.py https://<IP-trả-về>

# 6) Kiểm tra DNSSEC và CAA trước khi cấp chứng chỉ / đổi nameserver
python dnslookup.py example.com -t DNSKEY --dnssec
python dnslookup.py example.com -t CAA

# 7) Enumerate subdomain → resolve IP → quét cổng + HTTP trên từng host
python subfind.py example.com --top 200 -w big.txt --resolve --short > C:\scans\subs.txt
python pyscan.py -sT -sV -p 80,443,8080,8443 -iL C:\scans\subs.txt
python httpsec.py https://api.example.com --active

# 8) Sau khi quét HTTP, phân tích access log web server phát hiện tấn công
python logsec.py C:\var\log\access.log --threats-only --exit-on MEDIUM
python logsec.py C:\var\log\access.log --json -o C:\scans\access-report.json

# 9) Theo dõi brute-force SSH từ auth.log trong CI (exit 1 khi có tấn công)
python logsec.py C:\var\log\auth.log --min-severity HIGH --short

# 10) Sinh mật khẩu / passphrase mạnh cho tài khoản mới
python pwgen.py -c 5 -l 20 --no-ambig
python pwgen.py --passphrase -w 10 --cap
python pwgen.py --strength "Tr0ub4dor&3"

# 11) Rà soát bí mật bị lộ trong mã nguồn trước khi push / release
python secretscan.py . --min-severity HIGH --short
python secretscan.py . --json -o C:\scans\secrets.json

# 12) Sinh mật khẩu rồi xác nhận không có mật khẩu yếu trong danh sách
python pwgen.py -c 10 -l 16 --no-ambig | python pwcheck.py --stdin
python pwcheck.py "Passw0rd" "xK9$fP2mQz@vB4wR" --json -o C:\scans\pwcheck.json
```

---

## 12. Lưu ý pháp lý

Các công cụ này chỉ dùng cho **mục tiêu bạn sở hữu hoặc được ủy quyền kiểm tra**. Quét hệ thống không thuộc quyền sở hữu có thể vi phạm pháp luật và điều khoản sử dụng của nhà cung cấp. Hãy đảm bảo có văn bản cho phép trước khi chạy.
