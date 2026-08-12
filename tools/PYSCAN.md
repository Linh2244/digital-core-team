# PyScan 1.0.0 — Tài liệu chi tiết tham số

**Sản phẩm của Digital Core team.**

Port scanner nâng cao viết bằng Python thuần (một file `pyscan.py`), mô phỏng đầy đủ chức năng nmap và bổ sung một số tính năng nmap chưa có (JSON native, lịch sử scan + diff, kiểm tra SSL/TLS chi tiết).

```
python pyscan.py [tùy chọn] targets...
```

---

## Mục lục

1. [Cài đặt và yêu cầu](#1-cài-đặt-và-yêu-cầu)
2. [Tham số vị trí: targets](#2-tham-số-vị-trí-targets)
3. [Chế độ scan](#3-chế-độ-scan)
4. [Chọn cổng](#4-chọn-cổng)
5. [Kiểm soát tốc độ](#5-kiểm-soát-tốc-độ)
6. [Phát hiện dịch vụ / banner](#6-phát-định-dịch-vụ--banner)
7. [Host discovery](#7-host-discovery)
8. [Đoán hệ điều hành](#8-đoán-hệ-điều-hành)
9. [SSL/TLS chi tiết](#9-ssltls-chi-tiết)
10. [Diff so sánh với lần scan trước](#10-diff-so-sánh-với-lần-scan-trước)
11. [Định dạng output](#11-định-dạng-output)
12. [Tham số hiển thị khác](#12-tham-số-hiển-thị-khác)
13. [Exit codes](#13-exit-codes)
14. [Ví dụ kết hợp](#14-ví-dụ-kết-hợp)
15. [Hạn chế và cơ chế fallback](#15-hạn-chế-và-cơ-chế-fallback)
16. [Cấu trúc bên trong](#16-cấu-trúc-bên-trong)

---

## 1. Cài đặt và yêu cầu

| Thành phần | Bắt buộc? | Mô tả |
|---|---|---|
| Python ≥ 3.10 | Bắt buộc | `socket`, `ssl`, `argparse`, `concurrent.futures`, `xml.etree` (stdlib) |
| `scapy` | Tùy chọn | Cần cho scan raw: `-sS -sU -sN -sF -sX -sA -sW`. Thiếu sẽ tự hạ về TCP connect |
| `cryptography` | Tùy chọn | Giải mã toàn bộ chứng chỉ SSL. Thiếu thì chỉ hiện TLS version + cipher |
| Npcap (Windows) | Tùy chọn | Để raw socket hoạt động trên Windows (scan SYN trở lên) |

Cài đặt:

```powershell
pip install scapy          # cho scan raw
pip install cryptography   # cho SSL cert đầy đủ (hầu hết máy đã có sẵn)
```

---

## 2. Tham số vị trí: targets

Danh sách mục tiêu, có thể nhập nhiều, cách nhau bởi dấu cách.

```bash
python pyscan.py example.com 192.168.1.10
```

### Các định dạng hỗ trợ

| Dạng | Ví dụ | Kết quả |
|---|---|---|
| Hostname | `example.com` | Giải mã DNS → tất cả IP (A + AAAA). Dùng tên này làm SNI khi inspect SSL |
| IPv4 | `192.168.1.10` | Scan IP đó |
| IPv6 | `::1`, `2606:4700::1111` | Scan qua TCP connect |
| CIDR | `192.168.1.0/24` | Toàn bộ IP trong mạng (tối đa 65536 host, lớn hơn sẽ từ chối) |
| Range (cùng octet cuối) | `192.168.1.1-20` | Từ .1 đến .20 |
| Range đầy đủ | `192.168.1.1-192.168.1.5` | Từ .1 đến .5 |

### Lưu ý
- Mỗi hostname giải ra nhiều IP (ví dụ `example.com` → 2 IPv4 + 2 IPv6) sẽ được scan tất cả.
- Hostname sai / IP không hợp lệ sẽ bị bỏ qua kèm cảnh báo trên `stderr`.
- Không hợp lệ → thoát với exit code `2`.

---

## 3. Chế độ scan

Mỗi chế độ dùng một kỹ thuật khác nhau để xác định trạng thái cổng. Kết quả trạng thái gồm: `open`, `closed`, `filtered`, `unfiltered`, `open|filtered`.

> Mặc định khi không truyền tham số nào: **TCP connect scan** (`-sT`), an toàn nhất, chạy được mọi nơi.

| Tham số | Kỹ thuật | Cần scapy/admin | Nguyên lý phát hiện |
|---|---|---|---|
| `-sT` | TCP connect | Không | Hoàn tất bắt tay 3 bước → open; bị từ chối → closed; timeout → filtered |
| `-sS` | SYN (half-open) | Có | SYN → SYN-ACK = open; RST = closed; không trả lời = filtered. Không để lại bản ghi kết nối |
| `-sU` | UDP | Có (raw) | Nhận ICMP "port unreachable" = closed; ICMP admin/network = filtered; không trả lời = `open\|filtered`. Nếu thiếu quyền, dùng socket heuristic |
| `-sN` | NULL | Có | Gói không cờ: RST = closed; im lặng = `open\|filtered` |
| `-sF` | FIN | Có | Gói cờ FIN: RST = closed; im lặng = `open\|filtered` |
| `-sX` | XMAS | Có | Gói cờ FIN+PSH+URG: RST = closed; im lặng = `open\|filtered` |
| `-sA` | ACK | Có | Gói cờ ACK: RST = `unfiltered` (tới được); im lặng = `filtered`. Không phân biệt open/closed — dùng để rà tường lửa |
| `-sW` | Window | Có | ACK với cửa sổ > 0 = open; = 0 = closed; im lặng = filtered |

### Ví dụ

```bash
python pyscan.py -sT -p 1-1000 example.com        # an toàn, mọi nơi
python pyscan.py -sS -p- -T4 192.168.1.10         # nhanh, bán tàng hình
python pyscan.py -sU -p 53,161,500 10.0.0.5       # scan UDP
python pyscan.py -sA -p 1-5000 target             # rà cổng "unfiltered"
```

### Cơ chế fallback
- `-sS/-sN/-sF/-sX/-sA/-sW`: nếu thiếu `scapy` → tự hạ về connect kèm cảnh báo. Nếu có scapy nhưng raw socket bị chặn → thử scan, thất bại thì **tự động chuyển sang connect và chạy lại toàn bộ**.
- `-sU`: nếu không có scapy+admin → dùng socket UDP heuristic (kết quả `open|filtered`, không đọc được ICMP).

---

## 4. Chọn cổng

### `-p, --ports PORTS`

Cú pháp danh sách: phân tách dấu phẩy, khoảng bằng dấu gạch ngang.

| Giá trị | Ý nghĩa |
|---|---|
| `-p 22,80,443` | Chỉ 3 cổng |
| `-p 22,80-100,443` | Hỗn hợp cổng đơn + khoảng |
| `-p-` hoặc `-p -` hoặc `--ports -` | Toàn bộ 65535 cổng |
| `-p 1-65535` | Tương đương `-p-` |
| `-p 0-` / `-p -100` | Khoảng mở (từ 1 hoặc đến 65535) |

Ví dụ:

```bash
python pyscan.py -sT -p 22,80,443 example.com
python pyscan.py -sS -p- target                    # full port scan
python pyscan.py -sT -p 1-1024 10.0.0.1            # well-known ports
```

### `--top-ports N`

Scan `N` cổng phổ biến nhất (danh sách 50 cổng thường mở: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 179, 389, 443, 445, 465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 3000, 3128, 3306, 3389, 5060, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 10000, 27017, 11211, 50000).

```bash
python pyscan.py --top-ports 1000 example.com      # giống nmap -F
```

> Nếu truyền cả `-p` và `--top-ports` thì `--top-ports` được ưu tiên.

---

## 5. Kiểm soát tốc độ

### `-T, --timing 0-5`

Template tốc độ, giống nmap `-T0..-T5`. Mặc định `-T3`.

| Mức | Tên (nmap) | Concurrency host | Concurrency cổng | Timeout (s) | Delay giữa gói (s) | Retries |
|---|---|---|---|---|---|---|
| 0 | Paranoid | 1 | 1 | 10.0 | 5.0 | 4 |
| 1 | Sneaky | 1 | 2 | 10.0 | 1.0 | 2 |
| 2 | Polite | 1 | 5 | 3.0 | 0.1 | 1 |
| 3 | Normal | 2 | 15 | 1.5 | 0.0 | 1 |
| 4 | Aggressive | 4 | 50 | 1.0 | 0.0 | 0 |
| 5 | Insane | 8 | 200 | 0.5 | 0.0 | 0 |

```bash
python pyscan.py -sS -T4 -p- 192.168.1.10      # nhanh trong LAN
python pyscan.py -sT -T0 -p 80 target         # rất chậm, ít bị phát hiện
```

### `--timeout SEC`

Ghi đè timeout mỗi cổng (giây). Dùng khi mạng chậm mà `-T3` đánh mất cổng mở.

```bash
python pyscan.py -sT -p 80,443 --timeout 10 example.com
```

---

## 6. Phát định dịch vụ / banner

### `-sV, --service-version`

Kích hoạt phát hiện dịch vụ + phiên bản: chờ banner, gửi probe (HTTP HEAD, Redis PING...) nếu im lặng, đối chiếu với cơ sở dữ liệu chữ ký, kèm fallback theo cổng (giống bảng `port → service` của nmap).

Các dịch vụ nhận diện bằng chữ ký: ssh, http, smtp, ftp, proftpd, vsftpd, mysql, redis, postgresql, mongodb, imap, pop3, rdp, vnc...

```bash
python pyscan.py -sT -p 22,80 -sV scanme.nmap.org
# 22/tcp  open  ssh   OpenSSH_6.6.1p1
# 80/tcp  open  http  Apache/2.4.7 (Ubuntu)
```

### `-sC, --banner`

Bí danh tương đương `-sV` (banner grab + service detection).

> Chỉ chạy trên cổng TCP `open`. Cổng UDP không grab banner.

---

## 7. Host discovery

### `-sn, --ping-scan`

Chỉ dò host mà không scan cổng. Thứ tự phát hiện:
1. ICMP Echo (cần scapy + raw socket) → có luôn TTL.
2. TCP ping (thử kết nối cổng 80, 443, 22, 445).

```bash
python pyscan.py -sn 192.168.1.0/24
python pyscan.py -sn 10.0.0.1-10
```

```
Host is up: 192.168.1.1 (latency 0.82 ms)
Host seems down: 192.168.1.2
```

> Ở chế độ scan thường, PyScan vẫn gọi bước dò host này để hiển thị "Host is up (latency...)" và thu TTL phục vụ `-O`.

---

## 8. Đoán hệ điều hành

### `-O, --os-guess`

Dự đoán OS từ TTL của gói SYN-ACK (scan raw) hoặc ICMP (ping) và kích thước TCP window.

| TTL | Dự đoán |
|---|---|
| ≤ 64 | Linux/Unix |
| ≤ 128 | Windows |
| ≤ 255 | Cisco/router |

```bash
python pyscan.py -sS -p 22,80 -O 192.168.1.10
# OS guess: Windows (ttl=128, window=65535)
```

> Lưu ý: đây là dự đoán TTL thô, **không** phải fingerprint đầy đủ như nmap `-O`. Chỉ có ý nghĩa khi scan bằng kỹ thuật raw (connect scan không nhận được TTL từ phía máy chủ).

---

## 9. SSL/TLS chi tiết

### `--ssl-detail`

Kiểm tra sâu cổng TLS: bắt tay SSL, lấy và giải mã chứng chỉ, đưa cả cảnh báo hết hạn vào kết quả. Tự động bật cho các cổng TLS phổ biến (443, 465, 587, 636, 993, 995, 8443, 8883, 9443...). `--ssl-detail` buộc thử với **mọi** cổng open.

Thông tin trả về:
- TLS version, cipher (tên, protocol, bit)
- Subject (CN), Issuer, Subject Alternative Name (SAN)
- `notBefore`, `notAfter`, số ngày còn hiệu lực (`days_remaining`)
- Cảnh báo tự động: `CERTIFICATE EXPIRED`, `expires in N days` (khi < 30 ngày)
- Với `-v`: thêm public key (độ dài + loại), thuật toán ký, serial number

```bash
python pyscan.py -sT -p 443 --ssl-detail example.com
python pyscan.py -sT -p 443,8443 --ssl-detail -v example.com
```

```
443/tcp  open  https  [TLS TLSv1.3]
  |_ CN: commonName=example.com
  |_ issuer: countryName=US, organizationName=SSL Corporation, commonName=Cloudflare TLS Issuing ECC CA 3
  |_ valid: 2026-10-27T22:17:21+00:00 (76d left)  cipher: TLS_AES_256_GCM_SHA384 (TLSv1.3, 256 bits)
```

> SNI dùng tên hostname gốc (nếu scan bằng hostname), tránh bị chặn như khi dùng IP.

---

## 10. Diff so sánh với lần scan trước

### `--diff`

**Tính năng nmap chưa có.** Mỗi lần scan tự lưu lịch sử (các cổng `open`) vào thư mục lịch sử. Chạy lại với cùng target sẽ so sánh và in chênh lệch:

- `[+]` cổng mới mở
- `[-]` cổng đóng (trước mở)
- `[~]` dịch vụ/phiên bản thay đổi
- `unchanged: N` số cổng không đổi

```bash
python pyscan.py --diff -p- example.com
```

```
Diff report for 127.0.0.1 vs previous scan (baseline 2026-08-12T10:13:06+07:00):
  [+] 9090/tcp open (new) http-alt
  unchanged: 4 open port(s)
```

Exit code: `1` nếu có thay đổi, `0` nếu không — tiện cho CI giám sát drift.

### `--history-dir DIR`

Thư mục lưu lịch sử (mặc định `.pyscan_history`). Mỗi host lưu một file JSON riêng.

```bash
python pyscan.py --diff --history-dir C:\scans\history example.com
```

---

## 11. Định dạng output

Có thể xuất nhiều định dạng cùng lúc.

| Tham số | Định dạng | Đặc điểm |
|---|---|---|
| `-oN FILE` | Normal text | Giống output nmap, có màu (khi tty) |
| `-oX FILE` | XML | Cấu trúc `<nmaprun>` chuẩn nmap, dễ nạp vào NSE/parser khác |
| `-oG FILE` | Grepable | Mỗi host 2 dòng: `Host:` và `Ports:`, dễ `grep` |
| `-oJ FILE` | **JSON** (nmap không có) | Cấu trúc có `tool/version/hosts[]/ports[]` gồm cả dữ liệu SSL |

```bash
python pyscan.py -sT -p 22,80 -sV -oN out.txt -oJ out.json -oX out.xml -oG out.grep example.com
```

### Ví dụ JSON output

```json
{
  "tool": "PyScan",
  "version": "1.0.0",
  "scan_type": "connect",
  "duration_seconds": 1.484,
  "hosts": [
    {
      "ip": "127.0.0.1",
      "hostname": "Linh",
      "up": true,
      "latency": 0.0007,
      "ttl": null,
      "os_guess": null,
      "ports": [
        {"port": 2222, "proto": "tcp", "state": "open",
         "service": "ssh", "version": "OpenSSH_9.5p1", "banner": "SSH-2.0-..."}
      ]
    }
  ]
}
```

### Ví dụ grepable output

```
Host: 127.0.0.1 (Linh)
Ports: 2222/tcp/open//ssh/OpenSSH_9.5p1/,8080/tcp/open//http/nginx/1.25.3/
```

---

## 12. Tham số hiển thị khác

| Tham số | Mô tả |
|---|---|
| `-v, --verbose` | Lặp lại để tăng chi tiết: `-v` (banner kèm dòng cổng), `-vv` (đủ chi tiết SSL: key, sig, serial, SAN) |
| `--no-color` | Tắt màu ANSI (khi xuất file hoặc chạy qua pipe/CI) |
| `-h, --help` | In trợ giúp |

Màu tự bật khi output là terminal (tty), tự tắt khi pipe vào file/lệnh khác.

---

## 13. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Scan thành công (không có thay đổi khi dùng `--diff`) |
| `1` | Có thay đổi phát hiện bởi `--diff` |
| `2` | Lỗi đầu vào (không có target hợp lệ, CIDR quá lớn...) |
| khác | Lỗi argparse (tham số không hợp lệ) |

```powershell
python pyscan.py --diff -p- example.com; echo "exit=$LASTEXITCODE"
```

---

## 14. Ví dụ kết hợp

```bash
# 1) Scan nhanh toàn bộ cổng một máy trong LAN (SYN + service + OS guess)
python pyscan.py -sS -sV -O -T4 -p- 192.168.1.10

# 2) Rà nhanh 1000 cổng phổ biến, không gây tiếng ồn
python pyscan.py -sT -T2 --top-ports 1000 example.com

# 3) Kiểm tra chứng chỉ TLS của một loạt cổng
python pyscan.py -sT --ssl-detail -p 443,8443,993 example.com

# 4) Giám sát drift: chạy định kỳ, báo khi có cổng mới/đóng
python pyscan.py --diff --history-dir C:\scans\history -sT -p- 192.168.1.10

# 5) Quét toàn bộ subnet, xuất JSON để xử lý tiếp
python pyscan.py -sT -p 22,80,443 -oJ C:\scans\subnet.json 192.168.1.0/24

# 6) Chỉ dò host nào đang sống
python pyscan.py -sn 10.0.0.1-50
```

---

## 15. Hạn chế và cơ chế fallback

| Tình huống | Hành vi |
|---|---|
| Scan raw (`-sS...`) nhưng không cài scapy | Cảnh báo + tự hạ về TCP connect |
| Scan raw nhưng không có quyền admin/raw socket | Thử trước; thất bại → tự chuyển connect và chạy lại toàn bộ |
| `-sU` không có scapy/admin | Dùng socket heuristic: chỉ phân biệt được closed với `open\|filtered` |
| Thiếu `cryptography` | Vẫn bắt tay TLS, hiện version + cipher; không có chi tiết cert |
| `-O` | Chỉ dự đoán theo TTL/window, không phải fingerprint đầy đủ như nmap |
| Cổng đóng trong mạng bị firewall drop | Báo `filtered` thay vì `closed` (đúng bản chất) |
| Hostname ra nhiều IP | Scan tất cả các IP |

---

## 16. Cấu trúc bên trong

Một file, các thành phần chính:

| Thành phần | Nhiệm vụ |
|---|---|
| `expand_targets()` / `parse_port_spec()` | Phân tích target và cổng |
| `ConnectScanner`, `SynScanner`, `UdpScanner`, `NullScanner`, `FinScanner`, `XmasScanner`, `AckScanner`, `WindowScanner`, `SocketUdpScanner` | Các kỹ thuật scan |
| `choose_scanner()` | Chọn scanner + fallback |
| `ServiceDetector` | Banner grab, DB chữ ký, `inspect_ssl()` |
| `Pinger` | Host discovery (ICMP / TCP ping) |
| `guess_os()` | Dự đoán OS từ TTL/window |
| `HistoryStore`, `DiffEngine` | Lưu lịch sử + so sánh thay đổi |
| `OutputManager` | Render text / XML / grepable / JSON |
| `Config` + `TIMING_TEMPLATES` | Cấu hình `-T0..-T5` |
