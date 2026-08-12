# DnsLookup 1.0.0 — Tài liệu sử dụng

**Sản phẩm của Digital Core team.**

Công cụ tra cứu DNS đầy đủ viết bằng Python thuần (một file `dnslookup.py`), **không cần cài thêm thư viện**. Tự dựng/giải mã gói tin DNS (wire format) qua UDP (tự chuyển TCP khi bị truncated), hỗ trợ nhiều loại bản ghi, truy vết đường phân giải (trace), DNSSEC, tra ngược IPv4/IPv6, xuất JSON và query hàng loạt.

```
python dnslookup.py [tùy chọn] [tên miền]
```

---

## Mục lục

1. [Yêu cầu](#1-yêu-cầu)
2. [Ví dụ nhanh](#2-ví-dụ-nhanh)
3. [Loại bản ghi hỗ trợ](#3-loại-bản-ghi-hỗ-trợ)
4. [Chọn DNS server](#4-chọn-dns-server)
5. [Tra ngược (reverse lookup)](#5-tra-ngược-reverse-lookup)
6. [Truy vết đường phân giải (trace)](#6-truy-vết-đường-phân-giải-trace)
7. [DNSSEC](#7-dnssec)
8. [TCP và EDNS](#8-tcp-và-edns)
9. [Query hàng loạt từ file](#9-query-hàng-loạt-từ-file)
10. [Định dạng output](#10-định-dạng-output)
11. [Exit codes](#11-exit-codes)
12. [Tham số đầy đủ](#12-tham-số-đầy-đủ)
13. [Ví dụ kết hợp](#13-ví-dụ-kết-hợp)
14. [Hạn chế](#14-hạn-chế)

---

## 1. Yêu cầu

| Thành phần | Ghi chú |
|---|---|
| Python ≥ 3.10 | Chỉ dùng thư viện chuẩn (`socket`, `struct`, `ssl`-free, `json`, `ipaddress`) |

Không cần `pip install` gì cả.

---

## 2. Ví dụ nhanh

```bash
# Tra bản ghi A (mặc định)
python dnslookup.py example.com

# Các loại bản ghi khác
python dnslookup.py google.com --aaaa
python dnslookup.py gmail.com --mx
python dnslookup.py google.com --ns
python dnslookup.py google.com --txt
python dnslookup.py google.com --soa
python dnslookup.py google.com --caa
python dnslookup.py _sip._tcp.sip2sip.info --srv

# Dùng -t để chọn loại bất kỳ (cả số hiệu)
python dnslookup.py cloudflare.com -t DNSKEY --dnssec
python dnslookup.py cloudflare.com -t HTTPS
python dnslookup.py cloudflare.com -t DS
python dnslookup.py google.com -t 28

# Tra ngược IP
python dnslookup.py -x 8.8.8.8

# Truy vết đường phân giải root -> TLD -> authoritative
python dnslookup.py example.com --trace

# Chỉ định DNS server
python dnslookup.py example.com -s 8.8.8.8 -s 1.1.1.1
```

### Output mẫu

```
;; DnsLookup 1.0.0 <<>> example.com A
;; ->>HEADER<<- opcode QUERY, status NOERROR, id 48917
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.			IN	A

;; ANSWER SECTION:
example.com  93  IN  A  104.20.23.154
example.com  93  IN  A  172.66.147.243

;; Query time: 38.6 msec
;; SERVER: 1.1.1.1#53 (udp)
;; WHEN: Wed Aug 12 11:02:50 2026
;; MSG SIZE  rcvd: 61
```

---

## 3. Loại bản ghi hỗ trợ

`-t, --type TYPE` chọn loại bản ghi; phân biệt hoa/thường không quan trọng. Ngoài tên, chấp nhận cả số hiệu (ví dụ `-t 28`).

| Loại | Số | Giải mã rdata |
|---|---|---|
| `A` | 1 | Địa chỉ IPv4 |
| `AAAA` | 28 | Địa chỉ IPv6 |
| `CNAME` | 5 | Tên trỏ tới |
| `NS` | 2 | Nameserver |
| `HINFO` | 13 | CPU + OS |
| `PTR` | 12 | Tên ngược |
| `MX` | 15 | Preferrence + exchange |
| `TXT` | 16 | Chuỗi văn bản |
| `SPF` | 99 | Như TXT |
| `SOA` | 6 | mname, rname, serial, refresh, retry, expire, minimum |
| `SRV` | 33 | Priority, weight, port, target |
| `NAPTR` | 35 | Order, pref, flags, services, regexp, replacement |
| `CAA` | 257 | Flags, tag, value |
| `DS` | 43 | key tag, algorithm, digest type, digest |
| `DNSKEY` | 48 | Flags, protocol, algorithm, public key (base64) |
| `RRSIG` | 46 | Type covered, thuật toán, TTL gốc, key tag, signer, signature |
| `NSEC` | 47 | Next domain + danh sách type |
| `NSEC3` | 50 | Alg, flags, iterations, salt, next-hashed-owner (base32hex) |
| `TLSA` | 52 | Usage, selector, matching type, cert data |
| `HTTPS` (SVCB) | 65 | Priority, target, params (alpn, ipv4hint, ipv6hint, port...) |
| `ANY` | 255 | Tất cả bản ghi |

Tên miền quốc tế (IDN) tự chuyển sang punycode, ví dụ `bücher.de` → `xn--mnchen-3ya.de`.

---

## 4. Chọn DNS server

Mặc định tự đọc DNS server từ hệ thống (Windows qua `GetNetworkParams`, Linux/macOS qua `/etc/resolv.conf`), fallback về `1.1.1.1`. Có thể chỉ định nhiều server — công cụ thử lần lượt cho đến khi có phản hồi.

```bash
python dnslookup.py example.com -s 8.8.8.8
python dnslookup.py example.com -s 9.9.9.9 -s 8.8.8.8 -s 1.1.1.1
python dnslookup.py example.com -s 127.0.0.53 -p 5353    # dnsmasq/khác port
```

| Tham số | Mô tả |
|---|---|
| `-s, --server` | DNS server (dùng nhiều lần). Mặc định lấy từ hệ thống |
| `-p, --port` | Port DNS, mặc định 53 |
| `-T, --timeout` | Timeout mỗi request (giây), mặc định 3 |
| `--retries` | Số lần thử lại mỗi server, mặc định 2 |

---

## 5. Tra ngược (reverse lookup)

`-x IP` tự chuyển IP thành tên ngược và tra bản ghi `PTR`. Hỗ trợ cả IPv4 lẫn IPv6.

```bash
python dnslookup.py -x 8.8.8.8
# 8.8.8.8.in-addr.arpa  81184  IN  PTR  dns.google

python dnslookup.py -x 2606:4700::1111
# Tự chuyển thành 0.0.7.4.6.0.6.2.ip6.arpa
```

---

## 6. Truy vết đường phân giải (trace)

`--trace` mô phỏng trình phân giải đệ quy: hỏi lần lượt **root → TLD → authoritative**, mỗi bước hiện server được hỏi và kết quả (referral NS kèm glue, hoặc câu trả lời cuối).

```bash
python dnslookup.py example.com --trace
```

```
;; DnsLookup 1.0.0 <<>> TRACE example.com A
;; step 0: 198.41.0.4 (status NOERROR)
  [NS] com NS l.gtld-servers.net
  ...
;; step 1: 192.41.162.30 (status NOERROR)
  [NS] example.com NS hera.ns.cloudflare.com
  ...
;; step 2: 108.162.192.162 (status NOERROR)
  example.com 300 IN A 104.20.23.154
```

---

## 7. DNSSEC

`--dnssec` bật cờ DO (DNSSEC OK) để server gửi kèm bản ghi `RRSIG`. Tự động bật luôn khi query `DNSKEY`. Cờ `ad` trong header báo dữ liệu đã xác thực.

```bash
python dnslookup.py cloudflare.com -t DNSKEY --dnssec
python dnslookup.py nonexist.cloudflare.com -t A --dnssec -v   # bằng chứng NSEC/NSEC3
```

> Công cụ hiển thị và giải mã đầy đủ các bản ghi DNSSEC (DNSKEY/DS/RRSIG/NSEC/NSEC3) nhưng **không** thực hiện xác thực chữ ký. Xác thực cần thư viện chuyên dụng.

---

## 8. TCP và EDNS

| Tham số | Mô tả |
|---|---|
| `--tcp` | Ép dùng TCP. Mặc định dùng UDP; nếu phản hồi có cờ `TC` (truncated) sẽ **tự chuyển TCP**. Hữu ích khi cần chặn các zone lớn (AXFR-style) |
| `--edns-size N` | Gửi EDNS0 OPT với UDP payload size `N` (mặc định 1232 khi bật EDNS) |
| `--dnssec` | Kèm bit DO trong EDNS |

```bash
python dnslookup.py example.com --tcp
python dnslookup.py example.com --edns-size 4096 -v   # xem dòng "EDNS: version 0, udp 4096"
```

---

## 9. Query hàng loạt từ file

`--file FILE` đọc danh sách tên miền (mỗi dòng một tên, dòng bắt đầu bằng `#` là comment, tự bỏ BOM), query cùng một loại bản ghi cho tất cả.

```bash
# domains.txt:
#   example.com
#   gmail.com
#   cloudflare.com
python dnslookup.py --file domains.txt -t A
python dnslookup.py --file domains.txt --mx --short
```

---

## 10. Định dạng output

### Text (mặc định)

Kiểu dig: header, question, answer, authority, additional, thời gian, server. Thêm `-v` để xem thêm authority/additional (kể cả dòng EDNS).

### `--short`

Một dòng một bản ghi, dễ `grep`/xử lý:

```bash
python dnslookup.py gmail.com --mx --short
# gmail.com	774	IN	MX	5 gmail-smtp-in.l.google.com
# ...
```

### `--json` + `-o FILE`

Xuất JSON có cấu trúc: header, cờ, server, transport, thời gian, và các section answer/authority/additional với rdata được giải mã thành trường có tên.

```bash
python dnslookup.py example.com --json -o out.json
python dnslookup.py --file list.txt -t A --json -o out.json
```

```json
{
  "tool": "DnsLookup",
  "version": "1.0.0",
  "queries": [
    {
      "name": "example.com",
      "type": "A",
      "status": "NOERROR",
      "flags": {"qr": true, "aa": false, "rd": true, "ra": true},
      "server": "1.1.1.1",
      "port": 53,
      "transport": "udp",
      "time_ms": 38.6,
      "answer": [
        {"name": "example.com", "type": "A", "class": "IN", "ttl": 93,
         "rdata": {"type": "A", "address": "104.20.23.154"}}
      ]
    }
  ]
}
```

---

## 11. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | NOERROR (tra cứu thành công, có thể 0 bản ghi) |
| `1` | NXDOMAIN (tên miền không tồn tại) |
| `2` | Lỗi mạng/timeout/với mọi server |
| `3` | Lỗi đầu vào (type/domain/IP/file không hợp lệ) |

```powershell
python dnslookup.py this-domain-not-exist.com; echo "exit=$LASTEXITCODE"   # 1
```

> Khi query nhiều tên (file), exit code là giá trị **lớn nhất** gặp phải.

---

## 12. Tham số đầy đủ

| Tham số | Mô tả |
|---|---|
| `name` | Tên miền (vị trí), mặc định type `A` |
| `-t, --type TYPE` | Loại bản ghi (tên hoặc số hiệu) |
| `-s, --server SERVER` | DNS server, dùng nhiều lần |
| `-p, --port PORT` | Port DNS (53) |
| `-x IP` | Tra ngược PTR từ IP (IPv4/IPv6) |
| `--tcp` | Ép giao thức TCP |
| `-T, --timeout SEC` | Timeout mỗi request (3s) |
| `--retries N` | Số lần thử lại (2) |
| `--edns-size N` | EDNS0 UDP payload size |
| `--dnssec` | Bật cờ DO để nhận RRSIG |
| `--norecurse` | RD=0, chỉ hỏi authoritative |
| `--trace` | Truy vết root → TLD → authoritative |
| `--short` | Output gọn, 1 dòng/bản ghi |
| `--json` | Xuất JSON |
| `-o FILE` | Ghi kết quả ra file (kèm hiển thị) |
| `--file FILE` | Query hàng loạt từ file |
| `--aaaa` / `--mx` / `--ns` / `--txt` / `--cname` / `--soa` / `--caa` / `--srv` / `--any` | Phím tắt chọn loại bản ghi |
| `-v, --verbose` | Chi tiết hơn (authority/additional, EDNS) |
| `-h, --help` | Trợ giúp |

---

## 13. Ví dụ kết hợp

```bash
# 1) Kiểm tra phân giải + mail server của một loạt domain
python dnslookup.py --file domains.txt --mx --short

# 2) Chứng minh DNSSEC: DNSKEY + bằng chứng NSEC3
python dnslookup.py cloudflare.com -t DNSKEY --dnssec
python dnslookup.py qwerty.cloudflare.com -t A --dnssec -v

# 3) Truy vết toàn bộ đường phân giải để debug (khác biệt TTL giữa các bước)
python dnslookup.py example.com --trace

# 4) Tra ngược một /24 hoặc vài IP (viết từng IP vào file rồi -t PTR)
python dnslookup.py -x 8.8.8.8
python dnslookup.py -x 2001:4860:4860::8888

# 5) Kiểm tra SVCB/HTTPS (HTTP/3, alt-svc) và CAA (CA được phép cấp chứng chỉ)
python dnslookup.py cloudflare.com -t HTTPS
python dnslookup.py google.com -t CAA
```

---

## 14. Hạn chế

- **Không xác thực DNSSEC** (không kiểm tra chữ ký), chỉ query + hiển thị các bản ghi liên quan.
- Không hỗ trợ `IXFR`/`AXFR` (truyền zone) — chỉ tra cứu từng bản ghi.
- Không thực hiện cache; mỗi lần chạy là một query mới.
- `--norecurse` phụ thuộc server bạn hỏi — server đệ quy công cộng vẫn có thể trả lời từ cache.
- UDP mặc định giới hạn gói ~1232 byte (EDNS); query lớn hơn sẽ tự chuyển TCP.
