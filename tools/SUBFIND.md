# SubFind 1.0.0 — Tài liệu sử dụng

**Sản phẩm của Digital Core team.**

Công cụ tìm tên miền con (subdomain) viết bằng Python thuần (một file `subfind.py`), **không cần cài thêm thư viện**. Kết hợp ba nguồn dữ liệu: **Certificate Transparency (crt.sh)** (thụ động), **brute-force DNS** bằng wordlist (chủ động, có lọc wildcard), và **zone transfer (AXFR)** qua TCP. Tự dựng/giải mã gói tin DNS (wire format) như `dnslookup.py`, hỗ trợ xuất JSON, resolve A/AAAA kèm IP.

```
python subfind.py [tùy chọn] tên-miền
```

---

## Mục lục

1. [Yêu cầu](#1-yêu-cầu)
2. [Ví dụ nhanh](#2-ví-dụ-nhanh)
3. [Nguồn dữ liệu](#3-nguồn-dữ-liệu)
4. [Wildcard DNS](#4-wildcard-dns)
5. [Chọn DNS server và hiệu năng](#5-chọn-dns-server-và-hiệu-năng)
6. [Định dạng output](#6-định-dạng-output)
7. [Exit codes](#7-exit-codes)
8. [Tham số đầy đủ](#8-tham-số-đầy-đủ)
9. [Ví dụ kết hợp](#9-ví-dụ-kết-hợp)
10. [Hạn chế](#10-hạn-chế)
11. [Lưu ý pháp lý](#11-lưu-ý-pháp-lý)

---

## 1. Yêu cầu

| Thành phần | Ghi chú |
|---|---|
| Python ≥ 3.10 | Chỉ dùng thư viện chuẩn (`socket`, `struct`, `urllib`, `json`, `concurrent.futures`) |
| Kết nối internet | cần tới máy chủ DNS và crt.sh |

Không cần `pip install` gì cả.

---

## 2. Ví dụ nhanh

```bash
# Chỉ dùng crt.sh (thụ động, mặc định)
python subfind.py example.com

# Nhanh với ~N tên phổ biến tích hợp sẵn
python subfind.py example.com --top 100

# Brute-force với wordlist + resolve IP
python subfind.py cloudflare.com -w subdomains.txt --resolve

# Thử zone transfer (AXFR) trên các nameserver của miền
python subfind.py zonetransfer.me --axfr

# Kết hợp mọi nguồn, output JSON
python subfind.py example.com --top 200 -w big.txt --axfr --json -o out.json

# Tăng tốc / chỉ định DNS server
python subfind.py example.com -w list.txt -T 100 -s 8.8.8.8 -s 1.1.1.1
```

### Output mẫu

```
;; SubFind 1.0.0 <<>> cloudflare.com
;; crt.sh: 12 | brute-force: 34 | AXFR: 0

api.cloudflare.com  104.19.192.174, 2606:4700:300a::6813:c0ae
www.cloudflare.com  104.16.123.96, 2606:4700::6810:7b60

;; 46 subdomain(s) trong 3.2 s
```

> crt.sh thường xuyên chậm hoặc trả lỗi (502/404/timeout). Khi đó công cụ **không dừng** — chỉ ghi chú và tiếp tục các nguồn khác.

---

## 3. Nguồn dữ liệu

### 3.1 Certificate Transparency — crt.sh (thụ động, mặc định)

Truy vấn nhật ký chứng chỉ số công khai qua `https://crt.sh/?q=%25.<domain>&output=json` — liệt kê mọi tên miền từng xuất hiện trong chứng chỉ TLS đã cấp. Không cần API key, không chạm trực tiếp vào hệ thống đích.

- Tên wildcard trong chứng chỉ (`*.www.example.com`) được bỏ dấu `*.` và gom về `www.example.com`.
- Bản ghi không thuộc miền đang tìm bị loại.
- Tắt bằng `--no-crt`.

### 3.2 Brute-force DNS (chủ động)

```bash
python subfind.py example.com -w subdomains.txt
python subfind.py example.com --top 200        # wordlist tích hợp sẵn
```

Từng từ trong wordlist được ghép thành `<từ>.<domain>` và query trực tiếp bằng gói DNS thô (không qua resolver hệ thống), **chỉ giữ lại tên phân giải được** — NXDOMAIN tự bị loại. Mỗi tên được thử cả `A` và `AAAA`.

- `-w, --wordlist FILE` — mỗi dòng một từ; dòng bắt đầu bằng `#` là comment; tự bỏ BOM.
- `--top N` — dùng N tên phổ biến đầu tiên từ wordlist tích hợp (~60 tên: `www, mail, api, admin, dev...`).
- Tên chứa ký tự không hợp lệ hoặc dấu `.` bên trong sẽ bị bỏ qua (chỉ brute-force label đơn).

### 3.3 Zone transfer — AXFR (thụ động, mặc định tắt)

```bash
python subfind.py example.com --axfr
```

Tự tìm **nameserver** của miền (query `NS`), resolve ra IP, rồi lần lượt thử **AXFR** qua TCP trên từng server. Nếu server cấu hình sai (cho phép transfer), nhận được toàn bộ zone — gồm cả các bản ghi PTR/SRV mà brute-force không bao giờ tìm thấy.

- Chỉ cần **một** server cho phép là nhận đủ zone (các server sau không cần thử tiếp).
- Zone hiện đại gần như luôn chặn AXFR (`REFUSED`); `zonetransfer.me` là miền test kinh điển còn cho phép.

---

## 4. Wildcard DNS

Trước khi brute-force, công cụ query một tên ngẫu nhiên (`sf-probe-XXXXXXXX.<domain>`). Nếu tên đó **phân giải được**, miền đang dùng wildcard `*.domain` → mọi kết quả trùng IP với wildcard sẽ bị **loại** để tránh "subdomain giả" (false positive).

```bash
# Kết quả có wildcard:
python subfind.py github.com --top 50
# ;; wildcard: ['140.82.112.3', ...]  (ghi chú hiện ở dòng header)
```

---

## 5. Chọn DNS server và hiệu năng

Mặc định dùng `1.1.1.1`. Có thể chỉ định nhiều server — thử lần lượt tới khi có phản hồi.

| Tham số | Mô tả |
|---|---|
| `-s, --server SERVER` | DNS server, dùng nhiều lần |
| `-p, --port PORT` | Port DNS (53) |
| `-T, --threads N` | Số luồng brute-force song song (mặc định 40) |
| `--timeout SEC` | Timeout mỗi query DNS (3s) |
| `--retries N` | Số lần thử lại mỗi query (2) |

Wordlist lớn (hàng trăm nghìn tên) chạy nhanh nhờ `ThreadPoolExecutor`. Giảm `-T` nếu muốn "nhẹ tay" với mạng của bạn; tăng nếu muốn nhanh.

---

## 6. Định dạng output

### Text (mặc định)

Header kiểu dig, danh sách subdomain, tổng kết. Thêm `--resolve` để hiển thị IP (A/AAAA) sau mỗi tên.

### `--short`

Chỉ in tên, mỗi dòng một tên — dễ `grep`/nối vào pipeline:

```bash
python subfind.py example.com --top 100 --short > subs.txt
```

### `--json` + `-o FILE`

JSON có cấu trúc: nguồn dữ liệu (số lượng từng nguồn), wildcard phát hiện, danh sách subdomain kèm IP, thời gian chạy.

```json
{
  "tool": "SubFind",
  "version": "1.0.0",
  "domain": "example.com",
  "queried_at": "2026-08-12T11:30:12+07:00",
  "sources": {"crt.sh": 12, "bruteforce": 34, "axfr": 0},
  "wildcard": [],
  "total": 46,
  "subdomains": [
    {"name": "api.example.com", "ips": ["104.19.192.174"]}
  ]
}
```

`-o FILE` ghi kết quả ra file (vẫn hiển thị trên màn hình).

---

## 7. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Thành công (tìm thấy ≥ 1 subdomain) |
| `1` | Không tìm thấy subdomain nào |
| `2` | (dành cho lỗi mạng mọi nguồn) |
| `3` | Lỗi đầu vào (domain/wordlist không hợp lệ) |

```powershell
python subfind.py this-domain-does-not-exist.com --top 5; echo "exit=$LASTEXITCODE"   # 1
```

> Crt.sh lỗi tạm thời **không** làm exit code khác 0 nếu vẫn tìm thấy subdomain từ nguồn khác.

---

## 8. Tham số đầy đủ

| Tham số | Mô tả |
|---|---|
| `domain` | Tên miền cần tìm subdomain (vị trí) |
| `-w, --wordlist FILE` | Wordlist brute-force |
| `--top N` | Dùng N tên phổ biến tích hợp sẵn |
| `--no-crt` | Tắt nguồn crt.sh |
| `--axfr` | Thử zone transfer (AXFR) qua TCP |
| `--resolve` | Phân giải A/AAAA và hiển thị IP |
| `-s, --server SERVER` | DNS server, dùng nhiều lần |
| `-p, --port PORT` | Port DNS (53) |
| `-T, --threads N` | Số luồng brute-force (40) |
| `--timeout SEC` | Timeout mỗi query (3s) |
| `--retries N` | Số lần thử lại (2) |
| `--short` | Chỉ in tên, 1 dòng/1 tên |
| `--json` | Xuất JSON |
| `-o FILE` | Ghi kết quả ra file |
| `-v, --verbose` | In chi tiết tiến trình (tên tìm được, wildcard...) |
| `--no-color` | Tắt màu ANSI |
| `-h, --help` | Trợ giúp |

---

## 9. Ví dụ kết hợp

```powershell
# 1) Thu thập subdomain → resolve IP → đưa vào PyScan để quét cổng
python subfind.py example.com -w big.txt --resolve --json -o C:\scans\subs.json
python -c "import json;[print(s['name']) for s in json.load(open('C:\scans\subs.json'))['subdomains']]" > C:\scans\hosts.txt
python pyscan.py -sT -sV -p 80,443,8080,8443 -iL C:\scans\hosts.txt

# 2) Tìm host web rồi quét bảo mật HTTP
python subfind.py example.com --top 100 --short | Select-String "www|api|dev"
python httpsec.py https://api.example.com --active

# 3) Kiểm tra cấu hình zone transfer sai sót (pentest authorized)
python subfind.py example.com --axfr

# 4) Xác minh chứng chỉ / DNSSEC của từng subdomain
python dnslookup.py www.example.com --dnssec
```

---

## 10. Hạn chế

- **crt.sh phụ thuộc dịch vụ bên ngoài** — hay chậm/lỗi (502/404/timeout); công cụ chỉ ghi chú, không dừng.
- Brute-force chỉ tìm được **tên nằm trong wordlist**; tên có nhiều label (`a.b.example.com`) cần wordlist riêng.
- Wildcard phát hiện ở mức base domain; wildcard theo nhánh con (`*.sub.example.com`) có thể vẫn lọt vào kết quả.
- AXFR hiện bị chặn trên hầu hết zone; kết quả chỉ có khi server cấu hình sai.
- Không hỗ trợ source cần API key (VirusTotal, SecurityTrails...).

---

## 11. Lưu ý pháp lý

Chỉ dùng với **miền bạn sở hữu hoặc được ủy quyền kiểm tra**. Brute-force DNS và thử AXFR có thể vi phạm điều khoản sử dụng của bên thứ ba hoặc pháp luật nếu dùng không đúng mục đích.
