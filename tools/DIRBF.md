# DirBF 1.0.0 — Tài liệu sử dụng

**Sản phẩm của Digital Core team.**

Công cụ brute-force **thư mục/file trên web** viết bằng Python thuần (một file `dirbf.py`), **không cần cài thêm thư viện**. Có wordlist tích hợp sẵn (269 đường dẫn phổ biến: admin, .env, backup, actuator, wp-config...), hỗ trợ wordlist tùy chỉnh, thêm đuôi file tự động (`-x`), lọc theo status code, bắt redirect 3xx kèm `Location`, song song nhiều thread và xuất JSON.

```
python dirbf.py [tùy chọn] URL-gốc
```

---

## Mục lục

1. [Yêu cầu](#1-yêu-cầu)
2. [Ví dụ nhanh](#2-ví-dụ-nhanh)
3. [Cách hoạt động và nhận diện](#3-cách-hoạt-động-và-nhận-diện)
4. [Wordlist](#4-wordlist)
5. [Thêm đuôi file](#5-thêm-đuôi-file)
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
| Python ≥ 3.10 | Chỉ dùng thư viện chuẩn (`urllib`, `ssl`, `json`, `concurrent.futures`) |
| Kết nối tới máy chủ web | cần tới target |

Không cần `pip install` gì cả.

---

## 2. Ví dụ nhanh

```bash
# Quét nhanh bằng wordlist tích hợp
python dirbf.py http://192.168.1.10/

# Giới hạn N đường dẫn đầu tiên của built-in (dò nhanh)
python dirbf.py http://192.168.1.10/ --top 200

# Wordlist tùy chỉnh + tự thêm đuôi php/bak
python dirbf.py https://site.com -w dirs.txt -x php,bak

# Chỉ quan tâm 200/301, bỏ qua 403, tăng tốc 30 thread
python dirbf.py https://site.com --code 200,301 --hide 403 -t 30

# Quét một nhánh (base có path), bỏ built-in, kèm cookie
python dirbf.py http://10.0.0.5/app/ --no-defaults -w list.txt --cookie "sid=abc"

# Output JSON cho script / CI
python dirbf.py http://192.168.1.10 --json-output -o report.json
```

### Output mẫu

```
;; DirBF 1.0.0 <<>> Digital Core team
Mục tiêu: http://192.168.1.10/ | từ điển: 269 đường dẫn
Đã thử 269/269 | lỗi mạng 0 | 2.1s (128/s)

TÌM THẤY 6 đường dẫn:

  + http://192.168.1.10/admin  (200, 1.2KB)
  + http://192.168.1.10/.git    (403, 12B)
  + http://192.168.1.10/old     (301, 0B, -> /new)
  + http://192.168.1.10/api     (200, 45B)

;; 6 đường dẫn trong 2.1s
```

---

## 3. Cách hoạt động và nhận diện

Với mỗi đường dẫn trong từ điển, công cụ gửi một request **GET** tới `<base>/<đường-dẫn>` và quyết định "tìm thấy" theo status code:

| Trạng thái | Mặc định |
|---|---|
| `200, 204` | ✅ tìm thấy |
| `301, 302, 303, 307, 308` | ✅ tìm thấy (kèm `Location`) |
| `401, 403` | ✅ tìm thấy (thư mục tồn tại nhưng chặn truy cập) |
| `5xx` | ✅ tìm thấy (lỗi server) |
| `404` | ❌ bỏ qua (mặc định) |
| Lỗi mạng / timeout | đếm vào "lỗi mạng", không báo |

Điều chỉnh bằng:

- `--code 200,301` — **chỉ** báo các code này.
- `--hide 403,500` — bỏ qua thêm các code này (404 luôn bị bỏ qua).

> **Redirect được bắt nguyên trạng** (không tự follow) — bạn thấy cả `301` và đích `Location`, đây thường là thư mục tồn tại. Kèm **kích thước** (từ `Content-Length`, nếu thiếu thì độ dài body) để phát hiện trang "soft 404" (mọi path đều trả 200 cùng nội dung giống nhau).

---

## 4. Wordlist

| Nguồn | Cờ | Ghi chú |
|---|---|---|
| Tích hợp sẵn | (mặc định) | 269 đường dẫn phổ biến (admin, .env, .git, backup, wp-admin, actuator, phpinfo, swagger...) |
| File tùy chỉnh | `-w dirs.txt` | 1 dòng 1 đường dẫn, **cộng thêm** vào built-in; dòng bắt đầu `#` là comment |
| Chỉ dùng file | `--no-defaults` | bỏ hoàn toàn wordlist tích hợp |
| Giới hạn built-in | `--top N` | chỉ dùng N đường dẫn đầu tiên của built-in |

Dòng trùng lặp bị loại tự động. Các entry có thể chứa dấu `/` (`.git/HEAD`, `wp-content/uploads`, `actuator/health`) hoặc ký tự đặc biệt (`.env`, `.htaccess`).

```bash
# Chỉ thử đúng file của bạn
python dirbf.py http://10.0.0.5 --no-defaults -w dirs.txt
```

---

## 5. Thêm đuôi file

`-x php,html,bak` tự sinh thêm biến thể có đuôi cho từng từ trong từ điển:

```
admin      -> admin, admin.php, admin.html, admin.bak
login.php  -> login.php  (từ đã có dấu chấm, không thêm đuôi)
```

Hữu ích khi server đã có route gốc (như `admin`) nhưng bạn muốn tìm thêm `admin.php`, `admin.bak`... Wordlist file lớn có thể dùng cùng `-x`.

---

## 6. Định dạng output

### Text (mặc định)

Header kiểu dig (mục tiêu, số từ trong từ điển, số đã thử, lỗi mạng, thời gian/tốc độ), danh sách `+ URL (status, size[, -> Location])`, tổng kết.

### `--json-output` + `-o FILE`

```json
{
  "tool": "DirBF",
  "version": "1.0.0",
  "target": "http://192.168.1.10/",
  "total": 269,
  "tested": 269,
  "errors": 0,
  "elapsed": 2.1,
  "rate": 128,
  "found": [
    {"path": "admin", "status": 200, "size": 1229, "location": null}
  ]
}
```

`-o FILE` ghi kết quả ra file (vẫn hiển thị trên màn hình).

---

## 7. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Quét xong, **không** tìm thấy đường dẫn nào |
| `1` | Tìm thấy ≥ 1 đường dẫn |
| `2` | Lỗi đầu vào (URL sai, `--top`/`--threads`/`--delay`/`--code` không hợp lệ, không có đường dẫn nào để thử) |
| `3` | Mọi request đều lỗi mạng (target không tới được, timeout) |

```powershell
python dirbf.py http://192.168.1.10 --no-defaults -w dirs.txt; echo "exit=$LASTEXITCODE"
```

> Giống `grep`: exit `1` khi **có** kết quả — tiện cho script "tìm thấy rồi thì làm tiếp".

---

## 8. Tham số đầy đủ

| Tham số | Mô tả |
|---|---|
| `url` (vị trí) | URL gốc: `http://host/` hoặc `http://host/app/` |
| `-w, --wordlist FILE` | Wordlist đường dẫn (cộng thêm vào built-in) |
| `--no-defaults` | Không dùng wordlist tích hợp |
| `--top N` | Chỉ dùng N đường dẫn đầu tiên của built-in |
| `-x, --extensions EXTS` | Thêm đuôi cho từng từ: `php,html,bak` |
| `--code CODES` | Chỉ báo các status này: `200,301` |
| `--hide CODES` | Bỏ qua thêm các status này: `403,500` |
| `-t, --threads N` | Số luồng song song (10) |
| `--delay SEC` | Độ trễ giữa các lần thử |
| `--timeout SEC` | Timeout mỗi request (10s) |
| `--retries N` | Số lần thử lại khi lỗi mạng (0) |
| `-H "NAME: VAL"` | Header tùy chỉnh, dùng nhiều lần |
| `-A, --user-agent UA` | Đổi User-Agent |
| `--cookie STR` | Header Cookie (vd `sid=abc`) |
| `--proxy URL` | Proxy HTTP/HTTPS (vd `http://127.0.0.1:8080`) |
| `--insecure` | Bỏ qua xác minh TLS (self-signed) |
| `--stop-first` | Dừng ngay khi tìm thấy đường dẫn đầu tiên |
| `--json-output` | Xuất JSON thay vì text |
| `-o FILE` | Ghi kết quả ra file |
| `-v, --verbose` | In tiến trình ra stderr |
| `--no-color` | Tắt màu ANSI |
| `-h, --help` | Trợ giúp |

---

## 9. Ví dụ kết hợp

```powershell
# 1) Enumerate đường dẫn web → đưa các URL tìm được vào kiểm tra sâu
python dirbf.py http://192.168.1.10 --json-output -o C:\scans\dirs.json
python httpsec.py http://192.168.1.10/admin --active

# 2) Tìm backup/credential rồi brute-force đăng nhập với LoginBF
python dirbf.py https://site.com -x php,bak,zip --code 200 --no-color
python loginbf.py -U C:\scans\users.txt -P C:\scans\pass.txt --form https://site.com/admin

# 3) Kết hợp với SubFind: tìm subdomain → quét thư mục từng host web
python subfind.py example.com --top 100 --short | Select-String "www|api"
python dirbf.py http://api.example.com -w big-dirs.txt -t 50

# 4) Kiểm tra file cấu hình nhạy cảm rò rỉ (only authorized)
python dirbf.py http://10.0.0.5 --code 200 -x env,log,sql --no-color
```

---

## 10. Hạn chế

- Chỉ tìm được **đường dẫn nằm trong từ điển**; từ điển riêng theo context (framework, tên app) cho kết quả tốt hơn.
- Không tự **đệ quy** vào thư mục vừa tìm được — quét từng base một.
- Server trả 200 cho mọi path ("soft 404") gây nhiễu: dùng `--code` kết hợp `--hide`, so kích thước trả về, hoặc thử wordlist khác.
- Mọi path trả `403` (sau tường lửa/auth) — dùng `--hide 403`.
- Request GET có thể bị ghi log / rate-limit; dùng `--delay`, `-t` nhỏ khi cần "nhẹ tay".

---

## 11. Lưu ý pháp lý

Chỉ dùng với **máy chủ bạn sở hữu hoặc được ủy quyền kiểm tra**. Brute-force thư mục trái phép vi phạm pháp luật ở hầu hết quốc gia; người dùng chịu trách nhiệm tuân thủ.
