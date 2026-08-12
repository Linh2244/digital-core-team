# LoginBF 1.0.0 — Brute Force Login HTTP

`loginbf.py` thử các tổ hợp username/password vào một endpoint đăng nhập để tìm tài khoản hợp lệ. Hỗ trợ 4 mode: **HTTP Basic Auth**, **POST form**, **POST JSON**, **query string**. Có wordlist username/password tích hợp sẵn (tắt bằng `--no-defaults`) hoặc nạp từ file với `-U`/`-P`. Nhận diện thành công linh hoạt theo status code hoặc chuỗi trong body. Sản phẩm của **Digital Core team**, Python thuần (stdlib `urllib`), không cần cài thư viện.

```
python loginbf.py URL
python loginbf.py --basic -U users.txt -P pass.txt URL
python loginbf.py --form --failure-text "Invalid password" URL
```

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Kiểm tra nhanh](#2-kiểm-tra-nhanh)
3. [Các mode đăng nhập](#3-các-mode-đăng-nhập)
4. [Wordlist](#4-wordlist)
5. [Nhận diện thành công / thất bại](#5-nhận-diện-thành-công--thất-bại)
6. [Kiểm soát tốc độ](#6-kiểm-soát-tốc-độ)
7. [Tùy biến request](#7-tùy-biến-request)
8. [Tham số](#8-tham-số)
9. [Exit codes](#9-exit-codes)
10. [Ví dụ](#10-ví-dụ)
11. [Lưu ý](#11-lưu-ý)

---

## 1. Cài đặt

Yêu cầu: **Python ≥ 3.10** (có sẵn trong bộ Digital Core Toolkit). Không cần cài thêm:

```powershell
python loginbf.py http://192.168.1.10/login
```

Mặc định dùng wordlist tích hợp (9.619 username × 1.000 password), tự dò xem thử endpoint nào đăng nhập được. Để dò nhanh hơn, giới hạn bằng `--top N` (chỉ dùng N username + N password đầu tiên).

---

## 2. Kiểm tra nhanh

```
;; LoginBF 1.0.0 <<>> Digital Core team
Mục tiêu: http://192.168.1.10/login | mode: form
Đã thử 10000/10000 | lỗi mạng 0 | 9.0s (1111/s)   (dùng --top 100)

TÌM THẤY 2 tài khoản hợp lệ:
  1. admin : P@ssw0rd   (HTTP 200)
  2. root : letmein   (HTTP 200)
```

Khối kết quả gồm: mục tiêu + mode, tổng số lần thử, lỗi mạng, thời gian + tốc độ, và danh sách tài khoản tìm thấy (đủ user/password/HTTP status). Dùng `--json-output -o report.json` để xuất cấu trúc máy đọc được.

---

## 3. Các mode đăng nhập

| Mode | Cờ | Request |
|---|---|---|
| POST form | `--form` (mặc định) | `POST` body `application/x-www-form-urlencoded` với `username=...&password=...` |
| POST JSON | `--json` | `POST` body `{"username":"...","password":"..."}` |
| HTTP Basic | `--basic` | `GET` kèm header `Authorization: Basic ...` |
| Query string | `--get` | `GET` kèm `?username=...&password=...` |

Tên field mặc định là `username`/`password`, đổi được bằng `--user-field` và `--pass-field`. Field phụ (token CSRF, captcha fake...) thêm bằng `--data name=value` (lặp lại).

---

## 4. Wordlist

| Nguồn | Cờ | Ghi chú |
|---|---|---|
| Tích hợp sẵn | (mặc định) | 9.619 username (từ `username.txt`) + 1.000 password phổ biến nhất (từ `password.txt`) |
| File username | `-U users.txt` | 1 dòng 1 user, **cộng thêm** vào built-in |
| File password | `-P pass.txt` | 1 dòng 1 pass, **cộng thêm** vào built-in |
| Chỉ dùng file | `--no-defaults` | bỏ hoàn toàn wordlist tích hợp |
| Giới hạn built-in | `--top N` | chỉ dùng N username + N password đầu tiên của built-in (khuyên dùng khi dò nhanh) |

Các dòng trùng lặp bị loại tự động. Ví dụ `-U myusers.txt -P mypass.txt --no-defaults` → chỉ thử đúng 2 file đó. Số tổ hợp = số user × số password (duyệt theo thứ tự file trước, built-in sau).

---

## 5. Nhận diện thành công / thất bại

Thứ tự ưu tiên:

1. `--failure-text STR` — body chứa chuỗi này → thất bại (bỏ qua, không báo).
2. `--success-text STR` — body chứa chuỗi này → thành công (chỉ đúng chuỗi này mới tính).
3. `--success-code N` — status trùng (lặp lại được) → thành công.
4. `--failure-code N` — status trùng → thất bại. Mặc định là **401, 403**.
5. Nếu không khớp gì → thành công khi status **2xx**, còn lại là thất bại.

Nhiều trang login trả **cùng 200 cho cả đúng và sai**, chỉ khác body (ví dụ `Welcome back admin` vs `Invalid username or password`). Với trường hợp này bắt buộc dùng `--success-text` hoặc `--failure-text`, nếu không mọi cặp 2xx sẽ bị báo là tìm thấy.

---

## 6. Kiểm soát tốc độ

| Cờ | Ý nghĩa |
|---|---|
| `-t, --threads N` | Số thread song song (mặc định 10). Giảm nếu server hạn chế tốc độ |
| `--delay SECONDS` | Ngủ `SECONDS` giây sau mỗi lần thử (per attempt, mặc định 0) |
| `--timeout SECONDS` | Timeout mỗi request (mặc định 10) |
| `--retries N` | Thử lại khi lỗi mạng (mặc định 0) |
| `--stop-first` | Dừng ngay khi tìm thấy tài khoản đầu tiên (tiết kiệm thời gian cho bài test nhanh) |

`-t 1 --delay 1` = gần như chậm 1 request/giây — phù hợp khi cần né bộ chống brute force. Luôn chạy vài lần với `-t 4`/`-t 8` để ước lượng tốc độ server chịu được trước khi tăng.

---

## 7. Tùy biến request

| Cờ | Ý nghĩa |
|---|---|
| `--header "Name: value"` | Header thêm vào mọi request (lặp lại) |
| `--cookie "session=abc..."` | Gửi Cookie (đăng nhập sau khi đã có session, đổi field...) |
| `--user-agent STR` | User-Agent (mặc định `LoginBF/1.0.0`) |
| `--data name=value` | Field form/json phụ (lặp lại) |
| `--proxy URL` | Đi qua proxy (vd `http://127.0.0.1:8080`) |
| `--insecure` | Bỏ qua verify chứng chỉ TLS (self-signed) |

---

## 8. Tham số

| Tham số | Ý nghĩa |
|---|---|
| `url` (vị trí) | URL endpoint login (`http://` hoặc `https://`) |
| `--basic` / `--form` / `--json` / `--get` | Chọn mode (mặc định `--form`) |
| `-U, --users FILE` | File username (1 dòng 1 user) |
| `-P, --passwords FILE` | File password (1 dòng 1 pass) |
| `--no-defaults` | Không dùng wordlist tích hợp sẵn |
| `--top N` | Chỉ dùng N username + N password đầu tiên của wordlist tích hợp (mặc định full 9.619 × 1.000) |
| `--user-field NAME` | Tên field username (mặc định `username`) |
| `--pass-field NAME` | Tên field password (mặc định `password`) |
| `-t, --threads N` | Số thread (mặc định 10) |
| `--delay S` / `--timeout S` / `--retries N` | Tốc độ & độ bền (xem mục 6) |
| `--success-text` / `--failure-text` | Nhận diện theo chuỗi body |
| `--success-code N` / `--failure-code N` | Nhận diện theo status (mặc định fail 401, 403) |
| `--data NAME=VALUE` | Field form/json phụ (lặp lại) |
| `--header "NAME:VALUE"` / `--cookie STR` / `--user-agent STR` | Header tùy chỉnh |
| `--proxy URL` / `--insecure` | Proxy / bỏ qua TLS |
| `--stop-first` | Dừng khi tìm thấy cặp đầu tiên |
| `--json-output` | Output JSON |
| `-o, --output FILE` | Ghi kết quả ra file (vẫn in ra màn hình) |
| `-v, --verbose` | In tiến trình ra stderr |
| `--no-color` | Tắt màu ANSI |

Output JSON gồm `tool`, `version`, `team`, `queried_at`, `target`, `mode`, `total`, `tested`, `errors`, `elapsed`, `rate` và `found` (mảng `{username, password, status}`).

---

## 9. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Chạy xong, **không** tìm thấy tài khoản nào |
| `1` | Tìm thấy **≥ 1** tài khoản hợp lệ |
| `2` | Lỗi đầu vào: URL sai, thiếu wordlist sau khi lọc, tham số mâu thuẫn |

Dùng trong script/CI: `loginbf.py URL; if ($LASTEXITCODE -eq 1) { "TÌM THẤY CRED!" }`.

---

## 10. Ví dụ

```powershell
# Dò nhanh bằng wordlist tích hợp (mode form mặc định)
python loginbf.py http://192.168.1.10/login

# Basic auth với wordlist riêng
python loginbf.py --basic -U users.txt -P pass.txt https://mail.example.com/basic

# Form login trả 200 cả đúng/sai, phân biệt bằng body
python loginbf.py --form --failure-text "Invalid username or password" http://app/login

# API JSON login
python loginbf.py --json --success-text '"ok":true' https://api.example.com/auth

# Form có field phụ (vd hidden token / tên field khác)
python loginbf.py --form --user-field email --pass-field pw --data csrf=abc123 http://app/login

# Chậm, né rate-limit: 1 request/giây
python loginbf.py -t 1 --delay 1 http://app/login

# Chỉ dùng file wordlist riêng, không built-in
python loginbf.py --no-defaults -U users.txt -P pass.txt http://app/login

# Dừng khi tìm thấy tài khoản đầu tiên
python loginbf.py --stop-first http://app/login

# Qua proxy + bỏ qua TLS self-signed
python loginbf.py --insecure --proxy http://127.0.0.1:8080 https://app/login

# Xuất JSON cho script
python loginbf.py --json-output -o report.json http://app/login

# Script: thông báo ngay khi có cred
python loginbf.py http://app/login; if ($LASTEXITCODE -eq 1) { "CO CRED!" }
```

---

## 11. Lưu ý

- **Chỉ dùng trên hệ thống bạn sở hữu hoặc đã được cấp phép kiểm thử.** Brute force trái phép vi phạm pháp luật ở hầu hết quốc gia; người dùng chịu trách nhiệm tuân thủ.
- Brute force gây tải cho server và dễ bị khóa IP / kích hoạt rate-limit, lockout, ghi log. Bắt đầu với `--stop-first` và `-t` nhỏ, `--delay` phù hợp; nếu server có lockout sau N lần sai, chiến thuật này sẽ không hiệu quả — hãy cân nhắc thử từng user cho nhiều mật khẩu thay vì lướt cả grid.
- Kết quả "tìm thấy" phụ thuộc cách nhận diện. Nếu thấy quá nhiều cặp 2xx, gần như chắc chắn cần `--success-text`/`--failure-text`. Nếu không tìm thấy gì dù biết có cred, kiểm tra lại mode (`--basic` vs `--form`), tên field, header/cookie cần thiết.
- Wordlist tích hợp là **tham khảo nội bộ**, không đầy đủ (9.619 user × top 1.000 pass). Muốn hiệu quả hơn, dùng wordlist đúng context (tên công ty, mùa/năm, tên nhân viên) qua `-U`/`-P`.
- Công cụ dùng `urllib` thuần; endpoint nhận Content-Type khác (XML, multipart...) hoặc cần JS/anti-CSRF phức tạp sẽ cần chỉnh `--data`/`--header` hoặc script riêng.
