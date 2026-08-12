# JWTCheck 1.0.0 — JWT Inspector

`jwtcheck.py` giải mã và kiểm tra bảo mật JWT (JSON Web Token): phát hiện `alg: none`, algorithm confusion (jwk/x5c/jku), HMAC secret yếu, URL `jku`/`x5u` trỏ ra ngoài/private, kid injection, các claim `exp`/`nbf`/`iat`, rồi xác thực chữ ký bằng `--secret` (HMAC) hoặc `--pubkey` (RSA/ECDSA/EdDSA) và brute-force secret bằng wordlist. Sản phẩm của **Digital Core team**, Python thuần (stdlib, ngoại trừ `--pubkey` tùy chọn cần thư viện `cryptography`), không gọi dịch vụ ngoài.

```
python jwtcheck.py TOKEN_OR_FILE [TOKEN_OR_FILE...]
python jwtcheck.py --secret SECRET TOKEN        # verify HMAC
python jwtcheck.py --pubkey public.pem TOKEN    # verify RS*/PS*/ES*/EdDSA
```

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Kiểm tra nhanh](#2-kiểm-tra-nhanh)
3. [Nhiều token, file và stdin](#3-nhiều-token-file-và-stdin)
4. [Xác thực chữ ký](#4-xác-thực-chữ-ký)
5. [Các vấn đề bảo mật được phát hiện](#5-các-vấn-đề-bảo-mật-được-phát-hiện)
6. [Thang điểm](#6-thang-điểm)
7. [Tham số](#7-tham-số)
8. [Exit codes](#8-exit-codes)
9. [Ví dụ](#9-ví-dụ)
10. [Lưu ý](#10-lưu-ý)

---

## 1. Cài đặt

Yêu cầu: **Python ≥ 3.10**. Không cần cài thêm gì (bộ Digital Core Toolkit có sẵn Python):

```powershell
python jwtcheck.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ..."
```

Với `--pubkey` để xác thực chữ ký bất đối xứng cần thư viện `cryptography` (nếu thiếu, công cụ vẫn chạy và báo "can thu vien 'cryptography'" thay vì kết quả verify).

---

## 2. Kiểm tra nhanh

Mỗi token được in một khối gồm: tóm tắt header (alg, exp, iss) và danh sách phát hiện theo nhóm `HEADER` / `PAYLOAD` / `SIGNATURE` / `FORMAT`, mỗi dòng gồm trạng thái (PASS/INFO/WARN/FAIL), mức độ (CRITICAL/HIGH/MEDIUM/LOW/INFO) và mô tả:

```powershell
python jwtcheck.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ..."
# ;; JWTCheck 1.0.0 <<>> Digital Core team
#
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
#   alg: HS256   exp: khong co   iss: -
#   INFO  INFO     alg HS256 (HMAC) - chu ky doi xung
#   INFO  INFO     khong co header 'kid'
#   WARN  MEDIUM   thieu claim 'exp' - token khong het han
#   ...
#   VERDICT: Score 70/100 (B) | 1 token, 1 co loi
```

Khối cuối là **VERDICT**: điểm thấp nhất trong các token, xếp hạng A–F và số token bị phát hiện lỗi.

---

## 3. Nhiều token, file và stdin

Mỗi argument có thể là một JWT string **hoặc đường dẫn file** (tự nhận biết bằng `os.path.isfile`); mỗi file có thể chứa nhiều token, mỗi token trên một dòng:

```powershell
# Nhiều token trong 1 lệnh
python jwtcheck.py TOKEN_A TOKEN_B

# File chứa token (1 token/dòng)
python jwtcheck.py tokens.txt

# Nhiều file + token trộn lẫn
python jwtcheck.py tokens.txt "eyJhbGciOiJ..."

# Đọc từ stdin (ký tự -), hữu ích cho pipe
Get-Content token.txt | python jwtcheck.py -
```

Truyền file bị sai đường dẫn (không tồn tại) sẽ được coi là token string và báo lỗi định dạng — hãy đảm bảo path đúng.

---

## 4. Xác thực chữ ký

| Cách | Lệnh | Ý nghĩa |
|---|---|---|
| HMAC bằng secret đã biết | `--secret SECRET` | So chữ ký với HMAC-SHA256/384/512 (khớp → PASS, lệch → FAIL HIGH) |
| HMAC brute-force | `--wordlist file.txt` | Thử từng dòng wordlist, tìm thấy → FAIL CRITICAL |
| HMAC secret mặc định | tự động | Dò 30 secret yếu phổ biến (secret, password, jwt_secret...); tìm thấy → FAIL CRITICAL. Tắt bằng `--no-brute` |
| Bất đối xứng | `--pubkey public.pem` | Verify RS*/PS*/ES*/EdDSA (cần `cryptography`) |

Không cung cấp cách nào ở trên → báo `chua verify HMAC - dung --secret hoac --wordlist` (INFO). Riêng HMAC luôn tự dò secret mặc định trừ khi bật `--no-brute`.

---

## 5. Các vấn đề bảo mật được phát hiện

| Nhóm | Vấn đề | Mức |
|---|---|---|
| HEADER | `alg: none` hoặc `alg: None` (bỏ qua chữ ký) | CRITICAL |
| HEADER | `alg` lạ (ngoài danh sách đã biết) | WARN MEDIUM |
| HEADER | Alg HMAC nhưng kèm `jwk`/`x5c`/`jku`/`x5u` → nguy cơ algorithm confusion | CRITICAL |
| HEADER | `crit` cho phép header không khai báo | FAIL HIGH |
| HEADER | `kid` chứa `../`, `/`, `\`, `%` (path traversal / key injection) | FAIL HIGH |
| HEADER | `kid` dài bất thường (> 64 ký tự) | WARN LOW |
| HEADER | `jku`/`x5u` dùng `http://` (plaintext) | FAIL CRITICAL |
| HEADER | `jku`/`x5u` trỏ localhost/private IP | FAIL HIGH |
| HEADER | `jku`/`x5u` là URL ngoài — chỉ tin theo whitelist | WARN MEDIUM |
| PAYLOAD | Thiếu `exp` | WARN MEDIUM |
| PAYLOAD | Token hết hạn (`exp` < hiện tại − skew 60s) | FAIL HIGH |
| PAYLOAD | `exp` xa quá (> 1 năm) hoặc thời gian sống quá dài | WARN LOW/MEDIUM |
| PAYLOAD | `nbf` trong tương lai (token chưa hiệu lực) | FAIL MEDIUM |
| PAYLOAD | `iat` trong tương lai | WARN MEDIUM |
| SIGNATURE | Dò ra HMAC secret yếu / secret trong wordlist | CRITICAL |
| SIGNATURE | Chữ ký HMAC không khớp `--secret` | FAIL HIGH |
| FORMAT | JWE (5 phần, mã hóa) — chỉ báo, không phân tích nội dung | INFO |

Thiếu `iss`/`aud`/`sub` chỉ là INFO (có thể không quan trọng nếu không dùng). Không có `kid` cũng chỉ INFO.

---

## 6. Thang điểm

Bắt đầu từ **100**, trừ mỗi FAIL: CRITICAL −30, HIGH −20, MEDIUM −10, LOW −5 (chỉ FAIL mới trừ; INFO/WARN/PASS không). Điểm thấp nhất có thể là 0. Xếp hạng:

| Điểm | Xếp hạng |
|---|---|
| ≥ 90 | A |
| 75 – 89 | B |
| 60 – 74 | C |
| 45 – 59 | D |
| < 45 | F |

---

## 7. Tham số

| Tham số | Ý nghĩa |
|---|---|
| `token...` (vị trí) | JWT string hoặc file chứa JWT (dùng nhiều lần) |
| `-` | Đọc JWT từ stdin |
| `--secret STR` | Secret để verify HMAC (HS256/384/512) |
| `--pubkey FILE` | PEM public key để verify RS*/PS*/ES*/EdDSA (cần `cryptography`) |
| `--wordlist FILE` | Brute-force HMAC secret bằng wordlist (1 dòng 1 secret) |
| `--no-brute` | Không dò các HMAC secret mặc định |
| `--json` | Output JSON |
| `--md` | Output Markdown (thường dùng kèm `-o file.md`) |
| `-o, --output FILE` | Ghi kết quả ra file (vẫn in ra màn hình) |
| `--no-color` | Tắt màu ANSI |
| `--version` | In phiên bản |

Output JSON gồm `tool`, `version`, `team`, `queried_at` và `tokens`: mỗi phần tử có `token`, `header`, `payload`, `findings` (group/status/severity/detail), `score`, `ok`, `jwe`.

---

## 8. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Kiểm tra xong, **không** có lỗi hồng bảo mật (chỉ PASS/INFO/WARN) |
| `1` | Có **≥ 1** lỗi hồng bảo mật (FAIL) ở bất kỳ token nào |
| `2` | Lỗi đầu vào: không có JWT nào (thiếu argument/stdin), token sai định dạng, hoặc file không đọc được |

Dùng trong CI/script: `jwtcheck.py --json token` trả về `1` ngay khi phát hiện FAIL (secret yếu, alg none, hết hạn...).

---

## 9. Ví dụ

```powershell
# Kiểm tra token từ chuỗi
python jwtcheck.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abc"

# Kiểm tra token trong file (1 dòng/token)
python jwtcheck.py tokens.txt

# Nhiều token cùng lúc
python jwtcheck.py tokens.txt "eyJhbGciOiJIUzI1NiIs..."

# Verify HMAC với secret đã biết
python jwtcheck.py --secret "Sup3rS3cret!" token.txt

# Verify RSA/ECDSA bằng public key PEM
python jwtcheck.py --pubkey public.pem token.txt

# Brute-force secret bằng wordlist
python jwtcheck.py --wordlist rockyou-top.txt token.txt

# Bỏ qua brute secret mặc định (chỉ phân tích tĩnh)
python jwtcheck.py --no-brute token.txt

# Xuất JSON / Markdown
python jwtcheck.py token.txt --json -o report.json
python jwtcheck.py token.txt --md -o report.md

# Pipe token vào từ stdin
Get-Content token.txt | python jwtcheck.py -

# CI: thoát 1 khi phát hiện lỗ hồng bảo mật
python jwtcheck.py token.txt; if ($LASTEXITCODE -eq 1) { "CO LỖ HỒNG!" }
```

---

## 10. Lưu ý

- Brute-force HMAC là **điểm yếu lớn nhất** của JWT khi issuer dùng secret ngắn/đoán được — công cụ chỉ dò 30 secret mặc định + wordlist do bạn cấp; wordlist lớn có thể chậm.
- Danh sách thuật toán, secret yếu và thang điểm là **tham khảo nội bộ**. Phát hiện mang tính gợi ý, không phải chứng minh an toàn tuyệt đối.
- `alg` HMAC kèm khóa bất đối xứng (jwk/x5c/jku/x5u) báo algorithm confusion CRITICAL vì nếu server verify nhầm sang RSA bằng khóa lấy từ token, attacker tự ký được.
- JWE (token 5 phần) không được giải mã nội dung — chỉ báo `FORMAT`.
- Xác thực bất đối xứng cần `cryptography`; không cài sẵn thì phần verify bị bỏ qua (vẫn phân tích header/payload).
- Token nhạy cảm dán vào dòng lệnh sẽ lưu trong lịch sử shell — nên đọc từ file qua stdin (`-`).
