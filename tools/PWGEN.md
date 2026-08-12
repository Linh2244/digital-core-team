# PassGen 1.0.0 — Password Generator

`pwgen.py` sinh mật khẩu / passphrase ngẫu nhiên an toàn và kiểm tra độ mạnh của mật khẩu. Sản phẩm của **Digital Core team**, viết bằng Python thuần (stdlib), dùng mô-đun `secrets` (nguồn ngẫu nhiên mật mã an toàn) — **không dùng** `random` thông thường.

```
python pwgen.py [tùy chọn]
python pwgen.py --strength "mật-khẩu-cần-kiểm-tra"
```

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Mật khẩu ngẫu nhiên](#2-mật-khẩu-ngẫu-nhiên)
3. [Passphrase](#3-passphrase)
4. [Kiểm tra độ mạnh (`--strength`)](#4-kiểm-tra-độ-mạnh---strength)
5. [Tham số](#5-tham-số)
6. [Entropy và đánh giá độ mạnh](#6-entropy-và-đánh-giá-độ-mạnh)
7. [Exit codes](#7-exit-codes)
8. [Ví dụ](#8-ví-dụ)
9. [Lưu ý](#9-lưu-ý)

---

## 1. Cài đặt

Yêu cầu: **Python ≥ 3.10** (máy đã có sẵn trong bộ Digital Core Toolkit). Không cần cài thêm gì:

```powershell
python pwgen.py -c 5 -l 20
```

---

## 2. Mật khẩu ngẫu nhiên

Mặc định sinh **10 mật khẩu dài 16 ký tự** gồm đủ 4 nhóm: chữ thường, chữ hoa, số, ký tự đặc biệt (pool 88 ký tự). Mỗi mật khẩu **đảm bảo có ít nhất 1 ký tự của mỗi nhóm đã chọn**.

```powershell
python pwgen.py
# ;; PassGen 1.0.0 <<>> Digital Core team
# ;; 10 password, pool 88 ký tự | ~103.4 bits
# 1. pSN.+aLZqbs9)KoA
# 2. ...
```

Mật khẩu 16 ký tự (pool 88) có entropy ≈ **103 bits** — mức "RẤT MẠNH" (≥ 80 bits).

### Tùy chỉnh bộ ký tự

| Cờ | Hiệu lực |
|---|---|
| `--no-lower` | Bỏ chữ thường |
| `--no-upper` | Bỏ chữ hoa |
| `--no-digit` | Bỏ chữ số |
| `--no-symbol` | Bỏ ký tự đặc biệt |
| `--no-ambig` | Bỏ ký tự dễ nhầm lẫn: `0O1lI` (và `|` không nằm trong pool) |

> `--no-ambig` giảm pool từ 88 xuống 83 ký tự — tiện cho nhập tay (0/O, 1/l/I dễ gây nhầm), entropy vẫn cao.

---

## 3. Passphrase

Sinh chuỗi nhiều từ nối bằng dấu `-` (kiểu diceware, không cần dice). Mặc định **8 từ**, wordlist 349 từ (≈ 8.45 bits/từ → **~67.6 bits**):

```powershell
python pwgen.py --passphrase
# 1. bird-rock-guitar-helmet-toucan-berry-polar-prairie
```

Tùy chọn:

| Cờ | Ý nghĩa |
|---|---|
| `-w, --words N` | Số từ (mặc định 8; khuyến nghị ≥ 10 cho mật khẩu chính) |
| `--sep CHUỖI` | Ký tự nối (mặc định `-`) |
| `--cap` | Viết hoa chữ cái đầu mỗi từ |

10 từ → **~84.5 bits** (RẤT MẠNH). Passphrase dễ gõ/nhớ hơn mật khẩu ký tự nhưng vẫn mạnh nếu dùng đủ số từ.

---

## 4. Kiểm tra độ mạnh (`--strength`)

Phân tích một mật khẩu có sẵn: ước tính kích thước pool ký tự, entropy, xếp hạng và thời gian bẻ khóa (offline ~10¹² phép thử/giây):

```powershell
python pwgen.py --strength "Tr0ub4dor&3"
# ;; PassGen 1.0.0 <<>> Digital Core team
# Mật khẩu: Tr0ub4dor&3
# Độ dài: 11 | Pool ký tự: 88 | Entropy: 71.1 bits -> MẠNH
# Thời gian bẻ khóa (offline ~1e+12 phép thử/s): 77.7 năm
```

> Lưu ý: phép tính này là **giới hạn trên theo lý thuyết** (tìm kiếm toàn bộ không gian). Mật khẩu dễ đoán (từ điển, tên riêng, sửa đổi nhỏ của từ phổ biến) thực tế bẻ nhanh hơn nhiều — hãy tránh dùng.

---

## 5. Tham số

| Tham số | Ý nghĩa |
|---|---|
| `-c, --count N` | Số lượng mật khẩu/passphrase (mặc định 10) |
| `-l, --length N` | Độ dài mật khẩu, ≥ 4 (mặc định 16) |
| `--no-lower / --no-upper / --no-digit / --no-symbol` | Tắt từng nhóm ký tự |
| `--no-ambig` | Loại ký tự dễ nhầm lẫn (`0O1lI`) |
| `-p, --passphrase` | Chế độ passphrase |
| `-w, --words N` | Số từ trong passphrase, ≥ 3 (mặc định 8) |
| `--sep CHUỖI` | Ký tự nối giữa các từ (mặc định `-`) |
| `--cap` | Viết hoa đầu mỗi từ |
| `--strength PASSWORD` | Kiểm tra độ mạnh của mật khẩu cho sẵn (chỉ 1 chế độ này) |
| `--json` | Output JSON |
| `-o, --output FILE` | Ghi kết quả ra file (vẫn in ra màn hình) |
| `-v, --verbose` | Hiện entropy của từng mật khẩu |
| `--no-color` | Tắt màu ANSI |

---

## 6. Entropy và đánh giá độ mạnh

**Entropy** = `độ dài × log2(pool)`. Với passphrase: `số từ × log2(wordlist)`.

| Entropy | Xếp hạng |
|---|---|
| < 40 bits | YẾU (đỏ) |
| 40 – 59 bits | TRUNG BÌNH (vàng) |
| 60 – 79 bits | MẠNH (xanh dương) |
| ≥ 80 bits | RẤT MẠNH (xanh lá) |

Tham khảo nhanh (pool 88 ký tự):

| Độ dài | Entropy | Xếp hạng |
|---|---|---|
| 8 | 51.7 | TRUNG BÌNH |
| 12 | 77.6 | MẠNH |
| 16 | 103.4 | RẤT MẠNH |
| 20 | 129.3 | RẤT MẠNH |

Thời gian bẻ khóa tính với giả định bẻ offline ~10¹² phép thử/giây (GPU hiện đại).

---

## 7. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Thành công |
| `2` | Lỗi đầu vào: `--count < 1`, `--length < 4`, `--words < 3`, tắt hết charset, hoặc `--length` quá ngắn cho số charset đã chọn |

---

## 8. Ví dụ

```powershell
# Mật khẩu mặc định
python pwgen.py

# 5 mật khẩu dài 20, không ký tự gây nhầm
python pwgen.py -c 5 -l 20 --no-ambig

# 20 PIN 6 chữ số
python pwgen.py -c 20 -l 6 --no-upper --no-symbol

# Passphrase 10 từ, viết hoa, nối bằng dấu chấm
python pwgen.py --passphrase -w 10 --cap --sep .

# Kiểm tra độ mạnh
python pwgen.py --strength "Tr0ub4dor&3"

# Xuất JSON cho script
python pwgen.py -c 20 -l 20 --json -o passwords.json
python pwgen.py --passphrase -w 12 --json
```

---

## 9. Lưu ý

- Mật khẩu được sinh **ngẫu nhiên mật mã** (`secrets`) — không thể tái tạo, an toàn để làm mật khẩu.
- Không có cơ chế lưu trữ — mật khẩu in ra màn hình/file do bạn tự quản lý. Nên dùng chung với trình quản lý mật khẩu.
- Không nên tự ý "sửa tay" mật khẩu sinh ra (thêm/sửa ký tự làm giảm độ ngẫu nhiên thực tế).
- Độ mạnh tính theo lý thuyết; tránh dùng từ điển/tên riêng làm passphrase.
