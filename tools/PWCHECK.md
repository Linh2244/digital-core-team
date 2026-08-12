# PWCheck 1.0.0 — Password Strength Checker

`pwcheck.py` phân tích độ mạnh của mật khẩu dựa trên **mô hình zxcvbn-like**: bên cạnh entropy lý thuyết, nó phát hiện các mẫu yếu thực tế mà entropy không thấy được — mật khẩu phổ biến, từ thông dụng (kể cả leetspeak `p@ssw0rd` và từ đảo ngược), chuỗi tuần tự, mẫu bàn phím, ký tự lặp, năm... Sản phẩm của **Digital Core team**, Python thuần (stdlib), không gọi dịch vụ ngoài.

```
python pwcheck.py mật-khẩu [mật-khẩu...]
python pwcheck.py --stdin   # đọc từ stdin, 1 dòng 1 mật khẩu
```

---

## Mục lục

1. [Cài đặt](#1-cài-đặt)
2. [Kiểm tra nhanh](#2-kiểm-tra-nhanh)
3. [Nhiều mật khẩu và `--stdin`](#3-nhiều-mật-khẩu-và---stdin)
4. [Mô hình đánh giá](#4-mô-hình-đánh-giá)
5. [Các mẫu yếu được phát hiện](#5-các-mẫu-yếu-được-phát-hiện)
6. [Thang điểm và thời gian bẻ khóa](#6-thang-điểm-và-thời-gian-bẻ-khóa)
7. [Tham số](#7-tham-số)
8. [Exit codes](#8-exit-codes)
9. [Ví dụ](#9-ví-dụ)
10. [Lưu ý](#10-lưu-ý)

---

## 1. Cài đặt

Yêu cầu: **Python ≥ 3.10** (có sẵn trong bộ Digital Core Toolkit). Không cần cài thêm gì:

```powershell
python pwcheck.py "mật-khẩu-cần-kiểm-tra"
```

---

## 2. Kiểm tra nhanh

Mỗi mật khẩu được in một khối gồm: độ dài, pool ký tự ước tính, thành phần ký tự, entropy cơ bản → còn lại sau khi trừ mẫu yếu, danh sách mẫu phát hiện, xếp hạng và thời gian bẻ khóa offline:

```powershell
python pwcheck.py "P@ssw0rd" "xK9$fP2mQz@vB4wR"
# ;; PWCheck 1.0.0 <<>> Digital Core team
# ;; 2 mật khẩu | 1 YẾU | 1 RẤT MẠNH
#
# 1. P@ssw0rd  ->  YẾU
#    Độ dài 8 | Pool ước tính 94 | Ký tự riêng 7
#    Thành phần: digit 1, lower 5, symbol 1, upper 1
#    Entropy cơ bản 52.4 bits -> còn 7.0 bits
#    Phát hiện: trong top mật khẩu phổ biến (hạng 2); leetspeak (password); chứa từ thông dụng (password)
#    Bẻ khóa offline (~1e+12 phép thử/s): 0.0 giây
#
# 2. xK9$fP2mQz@vB4wR  ->  RẤT MẠNH
#    Độ dài 16 | Pool ước tính 94 | Ký tự riêng 16
#    ...
```

Mật khẩu càng dài + nhiều nhóm ký tự → pool lớn, entropy cao. Nhưng nếu nó **khớp mẫu yếu** (từ phổ biến, bàn phím...) thì entropy thực tế bị hạ mạnh — đúng điều entropy lý thuyết thuần túy bỏ sót.

---

## 3. Nhiều mật khẩu và `--stdin`

Truyền nhiều mật khẩu cùng lúc, hoặc đọc từ stdin (1 dòng 1 mật khẩu) để kiểm tra hàng loạt từ file hoặc pipe:

```powershell
# Nhiều mật khẩu trong 1 lệnh
python pwcheck.py 123456 password "Tr0ub4dor&3"

# Từ file, 1 dòng 1 mật khẩu
Get-Content C:\sec\pwd.txt | python pwcheck.py --stdin

# Pipe trực tiếp từ PassGen (tự bỏ dòng tiêu đề và số thứ tự)
python pwgen.py -c 5 -l 12 | python pwcheck.py --stdin
```

Khi `--stdin`, các dòng bắt đầu bằng `;;` (dòng tiêu đề/ghi chú kiểu dig/pwgen) và dạng `1. xxx` (số thứ tự của PassGen) được bỏ qua tự động.

---

## 4. Mô hình đánh giá

**Bước 1 — Entropy cơ bản (brute-force):** `độ dài × log2(pool)`. Pool ước tính bằng tổng kích thước các nhóm ký tự có mặt:

| Nhóm | Kích thước |
|---|---|
| chữ thường `a–z` | 26 |
| chữ hoa `A–Z` | 26 |
| chữ số `0–9` | 10 |
| ký tự đặc biệt | 32 |
| khoảng trắng | 1 |
| ký tự khác (Unicode...) | 100 |

**Bước 2 — Khớp từ điển (nếu không tắt bằng `--no-blacklist`):**

- Trùng chính xác một mật khẩu trong **top 50 phổ biến** tích hợp sẵn → `bits = min(cơ bản, 6 + log2(hạng))`. Ví dụ `password` (hạng 2) → ~7 bits.
- Chứa **từ gốc thông dụng** (≥ 4 ký tự, gồm leetspeak `p@ssw0rd` và tiếng Việt `matkhau`, `vietnam`...) → `bits = min(cơ bản, 18) − 4×(số từ − 1)`.
- Chứa **từ đảo ngược** (`drowssap`) → −4 bits.
- **Leetspeak** được giải mã trước khi khớp (`P@ssw0rd` = `password`) và hiện rõ trong phần "Phát hiện".

**Bước 3 — Trừ điểm các mẫu yếu** (chi tiết ở mục 5), giới hạn dưới cùng là **4 bits**.

Sau đó xếp hạng theo entropy còn lại và ước tính thời gian bẻ khóa offline.

---

## 5. Các mẫu yếu được phát hiện

| Mẫu | Ví dụ | Trừ |
|---|---|---|
| Chuỗi tuần tự (tăng/giảm liên tiếp ≥ 3) | `abc`, `123456`, `zyx`, `098` | −6 bits |
| Mẫu bàn phím QWERTY (≥ 4 ký tự) | `qwerty`, `asdf`, `zxcvb`, `1qaz`, `6yhn` | −8 bits |
| Ký tự lặp (≥ 3) | `aaa`, `111`, `0000` | −8 bits |
| Chuỗi lặp lại | `ababab`, `abcabc`, `121212` | −8 bits |
| Năm `19xx`/`20xx` | `1990`, `2026` | −8 nếu dài ≤ 8, −4 nếu dài hơn |
| Toàn bộ là 1 ký tự | `aaaa`, `11111111` | chốt 4 bits |
| Trong top 50 phổ biến | `123456`, `qwerty`, `dragon1` | `min(base, 6 + log2(hạng))` |
| Chứa từ gốc thông dụng | `password`, `letmein`, `matkhau` | `min(base, 18)`, −4 mỗi từ thêm |
| Từ đảo ngược | `drowssap`, `1ssap` | −4 bits |
| Leetspeak | `p@ssw0rd`, `tr0ub4d0r` | báo trong kết quả (đã tính trong từ) |

Nếu `--no-blacklist` → bỏ khối từ điển (top phổ biến, từ gốc, đảo ngược); `--no-leet` → chỉ khớp từ ở dạng gốc, không giải mã leetspeak.

---

## 6. Thang điểm và thời gian bẻ khóa

| Entropy còn lại | Xếp hạng |
|---|---|
| < 40 bits | YẾU (đỏ) |
| 40 – 59 bits | TRUNG BÌNH (vàng) |
| 60 – 79 bits | MẠNH (xanh dương) |
| ≥ 80 bits | RẤT MẠNH (xanh lá) |

Thời gian bẻ khóa giả định offline **~10¹² phép thử/giây** (GPU hiện đại): `2^bits / 10¹²`. Lưu ý đây là giới hạn trên lý thuyết — mật khẩu dính từ điển/mẫu thực tế còn nhanh hơn nhiều, nên phần "Phát hiện" đáng tin hơn con số entropy.

---

## 7. Tham số

| Tham số | Ý nghĩa |
|---|---|
| `password...` (vị trí) | Mật khẩu cần kiểm tra (dùng nhiều lần) |
| `--stdin` | Đọc mật khẩu từ stdin, 1 dòng 1 cái; bỏ dòng `;;` và số thứ tự |
| `--no-leet` | Không giải mã leetspeak khi khớp từ |
| `--no-blacklist` | Bỏ qua danh sách mật khẩu/từ thông dụng, chỉ tính entropy + mẫu |
| `--json` | Output JSON |
| `-o, --output FILE` | Ghi kết quả ra file (vẫn in ra màn hình) |
| `--no-color` | Tắt màu ANSI |

---

## 8. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | Kiểm tra xong, **không** có mật khẩu nào bị xếp YẾU |
| `1` | Có **≥ 1** mật khẩu bị xếp YẾU |
| `2` | Lỗi đầu vào: không có mật khẩu nào (thiếu argument và không `--stdin`) |

Dùng exit code trong CI/script: `pwcheck.py --stdin < pwd.txt` trả về `1` ngay khi phát hiện mật khẩu yếu.

---

## 9. Ví dụ

```powershell
# Kiểm tra 1 mật khẩu
python pwcheck.py "Tr0ub4dor&3"

# Một loạt từ yếu đến mạnh
python pwcheck.py 123456 "P@ssw0rd" letmein2026 "correcthorsebatterystaple"

# Kiểm tra toàn bộ mật khẩu trong file (1 dòng/cái)
Get-Content C:\sec\pwd.txt | python pwcheck.py --stdin

# Pipe mật khẩu vừa sinh từ PassGen để xác nhận độ mạnh
python pwgen.py -c 5 -l 12 --no-symbol | python pwcheck.py --stdin

# Chỉ tính entropy + mẫu, bỏ qua từ điển / leetspeak
python pwcheck.py --no-blacklist "P@ssw0rd"
python pwcheck.py --no-leet "P@ssw0rd"

# Xuất JSON cho script
python pwcheck.py "Passw0rd" "xK9$fP2mQz@vB4wR" --json -o report.json

# CI: thoát 1 khi phát hiện mật khẩu yếu
Get-Content C:\sec\pwd.txt | python pwcheck.py --stdin; if ($LASTEXITCODE -eq 1) { "CO MAT KHAU YEU!" }
```

---

## 10. Lưu ý

- Đây là **ước lượng heuristic**, không phải chứng minh an toàn. Mật khẩu "ngẫu nhiên" nhưng chứa mẫu (ví dụ sinh ra rồi tự sửa tay) sẽ bị hạ điểm — điều tốt.
- Danh sách top-50 và từ gốc là **tham khảo nội bộ**, không đầy đủ. Mật khẩu dính từ điển ngoài danh sách có thể bị đánh giá cao hơn thực tế.
- Mật khẩu ngẫu nhiên do `pwgen.py` sinh (dài ≥ 12, đủ 4 nhóm ký tự) thường đạt MẠNH/RẤT MẠNH.
- So với `pwgen.py --strength`: công cụ đó chỉ tính entropy lý thuyết; `pwcheck.py` bổ sung phát hiện mẫu yếu thực tế — dùng `pwcheck.py` khi cần đánh giá kỹ mật khẩu có sẵn.
- Mật khẩu nhập trực tiếp sẽ xuất hiện trong dòng lệnh và lịch sử shell. Với mật khẩu nhạy cảm, nên đọc từ file qua `--stdin` và xóa file sau đó.
