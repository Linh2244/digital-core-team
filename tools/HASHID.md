# HashID 1.0.0 — Tài liệu sử dụng

**Sản phẩm của Digital Core team.**

Công cụ **nhận diện loại hash** (hash identifier) viết bằng Python thuần (một file `hashid.py`), **không cần cài thêm thư viện**. Dựa trên độ dài, bộ ký tự và prefix để liệt kê các loại hash khả dĩ, kèm **hashcat mode (`-m`)** và **John the Ripper format** để chuyển thẳng vào bước bẻ khóa. Nhận diện trực tiếp nhiều hash một lúc (tham số, `--file` hoặc `--stdin`), xuất JSON, có chế độ `--short` cho script.

```
python hashid.py [tùy chọn] hash1 [hash2 ...]
```

---

## Mục lục

1. [Yêu cầu](#1-yêu-cầu)
2. [Ví dụ nhanh](#2-ví-dụ-nhanh)
3. [Cách nhận diện](#3-cách-nhận-diện)
4. [Bảng hash hỗ trợ](#4-bảng-hash-hỗ-trợ)
5. [Định dạng output](#5-định-dạng-output)
6. [Exit codes](#6-exit-codes)
7. [Tham số đầy đủ](#7-tham-số-đầy-đủ)
8. [Ví dụ kết hợp](#8-ví-dụ-kết-hợp)
9. [Hạn chế](#9-hạn-chế)
10. [Lưu ý pháp lý](#10-lưu-ý-pháp-lý)

---

## 1. Yêu cầu

| Thành phần | Ghi chú |
|---|---|
| Python ≥ 3.10 | Chỉ dùng thư viện chuẩn (`re`, `json`, `argparse`) |

Không cần `pip install` gì cả.

---

## 2. Ví dụ nhanh

```bash
# Một hash
python hashid.py d41d8cd98f00b204e9800998ecf8427e

# Nhiều hash trên dòng lệnh
python hashid.py d41d8cd98f00b204e9800998ecf8427e a94a8fe5ccb19ba61c4c0873d391e987982fbbd3

# File chứa nhiều hash (1 dòng 1 hash, dòng # là comment)
python hashid.py --file hashes.txt

# Đọc từ stdin, xuất JSON cho script / CI
python hashid.py --stdin --json-output -o report.json < hashes.txt

# Chế độ ngắn: chỉ hash + tên loại đầu tiên (dễ dùng trong pipeline)
python hashid.py --file hashes.txt --short

# Hiện thêm gợi ý (vd: hash 32 ký tự in hoa -> khả năng cao NTLM/LM)
python hashid.py 32ED87BDB5FDC5E9CBA88547376818D4 -v
```

**Lưu ý PowerShell**: hash chứa `$` (bcrypt, argon2, `$1$`...) phải đặt trong **nháy đơn**, nếu không PowerShell sẽ hiểu `$` là biến:

```powershell
python hashid.py '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
```

### Output mẫu

```
;; HashID 1.0.0 <<>> Digital Core team
;; 2 hash | 2 xác định được

$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy  60 ký tự, other, mixed
  bcrypt | -m 3200 | john:bcrypt

d41d8cd98f00b204e9800998ecf8427e  32 ký tự, hex, lower
  MD5 | -m 0 | john:raw-md5
  NTLM | -m 1000 | john:nt
  LM | -m 3000 | john:lm
  MD4 | -m 900 | john:raw-md4
  ...
```

---

## 3. Cách nhận diện

Công cụ phân tích từng hash theo 3 lớp, không "đoán mò":

1. **Prefix / format đặc biệt** — khớp mẫu regex của các định dạng có cấu trúc riêng: bcrypt (`$2b$...`), md5crypt (`$1$...`), phpass/WordPress (`$P$`), argon2, Django (`pbkdf2_sha256$...`), MySQL (`*40hex`), MSSQL (`0x0100...`), Oracle 11g (`S:...`), Postgres (`md5...` / `SCRAM-SHA-256$`), Kerberos (`$krb5...$`), LDAP (`{SSHA}`, `{SHA}`, `{SMD5}`...).
2. **Độ dài (hex)** — hash thuần hex được tra theo độ dài ký tự → số bit: `32 → 128-bit`, `40 → 160-bit`, `64 → 256-bit`, etc. Với 32 hex liệt kê MD5/NTLM/LM/MD4/... vì không thể phân biệt chắc chắn nếu chỉ nhìn.
3. **Case + gợi ý** (`-v`) — hash 32 hex **in hoa** → nghiêng về NTLM/LM; 40 hex in hoa → nghiêng về Oracle 10g.

Mỗi loại kèm `-m <hashcat mode>` và `john:<format>` sẵn sàng đưa vào hashcat/john để bẻ khóa.

---

## 4. Bảng hash hỗ trợ

| Nhóm | Các loại |
|---|---|
| MD5 & bạn | `MD5`, `MD4`, `MD2`, `NTLM`, `LM`, `APOP (MD5)`, `XOR-32` |
| SHA | `SHA-0`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512` |
| SHA-3 | `SHA3-224/256/384/512`, `BLAKE2s-256`, `BLAKE2b-512` |
| RIPE/Haval/Tiger | `RIPEMD-128/160/256/320`, `Haval-128/160/192/224/256/320`, `Tiger-128/160/192/256`, `Snefru-128/256` |
| Khác | `Whirlpool`, `GOST R 34.11-94` |
| Checksum ngắn | `CRC-16/32`, `Adler-32`, `xxHash32/64`, `MurmurHash3/64A`, `FCS-16/32` |
| Unix crypt | `md5crypt ($1$)`, `sha256crypt ($5$)`, `sha512crypt ($6$)`, `bcrypt`, `scrypt`, `Argon2` |
| Web/App | `WordPress/phpass ($P$)`, `phpBB3 ($H$)`, `Drupal 7 ($S$)`, `Django PBKDF2-SHA256/SHA1`, `Joomla` |
| DB | `MySQL 3.x`, `MySQL 4.1/5 (sha1)`, `PostgreSQL MD5`, `PostgreSQL SCRAM-SHA-256`, `MSSQL (2000/2005/2012)`, `Oracle 10g`, `Oracle 11g/12c` |
| Network/OS | `Kerberos 5 (pre-auth/TGS/AS-REP)`, `Cisco IOS Type 5`, `Cisco Type 7 (0x...)`, `LDAP {SHA}/{SSHA}/{SMD5}/{SHA256}/{SHA512}` |

> Không phân biệt được tuyệt đối hash hex cùng độ dài (vd MD5 vs NTLM) — công cụ liệt kê **tất cả** loại khả dĩ, kèm gợi ý theo case.

---

## 5. Định dạng output

### Text (mặc định)

Một khối cho mỗi hash: hash (dài → cắt `...`), đặc điểm `số ký tự, bộ ký tự (hex/base64/other), case (lower/upper/mixed)`, rồi danh sách loại khả dĩ. Loại đầu tiên tô xanh (ưu tiên phổ biến nhất), các loại còn lại mờ. `-v` thêm dòng gợi ý.

### `--short`

Mỗi dòng một hash + loại đầu tiên (hoặc `?` nếu không xác định):

```
d41d8cd98f00b204e9800998ecf8427e  MD5
$2b$10$...  bcrypt
zzzz  ?
```

### `--json-output` + `-o FILE`

```json
{
  "tool": "HashID", "version": "1.0.0",
  "total": 2, "identified": 2,
  "results": [
    {
      "hash": "$2b$10$...",
      "length": 60, "characters": "other", "case": "mixed",
      "hint": null,
      "matches": [{"name": "bcrypt", "hashcat": 3200, "john": "bcrypt"}]
    }
  ]
}
```

`-o FILE` ghi kết quả ra file (vẫn hiển thị trên màn hình).

---

## 6. Exit codes

| Code | Ý nghĩa |
|---|---|
| `0` | **Tất cả** hash đều xác định được loại |
| `1` | Có ≥ 1 hash **không** xác định được |
| `2` | Lỗi đầu vào (không có hash nào, file không đọc được) |

```powershell
python hashid.py --file hashes.txt; echo "exit=$LASTEXITCODE"
```

---

## 7. Tham số đầy đủ

| Tham số | Mô tả |
|---|---|
| `hash...` (vị trí) | Một hoặc nhiều hash cần nhận diện |
| `--file FILE` | File chứa hash (1 dòng 1 hash; `#` = comment) |
| `--stdin` | Đọc hash từ stdin (1 dòng 1 hash) |
| `--short` | Chỉ in `hash + loại đầu tiên` |
| `--json-output` | Xuất JSON thay vì text |
| `-o FILE` | Ghi kết quả ra file |
| `-v, --verbose` | Thêm gợi ý theo hoa/thường + độ dài |
| `--no-color` | Tắt màu ANSI |
| `-h, --help` | Trợ giúp |

---

## 8. Ví dụ kết hợp

```powershell
# 1) Trích hash từ log/DB → nhận diện → bẻ khóa bằng hashcat với mode tương ứng
python hashid.py '$P$...'   # -> WordPress (phpass), -m 400
hashcat -m 400 -a 0 hash.txt rockyou.txt

# 2) Quét hash NTLM từ dump SAM/LSASS giữa cả đống hash lạ
Get-Content dump.txt | python hashid.py --stdin --short

# 3) Kết hợp với secretscan: tìm hash trong mã nguồn rồi nhận diện
python secretscan.py D:\code --json --extract-hashes | python hashid.py --stdin

# 4) Kiểm tra hash biết trước loại: dùng --short làm bộ lọc
python hashid.py --file hashes.txt --short | Select-String "MD5|NTLM"
```

---

## 9. Hạn chế

- Hash hex cùng độ dài **không thể phân biệt chắc chắn** chỉ bằng hình thức (MD5 vs NTLM vs MD4): công cụ liệt kê mọi khả năng, kết hợp `-v` để xem gợi ý.
- Các loại ít gặp (Haval, Snefru, Tiger...) được liệt kê dựa trên độ dài — tần suất thực tế thấp.
- Không thêm tùy chọn "salt:hash" dạng tùy ý; nếu là dạng `salt$hash` hoặc `salt:hash`, hãy tách trước.
- `hashcat mode` và `john format` là **tham khảo** — một số loại có thể đổi mode theo phiên bản hashcat/john.

---

## 10. Lưu ý pháp lý

Chỉ dùng trên hash bạn sở hữu hoặc đã được cấp phép kiểm tra (phục hồi mật khẩu của chính mình, kiểm thử bảo mật có ủy quyền). Bẻ khóa hash không thuộc quyền sở hữu có thể vi phạm pháp luật; người dùng chịu trách nhiệm tuân thủ.
