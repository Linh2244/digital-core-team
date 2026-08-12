# DigitalCore Team

DigitalCore Team là một website tĩnh về nền tảng máy tính, lập trình, Linux, an ninh mạng và AI. Project đồng thời cung cấp một bộ công cụ security/recon viết bằng Python thuần.

Website sử dụng HTML, CSS và JavaScript vanilla. Không có build system, package manager, framework frontend, test runner hoặc CI pipeline.

## Chạy local

Yêu cầu:

- Python 3.10+ cho các tool trong thư mục tools/.
- Trình duyệt hiện đại có JavaScript và hỗ trợ PDF embed.

Khởi động static server từ thư mục gốc:

    python -m http.server 8000

Mở http://localhost:8000/ trong trình duyệt. Nên dùng server thay vì mở trực tiếp bằng file://, vì PDF viewer có thể hoạt động không ổn định với file local.

## Cấu trúc project

    .
    ├── index.html              # Trang chủ
    ├── docs.html               # Giới thiệu hệ thống tài liệu
    ├── knowledge-base.html     # Danh sách PDF và tài liệu học tập
    ├── viewer.html             # PDF viewer: viewer.html?doc=<key>
    ├── tools.html              # Catalog DigitalCore Security Toolkit
    ├── about.html              # Giới thiệu team và nguyên tắc
    ├── styles.css              # Design system dùng chung
    ├── index.css               # Style riêng cho trang chủ
    ├── docs.css                # Style cho docs, knowledge base và tools
    ├── viewer.css              # Style cho PDF viewer
    ├── tools.css               # Style riêng cho catalog tools
    ├── about.css               # Style riêng cho trang about
    ├── pdfs/                   # Các PDF được hiển thị trong knowledge base
    ├── tools/                  # Python tools, tài liệu và trang detail HTML
    ├── favicon.svg
    ├── LICENSE
    └── AGENTS.md               # Quy tắc làm việc trong repository

## Các trang website

| Trang | Nội dung | CSS chính |
|---|---|---|
| index.html | Hero, features, roadmap, articles và stats | styles.css, index.css |
| docs.html | Giới thiệu platform modules | styles.css, docs.css |
| knowledge-base.html | Thư viện PDF và quick-reference table | styles.css, docs.css |
| viewer.html | Đọc PDF online và download PDF | styles.css, viewer.css |
| tools.html | Catalog 14 security/recon tools | styles.css, docs.css, tools.css |
| about.html | About, principles và project direction | styles.css, docs.css |

### PDF viewer

viewer.html nhận key qua query string:

    viewer.html?doc=nen-tang
    viewer.html?doc=lap-trinh
    viewer.html?doc=linux
    viewer.html?doc=security
    viewer.html?doc=bao-cao-ctf

Key không hợp lệ sẽ fallback về nen-tang. Khi thêm PDF mới, cần cập nhật đồng bộ file PDF, map DOCS trong viewer.html, link ở index.html và card trong knowledge-base.html.

## DigitalCore Security Toolkit

Các script nằm trong tools/ và có trang hướng dẫn tương ứng. Từ catalog, có thể mở trang detail HTML hoặc download trực tiếp file Python.

| Tool | Chức năng |
|---|---|
| pyscan.py | Quét port TCP/SYN/UDP, phát hiện service/version, đoán OS và kiểm tra SSL/TLS. |
| dnslookup.py | Tra DNS kiểu dig, hỗ trợ record types, DNSSEC, trace, TCP/EDNS, reverse lookup và JSON. |
| subfind.py | Tìm subdomain qua Certificate Transparency, DNS brute-force, wildcard filtering và AXFR. |
| httpsec.py | Kiểm tra bảo mật HTTP: TLS, headers, cookies, methods, paths, CORS và redirects. |
| dirbf.py | Brute-force thư mục/file web bằng wordlist, lọc status code, extensions và redirect. |
| loginbf.py | Kiểm thử login endpoint với Basic Auth, form, JSON hoặc query string. |
| secretscan.py | Quét source code để phát hiện API key, token, JWT, private key, password và connection string. |
| jwtcheck.py | Decode và audit JWT, kiểm tra alg:none, algorithm confusion, secret yếu và chữ ký. |
| pwgen.py | Sinh password/passphrase an toàn bằng module secrets, kèm entropy và JSON output. |
| pwcheck.py | Phân tích độ mạnh password theo mẫu phổ biến, leetspeak, keyboard pattern, sequence và date. |
| hashid.py | Nhận diện loại hash theo độ dài, charset và prefix, kèm hashcat/John format. |
| logsec.py | Phân tích log web/SSH để phát hiện SQLi, XSS, LFI, brute-force và scanner. |
| tlscheck.py | Kiểm tra TLS protocol, cipher và certificate trên HTTPS, SMTP, IMAP, LDAPS và dịch vụ khác. |
| depcheck.py | Đối chiếu dependency manifest/lockfile với OSV.dev để phát hiện vulnerability. |

### Dependency tùy chọn

Các chức năng core dùng Python standard library. Một số tính năng nâng cao cần cài thêm:

    pip install scapy
    pip install cryptography

- scapy: raw packet scan trong pyscan.py.
- cryptography: phân tích và xác thực certificate/crypto nâng cao.
- Windows raw scan có thể cần Npcap và quyền administrator.

Mỗi tool có tài liệu chi tiết trong tools/, ví dụ tools/PYSCAN.md, tools/DNSLOOKUP.md và tools/README.md. Chạy help để xem tham số hiện tại:

    python tools/pyscan.py --help
    python tools/httpsec.py --help
    python tools/depcheck.py --help

## Ngôn ngữ EN/VN

Các trang hỗ trợ English và Vietnamese bằng thuộc tính data-en/data-vn trên mọi chuỗi hiển thị.

- Nội dung literal trong HTML là English mặc định.
- Nút language toggle chuyển sang ngôn ngữ còn lại.
- Lựa chọn ngôn ngữ được lưu trong localStorage["dc-lang"].
- Khi thêm text mới, luôn thêm đủ cả data-en và data-vn.
- JavaScript inline đang dùng ES5 style (var, IIFE, "use strict"); giữ cùng pattern khi chỉnh sửa.

## Quy trình chỉnh sửa

1. Đọc AGENTS.md trước khi thay đổi.
2. Giữ nguyên design tokens trong styles.css; ưu tiên CSS variables thay vì hardcode màu.
3. Nếu thêm trang hoặc component, cập nhật navigation desktop và mobile.
4. Nếu thêm PDF, cập nhật tất cả nơi tham chiếu như phần PDF viewer đã mô tả.
5. Nếu thêm tool, cập nhật catalog, trang detail, file Python, tài liệu Markdown và nút download.
6. Kiểm tra encoding UTF-8, link nội bộ và các đường dẫn asset.
7. Chạy thử static server và mở các trang bị ảnh hưởng trong trình duyệt.

Không có linter, test suite hoặc build command chính thức trong repository. Có thể compile nhanh toàn bộ Python tools bằng:

    Get-ChildItem tools -Filter *.py | ForEach-Object { python -m py_compile $_.FullName }

## Cảnh báo sử dụng

Các tool scanning, brute-force và reconnaissance chỉ được sử dụng trên hệ thống mà bạn sở hữu hoặc có ủy quyền kiểm thử rõ ràng. Người sử dụng chịu trách nhiệm tuân thủ pháp luật, chính sách nhà cung cấp và phạm vi kiểm thử được phê duyệt.

## License

Project được phát hành theo MIT License trong file LICENSE.
