#!/usr/bin/env python3
import argparse
import json
import re
import sys
from datetime import datetime

TOOL = "HashID"
VERSION = "1.0.0"
TEAM = "Digital Core team"

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def T(name, mode=None, john=None):
    return {"name": name, "hashcat": mode, "john": john}


SPECIAL_RULES = [
    (re.compile(r"^\$(?:2a|2b|2x|2y|2)\$\d{2}\$[./A-Za-z0-9]{53}$"),
     [T("bcrypt", 3200, "bcrypt")]),
    (re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$"
                r"[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"),
     [T("Argon2 (argon2i/d/id)", None, "argon2")]),
    (re.compile(r"^\$scrypt\$(?:ln=\d+,N=\d+,r=\d+,p=\d+)\$"
                r"[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"),
     [T("scrypt", 8900, "scrypt")]),
    (re.compile(r"^\$1\$(?:[^\s$]{0,16})\$[./A-Za-z0-9]{22}$"),
     [T("md5crypt ($1$)", 500, "md5crypt"),
      T("Cisco IOS Type 5", 5700, "md5crypt")]),
    (re.compile(r"^\$5\$(?:rounds=\d+\$)?[^\s$]{0,16}\$[./A-Za-z0-9]{43}$"),
     [T("sha256crypt ($5$)", 7400, "sha256crypt")]),
    (re.compile(r"^\$6\$(?:rounds=\d+\$)?[^\s$]{0,16}\$[./A-Za-z0-9]{86}$"),
     [T("sha512crypt ($6$)", 1800, "sha512crypt")]),
    (re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"),
     [T("WordPress / phpass ($P$)", 400, "phpass")]),
    (re.compile(r"^\$H\$[./A-Za-z0-9]{31}$"),
     [T("phpBB3 ($H$)", 400, "phpass")]),
    (re.compile(r"^\$S\$[./A-Za-z0-9]{52}$"),
     [T("Drupal 7 ($S$)", 7900, "drupal7")]),
    (re.compile(r"^md5[0-9a-f]{32}$"),
     [T("PostgreSQL MD5", 3710, "postgres")]),
    (re.compile(r"^SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$"
                r"[A-Za-z0-9+/=]+$"),
     [T("PostgreSQL SCRAM-SHA-256", 11100, "postgres-scram")]),
    (re.compile(r"^\*[0-9A-F]{40}$"),
     [T("MySQL 4.1/5 (sha1)", 300, "mysql-sha1")]),
    (re.compile(r"^0x0100[0-9a-fA-F]+$"),
     [T("MSSQL (2000)", 131, "mssql")]),
    (re.compile(r"^0x0200[0-9a-fA-F]+$"),
     [T("MSSQL (2005)", 132, "mssql")]),
    (re.compile(r"^0x0240[0-9a-fA-F]+$"),
     [T("MSSQL (2012/2014)", 1731, "mssql")]),
    (re.compile(r"^S:[0-9A-F]{40}:[0-9A-F]{20}:[0-9A-F]{40}$"),
     [T("Oracle 11g/12c", 12300, "oracle11")]),
    (re.compile(r"^\$krb5pa\$"), [T("Kerberos 5 pre-auth", 7500,
                                    "krb5preauth")]),
    (re.compile(r"^\$krb5tgs\$"), [T("Kerberos 5 TGS-REP", 13100,
                                     "krb5tgs")]),
    (re.compile(r"^\$krb5asrep\$"), [T("Kerberos 5 AS-REP", 18200,
                                       "krb5asrep")]),
    (re.compile(r"^\{SSHA512\}[A-Za-z0-9+/=]+$"),
     [T("Salted SHA-512 ({SSHA512})", None, "ssha512")]),
    (re.compile(r"^\{SHA512\}[A-Za-z0-9+/=]+$"),
     [T("SHA-512 ({SHA512})", 1700, "raw-sha512")]),
    (re.compile(r"^\{SSHA256\}[A-Za-z0-9+/=]+$"),
     [T("Salted SHA-256 ({SSHA256})", None, "ssha256")]),
    (re.compile(r"^\{SHA256\}[A-Za-z0-9+/=]+$"),
     [T("SHA-256 ({SHA256})", 1400, "raw-sha256")]),
    (re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]+$"),
     [T("Salted SHA-1 ({SSHA})", 101, "ssha")]),
    (re.compile(r"^\{SMD5\}[A-Za-z0-9+/=]+$"),
     [T("Salted MD5 ({SMD5})", 20, "smd5")]),
    (re.compile(r"^\{SHA\}[A-Za-z0-9+/=]+$"),
     [T("SHA-1 ({SHA})", 100, "raw-sha1")]),
    (re.compile(r"^pbkdf2_sha256\$"),
     [T("Django PBKDF2-SHA256", 10000, "django")]),
    (re.compile(r"^pbkdf2_sha1\$"),
     [T("Django PBKDF2-SHA1", 11000, "django")]),
    (re.compile(r"^sha256\$"),
     [T("Django SHA-256", None, "django")]),
    (re.compile(r"^sha1\$"),
     [T("Django SHA-1", None, "django")]),
    (re.compile(r"^md5\$"),
     [T("Django MD5", None, "django")]),
    (re.compile(r"^bcrypt\$"),
     [T("Django bcrypt", 3200, "django")]),
    (re.compile(r"^argon2\$"),
     [T("Django Argon2", None, "argon2")]),
]

HEX_RULES = {
    4: [T("CRC-16"), T("FCS-16"), T("X-25 CRC")],
    8: [T("CRC-32"), T("CRC-32B"), T("Adler-32"), T("xxHash32"),
        T("MurmurHash3 (32-bit)"), T("FCS-32")],
    16: [T("MySQL 3.x", 200, "mysql323"), T("CRC-64"), T("xxHash64"),
         T("MurmurHash64A"), T("Half MD5")],
    32: [T("MD5", 0, "raw-md5"), T("NTLM", 1000, "nt"),
         T("LM", 3000, "lm"), T("MD4", 900, "raw-md4"), T("MD2"),
         T("RIPEMD-128", None, "raw-ripemd-128"), T("Haval-128"),
         T("Tiger-128"), T("Snefru-128"), T("MySQL 3.x", 200, "mysql323"),
         T("XOR-32"), T("APOP (MD5)", 0, None)],
    40: [T("SHA-1", 100, "raw-sha1"), T("RIPEMD-160", 6000, "ripemd-160"),
         T("Haval-160"), T("Tiger-160"), T("SHA-0"),
         T("Oracle 10g", 112, "oracle")],
    48: [T("Tiger-192"), T("Haval-192")],
    56: [T("SHA-224", 1300, "raw-sha224"),
         T("SHA3-224", 17300, "raw-sha3-224"), T("BLAKE2s-224"),
         T("Haval-224")],
    64: [T("SHA-256", 1400, "raw-sha256"),
         T("SHA3-256", 5000, "raw-sha3-256"), T("BLAKE2s-256"),
         T("GOST R 34.11-94", 6900, "gost"), T("Haval-256"),
         T("Snefru-256"), T("RIPEMD-256", None, "raw-ripemd-256"),
         T("Tiger-256")],
    80: [T("RIPEMD-320"), T("Haval-320")],
    96: [T("SHA-384", 10800, "raw-sha384"),
         T("SHA3-384", 10100, "raw-sha3-384"), T("BLAKE2b-384")],
    128: [T("SHA-512", 1700, "raw-sha512"),
          T("SHA3-512", 5100, "raw-sha3-512"), T("BLAKE2b-512"),
          T("Whirlpool", 6100, "whirlpool")],
}


class Color:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def green(self, s): return self._w("32", s)
    def red(self, s): return self._w("31", s)
    def yellow(self, s): return self._w("33", s)
    def cyan(self, s): return self._w("36", s)
    def bold(self, s): return self._w("1", s)
    def dim(self, s): return self._w("2", s)


def chars_of(h):
    if HEX_RE.match(h):
        return "hex"
    if BASE64_RE.match(h):
        return "base64"
    return "other"


def case_of(h):
    if h.islower() or h.isdigit():
        return "lower"
    if h.isupper():
        return "upper"
    return "mixed"


def identify(h):
    matches = []
    for rx, cands in SPECIAL_RULES:
        if rx.match(h):
            matches.extend(cands)
    if not matches and HEX_RE.match(h):
        matches.extend(HEX_RULES.get(len(h), []))
    return matches


def hint(h, matches):
    if len(h) == 32 and h.isupper() and any(m["name"] == "NTLM"
                                             for m in matches):
        return "chữ in hoa -> khả năng cao NTLM/LM"
    if len(h) == 40 and h.isupper() and any(m["name"] == "Oracle 10g"
                                             for m in matches):
        return "chữ in hoa -> khả năng cao Oracle 10g"
    return None


def fmt_match(m):
    parts = [m["name"]]
    if m["hashcat"] is not None:
        parts.append(f"-m {m['hashcat']}")
    if m["john"] is not None:
        parts.append(f"john:{m['john']}")
    return " | ".join(parts)


def render_text(res, color, short):
    lines = [f";; {TOOL} {VERSION} <<>> {TEAM}"]
    if not short:
        lines.append(f";; {res['total']} hash | {res['identified']} "
                     f"xác định được")
    for item in res["results"]:
        h = item["hash"]
        if short:
            top = item["matches"][0]["name"] if item["matches"] else "?"
            lines.append(f"{h}  {color.cyan(top)}")
            continue
        disp = h if len(h) <= 44 else h[:41] + "..."
        tag = (f"{len(h)} ký tự, {item['characters']}, {item['case']}")
        lines.append("")
        lines.append(f"{color.bold(disp)}  {color.dim(tag)}")
        if item["matches"]:
            for i, m in enumerate(item["matches"]):
                if i == 0:
                    lines.append("  " + color.green(fmt_match(m)))
                else:
                    lines.append("  " + color.dim(fmt_match(m)))
        else:
            lines.append("  " + color.red("không xác định được loại hash"))
        if item["hint"]:
            lines.append("  " + color.yellow("! " + item["hint"]))
    return "\n".join(lines)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="hashid",
        description=f"{TOOL} {VERSION} - hash identifier ({TEAM}). "
                    "Python thuần, không cần cài đặt.",
        epilog="Vi du:\n"
               "  hashid.py d41d8cd98f00b204e9800998ecf8427e\n"
               "  hashid.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -v\n"
               "  hashid.py --file hashes.txt --short\n"
               "  hashid.py --stdin < hashes.txt --json-output -o report.json")
    ap.add_argument("hash", nargs="*", help="chuoi hash can nhan dang")
    ap.add_argument("--file", metavar="FILE",
                    help="file chua hash (1 dong 1 hash; dong # la comment)")
    ap.add_argument("--stdin", action="store_true",
                    help="doc hash tu stdin (1 dong 1 hash)")
    ap.add_argument("--short", action="store_true",
                    help="chi in hash + ten loai dau tien (de script)")
    ap.add_argument("--json-output", action="store_true",
                    help="xuat JSON thay vi text")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="in them goi y theo hoa thuong / do dai")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    color = Color(enabled=not args.no_color and sys.stdout.isatty()
                  and not args.output)

    hashes = []
    seen = set()
    for h in args.hash:
        h = h.strip()
        if h and h not in seen:
            seen.add(h)
            hashes.append(h)
    if args.file:
        try:
            with open(args.file, encoding="utf-8-sig") as f:
                for line in f:
                    h = line.strip()
                    if not h or h.startswith("#") or h in seen:
                        continue
                    seen.add(h)
                    hashes.append(h)
        except OSError as e:
            print(f"{TOOL}: khong doc duoc file {args.file}: {e}",
                  file=sys.stderr)
            return 2
    if args.stdin:
        for line in sys.stdin:
            h = line.strip()
            if not h or h.startswith("#") or h in seen:
                continue
            seen.add(h)
            hashes.append(h)

    if not hashes:
        print(f"{TOOL}: khong co hash nao (truyen hash, dung --file hoac "
              f"--stdin)", file=sys.stderr)
        return 2

    results = []
    identified = 0
    for h in hashes:
        matches = identify(h)
        if matches:
            identified += 1
        results.append({
            "hash": h,
            "length": len(h),
            "characters": chars_of(h),
            "case": case_of(h),
            "hint": hint(h, matches) if args.verbose else None,
            "matches": matches,
        })

    res = {"tool": TOOL, "version": VERSION, "team": TEAM,
           "queried_at": datetime.now().astimezone().isoformat(),
           "total": len(hashes), "identified": identified,
           "results": results}

    if args.json_output:
        text = json.dumps(res, indent=2, ensure_ascii=False)
    else:
        text = render_text(res, color, args.short)

    print(text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"{TOOL}: khong ghi duoc file {args.output}: {e}",
                  file=sys.stderr)
            return 2

    return 0 if identified == len(hashes) else 1


if __name__ == "__main__":
    sys.exit(main())
