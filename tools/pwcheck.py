#!/usr/bin/env python3
import argparse
import json
import math
import re
import string
import sys
from datetime import datetime

TOOL = "PWCheck"
VERSION = "1.0.0"
TEAM = "Digital Core team"

GUESSES_PER_SEC = 1e12

SYMBOLS = string.punctuation

LEET_CHARS = {"a": "4@", "e": "3", "i": "1!", "o": "0",
              "s": "5$", "t": "7", "g": "6", "b": "8", "z": "2"}

COMMON = {
    "123456": 1, "password": 2, "123456789": 3, "12345678": 4, "12345": 5,
    "1234567": 6, "qwerty": 7, "1234567890": 8, "abc123": 9, "111111": 10,
    "123123": 11, "password1": 12, "iloveyou": 13, "admin": 14,
    "welcome": 15, "monkey": 16, "login": 17, "letmein": 18, "dragon": 19,
    "master": 20, "654321": 21, "1q2w3e4r": 22, "princess": 23,
    "sunshine": 24, "football": 25, "baseball": 26, "shadow": 27,
    "superman": 28, "qwertyuiop": 29, "trustno1": 30, "batman": 31,
    "hello": 32, "charlie": 33, "whatever": 34, "freedom": 35,
    "1qaz2wsx": 36, "qazwsx": 37, "000000": 38, "121212": 39,
    "zaq12wsx": 40, "88888888": 41, "159753": 42, "147258": 43,
    "starwars": 44, "qweasd": 45, "zxcvbnm": 46, "696969": 47,
    "dragon1": 48, "michael": 49, "jordan": 50,
}

STEMS = (
    "password", "letmein", "welcome", "admin", "qwerty", "secret", "love",
    "dragon", "monkey", "master", "shadow", "superman", "trustno1",
    "football", "baseball", "hunter", "batman", "matrix", "jordan",
    "michael", "jennifer", "ninja", "mustang", "charlie", "freedom",
    "princess", "whatever", "starwars", "access", "default", "changeme",
    "root", "test", "guest", "hello", "world", "summer", "winter",
    "spring", "computer", "internet", "iloveyou", "abc123", "123qwe",
    "qwe123", "654321", "000000", "111111", "666666", "888888", "121212",
    "112233", "123321", "987654", "159753", "147258", "qazwsx",
    "zaq12wsx", "1qaz2wsx", "1q2w3e4r", "qwerty123", "motdepasse",
    "matkhau", "vietnam", "saigon", "hanoi", "passwd", "123456", "12345",
    "1234", "admin123", "asdfgh", "zxcvbn",
)

KBRD = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
        "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn",
        "7ujm", "8ik,", "9ol.", "0p;/")

CLASS_SIZES = {"lower": 26, "upper": 26, "digit": 10,
               "symbol": len(SYMBOLS), "space": 1, "other": 100}


class Color:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def red(self, s): return self._w("31", s)
    def green(self, s): return self._w("32", s)
    def yellow(self, s): return self._w("33", s)
    def cyan(self, s): return self._w("36", s)
    def bold(self, s): return self._w("1", s)
    def dim(self, s): return self._w("2", s)


def fmt_duration(secs):
    if secs >= 31557600:
        years = secs / 31557600
        if years >= 1e9:
            return f"{years:.2e} năm"
        if years >= 1e6:
            return f"{years / 1e6:.1f} triệu năm"
        if years >= 1000:
            return f"{years / 1000:.1f} nghìn năm"
        return f"{years:.1f} năm"
    if secs >= 86400:
        return f"{secs / 86400:.1f} ngày"
    if secs >= 3600:
        return f"{secs / 3600:.1f} giờ"
    if secs >= 60:
        return f"{secs / 60:.1f} phút"
    return f"{secs:.1f} giây"


def rating(bits):
    if bits < 40:
        return "YẾU", "red"
    if bits < 60:
        return "TRUNG BÌNH", "yellow"
    if bits < 80:
        return "MẠNH", "cyan"
    return "RẤT MẠNH", "green"


def estimate(pw):
    counts = {"lower": 0, "upper": 0, "digit": 0,
              "symbol": 0, "space": 0, "other": 0}
    for c in pw:
        if c.islower():
            counts["lower"] += 1
        elif c.isupper():
            counts["upper"] += 1
        elif c.isdigit():
            counts["digit"] += 1
        elif c.isspace():
            counts["space"] += 1
        elif c in SYMBOLS:
            counts["symbol"] += 1
        else:
            counts["other"] += 1
    present = {k: v for k, v in counts.items() if v}
    pool = sum(CLASS_SIZES[k] for k in present)
    return pool, present


def leet_variants(word, max_variants=512):
    words = [word]
    for i, ch in enumerate(word):
        subs = LEET_CHARS.get(ch)
        if not subs or len(words) >= max_variants:
            continue
        words = list(dict.fromkeys(
            w[:i] + s + w[i + 1:] for w in words for s in (ch, *subs)))
    return words


_COMMON_VARIANTS = {}
for _w, _r in COMMON.items():
    for _v in leet_variants(_w):
        _COMMON_VARIANTS.setdefault(_v, (_w, _r))
_COMMON_PLAIN = {_w: (_w, _r) for _w, _r in COMMON.items()}

_STEM_MATCH = sorted(
    ((_v, _stem) for _stem in STEMS for _v in leet_variants(_stem)),
    key=lambda x: -len(x[0]))
_STEM_MATCH_PLAIN = sorted(
    ((_stem, _stem) for _stem in STEMS), key=lambda x: -len(x[0]))


def find_stems(norm, match_list):
    hits = []
    used = [False] * len(norm)
    for variant, stem in match_list:
        start = 0
        while True:
            p = norm.find(variant, start)
            if p == -1:
                break
            if not any(used[p:p + len(variant)]):
                for i in range(p, p + len(variant)):
                    used[i] = True
                hits.append((stem, variant != stem))
                break
            start = p + 1
    return hits


def find_sequence(norm):
    best = ""
    n = len(norm)
    i = 0
    while i < n:
        run = [norm[i]]
        j = i
        direction = 0
        while j + 1 < n:
            a, b = norm[j], norm[j + 1]
            if a.isdigit() and b.isdigit():
                d = int(b) - int(a)
            elif a.isalpha() and b.isalpha() and a.islower() == b.islower():
                d = ord(b) - ord(a)
            else:
                d = 0
            if abs(d) != 1:
                break
            if direction == 0:
                direction = d
            elif d != direction:
                break
            run.append(b)
            j += 1
        if len(run) >= 3 and len(run) > len(best):
            best = "".join(run)
        i = j if j > i else i + 1
    return best or None


def find_keyboard(norm):
    best = ""
    for row in KBRD:
        for s in (row, row[::-1]):
            L = len(s)
            for k in range(L, 3, -1):
                if k <= len(best):
                    break
                for p in range(L - k + 1):
                    sub = s[p:p + k]
                    if sub in norm:
                        best = sub
                        break
    return best or None


def find_repeat_char(norm):
    best = ""
    for m in re.finditer(r"(.)\1{2,}", norm):
        if len(m.group(0)) > len(best):
            best = m.group(0)
    return best or None


def find_repeat_substring(norm):
    best = ""
    for m in re.finditer(r"(.{1,5})\1{2,}", norm):
        if len(m.group(0)) > len(best):
            best = m.group(0)
    return best or None


def find_year(norm):
    m = re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", norm)
    return m.group(0) if m else None


def assess(pw, no_leet=False, no_blacklist=False):
    length = len(pw)
    pool, classes = estimate(pw)
    base = length * math.log2(pool) if pool else 0.0
    bits = base
    findings = []
    norm = pw.lower()

    if not no_blacklist:
        common_map = _COMMON_PLAIN if no_leet else _COMMON_VARIANTS
        hit = common_map.get(norm)
        if hit:
            canonical, rank = hit
            bits = min(bits, 6 + math.log2(rank))
            findings.append(("trong top mật khẩu phổ biến", f"hạng {rank}",
                             "common"))
            if canonical != norm:
                findings.append(("leetspeak", canonical, "leet"))

        stems = find_stems(norm,
                           _STEM_MATCH_PLAIN if no_leet else _STEM_MATCH)
        if stems:
            bits = min(bits, 18) - 4 * (len(stems) - 1)
            findings.append(("chứa từ thông dụng",
                             ", ".join(s for s, _ in stems), "common"))
            if any(l for _, l in stems):
                findings.append(("leetspeak",
                                 ", ".join(s for s, _ in stems), "leet"))
        rev = find_stems(norm[::-1],
                         _STEM_MATCH_PLAIN if no_leet else _STEM_MATCH)
        if rev:
            bits -= 4
            findings.append(("từ đảo ngược",
                             ", ".join(s for s, _ in rev), "rev"))
        seq = find_sequence(norm)
        if seq:
            bits -= 6
            findings.append(("chuỗi tuần tự", seq, "seq"))
        kb = find_keyboard(norm)
        if kb:
            bits -= 8
            findings.append(("mẫu bàn phím", kb, "kb"))
        rep = find_repeat_char(norm)
        if rep:
            bits -= 8
            findings.append(("ký tự lặp", rep, "repeat"))
        rsub = find_repeat_substring(norm)
        if rsub:
            bits -= 8
            findings.append(("chuỗi lặp lại", rsub, "subrep"))
        yr = find_year(norm)
        if yr:
            bits -= 8 if length <= 8 else 4
            findings.append(("năm", yr, "year"))

    if len(set(pw)) == 1:
        bits = 4.0
        findings.append(("toàn bộ là 1 ký tự lặp", pw[0], "allsame"))

    seen = set()
    uniq = []
    for label, detail, ftype in findings:
        key = (ftype, detail)
        if key not in seen:
            seen.add(key)
            uniq.append((label, detail, ftype))
    findings = uniq

    bits = max(4.0, bits)
    label, _ = rating(bits)
    return {
        "password": pw,
        "length": length,
        "pool_size": pool,
        "unique_chars": len(set(pw)),
        "classes": classes,
        "base_entropy_bits": round(base, 1),
        "effective_entropy_bits": round(bits, 1),
        "findings": [{"type": t, "label": l, "detail": d}
                     for l, d, t in findings],
        "rating": label,
        "crack_time": fmt_duration((2 ** bits) / GUESSES_PER_SEC),
    }


def render_text(results, color):
    counts = {}
    for r in results:
        counts[r["rating"]] = counts.get(r["rating"], 0) + 1
    summary = " | ".join(f"{v} {k}" for k, v in
                         sorted(counts.items(), key=lambda x: 0 if x[0] == "YẾU" else 1))
    lines = [f";; {TOOL} {VERSION} <<>> {TEAM}",
             f";; {len(results)} mật khẩu | {summary}"]
    for i, r in enumerate(results, 1):
        label, method = rating(r["effective_entropy_bits"])
        lines.append("")
        lines.append(f"{i}. {color.bold(r['password'])}  ->  "
                     f"{getattr(color, method)(label)}")
        comp = ", ".join(f"{k} {v}" for k, v in
                         sorted(r["classes"].items()))
        lines.append(f"   Độ dài {r['length']} | Pool ước tính "
                     f"{r['pool_size']} | Ký tự riêng {r['unique_chars']}")
        lines.append(f"   Thành phần: {comp}")
        lines.append(f"   Entropy cơ bản {r['base_entropy_bits']} bits -> "
                     f"còn {r['effective_entropy_bits']} bits")
        if r["findings"]:
            det = "; ".join(f"{f['label']} ({f['detail']})"
                            for f in r["findings"])
            lines.append(f"   Phát hiện: {det}")
        lines.append(f"   Bẻ khóa offline (~{GUESSES_PER_SEC:.0e} phép thử/s): "
                     f"{r['crack_time']}")
    return "\n".join(lines)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="pwcheck",
        description=f"{TOOL} {VERSION} - password strength checker "
                    f"(Digital Core team). Phân tích mật khẩu phat hien "
                    f"cac mau yeu thuc te (pho bien, tu dien, leetspeak, "
                    f"ban phim, tuan tu, nam...).")
    ap.add_argument("passwords", nargs="*", help="mat khau can kiem tra")
    ap.add_argument("--stdin", action="store_true",
                    help="doc mat khau tu stdin (1 dong 1 mat khau)")
    ap.add_argument("--no-leet", action="store_true",
                    help="khong giai ma leetspeak (p@ssw0rd)")
    ap.add_argument("--no-blacklist", action="store_true",
                    help="bo qua kiem tra danh sach mat khau/tu thong dung")
    ap.add_argument("--json", action="store_true",
                    help="output JSON")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    passwords = list(args.passwords)
    if args.stdin:
        for line in sys.stdin:
            line = line.rstrip("\r\n").strip()
            if not line or line.startswith(";;"):
                continue
            line = re.sub(r"^\d+\.\s+", "", line)
            passwords.append(line)
    if not passwords:
        print(f"{TOOL}: khong co mat khau nao de kiem tra "
              f"(dung positional hoac --stdin)", file=sys.stderr)
        return 2

    results = [assess(p, args.no_leet, args.no_blacklist)
               for p in passwords]

    if args.json:
        weak = sum(1 for r in results if r["rating"] == "YẾU")
        text = json.dumps({
            "tool": TOOL, "version": VERSION, "team": TEAM,
            "queried_at": datetime.now().astimezone().isoformat(),
            "count": len(results), "weak": weak,
            "passwords": results,
        }, indent=2, ensure_ascii=False)
    else:
        color = Color(enabled=not args.no_color and sys.stdout.isatty()
                      and not args.output)
        text = render_text(results, color)

    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return 1 if any(r["rating"] == "YẾU" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
