#!/usr/bin/env python3
import argparse
import csv
import fnmatch
import io
import json
import math
import os
import re
import sys
import time
from datetime import datetime

TOOL = "SecretScan"
VERSION = "1.0.0"
TEAM = "Digital Core team"

SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MB = 1024 * 1024

RULES = [
    # (name, regex, severity, min_entropy)
    ("AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b", "HIGH", None),
    ("AWS Secret Access Key",
     r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[=:]\s*['\"]?"
     r"(?P<s>[A-Za-z0-9/+=]{40})['\"]?", "HIGH", 3.5),
    ("GitHub Token", r"\bgh[pousr]_[0-9A-Za-z]{36}\b", "HIGH", None),
    ("GitHub Fine-grained PAT",
     r"\bgithub_pat_[0-9A-Za-z_]{22,}\b", "HIGH", None),
    ("Slack Token", r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b", "HIGH", None),
    ("Slack Webhook",
     r"https://hooks\.slack\.com/services/[0-9A-Za-z]{8,}/"
     r"[0-9A-Za-z]{8,}", "HIGH", None),
    ("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "HIGH", None),
    ("Google OAuth Token", r"\b1//0[0-9A-Za-z_\-]{20,}\b", "HIGH", None),
    ("GCP Service Account",
     r"\b[0-9]{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b",
     "HIGH", None),
    ("Stripe Live Secret Key", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24}\b",
     "HIGH", None),
    ("Stripe Test Secret Key", r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24}\b",
     "MEDIUM", None),
    ("Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b", "HIGH", None),
    ("SendGrid API Key", r"\bSG\.[0-9A-Za-z]{16}\.[0-9A-Za-z]{16,}\b",
     "HIGH", None),
    ("npm Token", r"\bnpm_[0-9A-Za-z]{36}\b", "HIGH", None),
    ("Telegram Bot Token", r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b",
     "HIGH", None),
    ("Private Key",
     r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
     "HIGH", None),
    ("JWT Token",
     r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}\b",
     "MEDIUM", None),
    ("API Key Assignment",
     r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|"
     r"auth[_-]?token|access[_-]?token|refresh[_-]?token|"
     r"private[_-]?key)\b\s*[=:]\s*['\"]?"
     r"(?P<s>[A-Za-z0-9_\-./+]{16,})['\"]?", "MEDIUM", 3.5),
    ("Password Assignment",
     r"(?i)\b(?:password|passwd|pwd)\b\s*[=:]\s*['\"]"
     r"(?P<s>[^'\"]{8,})['\"]", "MEDIUM", 3.0),
    ("Database Connection String",
     r"(?i)\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql)"
     r"://[^\s'\"$]{4,}:[^\s'\"$]{4,}@", "MEDIUM", None),
]

VALUE_FP = ("example", "sample", "dummy", "your", "changeme", "placeholder",
            "xxxx", "insert", "replace", "todo", "lorem", "foobar", "fake",
            "public", "default", "password")
LINE_FP = ("example", "sample", "dummy", "your", "changeme", "placeholder",
           "xxxx", "insert", "replace", "todo", "lorem", "foobar", "fake",
           "public", "demo")

RULES = [(n, re.compile(rx), s, e) for n, rx, s, e in RULES]

DEFAULT_DIR_EXCLUDE = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".venv", "dist", "build", ".idea", ".vscode", ".gradle",
    ".cargo", ".pytest_cache", ".mypy_cache", ".next", ".nuxt", "vendor",
    ".terraform", "target", "obj",
}
DEFAULT_FILE_EXCLUDE = (
    "*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json",
    "yarn.lock", "*.snap", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.bz2", "*.7z", "*.exe", "*.dll",
    "*.so", "*.dylib", "*.bin", "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.pyc", "*.pyo", "*.class", "*.jar", "*.min", "*.sqlite",
)


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

    def severity(self, sev):
        return {"CRITICAL": self.red, "HIGH": self.red,
                "MEDIUM": self.yellow, "LOW": self.dim}.get(sev,
                                                            lambda x: x)(sev)


def shannon(s):
    if not s:
        return 0.0
    n = len(s)
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def mask_secret(secret):
    n = len(secret)
    if n <= 4:
        return "*" * n
    if n <= 10:
        return secret[:2] + "*" * (n - 4) + secret[-2:]
    return secret[:4] + "*" * (n - 8) + secret[-4:]


def looks_binary(path):
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
    except OSError:
        return True
    if not chunk:
        return True
    if b"\x00" in chunk:
        return True
    control = sum(1 for b in chunk
                  if b < 9 or 13 < b < 32 or b == 127)
    return control / len(chunk) > 0.15


def parse_exts(s):
    return {e.strip().lower().lstrip(".") for e in s.split(",") if e.strip()}


def file_ext(name):
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def is_excluded_dir(name):
    if name in DEFAULT_DIR_EXCLUDE:
        return True
    return False


def is_excluded_file(name, extra_globs=()):
    for g in DEFAULT_FILE_EXCLUDE:
        if fnmatch.fnmatch(name, g):
            return True
    for g in extra_globs:
        if fnmatch.fnmatch(name, g):
            return True
    return False


def is_allowed(line, secret, allow_rx):
    for rx in allow_rx:
        if rx.search(secret) or rx.search(line):
            return True
    return False


def collect_files(paths, exts, extra_excludes, max_bytes):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if not is_excluded_dir(d)]
                for n in names:
                    if is_excluded_file(n, extra_excludes):
                        continue
                    if exts and file_ext(n) not in exts:
                        continue
                    full = os.path.join(root, n)
                    try:
                        if os.path.getsize(full) > max_bytes * MB:
                            continue
                    except OSError:
                        continue
                    files.append(full)
        elif os.path.isfile(p):
            files.append(p)
    return files


def scan_file(path, rules, allow_rx, args):
    results = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return results, 0
    for lineno, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        for name, rx, sev, min_ent in rules:
            if SEV_RANK[sev] < SEV_RANK[args.min_severity]:
                continue
            for m in rx.finditer(line):
                secret = m.group("s") if "s" in m.groupdict() else m.group(0)
                if not secret:
                    continue
                if min_ent is not None and shannon(secret) < min_ent:
                    continue
                sl = secret.lower()
                ll = line.lower()
                if any(w in sl for w in VALUE_FP) or any(w in ll for w in LINE_FP):
                    continue
                if is_allowed(line, secret, allow_rx):
                    continue
                results.append({
                    "rule": name, "severity": sev,
                    "line": lineno, "column": m.start() + 1,
                    "secret": secret, "context": line,
                })
    results.sort(key=lambda r: (-SEV_RANK[r["severity"]],
                                r["line"], r["column"]))
    seen, out = set(), []
    for r in results:
        k = (r["line"], r["secret"])
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out, len(lines)


def fmt_context(line, secret, args):
    shown = line.replace(secret, mask_secret(secret)) if not args.no_mask \
        else line
    shown = shown.strip()
    if len(shown) > 160:
        idx = shown.find(mask_secret(secret)) if not args.no_mask \
            else shown.find(secret)
        if idx < 0:
            shown = shown[:160]
        else:
            start = max(0, idx - 60)
            shown = shown[start:start + 160].strip()
            if start > 0:
                shown = "..." + shown
    return shown


def render_text(secrets, args, color):
    if not secrets:
        return "  (không phát hiện bí mật)"
    lines = []
    width = max(len(s["severity"]) for s in secrets)
    for s in secrets:
        sev = s["severity"].ljust(width)
        loc = f"{s['file']}:{s['line']}:{s['column']}"
        lines.append(f"[{color.severity(sev)}] {s['rule']}"
                     f"    {color.bold(loc)}")
        secret = s["secret"] if args.no_mask else mask_secret(s["secret"])
        lines.append(f"    ! {secret}")
        ctx = fmt_context(s["context"], s["secret"], args)
        lines.append(f"    @ {color.dim(ctx)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def build_json(secrets, stats):
    counts = Counter_sev(secrets)
    return {
        "tool": TOOL, "version": VERSION, "team": TEAM,
        "queried_at": datetime.now().astimezone().isoformat(),
        "summary": {
            "files": stats["files"], "bytes": stats["bytes"],
            "secrets": len(secrets),
            "critical": counts["CRITICAL"], "high": counts["HIGH"],
            "medium": counts["MEDIUM"], "low": counts["LOW"],
        },
        "secrets": secrets,
    }


def Counter_sev(secrets):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in secrets:
        c[s["severity"]] += 1
    return c


def build_csv(secrets):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "rule", "file", "line", "column", "secret"])
    for s in secrets:
        w.writerow([s["severity"], s["rule"], s["file"], s["line"],
                    s["column"], s["secret"]])
    return buf.getvalue().rstrip()


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="secretscan",
        description=f"{TOOL} {VERSION} - secret scanner (Digital Core "
                    f"team). Quét mã nguồn tìm khóa API, token, mật khẩu "
                    f"bị lộ.")
    ap.add_argument("files", nargs="*", help="file hoac thu muc can quet")
    ap.add_argument("-f", "--file", action="append", metavar="FILE",
                    help="them file quet (dung nhieu lan)")
    ap.add_argument("--ext", metavar="EXTS",
                    help="chi quet cac duoi mo rong nay (VD py,js,env)")
    ap.add_argument("--exclude", action="append", metavar="GLOB",
                    help="bo qua file/thu muc khop glob (dung nhieu lan)")
    ap.add_argument("--min-severity",
                    choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
                    default="LOW",
                    help="muc toi thieu de bao cao (mac dinh LOW)")
    ap.add_argument("--allow", action="append", metavar="REGEX",
                    help="bo qua ket qua khop regex nay (dung nhieu lan)")
    ap.add_argument("--allowlist", metavar="FILE",
                    help="file chua cac regex bo qua (1 regex/dong, "
                         "'#' la ghi chu)")
    ap.add_argument("--no-entropy", action="store_true",
                    help="tat kiem tra entropy (bao ca them ca ket qua "
                         "kha nang la duong nham)")
    ap.add_argument("--max-size", type=float, default=10.0, metavar="MB",
                    help="bo qua file lon hon N MB (mac dinh 10)")
    ap.add_argument("--no-mask", action="store_true",
                    help="hien day du bí mat trong output text")
    ap.add_argument("--rules", action="store_true",
                    help="liet ke cac quy tac phat hien roi thoat")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--csv", action="store_true", help="output CSV")
    ap.add_argument("--short", action="store_true",
                    help="output gon: 1 dong/file co bi mat")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="hien chi tiet file dang quet")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    if args.rules:
        for name, _, sev, _ in RULES:
            print(f"{sev:<8} {name}")
        return 0

    paths = list(args.files)
    if args.file:
        paths.extend(args.file)
    if not paths:
        ap.print_usage(sys.stderr)
        return 3

    if args.allowlist:
        try:
            with open(args.allowlist, encoding="utf-8") as f:
                patterns = [ln.strip() for ln in f
                            if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            print(f"{TOOL}: khong doc duoc allowlist '{args.allowlist}': {e}",
                  file=sys.stderr)
            return 3
    else:
        patterns = []
    if args.allow:
        patterns.extend(args.allow)
    allow_rx = []
    for p in patterns:
        try:
            allow_rx.append(re.compile(p))
        except re.error as e:
            print(f"{TOOL}: regex khong hop le '{p}': {e}",
                  file=sys.stderr)
            return 3

    if args.no_entropy:
        rules = [(n, rx, sev, None) for n, rx, sev, _ in RULES]
    else:
        rules = RULES

    color = Color(enabled=not args.no_color and sys.stdout.isatty()
                  and not args.output)
    exts = parse_exts(args.ext) if args.ext else None

    t0 = time.monotonic()
    files = collect_files(paths, exts, args.exclude or [], args.max_size)

    secrets = []
    scanned = 0
    total_bytes = 0
    for f in files:
        if looks_binary(f):
            if args.verbose:
                print(color.dim(f"[i] bo qua (binary/empty): {f}"),
                      file=sys.stderr)
            continue
        res, nlines = scan_file(f, rules, allow_rx, args)
        for r in res:
            r["file"] = f
        secrets.extend(res)
        scanned += 1
        try:
            total_bytes += os.path.getsize(f)
        except OSError:
            pass
        if args.verbose:
            print(color.dim(f"[i] {f}: {len(res)} phát hiện"),
                  file=sys.stderr)

    elapsed = time.monotonic() - t0

    if scanned == 0:
        print(f"{TOOL}: khong quet duoc file nao (loi duong dan, "
              f"khong co file hop le, hoac file deu bi binary?)",
              file=sys.stderr)
        return 2

    secrets.sort(key=lambda s: (-SEV_RANK[s["severity"]],
                                s["file"], s["line"], s["column"]))
    stats = {"files": scanned, "bytes": total_bytes}
    c = Counter_sev(secrets)

    if args.short:
        by_file = {}
        for s in secrets:
            by_file.setdefault(s["file"], []).append(s)
        lines = []
        for f, ss in sorted(by_file.items()):
            c = Counter_sev(ss)
            lines.append(f"{f}: {len(ss)} bí mật "
                         f"(H{c['HIGH']}/M{c['MEDIUM']}/L{c['LOW']})")
        c = Counter_sev(secrets)
        lines.append(f"TOTAL: {scanned} file, {len(secrets)} bí mật "
                     f"(C{c['CRITICAL']}/H{c['HIGH']}/M{c['MEDIUM']}"
                     f"/L{c['LOW']}) trong {elapsed:.1f}s")
        text = "\n".join(lines)
    elif args.json:
        text = json.dumps(build_json(secrets, stats), indent=2,
                          ensure_ascii=False)
    elif args.csv:
        text = build_csv(secrets)
    else:
        parts = [f";; {TOOL} {VERSION} <<>> {TEAM}"]
        parts.append(f";; {scanned} file, {len(secrets)} bí mật "
                     f"(C{c['CRITICAL']}/H{c['HIGH']}/M{c['MEDIUM']}"
                     f"/L{c['LOW']}) trong {elapsed:.1f}s")
        parts.append("")
        parts.append(render_text(secrets, args, color))
        text = "\n".join(parts)

    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")

    return 1 if secrets else 0


if __name__ == "__main__":
    sys.exit(main())
