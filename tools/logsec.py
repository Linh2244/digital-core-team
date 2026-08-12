#!/usr/bin/env python3
import argparse
import csv
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

TOOL = "LogSec"
VERSION = "1.0.0"
TEAM = "Digital Core team"

FORMATS = ("auto", "apache", "clf", "combined", "auth", "jsonl", "generic")

APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

AUTH_TIME_RE = re.compile(r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d)')
SSH_FAIL_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from '
    r'(?P<ip>\S+) port \d+')
SSH_ACCEPT_RE = re.compile(
    r'Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+')
SSH_INVALID_RE = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)')

IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-fA-F:]{3,}$')

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

THREAT_RULES = [
    (re.compile(r"\bunion\b.*\bselect\b", re.I),
     "SQLi", "SQL injection (UNION SELECT)", "HIGH"),
    (re.compile(r"(?:'|%27)[^']*--|\bor\s+1=1\b|\bsleep\s*\(|\bwaitfor\s+delay|"
                r"@@version|information_schema|(?:char|concat)\s*\(",
      re.I),
     "SQLi", "SQL injection payload", "HIGH"),
    (re.compile(r"<script|<iframe|<svg|javascript:|onerror\s*=|onload\s*=|"
                r"onclick\s*=|onmouseover\s*=", re.I),
     "XSS", "XSS payload", "HIGH"),
    (re.compile(r"(?:\.\./|\.\.%2f|%2e%2e%2f|\.\.\\|\.\.%5c|%2e%2e%5c)",
      re.I),
     "TRAV", "Path traversal", "HIGH"),
    (re.compile(r"/etc/passwd|/etc/shadow|php://filter|php://input|"
                r"file:///|data://|/proc/self/environ|win\.ini\b", re.I),
     "LFI", "Local file inclusion", "CRITICAL"),
    (re.compile(r"\.git/|\.env\b|\.aws/|config\.json|phpmyadmin|"
                r"wp-login\.php|wp-admin|\.bak\b|\.sql\b|\.tar\.gz\b|"
                r"\.zip\b|\.htaccess|/admin/|/console\b", re.I),
     "SENS", "Sensitive path probe", "MEDIUM"),
    (re.compile(r"masscan|sqlmap|nikto|nmap|nessus|acunetix|metasploit|"
                r"dirb|gobuster|wfuzz|hydra|theharvester", re.I),
     "UA", "Scanner user-agent", "LOW"),
]


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

    def severity(self, sev):
        return {"CRITICAL": self.red, "HIGH": self.red,
                "MEDIUM": self.yellow, "LOW": self.dim}.get(sev,
                                                            lambda x: x)(sev)


def _align(dt, ref):
    if dt.tzinfo is None and ref.tzinfo is not None:
        return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    if dt.tzinfo is not None and ref.tzinfo is None:
        return dt.replace(tzinfo=None)
    return dt


def fmt_int(n):
    return f"{n:,}"


def fmt_bytes(n):
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f} KB"
    return f"{n} B"


def parse_apache_time(t):
    try:
        return datetime.strptime(t, APACHE_TIME_FMT)
    except ValueError:
        return None


def parse_apache(line):
    m = APACHE_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    entry = {
        "ip": d["ip"] or None,
        "time": parse_apache_time(d["time"]),
        "method": d["method"] or None,
        "path": d["path"] or None,
        "status": int(d["status"]) if d["status"].isdigit() else None,
        "bytes": int(d["bytes"]) if d["bytes"].isdigit() else 0,
        "referer": d.get("referer"),
        "ua": d.get("ua"),
        "user": None,
        "event": None,
    }
    if entry["method"] == "-":
        entry["method"] = None
    return entry


def parse_auth_time(line):
    m = AUTH_TIME_RE.match(line)
    if not m:
        return None
    day = int(m.group("day"))
    mon = MONTHS.get(m.group("mon"))
    if not mon:
        return None
    year = datetime.now().year
    try:
        return datetime.strptime(
            f"{year}-{mon:02d}-{day:02d} {m.group('time')}",
            "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse_auth(line):
    t = parse_auth_time(line)
    base = {"time": t, "method": None, "path": None, "status": None,
            "bytes": 0, "referer": None, "ua": None}
    m = SSH_FAIL_RE.search(line)
    if m:
        return {**base, "ip": m.group("ip"), "user": m.group("user"),
                "event": "failed"}
    m = SSH_ACCEPT_RE.search(line)
    if m:
        return {**base, "ip": m.group("ip"), "user": m.group("user"),
                "event": "accepted"}
    m = SSH_INVALID_RE.search(line)
    if m:
        return {**base, "ip": m.group("ip"), "user": m.group("user"),
                "event": "invalid"}
    return None


def parse_json_time(v):
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v)
    s = str(v)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def parse_jsonl(line):
    try:
        o = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(o, dict):
        return None
    ip = next((o[k] for k in ("ip", "src_ip", "client_ip", "remote_addr",
                              "source_ip") if o.get(k)), None)
    ts = next((o[k] for k in ("timestamp", "time", "@timestamp", "ts",
                              "datetime") if o.get(k) is not None), None)
    method = next((o[k] for k in ("method", "http_method", "req_method")
                   if o.get(k)), None)
    path = next((o[k] for k in ("path", "uri", "request", "url", "full_request")
                 if o.get(k)), None)
    status = next((o[k] for k in ("status", "status_code", "http_status",
                                  "response") if o.get(k) is not None), None)
    ua = next((o[k] for k in ("user_agent", "ua", "agent") if o.get(k)), None)
    referer = next((o[k] for k in ("referer", "referrer") if o.get(k)), None)
    return {
        "ip": str(ip) if ip else None,
        "time": parse_json_time(ts),
        "method": str(method) if method else None,
        "path": str(path) if path else None,
        "status": int(status) if isinstance(status, (int, float)) else None,
        "bytes": 0,
        "referer": str(referer) if referer else None,
        "ua": str(ua) if ua else None,
        "user": None,
        "event": None,
    }


def parse_generic(line):
    ip = None
    m = re.match(r'^(\S+)', line)
    if m and IP_RE.match(m.group(1)):
        ip = m.group(1)
    return {"ip": ip, "time": None, "method": None, "path": None,
            "status": None, "bytes": 0, "referer": None, "ua": None,
            "user": None, "event": None}


PARSERS = {
    "apache": parse_apache,
    "clf": parse_apache,
    "combined": parse_apache,
    "auth": parse_auth,
    "jsonl": parse_jsonl,
    "generic": parse_generic,
}


def detect_format(lines):
    apache = 0
    auth = 0
    jsonl = 0
    total = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        total += 1
        if parse_apache(line):
            apache += 1
        if parse_auth(line):
            auth += 1
        if parse_jsonl(line):
            jsonl += 1
        if total >= 50:
            break
    if total == 0:
        return "generic"
    if apache * 4 >= total * 3:
        return "apache"
    if auth >= max(1, total // 3):
        return "auth"
    if jsonl * 4 >= total * 3:
        return "jsonl"
    return "generic"


class Analyzer:
    def __init__(self):
        self.lines = 0
        self.parsed = 0
        self.errors = 0
        self.first_time = None
        self.last_time = None
        self.ip_req = Counter()
        self.ip_bytes = Counter()
        self.paths = Counter()
        self.status = Counter()
        self.method = Counter()
        self.ua = Counter()
        self.referer = Counter()
        self.hour = Counter()
        self.ip_bad_auth = Counter()
        self.ip_scan = defaultdict(set)
        self.ip_failed = Counter()
        self.user_failed = Counter()
        self.ip_accepted = Counter()
        self.ip_invalid = Counter()
        self.threats = {}

    def feed(self, entry):
        self.parsed += 1
        t = entry["time"]
        if t:
            self.first_time = min(self.first_time, t) if self.first_time else t
            self.last_time = max(self.last_time, t) if self.last_time else t
            self.hour[t.strftime("%Y-%m-%d %H:00")] += 1

        ip = entry["ip"]
        if ip:
            self.ip_req[ip] += 1
            if entry["bytes"]:
                self.ip_bytes[ip] += entry["bytes"]

        if entry["event"] == "failed":
            self.ip_failed[ip] += 1
            if entry["user"]:
                self.user_failed[entry["user"]] += 1
            return
        if entry["event"] == "accepted":
            self.ip_accepted[ip] += 1
            return
        if entry["event"] == "invalid":
            self.ip_invalid[ip] += 1
            return

        if entry["path"]:
            self.paths[entry["path"]] += 1
        if entry["method"]:
            self.method[entry["method"]] += 1
        if entry["status"]:
            self.status[entry["status"]] += 1
            if entry["status"] in (401, 403):
                self.ip_bad_auth[ip] += 1
            if 400 <= entry["status"] < 500 and entry["path"]:
                if ip:
                    self.ip_scan[ip].add(entry["path"])
        if entry["ua"]:
            self.ua[entry["ua"]] += 1
        if entry["referer"]:
            self.referer[entry["referer"]] += 1

        target = " ".join(x for x in (entry["path"], entry["ua"]) if x)
        if not target:
            return
        for regex, code, name, sev in THREAT_RULES:
            if regex.search(target):
                self._threat(code, name, sev, ip, target)

    def _threat(self, code, name, sev, ip, sample):
        key = (code, ip)
        t = self.threats.setdefault(
            key, {"rule": code, "name": name, "severity": sev,
                  "ip": ip, "count": 0, "sample": sample[:400]})
        t["count"] += 1
        if len(sample) > len(t["sample"]):
            t["sample"] = sample[:400]

    def finalize(self):
        for ip, n in self.ip_bad_auth.items():
            if n >= 20:
                self._threat("BRUTE", "Web brute force (401/403)",
                             "HIGH", ip, f"{n} auth failures")
        for ip, paths in self.ip_scan.items():
            if len(paths) >= 30:
                self._threat("SCAN", "Scanner (unique 4xx paths)",
                             "MEDIUM", ip,
                             f"{len(paths)} unique 4xx paths")
        for ip, n in self.ip_failed.items():
            if n >= 5:
                self._threat("SSHBF", "SSH brute force", "HIGH", ip,
                             f"{n} failed passwords")
        for ip, n in self.ip_invalid.items():
            if n >= 10:
                self._threat("SSHE", "SSH user enumeration", "MEDIUM", ip,
                             f"{n} invalid users")


def threat_list(analyzer, min_sev=1):
    out = [t for t in analyzer.threats.values()
           if SEV_RANK[t["severity"]] >= min_sev]
    out.sort(key=lambda t: (-SEV_RANK[t["severity"]], -t["count"]))
    return out


def is_web(analyzer):
    return analyzer.paths or analyzer.status


def fmt_period(first, last):
    if not first and not last:
        return None
    a = first.strftime("%Y-%m-%d %H:%M") if first else "?"
    b = last.strftime("%Y-%m-%d %H:%M") if last else "?"
    days = None
    if first and last:
        days = (last - first).total_seconds() / 86400
    if days is not None and days >= 0:
        return f"{a} -> {b} ({days:.1f} days)"
    return f"{a} -> {b}"


def render_top(counter, n, fmt=None, label="requests"):
    rows = counter.most_common(n)
    if not rows:
        return ["  (no data)"]
    total = sum(counter.values())
    out = []
    for rank, (key, val) in enumerate(rows, 1):
        pct = val / total * 100 if total else 0
        extra = f"  {fmt(key)}" if fmt else ""
        out.append(f"  {rank:>3}. {key:<42} {fmt_int(val):>10} "
                   f"({pct:>5.1f}%){extra}")
    return out


def render_threats(threats, color):
    if not threats:
        return ["  (không phát hiện mối đe dọa)"]
    out = []
    for t in threats:
        label = f"{color.severity(t['severity'])}"
        sample = t["sample"].replace("\n", " ")
        if len(sample) > 110:
            sample = sample[:107] + "..."
        out.append(f"[{label:<8}] {t['name']}  "
                   f"{t['ip'] or '-':<16} x{t['count']}")
        out.append(f"    ! {sample}")
    return out


def build_report(results, args, color):
    min_sev = SEV_RANK[args.min_severity]
    total_lines = sum(a.lines for a in results)
    sev_counts = Counter()
    total_threats = 0
    for a in results:
        for t in threat_list(a, min_sev):
            sev_counts[t["severity"]] += 1
            total_threats += 1

    parts = []
    for a in results:
        parts.append(f";; {TOOL} {VERSION} <<>> {a.source} "
                     f"({a.format}, {fmt_int(a.lines)} dòng, "
                     f"parse {fmt_int(a.parsed)}, lỗi {fmt_int(a.errors)})")
    parts.append(f";; tổng: {fmt_int(total_lines)} dòng, "
                 f"{fmt_int(total_threats)} mối đe dọa"
                 f" (CRITICAL {sev_counts['CRITICAL']}, "
                 f"HIGH {sev_counts['HIGH']}, MEDIUM {sev_counts['MEDIUM']}, "
                 f"LOW {sev_counts['LOW']})")

    for a in results:
        if not is_web(a) and not a.ip_failed:
            continue
        parts.append("")
        period = fmt_period(a.first_time, a.last_time)
        if period:
            parts.append(f";; {a.source} — period: {period}")
        if a.status:
            parts.append("")
            parts.append(color.bold("== HTTP STATUS =="))
            for s, n in a.status.most_common(12):
                color_code = color.red(str(s)) if s >= 500 else (
                    color.yellow(str(s)) if s >= 400 else str(s))
                parts.append(f"  {color_code:<6} {fmt_int(n):>10}")
        if a.paths:
            parts.append("")
            parts.append(color.bold("== TOP PATHS =="))
            parts.extend(render_top(a.paths, args.top))
        if a.ip_req:
            parts.append("")
            parts.append(color.bold("== TOP SOURCES (IP) =="))
            parts.extend(render_top(a.ip_req, args.top,
                                    fmt=lambda ip: f"{fmt_bytes(a.ip_bytes[ip])}"))
        if a.ua and args.verbose:
            parts.append("")
            parts.append(color.bold("== TOP USER-AGENTS =="))
            parts.extend(render_top(a.ua, args.top))
        if a.referer and args.verbose:
            parts.append("")
            parts.append(color.bold("== TOP REFERRERS =="))
            parts.extend(render_top(a.referer, args.top))
        if a.hour:
            parts.append("")
            parts.append(color.bold("== TIMELINE (top giờ) =="))
            parts.extend(render_top(a.hour, min(12, args.top)))

        if a.ip_failed:
            parts.append("")
            parts.append(color.bold("== SSH: IP thất bại =="))
            parts.extend(render_top(a.ip_failed, args.top))
            parts.append("")
            parts.append(color.bold("== SSH: user thất bại =="))
            parts.extend(render_top(a.user_failed, args.top))
            parts.append(f"  login thành công: {fmt_int(sum(a.ip_accepted.values()))} "
                         f"(từ {len(a.ip_accepted)} IP)")

        threats = threat_list(a, SEV_RANK[args.min_severity])
        parts.append("")
        parts.append(color.bold("== THREATS =="))
        parts.extend(render_threats(threats, color))

    return "\n".join(parts)


def build_json(results, args):
    files = []
    web = {"top_ips": [], "status": {}, "top_paths": [], "top_ua": [],
           "timeline": []}
    auth = {"top_failed_ips": [], "top_failed_users": [], "accepted": 0}
    threats = []
    sev_counts = Counter()
    total_lines = total_parsed = 0
    for a in results:
        total_lines += a.lines
        total_parsed += a.parsed
        files.append({
            "source": a.source, "format": a.format, "lines": a.lines,
            "parsed": a.parsed, "errors": a.errors,
            "period": fmt_period(a.first_time, a.last_time),
        })
        web["top_ips"].extend({"ip": ip, "requests": n}
                              for ip, n in a.ip_req.most_common(args.top))
        web["status"].update({str(k): v for k, v in a.status.items()})
        web["top_paths"].extend({"path": p, "requests": n}
                                for p, n in a.paths.most_common(args.top))
        web["top_ua"].extend({"ua": u, "requests": n}
                             for u, n in a.ua.most_common(args.top))
        web["timeline"].extend({"hour": h, "requests": n}
                               for h, n in a.hour.most_common(24))
        auth["top_failed_ips"].extend({"ip": ip, "failed": n}
                                      for ip, n in a.ip_failed.most_common(args.top))
        auth["top_failed_users"].extend({"user": u, "failed": n}
                                        for u, n in a.user_failed.most_common(args.top))
        auth["accepted"] += sum(a.ip_accepted.values())
        for t in a.threats.values():
            sev_counts[t["severity"]] += 1
        threats.extend(t for t in threat_list(a, 1))

    threats.sort(key=lambda t: (-SEV_RANK[t["severity"]], -t["count"]))
    return {
        "tool": TOOL, "version": VERSION, "team": TEAM,
        "queried_at": datetime.now().astimezone().isoformat(),
        "files": files,
        "totals": {
            "lines": total_lines, "parsed": total_parsed,
            "threats": len(threats),
            "critical": sev_counts["CRITICAL"], "high": sev_counts["HIGH"],
            "medium": sev_counts["MEDIUM"], "low": sev_counts["LOW"],
        },
        "web": web, "auth": auth, "threats": threats,
    }


def build_csv(results, min_sev=1):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "rule", "name", "ip", "count", "sample"])
    for a in results:
        for t in sorted((t for t in a.threats.values()
                         if SEV_RANK[t["severity"]] >= min_sev),
                        key=lambda x: (-SEV_RANK[x["severity"]],
                                       -x["count"])):
            w.writerow([t["severity"], t["rule"], t["name"],
                        t["ip"] or "", t["count"],
                        t["sample"].replace("\n", " ")])
    return buf.getvalue().rstrip()


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="logsec",
        description=f"{TOOL} {VERSION} - log analyzer ({TEAM}). "
                    "Phân tích log access/SSH, phát hiện mối đe dọa.",
        epilog="Vi du:\n"
               "  logsec.py access.log\n"
               "  logsec.py access.log access.log.1 -T 20\n"
               "  logsec.py -f secure --format auth --ip 203.0.113.9\n"
               "  logsec.py access.log --json -o report.json\n"
               "  logsec.py access.log --csv -o threats.csv --threats-only\n"
               "  logsec.py access.log --since 2026-08-01T00:00")
    ap.add_argument("files", nargs="*", help="file log can phan tich")
    ap.add_argument("-f", "--file", action="append", dest="files2",
                    metavar="FILE", help="them file log (dung nhieu lan)")
    ap.add_argument("--format", dest="log_format", default="auto",
                    choices=FORMATS,
                    help="dinh dang log: auto (mac dinh), apache/clf/combined, "
                         "auth, jsonl, generic")
    ap.add_argument("--top", type=int, default=10,
                    help="so muc top moi bang (mac dinh 10)")
    ap.add_argument("--ip", metavar="IP",
                    help="chi phan tich cac dong cua IP nay")
    ap.add_argument("--path", metavar="SUB",
                    help="chi giu cac dong co duong dan chua chuoi nay")
    ap.add_argument("--since", metavar="TS",
                    help="chi giu dong tu moc thoi gian nay (ISO, VD 2026-08-01T00:00)")
    ap.add_argument("--until", metavar="TS",
                    help="chi giu dong truoc moc thoi gian nay")
    ap.add_argument("--last-hours", type=float, metavar="N",
                    help="chi giu dong trong N gio gan nhat")
    ap.add_argument("--threats-only", action="store_true",
                    help="chi in phan THREATS")
    ap.add_argument("--min-severity", default="LOW",
                    choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
                    help="muc nghiem trong toi thieu de hien thi (mac dinh LOW)")
    ap.add_argument("--exit-on", default="HIGH",
                    choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
                    help="exit 1 khi co thong bao o muc nay tro len (mac dinh HIGH)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--csv", action="store_true",
                    help="output CSV danh sach moi de doa")
    ap.add_argument("--short", action="store_true",
                    help="output gon 1 dong/file")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="chi tiet hon (top UA/referer, thong tin mo rong)")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    color = Color(enabled=not args.no_color and sys.stdout.isatty()
                  and not args.output)
    paths = list(args.files)
    if args.files2:
        paths.extend(args.files2)
    if not paths:
        ap.print_usage(sys.stderr)
        return 3

    since = until = None
    if args.since:
        try:
            since = datetime.fromisoformat(args.since)
        except ValueError:
            print(f"{TOOL}: --since khong hop le: {args.since}",
                  file=sys.stderr)
            return 3
    if args.until:
        try:
            until = datetime.fromisoformat(args.until)
        except ValueError:
            print(f"{TOOL}: --until khong hop le: {args.until}",
                  file=sys.stderr)
            return 3
    if args.last_hours is not None:
        since = datetime.now() - timedelta(hours=args.last_hours)

    results = []
    bad_files = 0
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError as e:
            print(f"{TOOL}: khong doc duoc '{p}': {e}", file=sys.stderr)
            bad_files += 1
            continue
        if lines and lines[0].startswith("\ufeff"):
            lines[0] = lines[0][1:]

        if args.log_format == "auto":
            log_format = detect_format(lines[:50])
        else:
            log_format = args.log_format
        parser = PARSERS[log_format]

        an = Analyzer()
        an.source = p
        an.format = log_format
        an.lines = len(lines)
        for idx, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                entry = parser(line)
            except Exception:
                entry = None
            if entry is None:
                an.errors += 1
                continue
            if entry["ip"] and args.ip and entry["ip"] != args.ip:
                continue
            if entry["path"] and args.path and \
                    args.path not in entry["path"]:
                continue
            if since and entry["time"] and \
                    _align(entry["time"], since) < since:
                continue
            if until and entry["time"] and \
                    _align(entry["time"], until) > until:
                continue
            an.feed(entry)
        an.finalize()
        results.append(an)
        if args.verbose:
            print(color.dim(f"[i] {p}: {log_format}, {an.lines} dòng, "
                            f"parse {an.parsed}, lỗi {an.errors}"),
                  file=sys.stderr)

    if not results:
        print(f"{TOOL}: khong phan tich duoc file nao", file=sys.stderr)
        return 2

    if args.short:
        sev = Counter()
        total_t = 0
        for a in results:
            for t in threat_list(a, SEV_RANK[args.min_severity]):
                sev[t["severity"]] += 1
                total_t += 1
        rows = []
        for a in results:
            rows.append(f"{a.source}: {fmt_int(a.lines)} dòng, "
                        f"{fmt_int(a.parsed)} parse, {fmt_int(a.errors)} lỗi")
        rows.append(f"TOTAL: {fmt_int(sum(a.lines for a in results))} dòng, "
                    f"{total_t} threats (C{sev['CRITICAL']}/H{sev['HIGH']}"
                    f"/M{sev['MEDIUM']}/L{sev['LOW']})")
        text = "\n".join(rows)
    elif args.json:
        text = json.dumps(build_json(results, args), indent=2,
                          ensure_ascii=False)
    elif args.csv:
        text = build_csv(results, SEV_RANK[args.min_severity])
    elif args.threats_only:
        parts = []
        for a in results:
            threats = threat_list(a, SEV_RANK[args.min_severity])
            parts.append(f";; {TOOL} {VERSION} <<>> {a.source}")
            parts.extend(render_threats(threats, color))
        text = "\n".join(parts)
    else:
        text = build_report(results, args, color)

    print(text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"{TOOL}: khong ghi duoc file: {e}", file=sys.stderr)
            return 3

    worst = 0
    for a in results:
        for t in a.threats.values():
            if SEV_RANK[t["severity"]] >= SEV_RANK[args.exit_on]:
                worst = 1
    if bad_files and not results:
        return 2
    return worst


if __name__ == "__main__":
    sys.exit(main())
