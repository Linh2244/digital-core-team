#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DepCheck - Dependency Vulnerability Checker (Digital Core team).

Quét dependencies tu cac file (requirements.txt, Pipfile, poetry.lock,
package.json, package-lock.json, pom.xml, go.mod, Cargo.lock) hoac tu dong
lenh "name==version", doi chieu voi co so du lieu CVE (OSV.dev) va xuat bao
cao text/JSON/Markdown.

Co so du lieu CVE: OSV.dev (https://api.osv.dev) - mien phi, khong can API
key. Du lieu duoc cache local tai ~/.depcheck/cache de co the dung offline
(sau khi da --update it nhat mot lan).

Exit codes:
  0  khong co loi hong bao mat
  1  co loi hong bao mat (>= --min-severity)
  2  input sai (file khong parse duoc, target sai)
  3  loi mang / khong lay duoc co so du lieu CVE
"""

import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

TOOL = "DepCheck"
VERSION = "1.0.0"
TEAM = "Digital Core team"

OSV_URL = "https://api.osv.dev/v1/query"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".depcheck", "cache")
CACHE_TTL = 86400  # 1 ngay

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_PENALTY = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
             "LOW": "cyan"}

FILE_PARSERS = {}
FILE_ECO = {}


class Color:
    def __init__(self, enabled=True):
        self.en = enabled

    def _w(self, code, s):
        return f"\x1b[{code}m{s}\x1b[0m" if self.en else s

    def red(self, s):
        return self._w("31", s)

    def green(self, s):
        return self._w("32", s)

    def yellow(self, s):
        return self._w("33", s)

    def cyan(self, s):
        return self._w("36", s)

    def bold(self, s):
        return self._w("1", s)


def status_color(st):
    return {"FAIL": "red", "WARN": "yellow", "PASS": "green",
            "INFO": "cyan"}.get(st, "bold")


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def cvss_level(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"


def vuln_severity(v):
    db = v.get("database_specific") or {}
    sev = db.get("severity")
    if isinstance(sev, list):
        for item in sev:
            t = (item.get("type") or "").upper()
            if t.startswith("CVSS_V3") or t.startswith("CVSS_V4"):
                try:
                    return cvss_level(float(item.get("score")))
                except (TypeError, ValueError):
                    pass
            s = str(item.get("score", "")).upper()
            if s in SEV_ORDER:
                return s
    elif isinstance(sev, str) and sev.upper() in SEV_ORDER:
        return sev.upper()
    s = str((v.get("ecosystem_specific") or {}).get("severity", "")).upper()
    if s in SEV_ORDER:
        return s
    return "MEDIUM"


def fixed_version(v):
    for aff in v.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                fx = ev.get("fixed")
                if fx and re.match(r"^[vV]?(\d+(\.\d+)+[\w.\-]*|\d+)$",
                                   str(fx)):
                    return str(fx)
    return None


# --------------------------------------------------------------------------
# So sanh phien ban (PEP440/semver don gian)
# --------------------------------------------------------------------------
def norm(v):
    s = str(v).strip().lstrip("vV")
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if not m:
        return (0, 0, 0, 0)
    a, b, c = int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0)
    t = s[m.end():].lstrip(".-_").lower()
    if t.startswith(("a", "b", "dev", "pre", "rc", "alpha", "beta")):
        return (a, b, c, -1)
    if t.startswith(("post", "rev", "final")):
        return (a, b, c, 1)
    return (a, b, c, 0)


def osv_range_bounds(rng):
    lo = hi = None
    hi_inc = False
    for ev in rng.get("events", []):
        if "introduced" in ev:
            lo = norm(ev["introduced"])
        elif "fixed" in ev:
            hi = norm(ev["fixed"])
            hi_inc = False
        elif "last_affected" in ev:
            hi = norm(ev["last_affected"])
            hi_inc = True
        elif "limit" in ev:
            hi = norm(ev["limit"])
            hi_inc = False
    return (lo, hi, hi_inc)


def affected_ranges(aff):
    return [osv_range_bounds(r) for r in aff.get("ranges", [])]


def in_range(vn, lo, hi, hi_inc):
    if lo is not None and vn < lo:
        return False
    if hi is not None:
        if hi_inc:
            if vn > hi:
                return False
        elif vn >= hi:
            return False
    return True


def _lo_max(x, y):
    if x is None:
        return y
    if y is None:
        return x
    return max(x, y)


def _hi_min(x, y):
    if x is None:
        return y
    if y is None:
        return x
    return min(x, y)


def overlap(a, b):
    lo = _lo_max(a[0], b[0])
    hi = _hi_min(a[1], b[1])
    if lo is None or hi is None:
        return True
    if lo < hi:
        return True
    if lo > hi:
        return False
    return a[2] or b[2]


def spec_bounds(spec):
    """-> (lo, hi, lo_inc, hi_inc). lo/hi la tuple norm() hoac None."""
    spec = (spec or "*").strip()
    if not spec or spec == "*" or spec.lower() in ("latest", "any"):
        return (None, None, False, False)
    lo = hi = None
    lo_inc = hi_inc = False
    for part in re.split(r"\s*,\s*", spec):
        m = re.match(r"^\s*(~=|==|!=|>=|<=|>|<)\s*(.+)$", part)
        if not m:
            m = re.match(r"^\s*([^\s,]+)\s*$", part)
            if m:
                v = norm(m.group(1))
                return (v, v, True, True)
            continue
        op, vstr = m.group(1), m.group(2).strip()
        v = norm(vstr)
        if op == "==":
            lo = hi = v
            lo_inc = hi_inc = True
        elif op == ">=":
            lo = v
            lo_inc = True
        elif op == ">":
            lo = v
            lo_inc = False
        elif op == "<=":
            hi = v
            hi_inc = True
        elif op == "<":
            hi = v
            hi_inc = False
        elif op == "~=":
            lo = v
            lo_inc = True
            nums = re.match(r"^(\d+)(?:\.(\d+))?", vstr)
            if nums and nums.group(2):
                hi = (int(nums.group(1)), int(nums.group(2)) + 1, 0, 0)
                hi_inc = False
    return (lo, hi, lo_inc, hi_inc)


def npm_bounds(v):
    v = v.strip()
    if not v or v == "*" or v == "latest":
        return (None, None, False, False)
    nums = re.match(r"^\^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if nums:
        a, b, c = (int(nums.group(1)), int(nums.group(2) or 0),
                   int(nums.group(3) or 0))
        return ((a, b, c, 0), (a + 1, 0, 0, 0), True, False)
    nums = re.match(r"^~v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if nums:
        a, b, c = (int(nums.group(1)), int(nums.group(2) or 0),
                   int(nums.group(3) or 0))
        return ((a, b, c, 0), (a, b + 1, 0, 0), True, False)
    nums = re.match(r"^v?(\d+)(?:\.(\d+))?\.(?:\*|x)", v, re.I)
    if nums:
        a, b = int(nums.group(1)), int(nums.group(2) or 0)
        return ((a, b, 0, 0), (a + 1, 0, 0, 0), True, False)
    m = re.match(r"^\s*v?(\d[\w.\-]*)\s*$", v)
    if m:
        n = norm(m.group(1))
        return (n, n, True, True)
    if re.match(r"^\s*[<>~=^]", v):
        return spec_bounds(v.replace("^", ">=").replace("~", ">="))
    return (None, None, False, False)


# --------------------------------------------------------------------------
# Parse file dependencies
# --------------------------------------------------------------------------
def parse_requirements(path):
    pkgs = []
    for line in open(path, encoding="utf-8-sig"):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "[", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", line)
        if not m:
            continue
        spec = re.split(r"\s*;\s*", m.group(2).strip())[0].strip() or "*"
        pkgs.append((m.group(1), spec))
    return pkgs


def parse_package_json(path):
    data = json.load(open(path, encoding="utf-8-sig"))
    pkgs = []
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for n, v in (data.get(sec) or {}).items():
            pkgs.append((n, v or "*"))
    return pkgs


def _npm_pkg(name):
    parts = name.split("/")
    if name.startswith("@"):
        return "/".join(parts[:2])
    return parts[0]


def parse_package_lock(path):
    data = json.load(open(path, encoding="utf-8-sig"))
    pkgs = []
    seen = set()
    for name, info in (data.get("packages") or {}).items():
        if not name:
            continue
        n = _npm_pkg(name[len("node_modules/"):]) \
            if name.startswith("node_modules/") else _npm_pkg(name)
        if n in seen:
            continue
        seen.add(n)
        ver = info.get("version")
        pkgs.append((n, f"=={ver}" if ver else "*"))
    if not pkgs:
        for n, info in (data.get("dependencies") or {}).items():
            ver = info.get("version")
            pkgs.append((n, f"=={ver}" if ver else "*"))
    return pkgs


def _parse_toml_packages(path, sections):
    pkgs = []
    cur = None
    cur_section = None
    for line in open(path, encoding="utf-8-sig"):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            sec = s[1:-1].strip()
            cur_section = sec if sec in sections else None
            cur = None
            continue
        if cur_section is None or not s or s.startswith("#"):
            continue
        if s.startswith("[[") and s.endswith("]]"):
            cur = {}
            continue
        if cur is not None:
            m = re.match(r'\s*name\s*=\s*"([^"]+)"', s)
            if m:
                cur["name"] = m.group(1)
            m = re.match(r'\s*version\s*=\s*"([^"]+)"', s)
            if m:
                cur["version"] = m.group(1)
            if cur.get("name") and cur.get("version"):
                pkgs.append((cur["name"], f"=={cur['version']}"))
                cur = None
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"',
                     s)
        if m:
            pkgs.append((m.group(1), m.group(2)))
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"', s)
        if m:
            pkgs.append((m.group(1), m.group(2) or "*"))
    return pkgs


def parse_poetry_lock(path):
    return _parse_toml_packages(path, ("package",))


def parse_pipfile(path):
    return _parse_toml_packages(path, ("packages", "dev-packages",
                                       "default", "develop"))


def parse_pom(path):
    data = open(path, encoding="utf-8-sig").read()
    pkgs = []
    for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>"
            r"\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            data):
        g, a, v = m.groups()
        pkgs.append((f"{g}:{a}", f"=={v}"))
    return pkgs


def parse_go_mod(path):
    pkgs = []
    inreq = False
    for line in open(path, encoding="utf-8-sig"):
        s = line.strip()
        if s.startswith("require ("):
            inreq = True
            continue
        if inreq:
            if s == ")":
                inreq = False
                continue
            m = re.match(r"^(\S+)\s+v(\S+)", s)
            if m:
                pkgs.append((m.group(1), f"=={m.group(2)}"))
        else:
            m = re.match(r"^require\s+(\S+)\s+v(\S+)$", s)
            if m:
                pkgs.append((m.group(1), f"=={m.group(2)}"))
    return pkgs


def parse_cargo(path):
    return _parse_toml_packages(path, ("package",))


def register(fname, eco):
    def deco(fn):
        FILE_PARSERS[fname] = fn
        FILE_ECO[fname] = eco
        return fn
    return deco


for _f, _eco in (("requirements.txt", "PyPI"), ("Pipfile", "PyPI"),
                 ("poetry.lock", "PyPI"), ("package.json", "npm"),
                 ("package-lock.json", "npm"), ("pom.xml", "Maven"),
                 ("go.mod", "Go"), ("Cargo.lock", "crates.io")):
    FILE_ECO[_f] = _eco
FILE_PARSERS.update({
    "requirements.txt": parse_requirements,
    "Pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "pom.xml": parse_pom,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo,
})

LOWER_ECO = {"PyPI", "npm", "crates.io"}


def osv_name(eco, name):
    return name.lower() if eco in LOWER_ECO else name


# --------------------------------------------------------------------------
# OSV query + cache
# --------------------------------------------------------------------------
def fetch_osv(eco, name, timeout, update=False, offline=False):
    key = osv_name(eco, name)
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", f"{eco}__{key}")
    cache_file = os.path.join(CACHE_DIR, safe + ".json")
    os.makedirs(CACHE_DIR, exist_ok=True)
    if os.path.exists(cache_file) and not update:
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            if time.time() - data.get("fetched_at", 0) < CACHE_TTL:
                return data.get("vulns", [])
        except Exception:
            pass
    if offline:
        if os.path.exists(cache_file):
            try:
                with open(cache_file, encoding="utf-8") as f:
                    return json.load(f).get("vulns", [])
            except Exception:
                pass
        raise ConnectionError(
            f"khong co cache local cho {name} ({eco}) va dang --offline")
    body = json.dumps({"package": {"ecosystem": eco,
                                   "name": key}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": f"{TOOL}/{VERSION} ({TEAM})"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        vulns = data.get("vulns", [])
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": time.time(), "vulns": vulns}, f,
                      ensure_ascii=False, indent=1)
        return vulns
    except (urllib.error.HTTPError, urllib.error.URLError, OSError,
            socket.timeout, TimeoutError) as e:
        if os.path.exists(cache_file):
            try:
                with open(cache_file, encoding="utf-8") as f:
                    return json.load(f).get("vulns", [])
            except Exception:
                pass
        raise ConnectionError(str(e))


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------
def matching_vulns(vulns, eco, name, version, sb):
    out = []
    for v in vulns:
        affected = v.get("affected") or []
        if not affected:
            out.append(v)
            continue
        hit = False
        for aff in affected:
            pkg = aff.get("package") or {}
            if osv_name(eco, pkg.get("name", "")).lower() != name.lower():
                continue
            ranges = aff.get("ranges") or []
            if not ranges:
                hit = True
                break
            for rng in ranges:
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                ob = osv_range_bounds(rng)
                if version is not None:
                    if in_range(norm(version), *ob):
                        hit = True
                        break
                else:
                    if overlap(sb, ob):
                        hit = True
                        break
            if hit:
                break
        if hit:
            out.append(v)
    return out


def canonical_id(v):
    for a in v.get("aliases") or []:
        if a.startswith("CVE-"):
            return a
    return v.get("id") or ""


def cve_id(v):
    return canonical_id(v) or v.get("id") or "?"


def score_of(sev):
    return SEV_PENALTY.get(sev, 0)


# --------------------------------------------------------------------------
# Scan & render
# --------------------------------------------------------------------------
def build_dep_result(source, eco, name, spec, vulns):
    version = None
    sb = (None, None, False, False)
    m = re.match(r"^==\s*(\S+)$", spec)
    if m:
        version = m.group(1)
    elif re.match(r"^[vV]?\d[\w.\-]*$", spec.strip()):
        version = spec.strip()
    elif eco == "npm":
        sb = npm_bounds(spec)
    else:
        sb = spec_bounds(spec)

    matched = matching_vulns(vulns, eco, name, version, sb)

    seen = set()
    dedup = []
    for v in matched:
        cid = canonical_id(v)
        if cid in seen:
            continue
        seen.add(cid)
        dedup.append(v)

    findings = []
    vuln_out = []
    for v in sorted(dedup,
                    key=lambda x: (SEV_ORDER.index(vuln_severity(x)),
                                   canonical_id(x))):
        sev = vuln_severity(v)
        cid = cve_id(v)
        fx = fixed_version(v) or "?"
        al = v.get("aliases") or []
        summary = (v.get("summary") or v.get("details") or "").strip()
        if len(summary) > 140:
            summary = summary[:137] + "..."
        tag = "" if version is not None else "[khoang phien ban] "
        findings.append({
            "group": "DEPENDENCY", "status": "FAIL", "severity": sev,
            "detail": f"{tag}{cid}: {sev} - fix: {fx} - {summary}",
        })
        vuln_out.append({
            "id": cid, "aliases": al, "severity": sev,
            "cvss": None, "summary": summary, "fixed": fx,
            "published": v.get("published"), "references": v.get("references"),
        })

    if not matched:
        label = version if version is not None else spec
        findings.append({
            "group": "DEPENDENCY", "status": "PASS", "severity": "INFO",
            "detail": f"Khong co CVE da biet cho {name} {label} ({eco})",
        })

    score = 100 - sum(score_of(f["severity"]) for f in findings
                      if f["status"] == "FAIL")
    score = max(0, min(100, score))
    worst = max((v["severity"] for v in vuln_out),
                key=SEV_ORDER.index) if vuln_out else "INFO"
    return {
        "source": source, "ecosystem": eco, "name": name,
        "version": version or spec, "ok": not matched,
        "severity": worst,
        "vulns": vuln_out, "findings": findings, "score": score,
    }


def render_text(results, color):
    lines = [f";; {TOOL} {VERSION} <<>> {TEAM}"]
    total = 100
    for r in results:
        total = min(total, r["score"])
        lines.append("")
        sev_col = getattr(color, SEV_COLOR.get(r["severity"], "bold"))
        lines.append(color.bold(
            f"{r['name']} {r['version']}  ({r['ecosystem']})"
            f"  [{r['source']}]"))
        for f in r["findings"]:
            sc = getattr(color, status_color(f["status"]))
            lines.append(f"  {sc(f['status']):<5} {f['severity']:<8} "
                         f"{f['detail']}")
    grade = grade_for(total)
    gcolor = {"A": color.green, "B": color.cyan, "C": color.yellow,
              "D": color.yellow, "F": color.red}.get(grade, color.bold)
    n_pkg = len(results)
    n_vuln = sum(len(r["vulns"]) for r in results)
    n_aff = sum(1 for r in results if not r["ok"])
    lines.append("")
    lines.append(f"  {color.bold('VERDICT')}: Score {total}/100 "
                 f"({gcolor(grade)}) | {n_pkg} goi, {n_aff} bi anh huong, "
                 f"{n_vuln} CVE")
    return "\n".join(lines)


def render_md(results, queried_at):
    L = [f"# {TOOL} Report", "",
         f"- Tool: {TOOL} {VERSION}",
         f"- Team: {TEAM}",
         f"- Queried at: {queried_at}",
         "- CVE database: OSV.dev (local cache: "
         "`~/.depcheck/cache`)", ""]
    total = 100
    n_vuln = 0
    n_aff = 0
    for r in results:
        total = min(total, r["score"])
        n_vuln += len(r["vulns"])
        n_aff += 1 if not r["ok"] else 0
    L += ["## Summary", "",
          "| Score | Grade | Packages | Affected | CVEs |",
          "|---|---|---|---|---|",
          f"| {total} | {grade_for(total)} | {len(results)} | {n_aff} | "
          f"{n_vuln} |", ""]
    for r in results:
        L += [f"## {r['name']} {r['version']} ({r['ecosystem']})",
              "", f"Source: `{r['source']}`", ""]
        if not r["vulns"]:
            L += ["No known CVEs.", ""]
            continue
        L += ["| CVE | Severity | Fixed | Summary |",
              "|---|---|---|---|"]
        for v in r["vulns"]:
            L += [f"| {v['id']} | {v['severity']} | {v['fixed']} | "
                  f"{v['summary'] or '-'} |"]
        L.append("")
    return "\n".join(L)


def render_json(results, queried_at, fetches):
    return json.dumps({
        "tool": TOOL, "version": VERSION, "team": TEAM,
        "queried_at": queried_at,
        "cache_dir": CACHE_DIR,
        "fetches": fetches,
        "targets": results,
    }, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------
def split_cli_spec(t):
    for sep in ("==", ":", "@", "="):
        if sep in t:
            n, v = t.split(sep, 1)
            if v:
                return n.strip(), v.strip()
    return t.strip(), "*"


def parse_targets(args_targets, args_eco):
    targets = []
    for t in args_targets:
        if os.path.isfile(t):
            base = os.path.basename(t)
            if base not in FILE_PARSERS:
                raise ValueError(
                    f"khong ho tro parse file {base!r} (ho tro: "
                    + ", ".join(sorted(FILE_PARSERS)) + ")")
            pkgs = FILE_PARSERS[base](t)
            targets.append((os.path.abspath(t), FILE_ECO[base], pkgs))
            continue
        name, spec = split_cli_spec(t)
        if not re.match(r"^[A-Za-z0-9_.\-@/]+$", name):
            raise ValueError(f"target khong hop le: {t!r}")
        targets.append((f"cli:{name}", args_eco, [(name, spec)]))
    return targets


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="depcheck",
        description=f"{TOOL} {VERSION} - Dependency Vulnerability Checker "
                    f"(Digital Core team). Quet dependencies doi chieu CVE "
                    f"database (OSV.dev) va xuat bao cao text/JSON/Markdown.")
    ap.add_argument("targets", nargs="*",
                    help="file lockfile (requirements.txt, package.json, "
                         "pom.xml, go.mod, ...) hoac 'name==version'")
    ap.add_argument("-e", "--ecosystem", default="PyPI",
                    help="ecosystem cho target dang name==version "
                         "(PyPI, npm, Maven, Go, crates.io, ... mac dinh "
                         "PyPI)")
    ap.add_argument("--update", action="store_true",
                    help="buoc cap nhat lai cache CVE tu OSV.dev")
    ap.add_argument("--offline", action="store_true",
                    help="chi dung cache local (~/.depcheck/cache), khong "
                         "goi mang")
    ap.add_argument("-T", "--timeout", type=float, default=10.0,
                    help="timeout goi API OSV (mac dinh 10s)")
    ap.add_argument("--threads", type=int, default=8,
                    help="so luong query CVE song song (mac dinh 8)")
    ap.add_argument("--min-severity", default="LOW",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    help="nguong bao cao / exit code 1 (mac dinh LOW)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--md", action="store_true",
                    help="output Markdown (dung chung voi -o de ghi file .md)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("--no-color", action="store_true", help="tat mau ANSI")
    ap.add_argument("--version", action="version",
                    version=f"{TOOL} {VERSION}")
    args = ap.parse_args()

    if not args.targets:
        print(f"{TOOL}: khong co target nao (file lockfile hoac "
              f"'requests==2.31.0')", file=sys.stderr)
        return 2
    try:
        targets = parse_targets(args.targets, args.ecosystem)
    except ValueError as e:
        print(f"{TOOL}: {e}", file=sys.stderr)
        return 2

    color = Color(enabled=sys.stdout.isatty() and not args.no_color)
    queried_at = datetime.now().astimezone().isoformat()

    # cac package can query (de loai trung)
    needed = {}
    for src, eco, pkgs in targets:
        for name, spec in pkgs:
            needed.setdefault((eco, osv_name(eco, name)), (src, name, spec))

    print(f"{TOOL}: dang kiem tra {len(needed)} goi phan mem "
          f"({len(targets)} nguon) ...", file=sys.stderr)

    cache = {}
    errors = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.threads)) as ex:
        fut = {ex.submit(fetch_osv, eco, name, args.timeout,
                         args.update, args.offline): (eco, name)
               for eco, name in needed}
        for f in concurrent.futures.as_completed(fut):
            eco, name = fut[f]
            try:
                cache[(eco, name)] = f.result()
            except ConnectionError as e:
                cache[(eco, name)] = None
                errors.append(f"{name} ({eco}): {e}")

    for err in errors:
        print(f"{TOOL}: WARN khong lay duoc CVE - {err}", file=sys.stderr)

    results = []
    for src, eco, pkgs in targets:
        for name, spec in pkgs:
            key = (eco, osv_name(eco, name))
            vulns = cache.get(key)
            if vulns is None:
                results.append({
                    "source": src, "ecosystem": eco, "name": name,
                    "version": spec, "ok": False, "severity": "LOW",
                    "vulns": [], "score": 0,
                    "error": "khong co du lieu CVE (check mang hoac --update)",
                    "findings": [{"group": "DEPENDENCY", "status": "WARN",
                                  "severity": "LOW",
                                  "detail": "Khong lay duoc du lieu CVE"}],
                })
                continue
            results.append(build_dep_result(src, eco, name, spec, vulns))

    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    threshold = sev_rank[args.min_severity]
    has_vuln = any(r.get("vulns") and any(
        sev_rank[v["severity"]] <= threshold for v in r["vulns"])
        for r in results)
    fetch_fail = sum(1 for r in results if r.get("error"))

    if args.json:
        out = render_json(results, queried_at, {"cache_dir": CACHE_DIR})
    elif args.md:
        out = render_md(results, queried_at)
    else:
        out = render_text(results, color)
    print(out)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out + "\n")
        except OSError as e:
            print(f"{TOOL}: khong ghi duoc file {args.output}: {e}",
                  file=sys.stderr)
            return 2

    if fetch_fail == len(results):
        return 3
    if has_vuln:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
