#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HttpSec - HTTP security scanner (product of Digital Core team).

Passive-first checks: TLS/SSL posture, security headers, cookies, HTTP methods,
sensitive paths, CORS policy, information disclosure. Optional --active tests
(add/delete probes, reflection checks). Output: colored text, JSON, HTML report.

Usage examples:
  python httpsec.py https://example.com
  python httpsec.py -u https://example.com -oJ report.json -oH report.html
  python httpsec.py http://10.0.0.5 --active -H "Authorization: Bearer xyz"
  python httpsec.py --list-checks
"""

import argparse
import ctypes
import html
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from datetime import datetime, timezone
from collections import OrderedDict

VERSION = "1.0.0"
TOOL = "HttpSec"
TEAM = "Digital Core team"
WEAK_TLS_NAMES = {ssl.TLSVersion.TLSv1: "TLSv1.0", ssl.TLSVersion.TLSv1_1: "TLSv1.1"}

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SENSITIVE_PATHS = [
    ("/.git/config", "Git config exposure", "HIGH",
     "repository file reachable -> source leak", "[core]"),
    ("/.git/HEAD", "Git HEAD exposure", "HIGH",
     "repository file reachable", "ref: refs/"),
    ("/.env", "Environment file exposure", "HIGH",
     "may contain secrets/credentials", "="),
    ("/.env.local", "Environment file exposure", "HIGH",
     "may contain secrets/credentials", "="),
    ("/.env.production", "Environment file exposure", "HIGH",
     "may contain secrets/credentials", "="),
    ("/backup.zip", "Backup archive exposure", "HIGH", "backup may contain source+database", None),
    ("/backup.sql", "Database backup exposure", "HIGH", "database dump reachable", None),
    ("/dump.sql", "Database backup exposure", "HIGH", "database dump reachable", None),
    ("/db.sql", "Database backup exposure", "HIGH", "database dump reachable", None),
    ("/web.config", "Config file exposure", "MEDIUM", "may contain connection strings", None),
    ("/phpinfo.php", "PHP info exposure", "MEDIUM", "reveals environment details", "phpinfo"),
    ("/server-status", "Apache server-status", "MEDIUM", "may expose request activity", None),
    ("/phpmyadmin/", "phpMyAdmin exposed", "HIGH", "DB admin panel reachable", None),
    ("/admin", "Admin panel reachable", "MEDIUM", "unauthenticated admin interface", None),
    ("/wp-admin", "WordPress admin", "MEDIUM", "unauthenticated admin interface", None),
    ("/.htaccess", "Htaccess exposure", "LOW", "may reveal rewrite rules", None),
    ("/.svn/entries", "SVN metadata exposure", "MEDIUM", "source control metadata", None),
    ("/.DS_Store", "macOS metadata exposure", "LOW", "may leak file listing", None),
    ("/crossdomain.xml", "Crossdomain policy", "LOW", "flash crossdomain policy", None),
    ("/robots.txt", "robots.txt", "INFO", "standard file", None),
    ("/security.txt", "security.txt", "INFO", "security contact", None),
    ("/sitemap.xml", "sitemap.xml", "INFO", "standard file", None),
]

INFO_HEADERS = [
    ("Server", "Server banner disclosure", "LOW"),
    ("X-Powered-By", "X-Powered-By disclosure", "LOW"),
    ("X-AspNet-Version", "ASP.NET version disclosure", "MEDIUM"),
    ("X-AspNetMvc-Version", "ASP.NET MVC version disclosure", "LOW"),
]

OPEN_REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnTo", "dest", "target", "out"]


class Color:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def green(self, s): return self._w("32", s)
    def red(self, s): return self._w("31", s)
    def yellow(self, s): return self._w("33", s)
    def cyan(self, s): return self._w("36", s)
    def magenta(self, s): return self._w("35", s)
    def bold(self, s): return self._w("1", s)
    def dim(self, s): return self._w("2", s)

    def severity(self, sev):
        return {"CRITICAL": self.red, "HIGH": self.red, "MEDIUM": self.yellow,
                "LOW": self.cyan, "INFO": self.dim}.get(sev, lambda x: x)(sev)


def enable_ansi_windows():
    if sys.platform == "win32":
        try:
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_url(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    p = urllib.parse.urlsplit(raw)
    return p


def grade_for(score):
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 50: return "D"
    return "F"


class Finding:
    def __init__(self, category, title, severity, status, detail, remediation):
        self.category = category
        self.title = title
        self.severity = severity
        self.status = status      # PASS | WARN | FAIL
        self.detail = detail
        self.remediation = remediation

    def to_dict(self):
        return OrderedDict([
            ("category", self.category), ("title", self.title),
            ("severity", self.severity), ("status", self.status),
            ("detail", self.detail), ("remediation", self.remediation),
        ])


# ---------------------------------------------------------------- HTTP fetch

class HTTP:
    def __init__(self, timeout=10.0, headers=None, verify=True, follow=True):
        self.timeout = timeout
        self.headers = {"User-Agent": f"{TOOL}/{VERSION} (security scanner)"}
        if headers:
            for h in headers:
                if ":" in h:
                    k, _, v = h.partition(":")
                    self.headers[k.strip()] = v.strip()
        self.verify = verify
        self.follow = follow
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._handler = urllib.request.HTTPSHandler(context=ctx)
        else:
            self._handler = urllib.request.HTTPSHandler()

    def _ssl_error(self):
        return None

    def request(self, url, method="GET", body=None, headers=None, timeout=None, follow=None):
        h = dict(self.headers)
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        use_follow = self.follow if follow is None else follow
        handlers = [self._handler]
        if not use_follow:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        try:
            resp = opener.open(req, timeout=timeout or self.timeout)
            data = resp.read(262144)
            return {"status": resp.status, "headers": resp.headers, "body": data,
                    "url": resp.geturl(), "method": method, "error": None}
        except urllib.error.HTTPError as e:
            data = e.read(262144)
            return {"status": e.code, "headers": e.headers, "body": data,
                    "url": e.geturl(), "method": method, "error": None}
        except ssl.SSLCertVerificationError as e:
            return {"status": None, "headers": None, "body": b"", "url": url,
                    "method": method, "error": f"certificate verify failed: {e.verify_message or e}"}
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as e:
            return {"status": None, "headers": None, "body": b"", "url": url,
                    "method": method, "error": str(e)}

    def get(self, url, headers=None, timeout=None, follow=None):
        return self.request(url, "GET", headers=headers, timeout=timeout, follow=follow)

    def head(self, url, headers=None, timeout=None, follow=None):
        return self.request(url, "HEAD", headers=headers, timeout=timeout, follow=follow)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------- TLS checks

class TLSChecker:
    def __init__(self, host, port, timeout=8.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.versions = []
        self.weak_ciphers = []
        self.cert = {}
        self.chain_ok = None
        self.chain_reason = None
        self.alpn = None

    def _connect(self, ctx):
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            raw.settimeout(self.timeout)
        except OSError as e:
            return None, str(e)
        try:
            with ctx.wrap_socket(raw, server_hostname=self.host) as s:
                return s, None
        except (ssl.SSLError, OSError) as e:
            try:
                raw.close()
            except Exception:
                pass
            return None, str(e)

    def run(self):
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            # protocol versions
            for ver, name in [(ssl.TLSVersion.TLSv1, "TLSv1.0"),
                              (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
                              (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
                              (ssl.TLSVersion.TLSv1_3, "TLSv1.3")]:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver
                    ctx.set_alpn_protocols(["h2", "http/1.1"])
                except (ValueError, ssl.SSLError):
                    continue
                s, err = self._connect(ctx)
                if s is not None:
                    self.versions.append(name)
                    if name == "TLSv1.3":
                        self.alpn = s.selected_alpn_protocol()
                    s.close()

            # weak cipher support (TLS1.2 CBC-SHA / legacy)
            for cipher in ["AES128-SHA", "ECDHE-RSA-AES128-SHA", "DES-CBC3-SHA", "RC4-SHA"]:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                    ctx.set_ciphers(cipher + ":@SECLEVEL=0")
                except (ssl.SSLError, ValueError):
                    continue
                s, _ = self._connect(ctx)
                if s is not None:
                    self.weak_ciphers.append(cipher)
                s.close()

        # certificate + chain trust
        self._cert_and_chain()
        return self

    def _cert_and_chain(self):
        # chain verification via system CAs
        ctx = ssl.create_default_context()
        try:
            s, err = self._connect(ctx)
            if s is not None:
                self.chain_ok = True
                self.cert = self._decode_cert(s.getpeercert(binary_form=True) or b"")
                s.close()
                return
            if "certificate verify failed" in (err or ""):
                self.chain_ok = False
                self.chain_reason = err
            else:
                self.chain_ok = None
                self.chain_reason = err
        except Exception:
            pass
        # fetch cert regardless of trust with CERT_NONE for detail
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            s, err = self._connect(ctx2)
            if s is not None:
                der = s.getpeercert(binary_form=True)
                self.cert = self._decode_cert(der or b"")
                s.close()
        except Exception:
            pass

    @staticmethod
    def _decode_cert(der):
        out = {}
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)

            def name(n):
                try:
                    return ", ".join(f"{a.oid._name or a.oid.dotted_string}={a.value}" for a in n)
                except Exception:
                    return str(n)

            san = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                san = [d.value for d in ext]
            except Exception:
                pass
            na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            na = na.astimezone(timezone.utc) if na.tzinfo else na.replace(tzinfo=timezone.utc)
            out = {
                "subject": name(cert.subject),
                "issuer": name(cert.issuer),
                "san": san,
                "not_after": na.isoformat(),
                "days_remaining": (na - datetime.now(timezone.utc)).days,
                "serial": format(cert.serial_number, "X"),
                "public_key": f"{cert.public_key().key_size}-bit "
                              f"{cert.public_key().__class__.__name__.replace('_', ' ')}",
            }
        except Exception:
            pass
        return out


# ---------------------------------------------------------------- checks

class HeadersAnalyzer:
    @staticmethod
    def analyze(scanner, resp, is_https):
        headers = resp["headers"] or {}
        get = lambda k: (headers.get(k) if isinstance(headers, dict)
                         else (headers.get(k) if hasattr(headers, "get") else None))
        # HSTS
        hsts = get("Strict-Transport-Security")
        if is_https and hsts:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            detail = f"max-age={age}"
            if "includesubdomains" in hsts.lower():
                detail += ", includeSubDomains"
            if "preload" in hsts.lower():
                detail += ", preload"
            scanner.add("headers", "Strict-Transport-Security", "INFO", "PASS",
                         detail, "keep max-age >= 6 months (31536000) with includeSubDomains")
            if age < 31536000:
                scanner.add("headers", "HSTS max-age too short", "LOW", "WARN",
                             f"max-age={age} < 31536000", "use max-age=31536000; includeSubDomains")
        elif is_https:
            scanner.add("headers", "Missing Strict-Transport-Security", "MEDIUM", "FAIL",
                         "HSTS absent on HTTPS site", "add Strict-Transport-Security header")
        # clickjacking
        xfo = get("X-Frame-Options")
        csp = get("Content-Security-Policy") or ""
        has_fa = "frame-ancestors" in csp.lower()
        if xfo or has_fa:
            scanner.add("headers", "Clickjacking protection", "INFO", "PASS",
                         f"X-Frame-Options={xfo or 'n/a'}, frame-ancestors={'yes' if has_fa else 'no'}",
                         "keep frame-ancestors in CSP or X-Frame-Options DENY/SAMEORIGIN")
        else:
            scanner.add("headers", "Missing clickjacking protection", "MEDIUM", "FAIL",
                         "no X-Frame-Options and no CSP frame-ancestors",
                         "set X-Frame-Options: DENY or CSP frame-ancestors 'self'")
        # CSP
        if csp:
            scanner.add("headers", "Content-Security-Policy", "INFO", "PASS",
                         "CSP present", "review policy, avoid unsafe-inline/unsafe-eval")
            if "unsafe-inline" in csp.lower():
                scanner.add("headers", "CSP allows unsafe-inline", "LOW", "WARN",
                             "unsafe-inline weakens XSS protection",
                             "remove unsafe-inline / use nonces or hashes")
            if "*" in csp and "frame-ancestors" not in csp.lower():
                scanner.add("headers", "CSP source '*'", "LOW", "WARN",
                             "broad source directive", "restrict CSP sources")
        else:
            scanner.add("headers", "Missing Content-Security-Policy", "LOW", "WARN",
                         "CSP absent", "define a CSP to mitigate XSS/clickjacking")
        # nosniff
        if (get("X-Content-Type-Options") or "").lower() == "nosniff":
            scanner.add("headers", "X-Content-Type-Options", "INFO", "PASS",
                         "nosniff", "keep it")
        else:
            scanner.add("headers", "Missing X-Content-Type-Options", "MEDIUM", "FAIL",
                         "no nosniff", "set X-Content-Type-Options: nosniff")
        # referrer-policy
        rp = get("Referrer-Policy")
        if rp:
            scanner.add("headers", "Referrer-Policy", "INFO", "PASS", rp, "review policy")
        else:
            scanner.add("headers", "Missing Referrer-Policy", "LOW", "WARN",
                         "leaks referrer", "set Referrer-Policy: strict-origin-when-cross-origin")
        # permissions policy
        pp = get("Permissions-Policy") or get("Feature-Policy")
        if pp:
            scanner.add("headers", "Permissions-Policy", "INFO", "PASS", pp[:80], "review policy")
        else:
            scanner.add("headers", "Missing Permissions-Policy", "LOW", "WARN",
                         "browser features unrestricted", "set Permissions-Policy")
        # x-xss-protection
        xp = get("X-XSS-Protection")
        if xp == "0":
            scanner.add("headers", "X-XSS-Protection disabled", "LOW", "WARN",
                         "header value 0 disables filter", "remove header (deprecated) or rely on CSP")
        elif xp:
            scanner.add("headers", "X-XSS-Protection (legacy)", "INFO", "INFO",
                         "deprecated header", "safe to remove; rely on CSP")
        # cross-origin policies
        for hname, title, good, rem in [
            ("Cross-Origin-Opener-Policy", "COOP", "same-origin",
             "set COOP: same-origin to isolate cross-origin windows"),
            ("Cross-Origin-Resource-Policy", "CORP", "same-origin",
             "set CORP: same-origin for non-public resources"),
            ("Cross-Origin-Embedder-Policy", "COEP", "require-corp",
             "set COEP: require-corp to harden against cross-origin reads")]:
            v = get(hname)
            if v and v.lower() == good:
                scanner.add("headers", hname, "INFO", "PASS", v, "keep it")
            elif v:
                scanner.add("headers", f"{hname} ({title})", "INFO", "INFO", v, rem)
            else:
                scanner.add("headers", f"Missing {hname} ({title})", "INFO", "INFO",
                             "header absent", rem)
        # info disclosure
        for hname, title, sev in INFO_HEADERS:
            v = get(hname)
            if v:
                scanner.add("headers", title, sev, "WARN", f"{hname}: {v[:120]}",
                             "remove or mask version detail headers")
        # content-type
        ct = get("Content-Type")
        if not ct:
            scanner.add("headers", "Missing Content-Type", "LOW", "WARN",
                         "response has no Content-Type", "set correct Content-Type")


class CookieAnalyzer:
    @staticmethod
    def analyze(scanner, resp):
        headers = resp.get("headers")
        if headers is None:
            return
        setcookies = []
        if hasattr(headers, "get_all"):
            setcookies = headers.get_all("Set-Cookie") or []
        elif isinstance(headers, dict):
            v = headers.get("Set-Cookie")
            setcookies = [v] if v else []
        if not setcookies:
            scanner.add("cookies", "Cookies", "INFO", "INFO", "no cookies set", "")
            return
        for sc in setcookies:
            name = sc.split("=")[0].strip().split(" ")[0]
            parts = [p.strip().lower() for p in sc.split(";")[1:]]
            secure = "secure" in parts
            httponly = "httponly" in parts
            samesite = None
            for p in parts:
                if p.startswith("samesite"):
                    samesite = p.split("=")[1].split(" ")[0]
            flags = []
            if not secure:
                scanner.add("cookies", f"Cookie '{name}' missing Secure", "HIGH", "FAIL",
                             "sent over plaintext HTTP", "add Secure attribute")
            if not httponly:
                scanner.add("cookies", f"Cookie '{name}' missing HttpOnly", "MEDIUM", "FAIL",
                             "readable by JavaScript -> XSS risk", "add HttpOnly attribute")
            if not samesite:
                scanner.add("cookies", f"Cookie '{name}' missing SameSite", "MEDIUM", "FAIL",
                             "CSRF risk", "set SameSite=Lax or Strict")
            elif samesite.lower() not in ("lax", "strict"):
                scanner.add("cookies", f"Cookie '{name}' SameSite=None", "LOW", "WARN",
                             "cross-site usage allowed", "use SameSite=Lax unless cross-site needed")


class MethodAnalyzer:
    @staticmethod
    def analyze(scanner, http, base, active):
        r = http.request(base, "OPTIONS")
        allowed = []
        if r["status"] is not None:
            allow = (r["headers"].get("Allow") if hasattr(r["headers"], "get") else None)
            if allow:
                allowed = [m.strip().upper() for m in allow.split(",") if m.strip()]
                scanner.add("methods", "OPTIONS / Allow", "INFO", "INFO",
                             "Allow: " + ", ".join(allowed), "restrict to required methods")
        if not allowed:
            scanner.add("methods", "OPTIONS", "INFO", "INFO",
                         "server returned no Allow header", "review exposed methods")
        if "TRACE" in allowed or r["status"] == 200 and self._trace_ok(http, base):
            scanner.add("methods", "TRACE enabled", "HIGH", "FAIL",
                         "cross-site tracing (XST) risk", "disable TRACE on the server")
        else:
            scanner.add("methods", "TRACE disabled", "INFO", "PASS", "TRACE not allowed", "")
        if active:
            MethodAnalyzer._write_tests(scanner, http, base, allowed)

    @staticmethod
    def _trace_ok(http, base):
        r = http.request(base, "TRACE")
        return r["status"] == 200 and b"TRACE" in r["body"]

    @staticmethod
    def _write_tests(scanner, http, base, allowed):
        probe = f"/{TOOL.lower()}-probe-{int(time.time())}.txt"
        for method in ("PUT", "DELETE", "PATCH"):
            if method not in allowed:
                scanner.add("methods", f"{method} not advertised", "INFO", "PASS", "", "")
                continue
            r = http.request(base + probe, method, body=b"probe")
            if r["status"] is not None and 200 <= r["status"] < 300:
                scanner.add("methods", f"Unauthenticated {method} allowed", "HIGH", "FAIL",
                             f"{method} {probe} -> {r['status']}",
                             "require authentication/authorization on write methods")
            else:
                scanner.add("methods", f"{method} restricted", "INFO", "PASS",
                             f"status {r['status']}", "")


class PathProbe:
    @staticmethod
    def run(scanner, http, base):
        for path, title, sev, desc, marker in SENSITIVE_PATHS:
            url = base.rstrip("/") + path
            r = http.get(url)
            code = r["status"]
            body = r["body"].decode("latin1", "replace")[:4000] if r["body"] else ""
            if code is None and r["error"]:
                continue
            if sev == "INFO":
                scanner.add("paths", title, "INFO", "INFO", f"{path} -> HTTP {code}", "")
                continue
            if code in (404, 410):
                scanner.add("paths", title, "INFO", "PASS", f"{path} -> HTTP {code}", "")
                continue
            if code in (401, 403):
                scanner.add("paths", title, sev, "WARN",
                            f"{path} -> HTTP {code} (restricted)", "keep blocked; confirm access control")
                continue
            if code == 200:
                if marker and marker.lower() in body.lower():
                    scanner.add("paths", title, sev, "FAIL",
                                f"{path} -> HTTP 200 (content matches {marker!r})",
                                "remove/block and require authentication")
                else:
                    scanner.add("paths", title, sev, "WARN",
                                f"{path} -> HTTP 200", "confirm whether this is intentional")
                continue
            if code is not None and 300 <= code < 400:
                scanner.add("paths", title, sev, "WARN", f"{path} -> HTTP {code} (redirect)", "")
                continue
            scanner.add("paths", title, sev, "PASS", f"{path} -> HTTP {code}", "")


class CORSChecker:
    @staticmethod
    def run(scanner, http, base):
        evil = "https://evil.example"
        r = http.request(base, headers={"Origin": evil})
        h = r.get("headers") or {}
        acao = h.get("Access-Control-Allow-Origin") if hasattr(h, "get") else None
        acc = (h.get("Access-Control-Allow-Credentials") or "").lower() if hasattr(h, "get") else ""
        if not acao:
            scanner.add("cors", "CORS policy", "INFO", "PASS",
                         "no Access-Control-Allow-Origin", "")
            return
        if acao == evil:
            if acc == "true":
                scanner.add("cors", "CORS reflects arbitrary origin + credentials", "HIGH", "FAIL",
                             f"ACAO echoes '{evil}' with credentials",
                             "whitelist origins, never reflect untrusted origins with credentials")
            else:
                scanner.add("cors", "CORS reflects arbitrary origin", "MEDIUM", "FAIL",
                             f"ACAO echoes '{evil}'",
                             "whitelist trusted origins")
        elif acao == "*":
            if acc == "true":
                scanner.add("cors", "CORS wildcard + credentials", "HIGH", "FAIL",
                             "ACAO * with Access-Control-Allow-Credentials: true",
                             "remove credentials or use explicit origin")
            else:
                scanner.add("cors", "CORS wildcard", "LOW", "WARN",
                             "ACAO: * allows any origin to read",
                             "restrict to trusted origins if data is sensitive")
        else:
            scanner.add("cors", "CORS policy", "INFO", "PASS",
                         f"ACAO restricted: {acao}", "")


class ReflectionChecker:
    @staticmethod
    def run(scanner, http, base, active):
        if not active:
            return
        payload = "zqx'\"<script>pyscan()</script>"
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}q={urllib.parse.quote(payload)}"
        r = http.get(url)
        if r["status"] is not None and payload in r["body"].decode("latin1", "replace"):
            scanner.add("app", "Reflected input (potential XSS)", "MEDIUM", "WARN",
                         "request value reflected unencoded in response",
                         "encode output; validate input; add CSP with nonces")
        else:
            scanner.add("app", "Reflection test", "INFO", "PASS", "no reflection of probe", "")


class OpenRedirectChecker:
    @staticmethod
    def run(scanner, http, base, active):
        if not active:
            return
        for param in OPEN_REDIRECT_PARAMS:
            sep = "&" if "?" in base else "?"
            url = f"{base}{sep}{param}=http%3A%2F%2Fevil.example"
            r = http.request(url, "GET")
            loc = r["headers"].get("Location") if r.get("headers") and hasattr(r["headers"], "get") else None
            if loc and "evil.example" in loc:
                scanner.add("app", f"Open redirect via '{param}'", "HIGH", "FAIL",
                             f"{param} -> Location: {loc}",
                             "validate/whitelist redirect destinations")


class RedirectToHttps:
    @staticmethod
    def run(scanner, http, base, scheme, hostport):
        if scheme == "https":
            return
        r = http.request(base, "HEAD", follow=False)
        if r["status"] is None:
            return
        loc = r["headers"].get("Location") if hasattr(r["headers"], "get") else None
        if loc and loc.lower().startswith("https://"):
            scanner.add("redirect", "HTTP -> HTTPS redirect", "INFO", "PASS",
                         f"Location: {loc[:60]}", "")
        else:
            scanner.add("redirect", "No HTTPS redirect", "HIGH", "FAIL",
                         "HTTP does not redirect to HTTPS",
                         "redirect all HTTP traffic to HTTPS and enable HSTS")


# ---------------------------------------------------------------- engine

class Scanner:
    def __init__(self, http, color, active=False, verbose=0):
        self.http = http
        self.color = color
        self.active = active
        self.verbose = verbose
        self.findings = []
        self.server_banner = None

    def add(self, category, title, severity, status, detail, remediation):
        self.findings.append(Finding(category, title, severity, status, detail, remediation))

    def scan(self, url):
        p = parse_url(url)
        scheme = p.scheme.lower()
        host = p.hostname
        port = p.port or (443 if scheme == "https" else 80)
        base = f"{scheme}://{p.netloc}"

        # baseline response (do not follow redirects: a 3xx means reachable)
        root = self.http.get(base, follow=False)
        if root["status"] is None:
            print(self.color.red(f"[ERROR] cannot reach {base}: {root['error']}"))
            return {"ok": False, "url": base, "error": root["error"]}
        self.add("info", "Reachability", "INFO", "PASS",
                 f"GET {base} -> HTTP {root['status']}", "")
        server = root["headers"].get("Server") if hasattr(root["headers"], "get") else None
        self.server_banner = server
        if server:
            self.add("info", "Server banner", "INFO", "INFO", f"Server: {server[:120]}",
                     "mask server version detail")

        is_https = scheme == "https"
        RedirectToHttps.run(self, self.http, base, scheme, f"{host}:{port}")
        if is_https:
            self.tls_checks(host, port)
        if root["status"] < 300:
            HeadersAnalyzer.analyze(self, root, is_https)
            CookieAnalyzer.analyze(self, root)
        else:
            loc = root["headers"].get("Location") if hasattr(root["headers"], "get") else None
            self.add("info", "Root redirects", "INFO", "INFO",
                     f"HTTP {root['status']}" + (f" -> {loc[:80]}" if loc else ""),
                     "scan the final URL for full header analysis")
        MethodAnalyzer.analyze(self, self.http, base, self.active)
        PathProbe.run(self, self.http, base)
        CORSChecker.run(self, self.http, base)
        ReflectionChecker.run(self, self.http, base, self.active)
        OpenRedirectChecker.run(self, self.http, base, self.active)
        return {"ok": True, "url": base}

    def tls_checks(self, host, port):
        self.add("tls", "TLS analysis", "INFO", "INFO", f"checking {host}:{port}", "")
        tls = TLSChecker(host, port).run()
        self.tls = tls
        weak = [v for v in tls.versions if v in ("TLSv1.0", "TLSv1.1")]
        if weak:
            self.add("tls", "Weak TLS protocols enabled", "HIGH", "FAIL",
                     "supported: " + ", ".join(weak),
                     "disable TLSv1.0/1.1; enable TLSv1.2/1.3 only")
        if tls.versions:
            self.add("tls", "Supported TLS versions", "INFO", "PASS",
                     ", ".join(sorted(tls.versions)), "")
        if not tls.versions:
            self.add("tls", "No TLS handshake", "CRITICAL", "FAIL",
                     "server did not complete TLS handshake", "fix TLS configuration")
        if tls.weak_ciphers:
            self.add("tls", "Weak cipher suites supported", "MEDIUM", "WARN",
                     "accepts: " + ", ".join(tls.weak_ciphers),
                     "disable CBC-SHA / legacy ciphers, use TLS1.3 AEAD")
        else:
            self.add("tls", "Weak ciphers", "INFO", "PASS", "none negotiated", "")
        if tls.alpn:
            self.add("tls", "HTTP/2 (ALPN)", "INFO", "PASS", f"negotiated {tls.alpn}", "")
        c = tls.cert
        if c:
            self.add("tls", "Certificate", "INFO", "INFO",
                     f"CN: {c.get('subject')}; expires {c.get('not_after')} "
                     f"({c.get('days_remaining')}d); key {c.get('public_key')}",
                     "auto-renew before expiry")
            dr = c.get("days_remaining")
            if dr is not None and dr < 0:
                self.add("tls", "Certificate EXPIRED", "CRITICAL", "FAIL",
                         f"expired {abs(dr)} days ago", "renew immediately")
            elif dr is not None and dr < 30:
                self.add("tls", "Certificate expires soon", "MEDIUM", "WARN",
                         f"{dr} days left", "renew within {dr} days".replace("{dr}", str(dr)))
        if tls.chain_ok is False:
            self.add("tls", "Untrusted certificate chain", "HIGH", "FAIL",
                     tls.chain_reason or "verification failed",
                     "use cert from a trusted public CA or install the private CA")
        elif tls.chain_ok:
            self.add("tls", "Certificate chain trusted", "INFO", "PASS",
                     "validated against system trust store", "")

    def score(self):
        score = 100
        for f in self.findings:
            if f.status == "FAIL":
                score -= SEVERITY_WEIGHT.get(f.severity, 0)
            elif f.status == "WARN":
                score -= SEVERITY_WEIGHT.get(f.severity, 0) // 2
        return max(0, min(100, score))


# ---------------------------------------------------------------- output

class Report:
    def __init__(self, scanner, color, url, active, verbose):
        self.scanner = scanner
        self.color = color
        self.url = url
        self.active = active
        self.verbose = verbose

    def text(self):
        s = self.scanner
        c = self.color
        score = s.score()
        L = [c.bold(f"{TOOL} {VERSION} - HTTP Security Scan Report ({TEAM})"),
             f"Target: {self.url}",
             f"Started: {now_iso()}",
             f"Mode: {'active' if self.active else 'passive'}",
             f"Server: {s.server_banner or 'n/a'}"]
        if getattr(s, "tls", None):
            L.append(f"TLS: {', '.join(sorted(s.tls.versions)) or 'n/a'}  ALPN: {s.tls.alpn or 'n/a'}")
        L.append("")
        L.append(c.bold(f"Score: {score}/100 ({grade_for(score)})") +
                 "  " + self._score_bar(score))
        L.append("")
        L.append(c.bold(f"{'='*60}"))
        by_cat = {}
        for f in s.findings:
            by_cat.setdefault(f.category, []).append(f)
        for cat in ["info", "tls", "headers", "cookies", "methods", "paths", "cors", "redirect", "app"]:
            if cat not in by_cat:
                continue
            L.append("")
            L.append(c.bold(f"[ {cat.upper()} ]"))
            for f in by_cat[cat]:
                if f.status == "PASS" and self.verbose < 1:
                    continue
                tag = {"PASS": c.green("PASS"), "FAIL": c.red("FAIL"), "WARN": c.yellow("WARN"),
                       "INFO": c.dim("INFO")}[f.status]
                L.append(f"  {tag} {c.severity(f.severity):<8} {f.title}")
                if self.verbose >= 1 and f.detail:
                    L.append(f"        {c.dim(f.detail)}")
                if f.status == "FAIL" and f.remediation:
                    L.append(f"        fix: {c.cyan(f.remediation)}")
        counts = self._counts()
        L.append("")
        L.append(c.bold(f"Findings: {counts['FAIL']} FAIL / {counts['WARN']} WARN / "
                        f"{counts['PASS']} PASS / {counts['INFO']} INFO"))
        return "\n".join(L)

    def _counts(self):
        c = {"FAIL": 0, "WARN": 0, "PASS": 0, "INFO": 0}
        for f in self.scanner.findings:
            c[f.status] = c.get(f.status, 0) + 1
        return c

    @staticmethod
    def _score_bar(score):
        filled = int(score / 10)
        return "[" + "#" * filled + "-" * (10 - filled) + "]"

    def to_dict(self):
        s = self.scanner
        tls = getattr(s, "tls", None)
        return {
            "tool": TOOL, "version": VERSION, "team": TEAM,
            "url": self.url, "started_at": now_iso(), "active": self.active,
            "score": s.score(), "grade": grade_for(s.score()),
            "server": s.server_banner,
            "tls": {
                "versions": sorted(tls.versions) if tls else None,
                "alpn": tls.alpn if tls else None,
                "weak_ciphers": tls.weak_ciphers if tls else None,
                "cert": tls.cert if tls else None,
                "chain_trusted": tls.chain_ok if tls else None,
            } if tls else None,
            "findings": [f.to_dict() for f in s.findings],
            "summary": self._counts(),
        }

    def html(self):
        d = self.to_dict()
        rows = []
        for f in d["findings"]:
            if f["status"] == "PASS":
                continue
            badge = f'<span class="b {f["severity"].lower()}">{f["status"]}</span>'
            rows.append(f"<tr><td>{badge}</td><td>{f['severity']}</td><td>{html.escape(f['title'])}</td>"
                        f"<td>{html.escape(f['detail'] or '')}</td><td>{html.escape(f['remediation'] or '')}</td></tr>")
        tls_rows = ""
        if d.get("tls"):
            t = d["tls"]
            cert = t.get("cert") or {}
            tls_rows = f"""
            <tr><td>Versions</td><td>{html.escape(', '.join(t['versions']) if t['versions'] else 'n/a')}</td></tr>
            <tr><td>ALPN / HTTP2</td><td>{html.escape(t['alpn'] or 'n/a')}</td></tr>
            <tr><td>Weak ciphers</td><td>{html.escape(', '.join(t['weak_ciphers']) if t['weak_ciphers'] else 'none')}</td></tr>
            <tr><td>Chain trusted</td><td>{t['chain_trusted'] if t['chain_trusted'] is not None else 'n/a'}</td></tr>
            <tr><td>Cert CN</td><td>{html.escape(cert.get('subject',''))}</td></tr>
            <tr><td>Expires</td><td>{html.escape(str(cert.get('not_after','')))} ({cert.get('days_remaining')}d)</td></tr>
            <tr><td>Public key</td><td>{html.escape(cert.get('public_key',''))}</td></tr>"""
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{html.escape(TOOL)} report - {html.escape(self.url)}</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fafafa}}
 h1{{font-size:20px}} .score{{font-size:28px;font-weight:700}}
 table{{border-collapse:collapse;width:100%;margin:12px 0;background:#fff}}
 td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:13px;vertical-align:top}}
 th{{background:#f0f0f0}}
 .b{{font-weight:700;padding:2px 6px;border-radius:3px;color:#fff}}
 .fail{{background:#d9534f}} .warn{{background:#f0ad4e}} .info{{background:#888}}
 .high{{color:#c0392b}} .medium{{color:#e67e22}} .low{{color:#2980b9}} .info{{color:#888}}
</style></head><body>
<h1>{html.escape(TOOL)} {VERSION} &mdash; HTTP Security Scan Report</h1>
<p>Team: {html.escape(TEAM)} &nbsp;|&nbsp; Target: <b>{html.escape(self.url)}</b>
 &nbsp;|&nbsp; Mode: {('active' if self.active else 'passive')}
 &nbsp;|&nbsp; Started: {html.escape(d['started_at'])}</p>
<p class="score">Score: {d['score']}/100 ({d['grade']})</p>
<p>Summary: {d['summary']['FAIL']} FAIL / {d['summary']['WARN']} WARN / {d['summary']['INFO']} INFO</p>
<h2>TLS / HTTPS</h2><table><tbody>{tls_rows}</tbody></table>
<h2>Findings</h2>
<table><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p style="color:#888;font-size:11px">Generated by {html.escape(TOOL)} {VERSION} on {html.escape(now_iso())}</p>
</body></html>"""


# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="httpsec",
        description=f"{TOOL} {VERSION} - HTTP security scanner ({TEAM}). "
                    "Passive-first TLS/headers/cookies/methods/paths/CORS checks.",
        epilog="Examples:\n"
               "  httpsec.py https://example.com\n"
               "  httpsec.py -u http://10.0.0.5 --active -oJ out.json -oH out.html\n"
               "  httpsec.py https://example.com -H 'Authorization: Bearer xyz' -v")
    p.add_argument("url", nargs="?", help="target URL (scheme default http)")
    p.add_argument("-u", "--url", dest="url2", help="target URL (alternative)")
    p.add_argument("-T", "--timeout", type=float, default=10.0, metavar="SEC", help="request timeout (default 10)")
    p.add_argument("-H", dest="headers", action="append", metavar="HEADER", help="extra header, e.g. -H 'Cookie: a=1'")
    p.add_argument("-A", "--user-agent", metavar="UA", help="custom User-Agent")
    p.add_argument("--active", action="store_true", help="enable active tests (PUT/DELETE, reflection, open redirect)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (still reported)")
    p.add_argument("--list-checks", action="store_true", help="list all checks and exit")
    p.add_argument("-oJ", dest="out_json", metavar="FILE", help="JSON report output")
    p.add_argument("-oH", dest="out_html", metavar="FILE", help="HTML report output")
    p.add_argument("-oT", dest="out_text", metavar="FILE", help="text report output")
    p.add_argument("-v", "--verbose", action="count", default=0, help="verbose detail (-v shows PASS/detail)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return p


def list_checks():
    print(f"{TOOL} {VERSION} check list:\n")
    print("TLS      - protocol versions, weak ciphers, cert expiry, chain trust, HTTP/2")
    print("Headers  - HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy,")
    print("           COOP/CORP/COEP, X-XSS-Protection, info disclosure (Server/X-Powered-By)")
    print("Cookies  - Secure, HttpOnly, SameSite attributes")
    print("Methods  - OPTIONS/Allow, TRACE (XST); [active] PUT/DELETE/PATCH write tests")
    print("Paths    - .git/.env/backups/admin/phpinfo/robots.txt etc. (%d paths)" % len(SENSITIVE_PATHS))
    print("CORS     - origin reflection, wildcard + credentials")
    print("Redirect - HTTP->HTTPS enforcement")
    print("App      - [active] reflected-input (XSS) probe, open redirect params")


def main():
    enable_ansi_windows()
    args = build_parser().parse_args()
    if args.list_checks:
        list_checks()
        return 0
    url = args.url or args.url2
    if not url:
        print("httpsec: target URL required (positional or -u)", file=sys.stderr)
        return 2
    color = Color(enabled=not args.no_color and sys.stdout.isatty())
    headers = list(args.headers or [])
    if args.user_agent:
        headers.append(f"User-Agent: {args.user_agent}")
    http = HTTP(timeout=args.timeout, headers=headers, verify=not args.insecure)
    scanner = Scanner(http, color, active=args.active, verbose=args.verbose)
    result = scanner.scan(url)
    if not result["ok"]:
        return 1
    report = Report(scanner, color, url, args.active, args.verbose)
    text = report.text()
    print(color.bold(text))
    if args.out_text:
        with open(args.out_text, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    if args.out_html:
        with open(args.out_html, "w", encoding="utf-8") as f:
            f.write(report.html())
    return 0


if __name__ == "__main__":
    sys.exit(main())
