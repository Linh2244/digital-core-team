#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JWTCheck - JWT Inspector (Digital Core team).

Giai ma va kiem tra bao mat JWT (JSON Web Token): header alg none,
algorithm confusion, HMAC secret yeu, jku/x5u ben ngoai, kid injection,
exp/nbf/iat, chu ky (HMAC hoac RSA/ECDSA/EdDSA), brute-force HMAC bang
wordlist. Xuat bao cao text/JSON/Markdown.

Exit codes:
  0  khong co loi hong bao mat (chi PASS/INFO/WARN)
  1  co loi hong bao mat (FAIL)
  2  input sai (JWT khong hop le, file loi)
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

TOOL = "JWTCheck"
VERSION = "1.0.0"
TEAM = "Digital Core team"

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_PENALTY = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
             "LOW": "cyan", "INFO": "cyan"}

KNOWN_ALGS = {"none", "HS256", "HS384", "HS512",
              "RS256", "RS384", "RS512",
              "PS256", "PS384", "PS512",
              "ES256", "ES384", "ES512", "EdDSA"}
HMAC_ALGS = {"HS256", "HS384", "HS512"}
ASYMM_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
              "ES256", "ES384", "ES512", "EdDSA"}

WEAK_SECRETS = [
    "secret", "password", "changeme", "123456", "12345678", "qwerty",
    "admin", "test", "demo", "token", "key", "private", "public",
    "passw0rd", "letmein", "iloveyou", "superman", "dragon", "monkey",
    "abc123", "jwt_secret", "your-256-bit-secret", "default", "root",
    "toor", "1qaz2wsx", "p@ssw0rd", "secret123", "jsonwebtoken",
]

MAX_LIFETIME_DAYS = 365
CLOCK_SKEW = 60


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


def _now():
    return time.time()


def b64u_decode(s):
    s = s.strip()
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def check_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"khoa trung lap trong JSON: {k!r}")
        d[k] = v
    return d


def parse_json(s, what):
    try:
        return json.loads(s, object_pairs_hook=check_dupes)
    except ValueError as e:
        raise ValueError(f"{what} khong phai JSON hop le: {e}")


def decode_jwt(token):
    parts = token.strip().split(".")
    if len(parts) == 5:
        return {"jwe": True}
    if len(parts) != 3:
        raise ValueError(
            "JWT phai co 3 phan (header.payload.signature), co "
            f"{len(parts)} phan")
    try:
        header_raw = b64u_decode(parts[0])
        payload_raw = b64u_decode(parts[1])
    except Exception as e:
        raise ValueError(f"base64url khong hop le: {e}")
    header = parse_json(header_raw, "header")
    payload = parse_json(payload_raw, "payload")
    return {"header": header, "payload": payload, "parts": parts}


def _ip_is_private(host):
    try:
        info = socket.getaddrinfo(host, None)
        for fam, _, _, _, addr in info:
            ip = addr[0]
            if ip.startswith(("127.", "10.", "192.168.", "169.254.",
                              "0.")) or ip == "::1" or ip.startswith("fc"):
                return True
        return False
    except socket.gaierror:
        return False


def hmac_sign(signing_input, alg, secret):
    h = getattr(hashlib, "sha" + alg[2:].lower())
    return hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"),
                    h).digest()


def verify_public_key(header, signing_input, sig, pubkey_pem):
    """Verify RS/PS/ES/EdDSA. Tra ve True/False, hoac None neu thieu lib."""
    alg = header.get("alg", "")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, \
            padding, rsa
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    try:
        key = serialization.load_pem_public_key(pubkey_pem)
    except Exception:
        return None
    try:
        if alg.startswith("RS"):
            key.verify(sig, signing_input.encode("utf-8"),
                       padding.PKCS1v15(),
                       hashes.SHA256() if alg.endswith("256")
                       else hashes.SHA384() if alg.endswith("384")
                       else hashes.SHA512())
        elif alg.startswith("PS"):
            key.verify(sig, signing_input.encode("utf-8"),
                       padding.PSS(mgf=padding.MGF1(
                           hashes.SHA256() if alg.endswith("256")
                           else hashes.SHA384() if alg.endswith("384")
                           else hashes.SHA512()),
                           salt_length=padding.PSS.DIGEST_LENGTH),
                       hashes.SHA256() if alg.endswith("256")
                       else hashes.SHA384() if alg.endswith("384")
                       else hashes.SHA512())
        elif alg.startswith("ES"):
            nbits = {"ES256": 32, "ES384": 48, "ES512": 66}[alg]
            if len(sig) == 2 * nbits:
                from cryptography.hazmat.primitives.asymmetric.utils import \
                    decode_dss_signature
                r_, s_ = decode_dss_signature(sig)
            else:
                raise InvalidSignature
            key.verify(sig, signing_input.encode("utf-8"),
                       ec.ECDSA(hashes.SHA256() if alg.endswith("256")
                                else hashes.SHA384() if alg.endswith("384")
                                else hashes.SHA512()))
        elif alg == "EdDSA":
            key.verify(sig, signing_input.encode("utf-8"))
        else:
            return None
        return True
    except (InvalidSignature, Exception):
        return False


# --------------------------------------------------------------------------
# Kiem tra
# --------------------------------------------------------------------------
def inspect_token(token, args, color=None):
    res = {"token": token[:40] + ("..." if len(token) > 40 else ""),
           "ok": True, "findings": [], "score": 100,
           "header": None, "payload": None, "jwe": False}

    F = res["findings"]

    def add(group, status, sev, detail):
        F.append({"group": group, "status": status, "severity": sev,
                  "detail": detail})

    try:
        dec = decode_jwt(token)
    except ValueError as e:
        return {"token": res["token"], "ok": False, "error": str(e),
                "findings": [], "score": 0}

    if dec.get("jwe"):
        res["jwe"] = True
        add("FORMAT", "INFO", "INFO",
            "Token dang JWE (5 phan, ma hoa) - khong phan tich duoc noi dung")
        res["score"] = 100
        return res

    header = dec["header"]
    payload = dec["payload"]
    parts = dec["parts"]
    res["header"] = header
    res["payload"] = payload
    signing_input = f"{parts[0]}.{parts[1]}"
    sig = parts[2]

    # -------- HEADER --------
    alg = str(header.get("alg", "")).strip()
    if not alg or alg.lower() == "none":
        add("HEADER", "FAIL", "CRITICAL",
            "alg la 'none' - chu ky bi bo qua, token co the gia mao tuy y")
    elif alg == "None":
        add("HEADER", "FAIL", "CRITICAL",
            "alg 'None' - chu ky bi bo qua (case-sensitivity bypass)")
    elif alg not in KNOWN_ALGS:
        add("HEADER", "WARN", "MEDIUM",
            f"thuat toan khong quen thuoc: {alg!r}")
    else:
        if alg in HMAC_ALGS:
            add("HEADER", "INFO", "INFO",
                f"alg {alg} (HMAC) - chu ky doi xung")
            if header.get("jwk") or header.get("x5c") or header.get("jku") \
                    or header.get("x5u"):
                add("HEADER", "FAIL", "CRITICAL",
                    f"alg {alg} nhung co key bat doi xung (jwk/x5c/jku/x5u) - "
                    "nguy co algorithm confusion")
        elif alg in ASYMM_ALGS:
            add("HEADER", "INFO", "INFO",
                f"alg {alg} - chu ky bat doi xung")

    if "typ" in header and header["typ"] not in ("JWT", "jwt"):
        add("HEADER", "WARN", "LOW",
            f"typ khong phai JWT: {header['typ']!r}")

    if "crit" in header:
        add("HEADER", "FAIL", "HIGH",
            f"header 'crit' cho phep header khong khai bao duoc dung: "
            f"{header['crit']}")

    kid = header.get("kid")
    if kid:
        if re.search(r"(\.\.|[/\\\\%])", str(kid)):
            add("HEADER", "FAIL", "HIGH",
                f"kid co ky tu nguy hiem (path traversal / key injection): "
                f"{kid!r}")
        elif len(str(kid)) > 64:
            add("HEADER", "WARN", "LOW", f"kid dai bat thuong: {kid!r}")
    else:
        add("HEADER", "INFO", "INFO", "khong co header 'kid'")

    for k in ("jku", "x5u"):
        if k in header:
            u = str(header[k])
            try:
                p = urlparse(u)
            except Exception:
                p = None
            if not p or p.scheme not in ("https", "http"):
                add("HEADER", "WARN", "MEDIUM",
                    f"{k} khong phai URL hop le: {u!r}")
            elif p.scheme != "https":
                add("HEADER", "FAIL", "CRITICAL",
                    f"{k} dung http (plaintext) - co the bi thay doi: {u}")
            elif p.hostname in ("localhost", "127.0.0.1", "::1") \
                    or _ip_is_private(p.hostname or ""):
                add("HEADER", "FAIL", "HIGH",
                    f"{k} tro toi host noi bo/private: {u}")
            else:
                add("HEADER", "WARN", "MEDIUM",
                    f"{k} la URL ben ngoai - chi nen tin tuong whitelist: {u}")

    # -------- PAYLOAD --------
    now = _now()
    exp = payload.get("exp")
    if exp is None:
        add("PAYLOAD", "WARN", "MEDIUM", "thieu claim 'exp' - token khong "
            "het han")
    else:
        try:
            exp_f = float(exp)
        except (TypeError, ValueError):
            add("PAYLOAD", "WARN", "LOW", f"'exp' khong phai so: {exp!r}")
            exp_f = None
        if exp_f is not None:
            if now - CLOCK_SKEW > exp_f:
                add("PAYLOAD", "FAIL", "HIGH",
                    f"token HET HAN (exp={datetime.fromtimestamp(exp_f, timezone.utc).isoformat()})")
            elif exp_f - now > MAX_LIFETIME_DAYS * 86400:
                add("PAYLOAD", "WARN", "LOW",
                    "exp rat xa trong tuong lai (> 1 nam)")

    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf_f = float(nbf)
            if now + CLOCK_SKEW < nbf_f:
                add("PAYLOAD", "FAIL", "MEDIUM",
                    f"token CHUA HIEU LUC (nbf trong tuong lai: {datetime.fromtimestamp(nbf_f, timezone.utc).isoformat()})")
        except (TypeError, ValueError):
            add("PAYLOAD", "WARN", "LOW", f"'nbf' khong phai so: {nbf!r}")

    iat = payload.get("iat")
    if iat is not None:
        try:
            iat_f = float(iat)
            if iat_f > now + CLOCK_SKEW:
                add("PAYLOAD", "WARN", "MEDIUM", "'iat' o trong tuong lai")
        except (TypeError, ValueError):
            add("PAYLOAD", "WARN", "LOW", f"'iat' khong phai so: {iat!r}")

    if exp is not None and iat is not None:
        try:
            life = float(exp) - float(iat)
            if life > MAX_LIFETIME_DAYS * 86400:
                add("PAYLOAD", "WARN", "MEDIUM",
                    f"thoi gian song token qua dai (~{int(life//86400)} "
                    "ngay)")
        except (TypeError, ValueError):
            pass

    for claim in ("iss", "aud", "sub"):
        if claim not in payload:
            add("PAYLOAD", "INFO", "INFO",
                f"thieu claim '{claim}' (co the khong quan trong neu "
                "unused)")

    # -------- SIGNATURE --------
    if alg == "None" or alg.lower() == "none":
        add("SIGNATURE", "FAIL", "CRITICAL",
            "khong the tin cay - header alg none cho phep khong can chu ky")
    elif alg in HMAC_ALGS:
        secret_found = None
        if args.secret:
            try:
                ok = hmac.compare_digest(
                    hmac_sign(signing_input, alg, args.secret),
                    b64u_decode(sig))
            except Exception:
                ok = False
            if ok:
                add("SIGNATURE", "PASS", "INFO",
                    f"chu ky HMAC hop le voi --secret")
            else:
                add("SIGNATURE", "FAIL", "HIGH",
                    "chu ky HMAC KHONG hop le voi --secret")
        if secret_found is None and not args.no_brute:
            secret_found = brute_hmac(signing_input, alg, sig,
                                      WEAK_SECRETS)
            if secret_found:
                add("SIGNATURE", "FAIL", "CRITICAL",
                    f"tim thay HMAC secret YEU: {secret_found!r} - co the "
                    "tu ky token")
        if args.wordlist:
            found = brute_hmac(signing_input, alg, sig,
                               load_wordlist(args.wordlist))
            if found:
                add("SIGNATURE", "FAIL", "CRITICAL",
                    f"brute-force tim thay secret: {found!r} (wordlist)")
                secret_found = found
        if not secret_found and not args.secret and not args.wordlist \
                and args.no_brute:
            add("SIGNATURE", "INFO", "INFO",
                "chua verify HMAC - dung --secret hoac --wordlist")
    elif alg in ASYMM_ALGS:
        if args.pubkey:
            try:
                pem = open(args.pubkey, "rb").read()
            except OSError as e:
                add("SIGNATURE", "WARN", "MEDIUM",
                    f"khong doc duoc --pubkey: {e}")
                pem = None
            if pem:
                try:
                    ok = verify_public_key(header, signing_input,
                                           b64u_decode(sig), pem)
                except Exception:
                    ok = False
                if ok is None:
                    add("SIGNATURE", "INFO", "INFO",
                        "can thu vien 'cryptography' de verify RSA/ECDSA/EdDSA")
                elif ok:
                    add("SIGNATURE", "PASS", "INFO",
                        "chu ky hop le voi --pubkey")
                else:
                    add("SIGNATURE", "FAIL", "HIGH",
                        "chu ky KHONG hop le voi --pubkey")
        else:
            add("SIGNATURE", "INFO", "INFO",
                "chua verify - cung cap --pubkey de xac thuc chu ky")

    # score
    score = 100 - sum(SEV_PENALTY.get(f["severity"], 0)
                      for f in F if f["status"] == "FAIL")
    res["score"] = max(0, min(100, score))
    res["ok"] = not any(f["status"] == "FAIL" for f in F)
    return res


def brute_hmac(signing_input, alg, sig, secrets):
    try:
        target = b64u_decode(sig)
    except Exception:
        return None
    for s in secrets:
        s = str(s).strip()
        if not s:
            continue
        try:
            if hmac.compare_digest(hmac_sign(signing_input, alg, s),
                                   target):
                return s
        except Exception:
            continue
    return None


def load_wordlist(path):
    words = []
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            words = [l.strip() for l in f if l.strip()]
    except OSError as e:
        print(f"{TOOL}: khong doc duoc wordlist {path}: {e}",
              file=sys.stderr)
    return words


# --------------------------------------------------------------------------
# Render
# --------------------------------------------------------------------------
def fmt_ts(v):
    try:
        return datetime.fromtimestamp(float(v), timezone.utc).isoformat()
    except (TypeError, ValueError):
        return str(v)


def render_text(results, color):
    lines = [f";; {TOOL} {VERSION} <<>> {TEAM}"]
    all_ok = True
    min_score = 100
    n_fail = 0
    for r in results:
        min_score = min(min_score, r["score"])
        lines.append("")
        if not r.get("ok") and r.get("error"):
            lines.append(color.red(f"{r['token']}  X  {r['error']}"))
            continue
        lines.append(color.bold(r["token"]))
        if r.get("jwe"):
            for f in r["findings"]:
                sc = getattr(color, status_color(f["status"]))
                lines.append(f"  {sc(f['status']):<5} "
                             f"{f['severity']:<8} {f['detail']}")
            continue
        h = r.get("header") or {}
        p = r.get("payload") or {}
        alg = h.get("alg", "?")
        exp = p.get("exp")
        exp_s = fmt_ts(exp) if exp is not None else "khong co"
        lines.append(f"  alg: {color.bold(alg)}   exp: {exp_s}   "
                     f"iss: {p.get('iss', '-')}")
        if r["findings"]:
            for f in r["findings"]:
                sc = getattr(color, status_color(f["status"]))
                lines.append(f"  {sc(f['status']):<5} "
                             f"{f['severity']:<8} {f['detail']}")
        else:
            lines.append(f"  {color.green('PASS')}  INFO     khong co van "
                         "de bao mat")
    grade = grade_for(min_score)
    gcolor = {"A": color.green, "B": color.cyan, "C": color.yellow,
              "D": color.yellow, "F": color.red}.get(grade, color.bold)
    lines.append("")
    lines.append(f"  {color.bold('VERDICT')}: Score {min_score}/100 "
                 f"({gcolor(grade)}) | {len(results)} token, "
                 f"{sum(1 for r in results if not r.get('ok'))} co loi")
    return "\n".join(lines)


def render_md(results, queried_at):
    L = [f"# {TOOL} Report", "",
         f"- Tool: {TOOL} {VERSION}",
         f"- Team: {TEAM}",
         f"- Queried at: {queried_at}", ""]
    min_score = min((r["score"] for r in results), default=100)
    n_bad = sum(1 for r in results if not r.get("ok"))
    L += ["## Summary", "",
          "| Score | Grade | Tokens | Issues |",
          "|---|---|---|---|",
          f"| {min_score} | {grade_for(min_score)} | {len(results)} | "
          f"{n_bad} |", ""]
    for i, r in enumerate(results, 1):
        L += [f"## Token {i}", "", f"`{r['token']}`", ""]
        if r.get("error"):
            L += [f"**Loi:** {r['error']}", ""]
            continue
        h = r.get("header") or {}
        p = r.get("payload") or {}
        if r.get("jwe"):
            L += ["JWE (token ma hoa), khong phan tich duoc noi dung.", ""]
            continue
        L += ["### Header", ""]
        L += ["| Claim | Value |", "|---|---|"]
        for k in sorted(h):
            L += [f"| `{k}` | `{json.dumps(h[k], ensure_ascii=False)}` |"]
        L += ["", "### Payload", ""]
        L += ["| Claim | Value |", "|---|---|"]
        for k in sorted(p):
            v = p[k]
            if k in ("exp", "nbf", "iat"):
                v = fmt_ts(v)
            L += [f"| `{k}` | `{json.dumps(v, ensure_ascii=False)}` |"]
        L += ["", "### Findings", ""]
        if r["findings"]:
            L += ["| Status | Severity | Detail |", "|---|---|---|"]
            for f in r["findings"]:
                L += [f"| {f['status']} | {f['severity']} | {f['detail']} |"]
        else:
            L += ["Khong co van de bao mat.", ""]
        L.append("")
    return "\n".join(L)


def render_json(results, queried_at):
    return json.dumps({
        "tool": TOOL, "version": VERSION, "team": TEAM,
        "queried_at": queried_at, "tokens": results,
    }, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="jwtcheck",
        description=f"{TOOL} {VERSION} - JWT Inspector (Digital Core team). "
                    f"Giai ma, kiem tra bao mat va xac thuc chu ky JWT, xuat "
                    f"bao cao text/JSON/Markdown.")
    ap.add_argument("tokens", nargs="*",
                    help="JWT string hoac file chua JWT (nhieu token duoc)")
    ap.add_argument("--secret", metavar="STR",
                    help="secret de verify HMAC (HS256/384/512)")
    ap.add_argument("--pubkey", metavar="FILE",
                    help="PEM public key de verify RS*/PS*/ES*/EdDSA "
                         "(can thu vien cryptography)")
    ap.add_argument("--wordlist", metavar="FILE",
                    help="brute-force HMAC secret bang wordlist")
    ap.add_argument("--no-brute", action="store_true",
                    help="khong thu cac HMAC secret mac dinh")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--md", action="store_true",
                    help="output Markdown (dung chung voi -o de ghi .md)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("--no-color", action="store_true", help="tat mau ANSI")
    ap.add_argument("--version", action="version",
                    version=f"{TOOL} {VERSION}")
    args = ap.parse_args()

    color = Color(enabled=sys.stdout.isatty() and not args.no_color)
    queried_at = datetime.now().astimezone().isoformat()

    raw = []
    for t in args.tokens:
        if t == "-":
            raw.append(sys.stdin.read().strip())
        elif os.path.isfile(t):
            try:
                raw.append(open(t, encoding="utf-8").read().strip())
            except OSError as e:
                print(f"{TOOL}: khong doc duoc file {t}: {e}",
                      file=sys.stderr)
                return 2
        else:
            raw.append(t)
    if not raw:
        inp = sys.stdin.read().strip()
        if inp:
            raw = [inp]
    if not raw:
        print(f"{TOOL}: khong co JWT nao (truyen token hoac file, hoac "
              "paste vao stdin)", file=sys.stderr)
        return 2

    tokens = []
    for r in raw:
        tokens.extend(t for t in r.replace("\r", "").split("\n") if t.strip())

    results = [inspect_token(t, args, color) for t in tokens]
    input_err = sum(1 for r in results if r.get("error"))
    has_fail = any(r.get("ok") is False and not r.get("error")
                   for r in results)

    if args.json:
        out = render_json(results, queried_at)
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

    if input_err == len(results):
        return 2
    if has_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())