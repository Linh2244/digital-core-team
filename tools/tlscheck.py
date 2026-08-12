#!/usr/bin/env python3
import argparse
import concurrent.futures
import hashlib
import json
import re
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone

TOOL = "TLSCheck"
VERSION = "1.0.0"
TEAM = "Digital Core team"

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8,
                   "LOW": 3, "INFO": 0}

VERSIONS = [(ssl.TLSVersion.TLSv1, "TLSv1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
            (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLSv1.3")]

TLS13_CIPHERS = ("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256",
                 "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256",
                 "TLS_AES_128_CCM_8_SHA256")

COMMON_TLS_PORTS = (443, 465, 636, 993, 995, 8443, 990, 853, 5061,
                    989, 992, 5222)

FAST_CIPHERS = (
    "AES128-SHA", "AES256-SHA", "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
    "DES-CBC-SHA", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "AES128-GCM-SHA256",
    "AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305",
    "ADH-AES128-GCM-SHA256", "AECDH-AES128-SHA", "NULL-SHA", "EXP-RC4-MD5",
)

EV_POLICY_OIDS = {"2.23.140.1.1", "2.23.140.1.2.1", "2.23.140.1.2.2",
                  "2.23.140.1.2.3", "1.3.6.1.4.1.4146.1.1",
                  "2.16.840.1.114412.2.1"}


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


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


def status_color(status):
    return {"PASS": "green", "FAIL": "red", "WARN": "yellow",
            "INFO": "cyan"}.get(status, "cyan")


def classify_cipher(name):
    n = name.upper()
    if "NULL" in n or "EXPORT" in n or n.startswith("ADH") \
            or n.startswith("AECDH"):
        return "CRITICAL", "anonymous/null/export"
    if "RC4" in n:
        return "HIGH", "RC4"
    if "DES-CBC3" in n or "3DES" in n:
        return "HIGH", "3DES"
    if "DES-CBC" in n:
        return "HIGH", "DES"
    m = re.search(r"\b([0-9]+)\b", n)
    if m and int(m.group(1)) < 128:
        return "HIGH", f"khóa {m.group(1)} bit"
    if "-GCM" not in n and "-CCM" not in n and "-CHACHA20" not in n \
            and ("-CBC" in n or n.endswith("-SHA")
                 or n.endswith("-SHA256") or n.endswith("-SHA384")):
        return "MEDIUM", "CBC"
    return None, None


def has_forward_secrecy(cipher):
    if cipher.startswith("TLS_AES_") or cipher.startswith("TLS_CHACHA20"):
        return True
    return cipher.startswith("ECDHE") or cipher.startswith("DHE")


class TLSChecker:
    def __init__(self, host, port, timeout=8.0, threads=8, fast=False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.threads = max(1, threads)
        self.fast = fast
        self.probe_timeout = min(timeout, 3.0)
        self.ip = None
        self.findings = []

    def _connect(self, ctx):
        try:
            raw = socket.create_connection((self.host, self.port),
                                           timeout=self.timeout)
            raw.settimeout(self.timeout)
        except OSError as e:
            return None, str(e)
        try:
            s = ctx.wrap_socket(raw, server_hostname=self.host)
            s.settimeout(self.timeout)
            return s, None
        except (ssl.SSLError, OSError) as e:
            try:
                raw.close()
            except Exception:
                pass
            return None, str(e)

    def _probe_version(self, ver):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            pass
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except (ValueError, ssl.SSLError):
            return None
        s, err = self._connect(ctx)
        if s is not None:
            s.close()
            return True
        return False

    def _probe_cipher(self, cipher):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(cipher + ":@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return None
        try:
            s, _ = self._connect(ctx)
            if s is not None:
                name = s.cipher()[0] if s.cipher() else cipher
                s.close()
                return name
        except Exception:
            pass
        return None

    def _probe_tls13_cipher(self, cipher):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ciphers(cipher)
        except (ValueError, ssl.SSLError):
            return None
        s, _ = self._connect(ctx)
        if s is not None:
            s.close()
            return cipher
        return None

    def enumerate_ciphers(self):
        supported = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            names = list(dict.fromkeys(
                c["name"] for c in ctx.get_ciphers()))
        except Exception:
            names = list(FAST_CIPHERS)
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as ex:
            for name in ex.map(self._probe_cipher, names):
                if name:
                    supported.append(name)
        for c in TLS13_CIPHERS:
            if self._probe_tls13_cipher(c):
                supported.append(c)
        return sorted(set(supported))

    def run(self):
        self.ip = socket.gethostbyname(self.host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            pass
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        s, err = self._connect(ctx)
        if s is None:
            raise ConnectionError(err or "không kết nối được")
        negotiated = {"protocol": s.version() or "unknown",
                      "cipher": (s.cipher() or ("unknown",))[0],
                      "alpn": s.selected_alpn_protocol()}
        peer = s.getpeercert()
        der = s.getpeercert(binary_form=True) or b""
        session = s.session
        negotiated["ticket"] = bool(
            getattr(session, "has_ticket", False)) if session else None
        s.close()
        cert = decode_cert(der, peer)

        versions = []
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            for ver, name in VERSIONS:
                try:
                    ok = self._probe_version(ver)
                except Exception:
                    ok = False
                versions.append({"name": name, "supported": ok})

        if self.fast:
            supported = []
            for c in FAST_CIPHERS:
                try:
                    r = self._probe_cipher(c)
                    if r:
                        supported.append(r)
                except Exception:
                    pass
        else:
            supported = self.enumerate_ciphers()

        chain_ok, chain_reason = self.verify_chain()

        self._build_findings(versions, negotiated, supported, cert,
                             chain_ok, chain_reason)
        score = self.score()
        return {
            "host": self.host, "port": self.port, "ip": self.ip,
            "ok": True,
            "negotiated": negotiated,
            "versions": versions,
            "cipher_count": len(supported),
            "ciphers_supported": supported,
            "cert": cert,
            "chain_ok": chain_ok,
            "chain_reason": chain_reason,
            "findings": self.findings,
            "score": score,
            "grade": grade_for(score),
        }

    def verify_chain(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            s, err = self._connect(ctx)
            if s is not None:
                s.close()
                return True, "chuỗi tin cậy, hostname hợp lệ"
            return False, err or "không xác minh được"
        except Exception as e:
            return False, str(e)

    def _build_findings(self, versions, negotiated, supported, cert,
                        chain_ok, chain_reason):
        F = self.findings
        v = {x["name"]: x["supported"] for x in versions}

        if v.get("TLSv1.0"):
            F.append({"group": "PROTOCOL", "status": "FAIL",
                      "severity": "CRITICAL",
                      "detail": "TLSv1.0 được hỗ trợ - đã lỗi thời "
                                "(POODLE/BEAST), nên tắt"})
        if v.get("TLSv1.1"):
            F.append({"group": "PROTOCOL", "status": "FAIL",
                      "severity": "HIGH",
                      "detail": "TLSv1.1 được hỗ trợ - đã lỗi thời, nên tắt"})
        if not v.get("TLSv1.0") and not v.get("TLSv1.1"):
            F.append({"group": "PROTOCOL", "status": "PASS",
                      "severity": "INFO",
                      "detail": "TLSv1.0/1.1 không được hỗ trợ"})
        if v.get("TLSv1.2"):
            F.append({"group": "PROTOCOL", "status": "PASS",
                      "severity": "INFO", "detail": "TLSv1.2 được hỗ trợ"})
        if v.get("TLSv1.3"):
            F.append({"group": "PROTOCOL", "status": "PASS",
                      "severity": "INFO", "detail": "TLSv1.3 được hỗ trợ"})
        else:
            if not v.get("TLSv1.2"):
                F.append({"group": "PROTOCOL", "status": "FAIL",
                          "severity": "CRITICAL",
                          "detail": "Không hỗ trợ TLSv1.2/1.3 hiện đại"})
            else:
                F.append({"group": "PROTOCOL", "status": "WARN",
                          "severity": "LOW",
                          "detail": "Chưa hỗ trợ TLSv1.3"})

        F.append({"group": "CIPHERS", "status": "INFO", "severity": "INFO",
                  "detail": f"Đang dùng: {negotiated['cipher']} "
                            f"({negotiated['protocol']})"})
        weak = {"CRITICAL": {}, "HIGH": {}}
        cbc = []
        for c in supported:
            sev, label = classify_cipher(c)
            if sev:
                if sev == "MEDIUM":
                    cbc.append(c)
                else:
                    weak[sev].setdefault(label, []).append(c)
        if weak["CRITICAL"]:
            det = "; ".join(f"{k}: {', '.join(vs)}"
                            for k, vs in weak["CRITICAL"].items())
            F.append({"group": "CIPHERS", "status": "FAIL",
                      "severity": "CRITICAL",
                      "detail": f"Cipher vô danh/null/export: {det}"})
        for label, cs in weak["HIGH"].items():
            F.append({"group": "CIPHERS", "status": "FAIL",
                      "severity": "HIGH",
                      "detail": f"Cipher yếu {label}: {', '.join(cs)}"})
        if cbc:
            F.append({"group": "CIPHERS", "status": "WARN",
                      "severity": "MEDIUM",
                      "detail": f"Cipher CBC TLSv1.2 (kém an toàn): "
                                f"{', '.join(cbc)}"})
        if not weak["CRITICAL"] and not weak["HIGH"]:
            F.append({"group": "CIPHERS", "status": "PASS",
                      "severity": "INFO", "detail": "Không có cipher yếu"})
        if has_forward_secrecy(negotiated["cipher"]):
            F.append({"group": "CIPHERS", "status": "PASS",
                      "severity": "INFO",
                      "detail": "Có forward secrecy (ECDHE/DHE/TLSv1.3)"})
        else:
            F.append({"group": "CIPHERS", "status": "FAIL",
                      "severity": "HIGH",
                      "detail": "Không có forward secrecy "
                                "(trao đổi khóa RSA)"})

        if chain_ok:
            F.append({"group": "CERTIFICATE", "status": "PASS",
                      "severity": "INFO", "detail": "Chuỗi tin cậy hợp lệ"})
        else:
            F.append({"group": "CERTIFICATE", "status": "FAIL",
                      "severity": "HIGH",
                      "detail": f"Không tin cậy: {chain_reason}"})

        now = datetime.now(timezone.utc)
        if cert.get("not_after"):
            if cert.get("days_remaining", 0) < 0:
                F.append({"group": "CERTIFICATE", "status": "FAIL",
                          "severity": "CRITICAL",
                          "detail": f"Chứng chỉ HẾT HẠN ({cert['not_after']})"})
            elif cert.get("days_remaining", 0) < 7:
                F.append({"group": "CERTIFICATE", "status": "FAIL",
                          "severity": "HIGH",
                          "detail": f"Còn {cert['days_remaining']} ngày "
                                    f"hết hạn"})
            elif cert.get("days_remaining", 0) < 30:
                F.append({"group": "CERTIFICATE", "status": "WARN",
                          "severity": "MEDIUM",
                          "detail": f"Còn {cert['days_remaining']} ngày "
                                    f"hết hạn"})
            else:
                F.append({"group": "CERTIFICATE", "status": "PASS",
                          "severity": "INFO",
                          "detail": f"Còn {cert['days_remaining']} ngày "
                                    f"hiệu lực"})
        if cert.get("not_before") and cert.get("not_before", "") > now.isoformat():
            F.append({"group": "CERTIFICATE", "status": "FAIL",
                      "severity": "HIGH",
                      "detail": "Chứng chỉ chưa có hiệu lực "
                                "(notBefore trong tương lai)"})

        if cert.get("key_size"):
            if cert.get("key_type", "").startswith("RSA") \
                    or cert.get("key_type", "").startswith("DSA"):
                if cert["key_size"] < 2048:
                    F.append({"group": "CERTIFICATE", "status": "FAIL",
                              "severity": "HIGH",
                              "detail": f"Khóa {cert['key_type']} "
                                        f"{cert['key_size']} bit "
                                        f"(nên >= 2048)"})
                else:
                    F.append({"group": "CERTIFICATE", "status": "PASS",
                              "severity": "INFO",
                              "detail": f"Khóa {cert['key_type']} "
                                        f"{cert['key_size']} bit"})
            elif "EC" in cert.get("key_type", ""):
                if cert["key_size"] < 224:
                    F.append({"group": "CERTIFICATE", "status": "WARN",
                              "severity": "MEDIUM",
                              "detail": f"Khóa EC {cert['key_size']} bit "
                                        f"(nên >= 224)"})
                else:
                    F.append({"group": "CERTIFICATE", "status": "PASS",
                              "severity": "INFO",
                              "detail": f"Khóa {cert['key_type']} "
                                        f"{cert['key_size']} bit"})

        sig = cert.get("signature_algorithm", "")
        if "SHA1" in sig or "sha1" in sig or "MD5" in sig:
            F.append({"group": "CERTIFICATE", "status": "FAIL",
                      "severity": "HIGH",
                      "detail": f"Chữ ký yếu: {sig}"})
        elif sig:
            F.append({"group": "CERTIFICATE", "status": "PASS",
                      "severity": "INFO", "detail": f"Chữ ký {sig}"})

        if cert.get("san"):
            ok_match = hostname_matches(self.host, cert["san"])
            if ok_match:
                F.append({"group": "CERTIFICATE", "status": "PASS",
                          "severity": "INFO",
                          "detail": "SAN chứa hostname"})
            else:
                F.append({"group": "CERTIFICATE", "status": "FAIL",
                          "severity": "HIGH",
                          "detail": "SAN không chứa hostname "
                                    "(có thể là cert sai tên miền)"})
        else:
            F.append({"group": "CERTIFICATE", "status": "WARN",
                      "severity": "MEDIUM",
                      "detail": "Không có SAN, chỉ dùng CN"})

        if cert.get("ev"):
            F.append({"group": "CERTIFICATE", "status": "PASS",
                      "severity": "INFO", "detail": "Chứng chỉ EV"})
        if cert.get("ocsp"):
            F.append({"group": "CERTIFICATE", "status": "INFO",
                      "severity": "INFO",
                      "detail": f"OCSP responder: {cert['ocsp'][0]}"})
        elif cert.get("limited") is not True:
            F.append({"group": "CERTIFICATE", "status": "WARN",
                      "severity": "LOW",
                      "detail": "Không có OCSP responder (AIA)"})

    def score(self):
        score = 100
        for f in self.findings:
            w = SEVERITY_WEIGHT.get(f["severity"], 0)
            if f["status"] == "FAIL":
                score -= w
            elif f["status"] == "WARN":
                score -= w // 2
        return max(0, min(100, score))


def hostname_matches(host, san):
    host_l = host.lower().rstrip(".")
    for typ, val in san:
        v = val.lower()
        if typ == "dns":
            if v.startswith("*."):
                if host_l.endswith(v[1:]):
                    left = host_l[:-len(v[1:])]
                    if left and "." not in left:
                        return True
            elif v == host_l:
                return True
        elif typ == "ip" and val == host:
            return True
    return False


def decode_cert(der, peer):
    out = {"san": [], "limited": False}
    if not der:
        out["note"] = "không lấy được chứng chỉ (DER rỗng)"
        return out
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)

        def rdn(n):
            return ", ".join(f"{a.oid._name or a.oid.dotted_string}"
                             f"={a.value}" for a in n)

        san = []
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            san = [("dns", d.value) if isinstance(d, x509.DNSName)
                   else ("ip", d.value) for d in ext]
        except Exception:
            pass
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        nb = getattr(cert, "not_valid_before_utc", None) \
            or cert.not_valid_before
        now = datetime.now(timezone.utc)
        na = na.astimezone(timezone.utc) if na.tzinfo \
            else na.replace(tzinfo=timezone.utc)
        nb = nb.astimezone(timezone.utc) if nb.tzinfo \
            else nb.replace(tzinfo=timezone.utc)
        pk = cert.public_key()
        sig = cert.signature_algorithm_oid._name \
            or cert.signature_algorithm_oid.dotted_string
        ocsp, ca_issuers, crl = [], [], []
        try:
            aia = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess).value
            for d in aia:
                if isinstance(d, x509.OCSP):
                    ocsp.append(d.access_location.value)
                elif isinstance(d, x509.CAIssuers):
                    ca_issuers.append(d.access_location.value)
        except Exception:
            pass
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.CRLDistributionPoints).value
            crl = [d.full_name[0].value for d in ext if d.full_name]
        except Exception:
            pass
        eku = []
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage).value
            eku = [e._name or e.dotted_string for e in ext]
        except Exception:
            pass
        org = None
        for a in cert.subject:
            if a.oid._name == "organizationName":
                org = a.value
                break
        is_ev = False
        try:
            pol = cert.extensions.get_extension_for_class(
                x509.CertificatePolicies).value
            is_ev = org is not None and any(
                p.policy_identifier.dotted_string in EV_POLICY_OIDS
                for p in pol)
        except Exception:
            pass
        out.update({
            "subject": rdn(cert.subject),
            "issuer": rdn(cert.issuer),
            "san": san,
            "serial": format(cert.serial_number, "X"),
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "days_remaining": (na - now).days,
            "key_type": pk.__class__.__name__.replace("_", " "),
            "key_size": getattr(pk, "key_size", 0),
            "signature_algorithm": sig,
            "sha1": hashlib.sha1(der).hexdigest(),
            "sha256": hashlib.sha256(der).hexdigest(),
            "ocsp": ocsp,
            "crl": crl,
            "ca_issuers": ca_issuers,
            "eku": eku,
            "ev": is_ev,
        })
    except ImportError:
        out["limited"] = True
        out["note"] = "cryptography không có sẵn - chi tiết hạn chế"
        try:
            subj = "; ".join(f"{k[0]}={k[1]}" for k in peer.get("subject", []))
            iss = "; ".join(f"{k[0]}={k[1]}" for k in peer.get("issuer", []))
            na = peer.get("notAfter", "")
            san = peer.get("subjectAltName", [])
            out.update({
                "subject": subj, "issuer": iss,
                "san": [(t.lower(), v) for t, v in san],
                "not_after": na, "serial": peer.get("serialNumber", ""),
            })
        except Exception:
            pass
    except Exception as e:
        out["note"] = f"không giải mã được chứng chỉ: {e}"
    return out


def parse_targets(args_targets, args_ports):
    targets = []
    for t in args_targets:
        host = t
        port = None
        if t.startswith("["):
            m = re.match(r"\[(.+)\](?::(\d+))?$", t)
            if m:
                host = m.group(1)
                port = int(m.group(2)) if m.group(2) else None
        elif t.count(":") == 1:
            h, p = t.rsplit(":", 1)
            if p.isdigit():
                host = h
                port = int(p)
        if not host or not re.match(r"^[0-9a-zA-Z.\-\[\]:]+$", host):
            raise ValueError(f"target không hợp lệ: {t!r}")
        ports = [port] if port else (args_ports or list(COMMON_TLS_PORTS))
        targets.append((host, ports))
    return targets


def scan_host(host, ports, args):
    last_err = None
    for port in ports:
        try:
            ck = TLSChecker(host, port, args.timeout, args.threads,
                            args.fast)
            return ck.run()
        except ConnectionError as e:
            last_err = str(e)
        except (ssl.SSLError, socket.gaierror, OSError, ValueError) as e:
            last_err = str(e)
    return {"host": host, "port": None, "ok": False,
            "error": last_err or "không kết nối được target nào"}


def render_text(results, color):
    lines = [f";; {TOOL} {VERSION} <<>> {TEAM}"]
    for r in results:
        lines.append("")
        if not r.get("ok"):
            lines.append(color.red(f"{r['host']}  X  {r['error']}"))
            continue
        lines.append(color.bold(f"{r['host']}:{r['port']}  ({r['ip']})"))
        groups = []
        for f in r["findings"]:
            if f["group"] not in groups:
                groups.append(f["group"])
        for g in groups:
            lines.append(f"[ {g} ]")
            for f in r["findings"]:
                if f["group"] != g:
                    continue
                sc = getattr(color, status_color(f["status"]))
                lines.append(f"  {sc(f['status']):<5} {f['severity']:<8} "
                             f"{f['detail']}")
        g = r["grade"]
        gcolor = {"A": color.green, "B": color.cyan, "C": color.yellow,
                  "D": color.yellow, "F": color.red}.get(g, color.bold)
        lines.append(f"  {color.bold('VERDICT')}: Score "
                     f"{r['score']}/100 ({gcolor(g)}) | "
                     f"{r['cipher_count']} cipher hỗ trợ")
    return "\n".join(lines)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="tlscheck",
        description=f"{TOOL} {VERSION} - TLS checker (Digital Core team). "
                    f"Kiem tra protocol, cipher, chung chi TLS tren bat ky "
                    f"dich vu nao (https, smtp, imap, ldaps, dot...).")
    ap.add_argument("targets", nargs="*",
                    help="host hoac host:port; nhieu target; ipv6 [::1]:443")
    ap.add_argument("-p", "--ports", type=int, nargs="+",
                    help="cac cong TLS de thu (mac dinh do tu dong cac cong "
                         "pho bien)")
    ap.add_argument("-T", "--timeout", type=float, default=8.0,
                    help="timeout ket noi (mac dinh 8s)")
    ap.add_argument("--threads", type=int, default=8,
                    help="so luong tien trinh do cipher song song "
                         "(mac dinh 8)")
    ap.add_argument("--fast", action="store_true",
                    help="khong enumerate day du cipher, chi do danh sach "
                         "chon loc (~25 cipher) cho nhanh")
    ap.add_argument("--json", action="store_true",
                    help="output JSON")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    ap.add_argument("--version", action="version",
                    version=f"{TOOL} {VERSION}")
    args = ap.parse_args()

    if not args.targets:
        print(f"{TOOL}: khong co target nao (vi du: example.com, "
              f"mail.example.com:465)", file=sys.stderr)
        return 2
    try:
        targets = parse_targets(args.targets, args.ports)
    except ValueError as e:
        print(f"{TOOL}: {e}", file=sys.stderr)
        return 2

    results = []
    for host, ports in targets:
        print(f"{TOOL}: dang kiem tra {host} ...", file=sys.stderr)
        results.append(scan_host(host, ports, args))

    if not any(r.get("ok") for r in results):
        print(f"{TOOL}: khong ket noi duoc target nao", file=sys.stderr)
        return 3

    if args.json:
        text = json.dumps({
            "tool": TOOL, "version": VERSION, "team": TEAM,
            "queried_at": datetime.now().astimezone().isoformat(),
            "targets": results,
        }, indent=2, ensure_ascii=False)
    else:
        color = Color(enabled=not args.no_color and sys.stdout.isatty()
                      and not args.output)
        text = render_text(results, color)

    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")

    for r in results:
        if r.get("ok") and any(f["severity"] in ("CRITICAL", "HIGH")
                               for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
