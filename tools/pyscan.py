#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyScan - advanced port scanner with nmap-like features plus extras
(native JSON, scan-history diff, deep SSL/TLS inspection).

Usage examples:
  python pyscan.py -sT -p 1-1000 scanme.example.com
  python pyscan.py -sS -sV -T4 -p- 192.168.1.10          # needs admin + scapy
  python pyscan.py -sT --ssl-detail -p 443,8443 example.com
  python pyscan.py --diff -p- example.com                # compare vs previous run
  python pyscan.py -sT -oJ out.json 192.168.1.0/24
"""

import argparse
import ctypes
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

VERSION = "1.0.0"
TOOL = "PyScan"
URL = "https://github.com/local/pyscan"

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
UNFILTERED = "unfiltered"
OPEN_FILTERED = "open|filtered"

SCAN_HELP = {
    "sS": ("SYN scan (raw, needs admin/scapy)", "syn"),
    "sT": ("TCP connect scan (default)", "connect"),
    "sU": ("UDP scan", "udp"),
    "sN": ("NULL scan (raw)", "null"),
    "sF": ("FIN scan (raw)", "fin"),
    "sX": ("XMAS scan (raw)", "xmas"),
    "sA": ("ACK scan (raw)", "ack"),
    "sW": ("Window scan (raw)", "window"),
}

TIMING_TEMPLATES = {
    0: dict(host_workers=1, port_workers=1, timeout=10.0, delay=5.0, retries=4),
    1: dict(host_workers=1, port_workers=2, timeout=10.0, delay=1.0, retries=2),
    2: dict(host_workers=1, port_workers=5, timeout=3.0, delay=0.1, retries=1),
    3: dict(host_workers=2, port_workers=15, timeout=1.5, delay=0.0, retries=1),
    4: dict(host_workers=4, port_workers=50, timeout=1.0, delay=0.0, retries=0),
    5: dict(host_workers=8, port_workers=200, timeout=0.5, delay=0.0, retries=0),
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 179, 389, 443,
             445, 465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049,
             2375, 3000, 3128, 3306, 3389, 5060, 5432, 5900, 5985, 5986, 6379, 8000,
             8080, 8443, 8888, 9000, 9090, 9200, 10000, 27017, 11211, 50000]

PORT_DEFAULTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    67: "dhcps", 68: "dhcpc", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    992: "telnets", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3128: "squid-http",
    3268: "globalcat", 3306: "mysql", 3389: "ms-wbt-server", 3546: "sip",
    4369: "epmd", 5000: "upnp", 5060: "sip", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 5985: "http-msrpc", 5986: "http-msrpc-ssl",
    6379: "redis", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp", 8080: "http-proxy", 8081: "http-alt", 8085: "http-alt",
    8088: "http-alt", 8200: "http-alt", 8443: "https-alt", 8888: "http-alt",
    8889: "http-alt", 9000: "http-alt", 9001: "http-alt", 9042: "cassandra",
    9090: "http-alt", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 10000: "http-alt", 11211: "memcached", 11214: "memcached-ssl",
    15672: "amqp-admin", 20000: "http-alt", 25565: "minecraft", 27017: "mongodb",
    27018: "mongodb", 28017: "mongodb-http", 50000: "sap", 61616: "activemq",
}

TLS_PORTS = {443, 465, 587, 636, 989, 990, 993, 995, 4443, 8443, 8883, 9443, 9901, 50001}

SIGNATURES = [
    (re.compile(rb"SSH-\d+\.\d+[-\s].*", re.I), "ssh"),
    (re.compile(rb"^HTTP/1\.[01] \d{3}", re.I), "http"),
    (re.compile(rb"220[- ].*Microsoft ESMTP MAIL Service", re.I), "smtp"),
    (re.compile(rb"220[- ].*SMTP", re.I), "smtp"),
    (re.compile(rb"220[- ].*FTP", re.I), "ftp"),
    (re.compile(rb"220[- ].*ProFTPD", re.I), "proftpd"),
    (re.compile(rb"220[- ].*vsFTPd", re.I), "vsftpd"),
    (re.compile(rb"500 OOPS:", re.I), "vsftpd"),
    (re.compile(rb"220[- ].*FileZilla", re.I), "ftp"),
    (re.compile(rb"MySQL|Welcome to the MySQL monitor", re.I), "mysql"),
    (re.compile(rb"redis_version:|PONG", re.I), "redis"),
    (re.compile(rb"PostgreSQL", re.I), "postgresql"),
    (re.compile(rb"Welcome to MongoDB", re.I), "mongodb"),
    (re.compile(rb"^MongoDB", re.I), "mongodb"),
    (re.compile(rb"\* OK.*IMAP", re.I), "imap"),
    (re.compile(rb"\+OK.*POP3", re.I), "pop3"),
    (re.compile(rb"^220[- ].*ESMTP", re.I), "smtp"),
    (re.compile(rb"^\+OK", re.I), "pop3"),
    (re.compile(rb"rdp|microsoft terminal", re.I), "ms-wbt-server"),
    (re.compile(rb"^VNC|RFB \d{3}\.\d{3}", re.I), "vnc"),
    (re.compile(rb"Banner: https|nginx|apache|caddy", re.I), "http"),
]

HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
REDIS_PROBE = b"PING\r\n"

class Color:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def _w(self, code, s):
        if not self.enabled:
            return s
        return f"\033[{code}m{s}\033[0m"

    def green(self, s): return self._w("32", s)
    def red(self, s): return self._w("31", s)
    def yellow(self, s): return self._w("33", s)
    def cyan(self, s): return self._w("36", s)
    def magenta(self, s): return self._w("35", s)
    def bold(self, s): return self._w("1", s)
    def dim(self, s): return self._w("2", s)


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


def is_admin():
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def get_scapy():
    try:
        import scapy.all as sp
        return sp
    except Exception:
        return None


def _sport():
    return random_port()


def random_port():
    import random
    return random.randint(1024, 65535)


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- port parsing

def parse_port_spec(spec):
    """Parse '22,80-100,443', '-' or None into sorted unique ports (1..65535)."""
    ports = set()
    if spec in (None, "", "-", "0-65535", "1-65535", "0-"):
        return list(range(1, 65536))
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a = 1 if a in ("", "0") else int(a)
            b = 65535 if b in ("", "0") else int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    ports = {p for p in ports if 1 <= p <= 65535}
    return sorted(ports)


def parse_top_ports(n):
    n = max(1, min(n, len(TOP_PORTS)))
    return TOP_PORTS[:n]


# ---------------------------------------------------------------- target parsing

class Target:
    def __init__(self, label, ip):
        self.label = label
        self.ip = ip
        self.up = None
        self.latency = None
        self.ttl = None
        self.window = None
        self.os_guess = None
        self.ports = {}      # port -> PortResult
        self.error = None


def _resolve(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except socket.gaierror:
        return []


def expand_targets(tokens):
    """Return list of Target objects from hostnames/IPs/CIDRs/ranges."""
    targets = []
    seen = set()
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        # CIDR
        if "/" in tok:
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                print(f"PyScan: skipping invalid CIDR '{tok}'", file=sys.stderr)
                continue
            if net.num_addresses > 65536:
                print(f"PyScan: '{tok}' expands to {net.num_addresses} hosts, aborting.", file=sys.stderr)
                sys.exit(1)
            for ip in net.hosts():
                k = str(ip)
                if k not in seen:
                    seen.add(k)
                    targets.append(Target(k, k))
            continue
        # range a.b.c.d-x or a.b.c.d-a.b.c.e
        m = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3})(?:\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?$", tok)
        if m:
            base = m.group(1)
            parts = base.split(".")
            lo = int(m.group(2))
            if "." in m.group(0).split("-")[1]:
                hi_parts = m.group(0).split("-")[1].split(".")
                hi = int(hi_parts[-1])
                if parts[:len(hi_parts) - 1] != hi_parts[:len(hi_parts) - 1]:
                    print(f"PyScan: skipping invalid range '{tok}'", file=sys.stderr)
                    continue
            else:
                hi = lo
                lo = int(parts[-1])
                parts = parts[:3]
            if lo > hi:
                lo, hi = hi, lo
            for i in range(lo, hi + 1):
                ip = ".".join(parts + [str(i)])
                if ip not in seen:
                    seen.add(ip)
                    targets.append(Target(ip, ip))
            continue
        # try IP literal
        try:
            ipaddress.ip_address(tok)
            if tok not in seen:
                seen.add(tok)
                targets.append(Target(tok, tok))
            continue
        except ValueError:
            pass
        # hostname
        ips = _resolve(tok)
        if not ips:
            print(f"PyScan: could not resolve hostname '{tok}'", file=sys.stderr)
            continue
        for ip in ips:
            key = f"{tok}|{ip}"
            if key not in seen:
                seen.add(key)
                targets.append(Target(tok, ip))
    return targets


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ---------------------------------------------------------------- config

class Config:
    def __init__(self, timing, timeout=None, delay=None, retries=None,
                 port_workers=None, host_workers=None):
        t = TIMING_TEMPLATES[timing]
        self.timing = timing
        self.timeout = timeout if timeout is not None else t["timeout"]
        self.delay = delay if delay is not None else t["delay"]
        self.retries = retries if retries is not None else t["retries"]
        self.port_workers = port_workers if port_workers is not None else t["port_workers"]
        self.host_workers = host_workers if host_workers is not None else t["host_workers"]


# ---------------------------------------------------------------- scanners

class ScanError(Exception):
    pass


class RawScanFailed(Exception):
    pass


class Scanner:
    name = "connect"
    proto = "tcp"
    needs_admin = False

    def scan_host(self, ip, ports, cfg):
        raise NotImplementedError


class ConnectScanner(Scanner):
    name = "connect"
    proto = "tcp"

    def _scan_port(self, ip, port, timeout):
        try:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
            return OPEN
        except socket.timeout:
            return FILTERED
        except ConnectionRefusedError:
            return CLOSED
        except socket.gaierror:
            return FILTERED
        except OSError as e:
            if e.errno in (10060, 10061, 10065, 110, 111, 113):
                return CLOSED if e.errno in (10061, 111) else FILTERED
            return CLOSED

    def scan_host(self, ip, ports, cfg):
        results = {}
        workers = max(1, cfg.port_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {}
            for p in ports:
                futs[ex.submit(self._scan_port, ip, p, cfg.timeout)] = p
                if cfg.delay:
                    time.sleep(cfg.delay)
            for f in as_completed(futs):
                results[futs[f]] = f.result()
        return results


class _RawScanner(Scanner):
    needs_admin = True
    flags = "S"
    proto = "tcp"
    default_state = FILTERED

    def _build(self, sp, ip, port):
        return sp.IP(dst=ip) / sp.TCP(dport=port, sport=_sport(), flags=self.flags)

    def _classify(self, sent, recv, sp):
        p = sent[sp.TCP].dport
        if sp.TCP in recv:
            f = int(recv[sp.TCP].flags)
            if f & 0x12 == 0x12:
                return p, OPEN
            if f & 0x04:
                return p, CLOSED
            return p, OPEN
        return p, FILTERED

    def scan_host(self, ip, ports, cfg):
        sp = get_scapy()
        if sp is None:
            raise ScanError("scapy is required for this scan type (pip install scapy)")
        sp.conf.verb = 0
        pkts = [self._build(sp, ip, p) for p in ports]
        try:
            ans, _ = sp.sr(pkts, timeout=max(cfg.timeout, 2.0), verbose=0, retry=cfg.retries)
        except PermissionError:
            raise RawScanFailed("raw socket permission denied (run as administrator)")
        except OSError as e:
            raise RawScanFailed(str(e))
        results = {p: self.default_state for p in ports}
        for sent, recv in ans:
            p, state = self._classify(sent, recv, sp)
            results[p] = state
            if self.name == "syn" and state == OPEN:
                try:
                    sp.send(sp.IP(dst=ip) / sp.TCP(dport=p, sport=sent[sp.TCP].sport, flags="R"), verbose=0)
                except Exception:
                    pass
        self._capture_info(ans, sp)
        return results

    def _capture_info(self, ans, sp):
        try:
            for sent, recv in ans:
                if sp.TCP in recv and sp.IP in recv:
                    self.last_ttl = int(recv[sp.IP].ttl)
                    self.last_window = int(recv[sp.TCP].window)
                    return
        except Exception:
            pass


class SynScanner(_RawScanner):
    name = "syn"
    flags = "S"


class NullScanner(_RawScanner):
    name = "null"
    flags = ""
    default_state = OPEN_FILTERED


class FinScanner(_RawScanner):
    name = "fin"
    flags = "F"
    default_state = OPEN_FILTERED


class XmasScanner(_RawScanner):
    name = "xmas"
    flags = "FPU"
    default_state = OPEN_FILTERED

    def _classify(self, sent, recv, sp):
        if sp.TCP in recv:
            if int(recv[sp.TCP].flags) & 0x04:
                return sent[sp.TCP].dport, CLOSED
            return sent[sp.TCP].dport, OPEN
        return sent[sp.TCP].dport, FILTERED


class AckScanner(_RawScanner):
    name = "ack"
    flags = "A"

    def _classify(self, sent, recv, sp):
        if sp.TCP in recv:
            return sent[sp.TCP].dport, UNFILTERED
        return sent[sp.TCP].dport, FILTERED


class WindowScanner(_RawScanner):
    name = "window"
    flags = "A"

    def _classify(self, sent, recv, sp):
        if sp.TCP in recv:
            win = int(recv[sp.TCP].window)
            return sent[sp.TCP].dport, (OPEN if win > 0 else CLOSED)
        return sent[sp.TCP].dport, FILTERED


class UdpScanner(_RawScanner):
    name = "udp"
    flags = ""
    proto = "udp"
    needs_admin = True
    default_state = OPEN_FILTERED

    def _build(self, sp, ip, port):
        return sp.IP(dst=ip) / sp.UDP(dport=port, sport=_sport()) / sp.Raw(b"\x00" * 8)

    def _classify(self, sent, recv, sp):
        p = sent[sp.UDP].dport
        if sp.UDP in recv:
            return p, OPEN
        if sp.ICMP in recv and int(recv[sp.ICMP].type) == 3:
            code = int(recv[sp.ICMP].code)
            return p, (CLOSED if code == 3 else FILTERED)
        return p, OPEN_FILTERED

    def scan_host(self, ip, ports, cfg):
        sp = get_scapy()
        if sp is None:
            raise ScanError("scapy is required for UDP scan (pip install scapy)")
        sp.conf.verb = 0
        pkts = [self._build(sp, ip, p) for p in ports]
        try:
            ans, _ = sp.sr(pkts, timeout=max(cfg.timeout, 2.0), verbose=0, retry=cfg.retries)
        except PermissionError:
            raise RawScanFailed("raw socket permission denied (run as administrator)")
        except OSError as e:
            raise RawScanFailed(str(e))
        results = {p: self.default_state for p in ports}
        for sent, recv in ans:
            p, state = self._classify(sent, recv, sp)
            results[p] = state
        return results


class SocketUdpScanner(Scanner):
    name = "udp-socket"
    proto = "udp"

    def _scan_port(self, ip, port, timeout):
        try:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"\x00" * 8, (ip, port))
                try:
                    s.recvfrom(1024)
                    return OPEN
                except socket.timeout:
                    return OPEN_FILTERED
        except ConnectionRefusedError:
            return CLOSED
        except OSError as e:
            if e.errno in (10054, 10061, 111):
                return CLOSED
            return OPEN_FILTERED

    def scan_host(self, ip, ports, cfg):
        results = {}
        with ThreadPoolExecutor(max_workers=max(1, cfg.port_workers)) as ex:
            futs = {ex.submit(self._scan_port, ip, p, cfg.timeout): p for p in ports}
            for f in as_completed(futs):
                results[futs[f]] = f.result()
        return results


SCANNER_CLASSES = {
    "syn": SynScanner,
    "connect": ConnectScanner,
    "udp": UdpScanner,
    "null": NullScanner,
    "fin": FinScanner,
    "xmas": XmasScanner,
    "ack": AckScanner,
    "window": WindowScanner,
}


def choose_scanner(mode, color):
    """Return (scanner, effective_mode, warnings). Falls back safely."""
    warnings = []
    if mode in ("syn", "null", "fin", "xmas", "ack", "window"):
        sp = get_scapy()
        if sp is None:
            warnings.append(f"{mode.upper()} scan needs scapy (pip install scapy). Falling back to connect scan.")
            return ConnectScanner(), "connect", warnings
        if not is_admin():
            warnings.append(f"{mode.upper()} scan may need raw sockets / administrator; "
                            f"falling back to connect scan automatically if it fails.")
        return SCANNER_CLASSES[mode](), mode, warnings
    if mode == "udp":
        sp = get_scapy()
        if sp is not None and is_admin():
            return UdpScanner(), "udp", warnings
        warnings.append("UDP raw scan unavailable (need admin+scapy); using socket-based UDP heuristic (open|filtered).")
        return SocketUdpScanner(), "udp", warnings
    return ConnectScanner(), "connect", warnings


# ---------------------------------------------------------------- service / SSL

class ServiceDetector:
    def __init__(self, timeout, color, ssl_detail=False):
        self.timeout = timeout
        self.color = color
        self.ssl_detail = ssl_detail

    def _probes(self, port, hostname=None):
        if port in (80, 8000, 8080, 8888):
            return [HTTP_PROBE.replace(b"{host}", (hostname or "localhost").encode())]
        if port == 6379:
            return [REDIS_PROBE]
        return []

    def detect(self, ip, port, hostname=None):
        out = {"port": port, "proto": "tcp", "state": OPEN,
               "service": PORT_DEFAULTS.get(port, "unknown"),
               "version": None, "banner": None, "ssl": None}
        # SSL first for TLS ports or explicit detail
        use_tls = port in TLS_PORTS or self.ssl_detail
        if use_tls:
            ssl_info = self.inspect_ssl(ip, port, hostname)
            if ssl_info.get("ssl"):
                out["service"] = PORT_DEFAULTS.get(port, "https")
                out["ssl"] = ssl_info
                return out
        banner = self.grab(ip, port, hostname)
        if banner:
            out["banner"] = banner[:512].decode("latin1", "replace")
            svc = self.match(banner, port)
            out["service"] = svc
            out["version"] = self.version(banner, svc)
        return out

    def grab(self, ip, port, hostname=None):
        try:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                s.settimeout(1.0)
                banner = b""
                try:
                    banner = s.recv(1024)
                except socket.timeout:
                    banner = b""
                if not banner:
                    for probe in self._probes(port, hostname):
                        try:
                            s.sendall(probe)
                            banner = s.recv(1024)
                        except (socket.timeout, OSError):
                            banner = b""
                        if banner:
                            break
                return banner
        except (socket.timeout, OSError):
            return b""

    @staticmethod
    def match(banner, port):
        for rx, svc in SIGNATURES:
            if rx.search(banner):
                return svc
        return PORT_DEFAULTS.get(port, "unknown")

    @staticmethod
    def version(banner, service):
        try:
            if service == "ssh":
                m = re.search(rb"SSH-\d+\.\d+[-\s]([^\s\r\n]+)", banner)
                return m.group(1).decode("latin1") if m else None
            if service in ("http", "http-alt", "http-proxy", "https-alt", "http-msrpc"):
                m = re.search(rb"Server:\s*([^\r\n]+)", banner)
                return m.group(1).strip().decode("latin1") if m else None
            line = banner.split(b"\r\n")[0].split(b"\n")[0].strip()
            return line.decode("latin1", "replace") if line else None
        except Exception:
            return None

    def inspect_ssl(self, ip, port, hostname=None):
        info = {"ssl": False}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sni = hostname if hostname and hostname != ip else None
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as s:
                    info["ssl"] = True
                    info["tls_version"] = s.version()
                    cipher = s.cipher()
                    info["cipher"] = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)" if cipher else None
                    cert = s.getpeercert()
                    if cert:
                        info["subject"] = self._fmt_name(cert.get("subject", []))
                        info["issuer"] = self._fmt_name(cert.get("issuer", []))
                        info["san"] = [v for _, v in cert.get("subjectAltName", [])]
                        info["not_before"] = cert.get("notBefore")
                        info["not_after"] = cert.get("notAfter")
                        info["days_remaining"] = self._days_left(cert.get("notAfter"))
                    else:
                        der = s.getpeercert(binary_form=True)
                        if der:
                            info.update(self._decode_cert_der(der))
            info["expired"] = bool(info.get("days_remaining") is not None and info["days_remaining"] < 0)
            info["warnings"] = []
            if info["expired"]:
                info["warnings"].append("CERTIFICATE EXPIRED")
            elif info.get("days_remaining") is not None and info["days_remaining"] < 30:
                info["warnings"].append(f"expires in {info['days_remaining']} days")
            return info
        except (ssl.SSLError, OSError, socket.timeout):
            return {"ssl": False}

    @staticmethod
    def _decode_cert_der(der):
        """Full cert decode using optional 'cryptography'; {} if unavailable."""
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)
            now = datetime.now(timezone.utc)

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
            nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            nb = nb.astimezone(timezone.utc) if nb.tzinfo else nb.replace(tzinfo=timezone.utc)
            na = na.astimezone(timezone.utc) if na.tzinfo else na.replace(tzinfo=timezone.utc)
            key = cert.public_key()
            return {
                "subject": name(cert.subject),
                "issuer": name(cert.issuer),
                "san": san,
                "not_before": nb.isoformat(),
                "not_after": na.isoformat(),
                "days_remaining": (na - now).days,
                "serial": format(cert.serial_number, "X"),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "public_key": f"{key.key_size}-bit {key.__class__.__name__.replace('_',' ')}",
            }
        except Exception:
            return {}

    @staticmethod
    def _fmt_name(pairs):
        parts = []
        for key, val in pairs:
            parts.append(f"{key}={val}")
        return ", ".join(parts)

    @staticmethod
    def _days_left(not_after):
        if not not_after:
            return None
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return (exp - datetime.now(timezone.utc)).days
        except Exception:
            return None


def guess_os(ttl, window=None):
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco/router"
    return "unknown"


# ---------------------------------------------------------------- host discovery

class Pinger:
    def __init__(self, timeout, color):
        self.timeout = timeout
        self.color = color

    def is_up(self, ip):
        sp = get_scapy()
        if sp is not None and is_admin():
            try:
                sp.conf.verb = 0
                ans, _ = sp.sr(sp.IP(dst=ip) / sp.ICMP(), timeout=min(self.timeout, 2.0),
                               verbose=0, retry=0)
                if ans and sp.ICMP in ans[0][1] and int(ans[0][1][sp.ICMP].type) == 0:
                    return True, 0.02, int(ans[0][1][sp.IP].ttl)
            except Exception:
                pass
        ttl = None
        for port in (80, 443, 22, 445):
            try:
                fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
                with socket.socket(fam, socket.SOCK_STREAM) as s:
                    s.settimeout(min(self.timeout, 0.8))
                    t0 = time.monotonic()
                    s.connect((ip, port))
                    lat = time.monotonic() - t0
                    return True, lat, ttl
            except OSError:
                continue
        return False, None, ttl


# ---------------------------------------------------------------- history & diff

class HistoryStore:
    def __init__(self, base=".pyscan_history"):
        self.base = base

    def _key(self, label, ip):
        safe = re.sub(r"[^\w.-]", "_", label or ip)
        return os.path.join(self.base, f"{safe}_{ip.replace(':', '_')}.json")

    def load(self, label, ip):
        path = self._key(label, ip)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def save(self, label, ip, data):
        os.makedirs(self.base, exist_ok=True)
        path = self._key(label, ip)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return path


class DiffEngine:
    def compare(self, prev, cur):
        prev_open = {p["port"]: p for p in (prev or {}).get("ports", []) if p.get("state") == OPEN}
        cur_open = {p["port"]: p for p in cur.get("ports", []) if p.get("state") == OPEN}
        added = [cur_open[p] for p in sorted(set(cur_open) - set(prev_open))]
        removed = [prev_open[p] for p in sorted(set(prev_open) - set(cur_open))]
        changed = []
        for p in sorted(set(cur_open) & set(prev_open)):
            a, b = prev_open[p], cur_open[p]
            if (a.get("service"), a.get("version")) != (b.get("service"), b.get("version")):
                changed.append((a, b))
        unchanged = len(set(cur_open) & set(prev_open)) - len(changed)
        return dict(added=added, removed=removed, changed=changed, unchanged=unchanged)

    def render(self, diff, color):
        lines = []
        for p in diff["added"]:
            lines.append(color.green(f"  [+] {p['port']}/{p['proto']} open (new) "
                                     f"{p.get('service','')} {p.get('version') or ''}".rstrip()))
        for p in diff["removed"]:
            lines.append(color.red(f"  [-] {p['port']}/{p['proto']} closed (was open "
                                   f"{p.get('service','')})".rstrip()))
        for old, new in diff["changed"]:
            lines.append(color.yellow(f"  [~] {new['port']}/{new['proto']} service changed "
                                      f"{old.get('service') or '?'} -> {new.get('service') or '?'}"))
        lines.append(color.dim(f"  unchanged: {diff['unchanged']} open port(s)"))
        return "\n".join(lines)


# ---------------------------------------------------------------- output

class OutputManager:
    def __init__(self, color, verbose=False):
        self.color = color
        self.verbose = verbose

    @staticmethod
    def _latency(t):
        t = t or 0.02
        return f"{t * 1000:.0f} ms" if t < 1 else f"{t:.2f} s"

    def render_text(self, targets, meta):
        lines = [f"Starting {TOOL} {VERSION} ( {URL} ) at {now_text()}"]
        lines += meta.get("warnings", [])
        for t in targets:
            label = t.label if t.label and t.label != t.ip else ""
            host = f"{t.ip} ({label})" if label else t.ip
            r = reverse_dns(t.ip)
            if r and not label:
                host = f"{t.ip} ({r})"
            lines.append("")
            lines.append(f"{TOOL} scan report for {host}")
            if t.error:
                lines.append(self.color.red(f"  Scan failed: {t.error}"))
                continue
            status = "up" if t.up else "unknown"
            lat = f" (latency {self._latency(t.latency)})" if t.latency else ""
            lines.append(f"Host is {status}{lat}.")
            if t.os_guess:
                guess = f"OS guess: {self.color.magenta(t.os_guess)} (ttl={t.ttl}"
                if t.window:
                    guess += f", window={t.window})"
                else:
                    guess += ")"
                lines.append(guess)
            if not t.ports:
                lines.append(self.color.dim("  All ports filtered or no open ports found."))
                continue
            lines.append("PORT     STATE        SERVICE     VERSION")
            for port in sorted(t.ports):
                pr = t.ports[port]
                state_color = {"open": self.color.green, "closed": self.color.red,
                               "filtered": self.color.dim, "open|filtered": self.color.yellow,
                               "unfiltered": self.color.cyan}.get(pr["state"], lambda x: x)
                state_str = state_color(pr["state"])
                svc = pr.get("service") or "unknown"
                ver = f" {pr.get('version') or ''}".rstrip()
                ssl_ = pr.get("ssl")
                line = f"{port:<6}/{pr.get('proto','tcp')}  {state_str:<10} {svc:<12} {ver}"
                if ssl_ and ssl_.get("ssl"):
                    line += f"  [TLS {ssl_.get('tls_version')}]"
                    if ssl_.get("warnings"):
                        line += self.color.yellow(f"  (cert {ssl_.get('warnings')[0]})")
                elif self.verbose and pr.get("banner"):
                    line += f"  {pr['banner'][:80]!r}"
                lines.append(line)
                if ssl_ and ssl_.get("ssl") and (ssl_.get("days_remaining") is not None or self.verbose):
                    lines.append(f"        |_ CN: {ssl_.get('subject')}")
                    lines.append(f"        |_ issuer: {ssl_.get('issuer')}")
                    lines.append(f"        |_ valid: {ssl_.get('not_after')} "
                                 f"({ssl_.get('days_remaining')}d left)  cipher: {ssl_.get('cipher')}")
                    if self.verbose:
                        lines.append(f"        |_ key: {ssl_.get('public_key')}  sig: {ssl_.get('signature_algorithm')}  "
                                     f"serial: {ssl_.get('serial')}  SAN: {', '.join(ssl_.get('san') or [])}")
        lines.append("")
        lines.append(f"{TOOL} done: {meta['host_count']} IP address(es) scanned "
                     f"in {meta['duration']:.2f} seconds")
        return "\n".join(lines)

    def render_grepable(self, targets, meta):
        lines = [f"# {TOOL} {VERSION} scan initiated {now_text()} as {meta.get('cmdline','')}",
                 f"# Hosts: {meta['host_count']} IP addresses scanned in {meta['duration']:.2f} seconds"]
        for t in targets:
            ports = ",".join(
                f"{p}/{t.ports[p]['proto']}/{t.ports[p]['state']}//{t.ports[p].get('service','')}/"
                f"{t.ports[p].get('version','') or ''}/"
                for p in sorted(t.ports)
            )
            hostname = t.label if t.label and t.label != t.ip else reverse_dns(t.ip) or ""
            lines.append(f"Host: {t.ip} ({hostname})")
            lines.append(f"Ports: {ports}".rstrip(","))
        return "\n".join(lines)

    def to_dict(self, targets, meta):
        hosts = []
        for t in targets:
            ports = [dict(t.ports[p]) for p in sorted(t.ports)]
            hosts.append({
                "ip": t.ip,
                "hostname": t.label if t.label and t.label != t.ip else reverse_dns(t.ip),
                "up": t.up,
                "latency": t.latency,
                "ttl": t.ttl,
                "os_guess": t.os_guess,
                "ports": ports,
            })
        return {
            "tool": TOOL,
            "version": VERSION,
            "started_at": meta.get("started_at"),
            "command_line": meta.get("cmdline"),
            "scan_type": meta.get("scan_type"),
            "duration_seconds": round(meta["duration"], 3),
            "hosts": hosts,
        }

    def render_xml(self, targets, meta):
        root = ET.Element("nmaprun", {"scanner": TOOL.lower(), "args": meta.get("cmdline", ""),
                                      "start": str(int(time.time())), "version": VERSION})
        h = ET.SubElement(root, "scaninfo", {"type": meta.get("scan_type", ""), "protocol": "tcp"})
        for t in targets:
            host = ET.SubElement(root, "host")
            ET.SubElement(host, "status", {"state": "up" if t.up else "unknown",
                                           "latency": f"{t.latency or 0.02:.2f}s"})
            ET.SubElement(host, "address", {"addr": t.ip, "addrtype": "ipv4" if ":" not in t.ip else "ipv6"})
            if t.label and t.label != t.ip:
                hn = ET.SubElement(host, "hostnames")
                ET.SubElement(hn, "hostname", {"name": t.label, "type": "user"})
            if t.os_guess:
                ET.SubElement(host, "os", {"guess": t.os_guess, "ttl": str(t.ttl)})
            for p in sorted(t.ports):
                pr = t.ports[p]
                port = ET.SubElement(host, "port", {"protocol": pr.get("proto", "tcp"), "portid": str(p)})
                ET.SubElement(port, "state", {"state": pr["state"], "reason": "syn-ack"})
                svc = ET.SubElement(port, "service", {"name": pr.get("service", ""), "version": pr.get("version") or ""})
                if pr.get("ssl") and pr["ssl"].get("ssl"):
                    ET.SubElement(svc, "cert", {"subject": pr["ssl"].get("subject", ""),
                                                "notafter": pr["ssl"].get("not_after", ""),
                                                "days_remaining": str(pr["ssl"].get("days_remaining", ""))})
        ET.indent(root)
        return ET.tostring(root, encoding="unicode", xml_declaration=True)


def write_outputs(args, targets, meta, color):
    om = OutputManager(color, verbose=args.verbose)
    data = om.to_dict(targets, meta)
    if args.output_text:
        with open(args.output_text, "w", encoding="utf-8") as f:
            f.write(om.render_text(targets, meta) + "\n")
    if args.output_xml:
        with open(args.output_xml, "w", encoding="utf-8") as f:
            f.write(om.render_xml(targets, meta) + "\n")
    if args.output_grep:
        with open(args.output_grep, "w", encoding="utf-8") as f:
            f.write(om.render_grepable(targets, meta) + "\n")
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="pyscan",
        description=f"{TOOL} {VERSION} - advanced port scanner (nmap-like + extras: JSON, history-diff, SSL detail).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  pyscan.py -sT -p 1-1000 example.com\n"
                "  pyscan.py -sS -sV -T4 -p- 192.168.1.10\n"
                "  pyscan.py --diff -p- example.com\n"
                "  pyscan.py --ssl-detail -p 443 example.com\n"
                "  pyscan.py -sT -oJ report.json 10.0.0.0/24\n"))
    p.add_argument("targets", nargs="+", help="hostnames, IPs, CIDRs or ranges")
    for flag, (desc, key) in SCAN_HELP.items():
        p.add_argument(f"-{flag}", dest="scan_mode", action="store_const", const=key, help=desc)
    p.add_argument("-p", "--ports", help="port list: 22,80-100,443 ; '-' or '-p-' = all 1-65535")
    p.add_argument("--top-ports", type=int, default=0, metavar="N",
                   help="scan the N most common ports")
    p.add_argument("-T", "--timing", type=int, default=3, choices=range(6), metavar="0-5",
                   help="timing template (0=paranoid .. 5=insane), default 3")
    p.add_argument("-sV", "--service-version", action="store_true", help="service/version detection + banner grab")
    p.add_argument("-sC", "--banner", action="store_true", help="alias: banner grab + service detection")
    p.add_argument("-sn", "--ping-scan", action="store_true", help="host discovery only (no port scan)")
    p.add_argument("-O", "--os-guess", action="store_true", help="guess OS from TTL/window (raw scans)")
    p.add_argument("--ssl-detail", action="store_true", help="deep SSL/TLS inspection of TLS ports")
    p.add_argument("--diff", action="store_true", help="diff against previous scan of same target (exit 1 on change)")
    p.add_argument("--history-dir", default=".pyscan_history", help="history dir for --diff (default .pyscan_history)")
    p.add_argument("-oN", dest="output_text", metavar="FILE", help="normal text output")
    p.add_argument("-oX", dest="output_xml", metavar="FILE", help="XML output (nmap-style)")
    p.add_argument("-oG", dest="output_grep", metavar="FILE", help="grepable output")
    p.add_argument("-oJ", dest="output_json", metavar="FILE", help="JSON output")
    p.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--timeout", type=float, metavar="SEC", help="per-port timeout override")
    return p


def preprocess_argv(argv):
    out = []
    for a in argv:
        if a in ("-p-", "--ports-", "-p-1-65535"):
            out += ["-p", "-"]
        else:
            out.append(a)
    return out


# ---------------------------------------------------------------- engine

def scan_host(t, scanner, cfg, args, color, service_detector):
    try:
        result = scanner.scan_host(t.ip, list(t.ports), cfg)
    except RawScanFailed as e:
        t.error = str(e)
        return
    t.ports = {}
    for port, state in result.items():
        t.ports[port] = {"port": port, "proto": scanner.proto, "state": state,
                         "service": None, "version": None, "banner": None, "ssl": None}
    if hasattr(scanner, "last_ttl"):
        t.ttl = getattr(scanner, "last_ttl", None)
        t.window = getattr(scanner, "last_window", None)
    open_ports = [p for p, pr in t.ports.items() if pr["state"] == OPEN]
    if open_ports and scanner.proto == "tcp" and (args.service_version or args.banner or args.ssl_detail):
        with ThreadPoolExecutor(max_workers=min(20, len(open_ports))) as ex:
            hostname = t.label if t.label and t.label != t.ip else None
            futs = {ex.submit(service_detector.detect, t.ip, p, hostname): p for p in open_ports}
            for f in as_completed(futs):
                info = f.result()
                p = futs[f]
                t.ports[p].update({k: v for k, v in info.items() if v is not None})
    else:
        for p in open_ports:
            t.ports[p]["service"] = PORT_DEFAULTS.get(p, "unknown")
    if args.os_guess and t.ttl:
        t.os_guess = guess_os(t.ttl, t.window)


def run(args):
    color = Color(enabled=not args.no_color and sys.stdout.isatty())
    cfg = Config(args.timing, timeout=args.timeout)

    mode = args.scan_mode or "connect"
    scanner, effective_mode, warnings = choose_scanner(mode, color)
    if args.scan_mode and effective_mode != args.scan_mode:
        for w in warnings:
            print(color.yellow(f"PyScan warning: {w}"), file=sys.stderr)

    if args.top_ports:
        ports = parse_top_ports(args.top_ports)
    else:
        ports = parse_port_spec(args.ports)
    if len(ports) > 65535:
        ports = list(range(1, 65536))

    targets = expand_targets(args.targets)
    if not targets:
        print("PyScan: no valid targets.", file=sys.stderr)
        return 2

    pinger = Pinger(cfg.timeout, color)
    if args.ping_scan:
        for t in targets:
            up, lat, ttl = pinger.is_up(t.ip)
            status = "Host is up" if up else "Host seems down"
            suffix = f" (latency {lat * 1000:.2f} ms)" if lat else ""
            name = f" ({t.label})" if t.label and t.label != t.ip else ""
            print(f"{status}: {t.ip}{name}{suffix}")
        return 0

    meta = {"warnings": warnings, "started_at": now_iso(),
            "cmdline": " ".join(sys.argv), "scan_type": effective_mode}

    # host discovery pass (informational)
    for t in targets:
        up, lat, ttl = pinger.is_up(t.ip)
        t.up = up if up is not None else None
        t.latency = lat
        if ttl:
            t.ttl = ttl

    # pre-scan host target ports
    for t in targets:
        t.ports = {p: None for p in ports}

    def do_scan():
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=host_workers) as ex:
            futs = {ex.submit(scan_host, t, scanner, cfg, args, color, service_detector): t for t in targets}
            for f in as_completed(futs):
                pass
        return time.monotonic() - start

    service_detector = ServiceDetector(min(cfg.timeout, 3.0), color, ssl_detail=args.ssl_detail)
    host_workers = max(1, cfg.host_workers)
    meta["duration"] = do_scan()
    if any(t.error for t in targets):
        print(color.yellow(f"{effective_mode.upper()} scan failed (raw sockets unavailable); "
                           "falling back to connect scan."), file=sys.stderr)
        for t in targets:
            t.error = None
        scanner = ConnectScanner()
        effective_mode = "connect"
        meta["scan_type"] = effective_mode
        meta["duration"] = do_scan()
    meta["host_count"] = len(targets)

    report = OutputManager(color).render_text(targets, meta)
    print(color.bold(report))
    write_outputs(args, targets, meta, color)

    exit_code = 0
    if args.diff:
        store = HistoryStore(args.history_dir)
        engine = DiffEngine()
        any_change = False
        for t in targets:
            if t.error:
                continue
            cur = {"scanned_at": meta["started_at"],
                   "ports": [t.ports[p] for p in sorted(t.ports) if t.ports[p] is not None and t.ports[p]["state"] == OPEN]}
            prev = store.load(t.label or t.ip, t.ip)
            store.save(t.label or t.ip, t.ip, cur)
            if not prev:
                print(color.dim(f"\nDiff ({t.ip}): no previous scan stored; saved baseline."))
                continue
            d = engine.compare(prev, cur)
            if d["added"] or d["removed"] or d["changed"]:
                any_change = True
            print(color.bold(f"\nDiff report for {t.ip} vs previous scan "
                             f"(baseline {prev.get('scanned_at', '?')}):"))
            print(engine.render(d, color))
        if any_change:
            exit_code = 1
    return exit_code


def main():
    enable_ansi_windows()
    argv = preprocess_argv(sys.argv[1:])
    args = build_parser().parse_args(argv)
    sys.exit(run(args))


if __name__ == "__main__":
    main()
