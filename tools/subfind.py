#!/usr/bin/env python3
import argparse
import json
import random
import socket
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

TOOL = "SubFind"
VERSION = "1.0.0"
TEAM = "Digital Core team"

Q_A = 1
Q_NS = 2
Q_AAAA = 28
Q_AXFR = 252

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
          8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}

TOP_WORDS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn",
    "dns", "ns1", "ns2", "ns3", "mx", "api", "dev", "test", "stage",
    "staging", "demo", "beta", "alpha", "admin", "portal", "app", "blog",
    "shop", "store", "cdn", "assets", "static", "www2", "webmail", "m",
    "mobile", "secure", "billing", "support", "help", "docs", "status",
    "internal", "intranet", "office", "owa", "autodiscover", "remote",
    "git", "jenkins", "ci", "grafana", "kibana", "db", "mysql", "redis",
    "mongo", "backup", "files", "data",
]

_print_lock = threading.Lock()


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


def now_str():
    return datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def vprint(color, msg, verbose, level=1):
    if verbose >= level:
        with _print_lock:
            print(msg, file=sys.stderr)


def escape_label(raw):
    out = []
    for byte in raw:
        if 0x20 <= byte <= 0x7E and byte not in (ord("."), ord("\\")):
            out.append(chr(byte))
        else:
            out.append("\\%03d" % byte)
    return "".join(out)


def encode_qname(name):
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = b""
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("idna")
        if len(b) > 63:
            raise ValueError(f"label quá dài: {label!r}")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def decode_name(data, offset, end=None):
    labels = []
    pos = offset
    endpos = None
    jumps = 0
    seen = set()
    limit = end if end is not None else len(data)
    while True:
        if pos >= limit:
            raise ValueError("tên vượt quá cuối vùng dữ liệu")
        b = data[pos]
        if b & 0xC0 == 0xC0:
            if endpos is None:
                endpos = pos + 2
            ptr = ((b & 0x3F) << 8) | data[pos + 1]
            if ptr in seen or jumps > 30:
                raise ValueError("con trỏ tên không hợp lệ")
            seen.add(ptr)
            jumps += 1
            pos = ptr
            continue
        if b == 0:
            if endpos is None:
                endpos = pos + 1
            break
        if end is not None and pos + 1 + b > end:
            raise ValueError("tên vượt quá độ dài rdata")
        labels.append(escape_label(data[pos + 1:pos + 1 + b]))
        pos += 1 + b
    return ".".join(labels), (endpos if endpos is not None else pos)


def build_query(qid, qname, qtype, rd=True):
    flags = 0x0100 if rd else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_answer(data):
    if len(data) < 12:
        raise ValueError("gói tin quá ngắn")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0xF
    pos = 12
    for _ in range(qd):
        _, pos = decode_name(data, pos)
        pos += 4
    recs = []
    for _ in range(an):
        name, pos = decode_name(data, pos)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        rd = data[pos:pos + rdlen]
        text = ""
        if rtype == Q_A and len(rd) == 4:
            text = socket.inet_ntop(socket.AF_INET, rd)
        elif rtype == Q_AAAA and len(rd) == 16:
            text = socket.inet_ntop(socket.AF_INET6, rd)
        elif rtype in (Q_NS, 5) and rdlen:
            text = decode_name(data, pos, pos + rdlen)[0]
        recs.append({"name": name, "type": rtype, "class": rclass,
                     "ttl": ttl, "text": text})
        pos += rdlen
    return rcode, recs


def udp_query(server, port, qname, qtype, timeout, retries, rd=True):
    last = None
    for _ in range(retries + 1):
        qid = random.randint(0, 65535)
        msg = build_query(qid, qname, qtype, rd)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, (server, port))
            deadline = time.time() + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise socket.timeout("timed out")
                sock.settimeout(remaining)
                data, _ = sock.recvfrom(65535)
                if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == qid:
                    return data
        except socket.timeout:
            last = "timeout"
        finally:
            sock.close()
    raise TimeoutError(last or "timeout")


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("kết nối đóng sớm")
        data += chunk
    return data


def axfr_transfer(server, port, qname, timeout):
    names = set()
    qid = random.randint(0, 65535)
    msg = build_query(qid, qname, Q_AXFR, rd=False)
    sock = socket.create_connection((server, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(struct.pack("!H", len(msg)) + msg)
        closing_soa = None
        total = 0
        while total < 100000:
            size = struct.unpack("!H", read_exact(sock, 2))[0]
            data = read_exact(sock, size)
            total += 1
            rcode, recs = parse_answer(data)
            if rcode != 0:
                break
            for r in recs:
                if r["type"] == 6:
                    owner = r["name"].rstrip(".").lower()
                    if closing_soa is None:
                        closing_soa = owner
                    elif owner == closing_soa:
                        return names
                else:
                    names.add(r["name"].rstrip(".").lower())
    finally:
        sock.close()
    return names


class Resolver:
    def __init__(self, servers, port=53, timeout=3.0, retries=2):
        self.servers = servers or ["1.1.1.1"]
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.ok = False

    def query(self, name, qtype, rd=True):
        qname = encode_qname(name)
        errors = []
        for srv in self.servers:
            try:
                data = udp_query(srv, self.port, qname, qtype,
                                 self.timeout, self.retries, rd)
                self.ok = True
                return parse_answer(data)
            except Exception as e:
                errors.append(f"{srv}: {e}")
        raise RuntimeError("; ".join(errors))

    def resolve(self, name):
        ips = set()
        for qt in (Q_A, Q_AAAA):
            try:
                _, recs = self.query(name, qt)
            except RuntimeError:
                continue
            for r in recs:
                if r["type"] == qt and r["text"]:
                    ips.add(r["text"])
        return ips


def valid_domain(domain):
    d = domain.strip().lower().rstrip(".")
    if not d or len(d) > 253 or any(ch.isspace() for ch in d) or ".." in d:
        return None
    for label in d.split("."):
        if not label or len(label) > 63:
            return None
    return d


def crt_subdomains(domain):
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    req = urllib.request.Request(
        url, headers={"User-Agent": f"{TOOL}/{VERSION} (subdomain finder)"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except Exception as e:
        raise RuntimeError(f"crt.sh: {e}")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("crt.sh: JSON không hợp lệ (server có thể đang quá tải)")
    names = set()
    for e in entries:
        for n in (e.get("name_value") or "").split("\n"):
            n = n.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if n and (n == domain or n.endswith("." + domain)):
                names.add(n)
    return names


def load_words(path):
    words = []
    seen = set()
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                w = line.strip().lower()
                if not w or w.startswith("#") or w in seen:
                    continue
                seen.add(w)
                words.append(w)
    except OSError as e:
        raise RuntimeError(f"không đọc được wordlist: {e}")
    return words


def brute_force(resolver, domain, words, wildcard_ips, threads, verbose, color):
    found = {}
    lock = threading.Lock()
    counted = [0]

    def work(word):
        if "." in word or any(not c.isalnum() and c not in "-_" for c in word):
            return None
        name = f"{word}.{domain}"
        ips = resolver.resolve(name)
        if not ips:
            return None
        if wildcard_ips and ips <= wildcard_ips:
            return None
        with lock:
            counted[0] += 1
            if verbose:
                print(color.green(f"[+] {name}") + (f"  {sorted(ips)}" if verbose > 1 else ""),
                      file=sys.stderr)
        return name, ips

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(work, words):
            if result:
                name, ips = result
                found[name] = set(ips)
    return found


def get_ns_ips(resolver, domain):
    try:
        _, recs = resolver.query(domain, Q_NS)
    except RuntimeError:
        return []
    targets = {r["text"].rstrip(".").lower() for r in recs
               if r["type"] == Q_NS and r["text"]}
    ips = set()
    for t in targets:
        try:
            ips |= resolver.resolve(t)
        except RuntimeError:
            continue
    return sorted(ips)


def try_axfr(resolver, domain, port, timeout):
    names = set()
    for ip in get_ns_ips(resolver, domain):
        try:
            got = axfr_transfer(ip, port, encode_qname(domain), timeout)
        except Exception:
            continue
        if got:
            names |= got
            break
    return names


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="subfind",
        description=f"{TOOL} {VERSION} - subdomain finder ({TEAM}). "
                    "Python thuần, không cần cài đặt.",
        epilog="Vi du:\n"
               "  subfind.py example.com\n"
               "  subfind.py example.com --top 100\n"
               "  subfind.py example.com -w wordlist.txt --resolve\n"
               "  subfind.py example.com --axfr -s 8.8.8.8\n"
               "  subfind.py example.com -w list.txt --json -o out.json")
    ap.add_argument("domain", help="ten mien can tim subdomain")
    ap.add_argument("-w", "--wordlist", metavar="FILE",
                    help="wordlist de brute-force ten con (moi dong mot ten)")
    ap.add_argument("--top", type=int, default=0, metavar="N",
                    help="dung N ten pho bien nhat tu bo wordlist tich hop (mac dinh 0 = tat)")
    ap.add_argument("--no-crt", action="store_true",
                    help="tat nguon Certificate Transparency (crt.sh)")
    ap.add_argument("--axfr", action="store_true",
                    help="thu chuyen vung (AXFR) qua TCP tren cac nameserver cua mien")
    ap.add_argument("--resolve", action="store_true",
                    help="phai giai (A/AAAA) cac ten tim duoc va hien thi IP")
    ap.add_argument("-s", "--server", action="append",
                    help="DNS server (nhieu lan duoc; mac dinh lay tu he thong)")
    ap.add_argument("-p", "--port", type=int, default=53,
                    help="port DNS (mac dinh 53)")
    ap.add_argument("-T", "--threads", type=int, default=40,
                    help="so luong thread brute-force (mac dinh 40)")
    ap.add_argument("--timeout", type=float, default=3.0,
                    help="timeout moi query DNS (giay, mac dinh 3)")
    ap.add_argument("--retries", type=int, default=2,
                    help="so lan thu lai moi query (mac dinh 2)")
    ap.add_argument("--short", action="store_true",
                    help="chi in ten subdomain, moi dong mot ten")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="chi tiet hon (in ten tim duoc khi brute-force)")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    color = Color(enabled=not args.no_color)
    domain = valid_domain(args.domain)
    if not domain:
        print(f"{TOOL}: ten mien khong hop le: {args.domain}", file=sys.stderr)
        return 3

    servers = args.server or ["1.1.1.1"]
    resolver = Resolver(servers, port=args.port, timeout=args.timeout,
                        retries=args.retries)

    start = time.time()
    found = {}
    source_counts = {"crt.sh": 0, "bruteforce": 0, "axfr": 0}
    wildcard_ips = set()
    notes = []

    if not args.no_crt:
        try:
            names = crt_subdomains(domain)
            source_counts["crt.sh"] = len(names)
            for n in names:
                found.setdefault(n, set())
            vprint(color, color.dim(f"[i] crt.sh: {len(names)} ten"), args.verbose)
        except RuntimeError as e:
            notes.append(str(e))
            vprint(color, color.yellow(f"[!] {e}"), args.verbose)

    words = []
    if args.wordlist:
        try:
            words = load_words(args.wordlist)
        except RuntimeError as e:
            print(f"{TOOL}: {e}", file=sys.stderr)
            return 3
    elif args.top > 0:
        words = TOP_WORDS[:args.top]

    if words:
        probe = f"sf-probe-{random.randint(10**8, 10**9)}.{domain}"
        wildcard_ips = resolver.resolve(probe)
        if wildcard_ips:
            notes.append(f"phat hien wildcard DNS -> {sorted(wildcard_ips)} "
                         f"(ket qua trung wildcard se bi loai)")
            vprint(color, color.yellow(f"[!] wildcard: {sorted(wildcard_ips)}"),
                   args.verbose, level=1)
        bf = brute_force(resolver, domain, words, wildcard_ips,
                         args.threads, args.verbose, color)
        source_counts["bruteforce"] = len(bf)
        found.update(bf)
        vprint(color, color.dim(f"[i] brute-force: xong ({len(words)} ten thu, "
                                f"{len(bf)} tim duoc)"), args.verbose)

    if args.axfr:
        ax_names = try_axfr(resolver, domain, args.port, args.timeout)
        source_counts["axfr"] = len(ax_names)
        for n in ax_names:
            found.setdefault(n, set())
        vprint(color, color.dim(f"[i] AXFR: {len(ax_names)} ten"), args.verbose)

    if args.resolve:
        for n in list(found):
            found[n] |= resolver.resolve(n)

    names_sorted = sorted(found)
    total = len(names_sorted)
    elapsed = time.time() - start

    results = [{"name": n, "ips": sorted(found[n])} for n in names_sorted]

    if args.json:
        data = {
            "tool": TOOL, "version": VERSION, "team": TEAM,
            "domain": domain, "queried_at": datetime.now().astimezone().isoformat(),
            "sources": source_counts, "wildcard": sorted(wildcard_ips),
            "notes": notes, "time_sec": round(elapsed, 2),
            "total": total, "subdomains": results,
        }
        text = json.dumps(data, indent=2, ensure_ascii=False)
    else:
        parts = [f";; {TOOL} {VERSION} <<>> {domain}"]
        parts.append(f";; crt.sh: {source_counts['crt.sh']} | "
                     f"brute-force: {source_counts['bruteforce']} | "
                     f"AXFR: {source_counts['axfr']}")
        if wildcard_ips:
            parts.append(color.yellow(f";; wildcard: {sorted(wildcard_ips)}"))
        if args.short:
            parts.append("")
            parts.extend(names_sorted)
        else:
            parts.append("")
            for r in results:
                line = r["name"]
                if args.resolve and r["ips"]:
                    line += "  " + color.cyan(", ".join(r["ips"]))
                parts.append(line)
            parts.append("")
        parts.append(color.bold(f";; {total} subdomain(s) trong {elapsed:.1f} s"))
        if notes:
            parts.append(";; ghi chu: " + "; ".join(notes))
        text = "\n".join(parts)

    print(text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"{TOOL}: khong ghi duoc file: {e}", file=sys.stderr)
            return 3

    if total == 0:
        crt_net_failed = any(n.startswith("crt.sh") for n in notes)
        any_dns = args.wordlist or args.top > 0 or args.axfr
        if not resolver.ok and (any_dns or crt_net_failed):
            return 2
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
