#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import json
import random
import socket
import struct
import sys
import time
from datetime import datetime

TOOL = "DnsLookup"
VERSION = "1.0.0"
TEAM = "Digital Core team"

QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "HINFO": 13,
    "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35,
    "DS": 43, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "NSEC3": 50,
    "TLSA": 52, "SPF": 99, "CAA": 257, "HTTPS": 65, "ANY": 255,
}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
QTYPE_NAMES[41] = "OPT"

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
          8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS"}

ROOT_HINTS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
]

B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"


def b32hex_encode(data):
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * ((5 - len(bits) % 5) % 5)
    out = "".join(B32HEX[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))
    return out


def now_str():
    return datetime.now().strftime("%a %b %d %H:%M:%S %Y")


def build_query(qid, qname, qtype, rd=True, edns_size=None, do_bit=False):
    flags = 0x0100 if rd else 0
    arcount = 0
    opts = b""
    if edns_size is not None or do_bit:
        opts = (b"\x00" + struct.pack("!HHIH", 41,
                edns_size if edns_size is not None else 1232,
               0x8000 if do_bit else 0, 0))
        arcount = 1
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, arcount)
    return header + qname + struct.pack("!HH", qtype, 1) + opts


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


def escape_label(raw):
    out = []
    for byte in raw:
        if 0x20 <= byte <= 0x7E and byte not in (ord("."), ord("\\"), ord('"')):
            out.append(chr(byte))
        else:
            out.append("\\%03d" % byte)
    return "".join(out)


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
            if ptr in seen or jumps > 40:
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


def decode_txt(data):
    parts = []
    pos = 0
    while pos < len(data):
        n = data[pos]
        pos += 1
        parts.append(data[pos:pos + n].decode("utf-8", "replace"))
        pos += n
    return parts


def decode_type_bitmap(data):
    types = []
    pos = 0
    while pos + 2 <= len(data):
        window = data[pos]
        blen = data[pos + 1]
        pos += 2
        if pos + blen > len(data):
            break
        for i in range(blen):
            byte = data[pos + i]
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.append(window * 256 + i * 8 + bit)
        pos += blen
    return types


def decode_rdata(rtype, payload, msgdata, rdata_off):
    name_end = rdata_off + len(payload)
    r = {"type": QTYPE_NAMES.get(rtype, str(rtype))}

    def dname():
        return decode_name(msgdata, rdata_off, name_end)[0]

    def dname_at(off):
        return decode_name(msgdata, rdata_off + off, name_end)[0]

    if rtype == 1:
        r["address"] = socket.inet_ntop(socket.AF_INET, payload)
    elif rtype == 28:
        r["address"] = socket.inet_ntop(socket.AF_INET6, payload)
    elif rtype in (2, 5, 12):
        r["target"] = dname()
    elif rtype == 15:
        r["preference"] = struct.unpack("!H", payload[:2])[0]
        r["exchange"] = dname_at(2)
    elif rtype in (16, 99):
        r["strings"] = decode_txt(payload)
    elif rtype == 13:
        n1 = payload[0]
        r["cpu"] = payload[1:1 + n1].decode("utf-8", "replace")
        r["os"] = payload[1 + n1:].decode("utf-8", "replace")
    elif rtype == 6:
        r["mname"] = dname_at(0)
        pos = decode_name(msgdata, rdata_off, name_end)[1] - rdata_off
        r["rname"] = dname_at(pos)
        pos = decode_name(msgdata, rdata_off + pos, name_end)[1] - rdata_off
        r["serial"], r["refresh"], r["retry"], r["expire"], r["minimum"] = \
            struct.unpack("!IIIII", payload[pos:pos + 20])
    elif rtype == 33:
        r["priority"], r["weight"], r["port"] = struct.unpack("!HHH", payload[:6])
        r["target"] = dname_at(6)
    elif rtype == 35:
        order, pref = struct.unpack("!HH", payload[:4])
        r["order"], r["preference"] = order, pref
        pos = 4
        for key in ("flags", "services", "regexp"):
            n = payload[pos]
            r[key] = payload[pos + 1:pos + 1 + n].decode("utf-8", "replace")
            pos += 1 + n
        r["replacement"] = decode_name(msgdata, rdata_off + pos, name_end)[0]
    elif rtype == 257:
        r["flags"] = payload[0]
        n = payload[1]
        r["tag"] = payload[2:2 + n].decode("ascii", "replace")
        r["value"] = payload[2 + n:].decode("utf-8", "replace")
    elif rtype == 43:
        r["key_tag"] = struct.unpack("!H", payload[:2])[0]
        r["algorithm"] = payload[2]
        r["digest_type"] = payload[3]
        r["digest"] = payload[4:].hex()
    elif rtype == 48:
        r["flags"] = struct.unpack("!H", payload[:2])[0]
        r["protocol"] = payload[2]
        r["algorithm"] = payload[3]
        r["public_key"] = base64.b64encode(payload[4:]).decode()
    elif rtype == 46:
        r["type_covered"] = QTYPE_NAMES.get(struct.unpack("!H", payload[:2])[0],
                                            str(struct.unpack("!H", payload[:2])[0]))
        r["algorithm"] = payload[2]
        r["labels"] = payload[3]
        r["original_ttl"], r["expiration"], r["inception"] = \
            struct.unpack("!III", payload[4:16])
        r["key_tag"] = struct.unpack("!H", payload[16:18])[0]
        r["signer"] = decode_name(msgdata, rdata_off + 18, name_end)[0]
        sn_off = decode_name(msgdata, rdata_off + 18, name_end)[1] - rdata_off
        r["signature"] = base64.b64encode(payload[sn_off:]).decode()
    elif rtype == 47:
        r["next_domain"] = dname()
        consumed = decode_name(msgdata, rdata_off, name_end)[1] - rdata_off
        r["types"] = [QTYPE_NAMES.get(t, str(t))
                      for t in decode_type_bitmap(payload[consumed:])]
    elif rtype == 50:
        r["hash_algorithm"] = payload[0]
        r["flags"] = payload[1]
        r["iterations"] = struct.unpack("!H", payload[2:4])[0]
        pos = 4
        saltlen = payload[pos]
        r["salt"] = payload[pos + 1:pos + 1 + saltlen].hex() or "-"
        pos += 1 + saltlen
        hlen = payload[pos]
        r["next_hashed_owner"] = b32hex_encode(payload[pos + 1:pos + 1 + hlen])
        pos += 1 + hlen
        r["types"] = [QTYPE_NAMES.get(t, str(t))
                      for t in decode_type_bitmap(payload[pos:])]
    elif rtype == 52:
        r["usage"], r["selector"], r["matching_type"] = payload[0], payload[1], payload[2]
        r["certificate"] = payload[3:].hex()
    elif rtype == 65:
        r["priority"] = struct.unpack("!H", payload[:2])[0]
        r["target"] = decode_name(msgdata, rdata_off + 2, name_end)[0]
        pos = decode_name(msgdata, rdata_off + 2, name_end)[1] - rdata_off
        params = []
        while pos + 4 <= len(payload):
            key = struct.unpack("!H", payload[pos:pos + 2])[0]
            plen = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
            pos += 4
            val = payload[pos:pos + plen]
            pos += plen
            params.append(format_svcb_param(key, val))
        r["params"] = params
    else:
        r["raw"] = payload.hex()

    text = format_rdata(rtype, r)
    return text, r


def format_svcb_param(key, val):
    names = {0: "mandatory", 1: "alpn", 2: "no-default-alpn",
             3: "port", 4: "ipv4hint", 5: "ech", 6: "ipv6hint",
             7: "dohpath", 8: "ohttp"}
    name = names.get(key, f"key{key}")
    if key == 0:
        codes = []
        for i in range(0, len(val) - 1, 2):
            c = struct.unpack("!H", val[i:i + 2])[0]
            codes.append(names.get(c, f"key{c}"))
        return f"{name}={','.join(codes)}"
    if key == 1:
        strings = []
        pos = 0
        while pos < len(val):
            n = val[pos]
            strings.append(val[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n
        return f"{name}=\"{','.join(strings)}\""
    if key == 3:
        return f"{name}={struct.unpack('!H', val[:2])[0]}"
    if key == 4:
        addrs = []
        for i in range(0, len(val) - 3, 4):
            addrs.append(socket.inet_ntop(socket.AF_INET, val[i:i + 4]))
        return f"{name}={','.join(addrs)}"
    if key == 6:
        addrs = []
        for i in range(0, len(val) - 15, 16):
            addrs.append(socket.inet_ntop(socket.AF_INET6, val[i:i + 16]))
        return f"{name}={','.join(addrs)}"
    if key in (5, 8):
        return f"{name}={val.hex()}"
    return f"{name}={val.decode('utf-8', 'replace')}"


def format_rdata(rtype, r):
    if rtype == 1:
        return r["address"]
    if rtype == 28:
        return r["address"]
    if rtype in (2, 5, 12):
        return r["target"]
    if rtype == 15:
        return f'{r["preference"]} {r["exchange"]}'
    if rtype in (16, 99):
        return " ".join('"' + s.replace('"', '\\"') + '"' for s in r["strings"])
    if rtype == 13:
        return f'"{r["cpu"]}" "{r["os"]}"'
    if rtype == 6:
        return (f'{r["mname"]} {r["rname"]} {r["serial"]} {r["refresh"]} '
                f'{r["retry"]} {r["expire"]} {r["minimum"]}')
    if rtype == 33:
        return f'{r["priority"]} {r["weight"]} {r["port"]} {r["target"]}'
    if rtype == 35:
        return (f'{r["order"]} {r["preference"]} "{r["flags"]}" '
                f'"{r["services"]}" "{r["regexp"]}" {r["replacement"]}')
    if rtype == 257:
        return f'{r["flags"]} {r["tag"]} "{r["value"]}"'
    if rtype == 43:
        return (f'{r["key_tag"]} {r["algorithm"]} {r["digest_type"]} '
                f'{r["digest"]}')
    if rtype == 48:
        return f'{r["flags"]} {r["protocol"]} {r["algorithm"]} {r["public_key"]}'
    if rtype == 46:
        return (f'{r["type_covered"]} {r["algorithm"]} {r["labels"]} '
                f'{r["original_ttl"]} {r["expiration"]} {r["inception"]} '
                f'{r["key_tag"]} {r["signer"]} {r["signature"]}')
    if rtype == 47:
        return f'{r["next_domain"]} ' + " ".join(r["types"])
    if rtype == 50:
        return (f'{r["hash_algorithm"]} {r["flags"]} {r["iterations"]} '
                f'{r["salt"]} {r["next_hashed_owner"]} ' + " ".join(r["types"]))
    if rtype == 52:
        return f'{r["usage"]} {r["selector"]} {r["matching_type"]} {r["certificate"]}'
    if rtype == 65:
        out = f'{r["priority"]} {r["target"]}'
        for p in r.get("params", []):
            out += f' {p}'
        return out
    return r.get("raw", "?")


def parse_header(data):
    if len(data) < 12:
        raise ValueError("gói tin quá ngắn")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    return {
        "id": qid, "flags": flags,
        "qr": bool(flags & 0x8000), "opcode": (flags >> 11) & 0xF,
        "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100), "ra": bool(flags & 0x0080),
        "ad": bool(flags & 0x0020), "cd": bool(flags & 0x0010),
        "rcode": flags & 0xF, "qdcount": qd, "ancount": an,
        "nscount": ns, "arcount": ar,
    }


def parse_rr(data, offset):
    end = len(data)
    name, pos = decode_name(data, offset, end)
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
    pos += 10
    rdata_off = pos
    payload = data[pos:pos + rdlen]
    pos += rdlen
    if rtype == 41:
        udp_size = rclass
        text = f"udp_size={udp_size}"
        rec = {"name": name, "type": "OPT", "class": rclass, "ttl": ttl,
               "rdata": {"udp_size": udp_size, "do": bool(ttl & 0x8000)},
               "text": text}
        return rec, pos
    text, r = decode_rdata(rtype, payload, data, rdata_off)
    rec = {"name": name, "type": QTYPE_NAMES.get(rtype, str(rtype)),
           "class": "IN", "ttl": ttl, "rdata": r, "text": text}
    return rec, pos


def parse_response(data, qname, qtype):
    h = parse_header(data)
    pos = 12
    questions = []
    for _ in range(h["qdcount"]):
        qn, pos = decode_name(data, pos, len(data))
        t, c = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        questions.append({"name": qn, "type": QTYPE_NAMES.get(t, str(t)),
                          "class": "IN", "qtype": t})
    sections = {"answer": [], "authority": [], "additional": []}
    counts = {"answer": h["ancount"], "authority": h["nscount"],
              "additional": h["arcount"]}
    for sec in ("answer", "authority", "additional"):
        for _ in range(counts[sec]):
            rec, pos = parse_rr(data, pos)
            sections[sec].append(rec)
    for rec in sections["additional"]:
        if rec["type"] == "OPT":
            ext = (rec["ttl"] >> 24) & 0xFF
            if ext:
                h["rcode"] = (ext << 4) | (h["rcode"] & 0xF)
    return {"header": h, "questions": questions, "sections": sections}


class Resolver:
    def __init__(self, servers, port=53, timeout=3.0, retries=2,
                 tcp=False, edns_size=None, do_bit=False):
        self.servers = servers or ["1.1.1.1"]
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.tcp = tcp
        self.edns_size = edns_size
        self.do_bit = do_bit

    def _family(self, server):
        return socket.AF_INET6 if ":" in server else socket.AF_INET

    def _udp_query(self, server, msg, qid):
        sock = socket.socket(self._family(server), socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(msg, (server, self.port))
            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise socket.timeout("timed out")
                sock.settimeout(remaining)
                data, _ = sock.recvfrom(65535)
                if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == qid:
                    return data
        finally:
            sock.close()

    def _tcp_query(self, server, msg):
        sock = socket.create_connection((server, self.port),
                                        timeout=self.timeout)
        sock.settimeout(self.timeout)
        try:
            sock.sendall(struct.pack("!H", len(msg)) + msg)
            size = b""
            while len(size) < 2:
                chunk = sock.recv(2 - len(size))
                if not chunk:
                    raise ConnectionError("kết nối đóng khi đọc độ dài")
                size += chunk
            n = struct.unpack("!H", size)[0]
            data = b""
            while len(data) < n:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()
        return data

    def query(self, qname, qtype, rd=True, server=None, tcp=None):
        targets = [server] if server else self.servers
        errors = []
        for srv in targets:
            try:
                return self._query_server(srv, qname, qtype, rd, tcp)
            except Exception as e:
                errors.append(f"{srv}: {e}")
        raise RuntimeError("; ".join(errors))

    def _query_server(self, server, qname, qtype, rd, tcp_override):
        t0 = time.time()
        use_tcp = self.tcp if tcp_override is None else tcp_override
        last = None
        for _ in range(self.retries + 1):
            qid = random.randint(0, 65535)
            msg = build_query(qid, qname, qtype, rd, self.edns_size, self.do_bit)
            actual_transport = "tcp" if use_tcp else "udp"
            try:
                if use_tcp:
                    data = self._tcp_query(server, msg)
                else:
                    data = self._udp_query(server, msg, qid)
                    if parse_header(data)["tc"]:
                        data = self._tcp_query(server, msg)
                        actual_transport = "tcp"
                resp = parse_response(data, qname, qtype)
                resp["server"] = server
                resp["port"] = self.port
                resp["transport"] = actual_transport
                resp["time_ms"] = round((time.time() - t0) * 1000, 1)
                resp["size"] = len(data)
                return resp
            except (socket.timeout, TimeoutError) as e:
                last = f"timeout"
            except Exception as e:
                last = str(e)
                break
        raise RuntimeError(f"{server}: {last or 'lỗi'}")


def reverse_name(ip):
    ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv4Address):
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    return ".".join(reversed(ip.exploded.replace(":", ""))) + ".ip6.arpa"


def trace_query(resolver, qname, qtype):
    steps = []
    qname_str = decode_name(qname, 0, len(qname))[0]
    servers = list(ROOT_HINTS)
    depth = 0
    while depth < 20:
        srv = servers[0]
        try:
            r = resolver.query(qname, qtype, rd=False, server=srv, tcp=True)
        except RuntimeError as e:
            steps.append({"server": srv, "error": str(e)})
            break
        steps.append({"server": srv, "response": r})
        ans = r["sections"]["answer"]
        if any(a["name"].rstrip(".") == qname_str and
               a["type"] == QTYPE_NAMES.get(qtype, str(qtype))
               for a in ans):
            break
        if r["header"]["rcode"] == 3 or r["header"]["aa"]:
            break
        glue = []
        ns_names = []
        for a in r["sections"]["authority"]:
            if a["type"] == "NS":
                ns_names.append(a["rdata"]["target"])
        for a in r["sections"]["additional"]:
            if a["type"] in ("A", "AAAA") and a["name"].rstrip(".") in \
                    {n.rstrip(".") for n in ns_names}:
                glue.append(a["rdata"]["address"])
        if glue:
            ipv4 = [g for g in glue if ":" not in g]
            servers = ipv4 or glue
        else:
            steps[-1]["note"] = "không có glue address, dừng"
            break
        depth += 1
    return steps


def column_format(rows):
    if not rows:
        return []
    wname = max(len(r["name"]) for r in rows)
    wtype = max(len(r["type"]) for r in rows)
    wttl = max(len(str(r["ttl"])) for r in rows)
    wclass = max(len(r["class"]) for r in rows)
    lines = []
    for r in rows:
        lines.append(f"{r['name']:<{wname}}  {str(r['ttl']):>{wttl}}  "
                     f"{r['class']:<{wclass}}  {r['type']:<{wtype}}  {r['text']}")
    return lines


def render_text(resp, verbose, show_opt):
    out = []
    q = resp["questions"][0]
    hdr = resp["header"]
    out.append(f";; ->>HEADER<<- opcode QUERY, status "
               f"{RCODES.get(hdr['rcode'], str(hdr['rcode']))}, id {hdr['id']}")
    flags = []
    for f in ("qr", "aa", "tc", "rd", "ra", "ad", "cd"):
        if hdr[f]:
            flags.append(f)
    out.append(f";; flags: {' '.join(flags)}; QUERY: {hdr['qdcount']}, "
               f"ANSWER: {hdr['ancount']}, AUTHORITY: {hdr['nscount']}, "
               f"ADDITIONAL: {hdr['arcount']}")
    if hdr["rd"] and not hdr["ra"]:
        out.append(";; WARNING: recursion requested but not available")
    out.append("")
    out.append(";; QUESTION SECTION:")
    out.append(f";{q['name']}.\t\t\tIN\t{q['type']}")
    out.append("")
    for sec in ("answer", "authority"):
        if resp["sections"][sec]:
            out.append(f";; {sec.upper()} SECTION:")
            out.extend(column_format(resp["sections"][sec]))
            out.append("")
    if show_opt and resp["sections"]["additional"]:
        out.append(";; ADDITIONAL SECTION:")
        for r in resp["sections"]["additional"]:
            if r["type"] == "OPT":
                do = "do" if r["rdata"].get("do") else ""
                out.append(f'; EDNS: version 0, udp {r["rdata"]["udp_size"]} {do}')
            else:
                out.append(f"{r['name']}  {r['ttl']}  {r['class']}  "
                           f"{r['type']}  {r['text']}")
        out.append("")
    out.append(f";; Query time: {resp['time_ms']} msec")
    out.append(f";; SERVER: {resp['server']}#{resp['port']} ({resp['transport']})")
    out.append(f";; WHEN: {now_str()}")
    out.append(f";; MSG SIZE  rcvd: {resp['size']}")
    return "\n".join(out)


def records_flat(resp):
    out = []
    for sec in ("answer", "authority", "additional"):
        for r in resp["sections"][sec]:
            if r["type"] == "OPT":
                continue
            out.append(r)
    return out


def render_short(resp):
    return "\n".join(
        f"{r['name']}\t{r['ttl']}\t{r['class']}\t{r['type']}\t{r['text']}"
        for r in records_flat(resp))


def resp_to_dict(resp):
    d = {
        "id": resp["header"]["id"],
        "status": RCODES.get(resp["header"]["rcode"], resp["header"]["rcode"]),
        "flags": {k: resp["header"][k]
                  for k in ("qr", "aa", "tc", "rd", "ra", "ad", "cd")},
        "server": resp["server"],
        "port": resp["port"],
        "transport": resp["transport"],
        "time_ms": resp["time_ms"],
        "size": resp["size"],
        "questions": resp["questions"],
    }
    for sec in ("answer", "authority", "additional"):
        d[sec] = resp["sections"][sec]
    return d


def pick_server(default):
    if sys.platform == "win32":
        try:
            import ctypes
            out = ctypes.create_string_buffer(512)
            size = ctypes.c_ulong(512)
            if ctypes.windll.ws2_32.GetNetworkParams(out, size) == 0:
                text = out.value.decode("latin1")
                for line in text.splitlines():
                    if ":" in line and line.split(":")[0].strip().lower() in \
                            ("dns server", "name server"):
                        return line.split(":", 1)[1].strip().split()[0]
        except Exception:
            pass
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        return parts[1]
        except OSError:
            pass
    return default


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="dnslookup",
        description=f"{TOOL} {VERSION} - DNS lookup ({TEAM}). "
                    "dig-style, thuần Python, không cần cài đặt.",
        epilog="Vi du:\n"
               "  dnslookup.py example.com\n"
               "  dnslookup.py example.com mx -s 8.8.8.8\n"
               "  dnslookup.py -x 8.8.8.8\n"
               "  dnslookup.py -t CAA google.com --json -o out.json\n"
               "  dnslookup.py example.com --trace\n"
               "  dnslookup.py --file list.txt -t A")
    ap.add_argument("name", nargs="?", help="domain cần tra cứu")
    ap.add_argument("-t", "--type", default="A",
                    help="loại bản ghi: A, AAAA, CNAME, MX, NS, SOA, TXT, "
                         "PTR, SRV, CAA, DS, DNSKEY, NSEC, NSEC3, TLSA, "
                         "NAPTR, SPF, HTTPS, ANY (mac dinh A)")
    ap.add_argument("-s", "--server", action="append",
                    help="DNS server (co the nhieu lan); mac dinh lay tu he thong")
    ap.add_argument("-p", "--port", type=int, default=53,
                    help="port DNS (mac dinh 53)")
    ap.add_argument("-x", dest="reverse", metavar="IP",
                    help="tra nguoc (PTR) tu dia chi IP")
    ap.add_argument("--tcp", action="store_true",
                    help="dung TCP (mac dinh UDP, tu chuyen sang TCP neu truncated)")
    ap.add_argument("-T", "--timeout", type=float, default=3.0,
                    help="timeout moi request (giay, mac dinh 3)")
    ap.add_argument("--retries", type=int, default=2,
                    help="so lan thu lai moi server (mac dinh 2)")
    ap.add_argument("--edns-size", type=int, metavar="N",
                    help="EDNS0 UDP payload size (mac dinh 1232 khi dung EDNS)")
    ap.add_argument("--dnssec", action="store_true",
                    help="bat co DO (DNSSEC OK) de nhan RRSIG/DNSKEY")
    ap.add_argument("--norecurse", action="store_true",
                    help="tat recursion (RD=0), chi hoi authoritative")
    ap.add_argument("--trace", action="store_true",
                    help="iterative: root -> TLD -> authoritative")
    ap.add_argument("--short", action="store_true",
                    help="output gon 1 dong/ban ghi")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("--file", metavar="FILE",
                    help="doc danh sach domain tu file (dong # la comment)")
    ap.add_argument("--aaaa", action="store_true", help="cu phap tat cho AAAA")
    ap.add_argument("--mx", action="store_true", help="cu phap tat cho MX")
    ap.add_argument("--ns", action="store_true", help="cu phap tat cho NS")
    ap.add_argument("--txt", action="store_true", help="cu phap tat cho TXT")
    ap.add_argument("--cname", action="store_true", help="cu phap tat cho CNAME")
    ap.add_argument("--soa", action="store_true", help="cu phap tat cho SOA")
    ap.add_argument("--caa", action="store_true", help="cu phap tat cho CAA")
    ap.add_argument("--srv", action="store_true", help="cu phap tat cho SRV")
    ap.add_argument("--any", action="store_true", help="cu phap tat cho ANY")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="chi tiet hon (-v xuat ca authority/additional)")
    args = ap.parse_args()

    shorthands = [("--aaaa", "AAAA"), ("--mx", "MX"), ("--ns", "NS"),
                  ("--txt", "TXT"), ("--cname", "CNAME"), ("--soa", "SOA"),
                  ("--caa", "CAA"), ("--srv", "SRV"), ("--any", "ANY")]
    for flag, typ in shorthands:
        if getattr(args, flag.replace("--", "")):
            args.type = typ

    if args.file and args.name:
        print(f"{TOOL}: khong duoc dung --file chung voi ten truc tiep",
              file=sys.stderr)
        return 3
    if not args.file and not args.name and not args.reverse:
        ap.print_usage(sys.stderr)
        return 3

    qtype_raw = args.type.upper()
    if qtype_raw in QTYPES:
        qtype = QTYPES[qtype_raw]
        qtype_name = qtype_raw
    elif qtype_raw.isdigit() and int(qtype_raw) in QTYPE_NAMES:
        qtype = int(qtype_raw)
        qtype_name = QTYPE_NAMES[qtype]
    else:
        print(f"{TOOL}: loai ban ghi khong hop le: {args.type}",
              file=sys.stderr)
        return 3

    servers = args.server or [pick_server("1.1.1.1")]
    resolver = Resolver(servers, port=args.port, timeout=args.timeout,
                        retries=args.retries, tcp=args.tcp,
                        edns_size=args.edns_size,
                        do_bit=args.dnssec or qtype == 48)

    names = []
    if args.file:
        try:
            with open(args.file, encoding="utf-8-sig") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        names.append(line)
        except OSError as e:
            print(f"{TOOL}: khong doc duoc file: {e}", file=sys.stderr)
            return 3
    elif args.reverse:
        try:
            names.append(reverse_name(args.reverse))
        except ValueError:
            print(f"{TOOL}: dia chi IP khong hop le: {args.reverse}",
                  file=sys.stderr)
            return 3
        qtype = 12
        qtype_name = "PTR"
    else:
        names.append(args.name)

    results = []
    exit_code = 0
    for name in names:
        try:
            qname = encode_qname(name)
        except (ValueError, UnicodeError) as e:
            print(f"{TOOL}: ten khong hop le '{name}': {e}", file=sys.stderr)
            exit_code = max(exit_code, 3)
            continue
        try:
            if args.trace:
                steps = trace_query(resolver, qname, qtype)
                results.append({"trace": steps, "name": name,
                                "type": qtype_name})
                last_resp = None
                for st in reversed(steps):
                    if "response" in st:
                        last_resp = st["response"]
                        break
                if last_resp and last_resp["header"]["rcode"] == 3:
                    exit_code = max(exit_code, 1)
            else:
                resp = resolver.query(qname, qtype, rd=not args.norecurse)
                results.append({"response": resp, "name": name,
                                "type": qtype_name})
                rcode = resp["header"]["rcode"]
                if rcode == 3:
                    exit_code = max(exit_code, 1)
        except RuntimeError as e:
            print(f"{TOOL}: {name}: {e}", file=sys.stderr)
            exit_code = max(exit_code, 2)

    chunks = []
    if args.json:
        data = {"tool": TOOL, "version": VERSION, "team": TEAM,
                "queried_at": datetime.now().astimezone().isoformat(),
                "queries": []}
        for r in results:
            if "response" in r:
                data["queries"].append({
                    "name": r["name"], "type": r["type"],
                    **resp_to_dict(r["response"])})
            else:
                steps = []
                for st in r["trace"]:
                    if "response" in st:
                        steps.append({"server": st["server"], "response":
                                      resp_to_dict(st["response"])})
                    else:
                        steps.append({"server": st["server"],
                                      "error": st.get("error"),
                                      "note": st.get("note")})
                data["queries"].append({"name": r["name"], "type": r["type"],
                                        "trace": steps})
        text = json.dumps(data, indent=2, ensure_ascii=False)
    else:
        parts = []
        for r in results:
            if "response" in r:
                resp = r["response"]
                parts.append(f";; {TOOL} {VERSION} <<>> {r['name']} {r['type']}")
                if args.short:
                    parts.append(render_short(resp))
                else:
                    parts.append(render_text(
                        resp, args.verbose,
                        args.verbose > 0 or args.dnssec))
            else:
                parts.append(f";; {TOOL} {VERSION} <<>> TRACE {r['name']} {r['type']}")
                for i, st in enumerate(r["trace"]):
                    if "response" in st:
                        resp = st["response"]
                        parts.append(f";; step {i}: {st['server']} "
                                     f"(status {RCODES.get(resp['header']['rcode'], '?')})")
                        for a in resp["sections"]["answer"]:
                            parts.append(f"  {a['name']} {a['ttl']} {a['class']} "
                                         f"{a['type']} {a['text']}")
                        for a in resp["sections"]["authority"]:
                            parts.append(f"  [NS] {a['name']} {a['type']} {a['text']}")
                    else:
                        parts.append(f";; step {i}: {st['server']} {st.get('error', st.get('note', ''))}")
        text = "\n".join(parts)

    print(text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"{TOOL}: khong ghi duoc file: {e}", file=sys.stderr)
            return 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
