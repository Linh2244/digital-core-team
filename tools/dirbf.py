#!/usr/bin/env python3
import argparse
import json
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

TOOL = "DirBF"
VERSION = "1.0.0"
TEAM = "Digital Core team"

BODY_LIMIT = 65536
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10
HIDE_DEFAULT = {404}

DEFAULT_PATHS = [
    "admin", "administrator", "adm", "login", "logon", "signin", "signup",
    "register", "account", "accounts", "profile", "user", "users",
    "userlist", "password", "forgot", "reset", "auth", "authorize",
    "login.php", "index", "index.php", "index.html", "home", "home.php",
    "main", "default", "default.aspx", "dashboard", "console",
    "controlpanel", "cpanel", "webmail", "mail", "outlook", "owa",
    "exchange", "portal", "employee", "employees", "hr", "payroll", "erp",
    "crm", "sso", "idp", "oauth", "token", "tokens", "api", "apis", "v1",
    "v2", "v3", "rest", "graphql", "swagger", "swagger-ui.html", "api-docs",
    "api/v1", "openapi.json", "wp-admin", "wp-login.php", "wp-content",
    "wp-includes", "wp-config.php", "wp-json", "wp-cron.php", "xmlrpc.php",
    "wp-content/uploads", "uploads", "upload", "downloads", "download",
    "files", "file", "static", "assets", "css", "js", "img", "images",
    "image", "media", "fonts", "themes", "vendor", "node_modules", "public",
    "private", "lib", "libs", "src", "dist", "build", "bin", "tmp", "temp",
    "logs", "log", "cache", "storage", "store", "sessions", "session",
    "backup", "backups", "db", "database", "dump", "dump.sql", "db.sql",
    "mysql", "phpmyadmin", "pma", "adminer", "drupal", "joomla", "magento",
    "prestashop", "laravel", "symfony", "django", "flask", "rails", "next",
    "nuxt", "config", "configuration", "conf", "settings", "config.php",
    "config.yml", "config.json", "config.yaml", ".env", ".git",
    ".gitignore", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd",
    ".ssh", ".ssh/id_rsa", ".aws", ".aws/credentials", ".npmrc", ".bashrc",
    ".bash_history", ".DS_Store", "Thumbs.db", "composer.json",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "requirements.txt", "Dockerfile", "docker-compose.yml",
    "server.js", "app.js", "main.py", "wsgi.py", "manage.py", "robots.txt",
    "sitemap.xml", "sitemap_index.xml", "security.txt", "humans.txt",
    "favicon.ico", "crossdomain.xml", ".well-known", "well-known",
    ".well-known/security.txt", "error", "errors", "404.html", "403.html",
    "500.html", "status", "health", "healthcheck", "ping", "metrics",
    "monitor", "monitoring", "grafana", "kibana", "jenkins", "sonar",
    "travis", "gitlab", "bitbucket", "svn", "cvs", "docs", "doc",
    "documentation", "help", "readme", "readme.md", "readme.txt",
    "changelog", "changelog.txt", "license", "license.txt", "version",
    "release", "install", "setup", "upgrade", "migration", "migrate",
    "init", "test", "tests", "test.php", "debug", "phpinfo", "phpinfo.php",
    "info.php", "server-status", "server-info", "shell", "cmd", "terminal",
    "cart", "checkout", "shop", "storefront", "product", "products",
    "order", "orders", "payment", "payments", "invoice", "invoices",
    "billing", "search", "results", "feed", "rss", "atom", "export",
    "import", "actuator", "actuator/health", "actuator/env",
    "actuator/heapdump", "jolokia", "h2-console", "healthz", "readyz",
    "livez", "credentials", "secrets", "password.txt", "users.txt",
    "backup.zip", "backup.tar.gz", "backup.sql", "site.zip", "wwwroot",
    "web.config", "app.config", "application.properties", "web.xml",
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_codes(text, name):
    out = set()
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            print(f"{TOOL}: {name} phai la cac so HTTP, phan cach bang "
                  f"phay: {text}", file=sys.stderr)
            sys.exit(2)
        out.add(int(part))
    return out


def build_headers(args):
    h = {"User-Agent": args.user_agent or f"{TOOL}/{VERSION}"}
    for kv in args.header:
        name, _, val = kv.partition(":")
        if name.strip():
            h[name.strip()] = val.strip()
    if args.cookie:
        h["Cookie"] = args.cookie
    return h


def load_lines(path):
    lines = []
    seen = set()
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                p = line.strip()
                if not p or p.startswith("#") or p in seen:
                    continue
                seen.add(p)
                lines.append(p)
    except OSError as e:
        print(f"{TOOL}: khong doc duoc wordlist {path}: {e}",
              file=sys.stderr)
        sys.exit(2)
    return lines


def build_paths(args):
    paths = []
    seen = set()
    if args.wordlist:
        for p in load_lines(args.wordlist):
            seen.add(p)
            paths.append(p)
    if not args.no_defaults:
        dp = DEFAULT_PATHS[:args.top] if args.top else DEFAULT_PATHS
        for p in dp:
            if p not in seen:
                seen.add(p)
                paths.append(p)
    if args.extensions:
        exts = [e.strip().lstrip(".") for e in args.extensions.split(",")]
        exts = [e for e in exts if e]
        extra = []
        for p in paths:
            if "." in p:
                continue
            for e in exts:
                cand = f"{p}.{e}"
                if cand not in seen:
                    seen.add(cand)
                    extra.append(cand)
        paths += extra
    if not paths:
        print(f"{TOOL}: khong co duong dan nao de thu (dung -w hoac bo "
              f"--no-defaults)", file=sys.stderr)
        sys.exit(2)
    return paths


def build_url(base, path):
    if path.startswith(("http://", "https://")):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def attempt(base, path, args, opener):
    url = build_url(base, path)
    req = urllib.request.Request(url, headers=build_headers(args),
                                 method="GET")
    try:
        with opener.open(req, timeout=args.timeout) as r:
            body = r.read(BODY_LIMIT)
            cl = r.headers.get("Content-Length")
            size = int(cl) if cl and cl.isdigit() else len(body)
            return r.status, size, r.headers.get("Location"), None
    except urllib.error.HTTPError as e:
        body = e.read(BODY_LIMIT)
        cl = e.headers.get("Content-Length")
        size = int(cl) if cl and cl.isdigit() else len(body)
        return e.code, size, e.headers.get("Location"), None
    except urllib.error.URLError as e:
        return 0, 0, None, str(e.reason)
    except Exception as e:
        return 0, 0, None, str(e)


def should_report(status, args, hide):
    if status == 0 or status in hide:
        return False
    if args.code and status not in args.code:
        return False
    return True


def run(base, paths, args, hide):
    total = len(paths)
    lock = threading.Lock()
    stop = threading.Event()
    tested = [0]
    errors = [0]
    found = []

    def worker(path):
        if stop.is_set():
            return
        status, size, location, err = 0, 0, None, None
        tries = 0
        while tries <= args.retries:
            status, size, location, err = attempt(base, path, args, opener)
            tries += 1
            if err is None or tries > args.retries:
                break
            time.sleep(args.delay)
        with lock:
            tested[0] += 1
            if err:
                errors[0] += 1
        if args.delay:
            time.sleep(args.delay)
        if err:
            return
        if should_report(status, args, hide):
            with lock:
                found.append({"path": path, "status": status, "size": size,
                              "location": location})
                if args.stop_first:
                    stop.set()

    handlers = [NoRedirect()]
    if args.proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": args.proxy, "https": args.proxy}))
    if args.insecure:
        handlers.append(urllib.request.HTTPSHandler(
            context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)

    start = time.time()
    done = [0]
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = [ex.submit(worker, p) for p in paths]
        for fut in as_completed(futures):
            fut.result()
            with lock:
                done[0] += 1
                n = done[0]
            if args.verbose and n % 100 == 0:
                el = max(time.time() - start, 0.001)
                print(f"\r  {TOOL}: {n}/{total} ({n/el:.0f}/s) - "
                      f"tim thay {len(found)}",
                      file=sys.stderr, end="")
    elapsed = time.time() - start

    return {
        "target": base, "total": total, "tested": tested[0],
        "errors": errors[0], "elapsed": round(elapsed, 2),
        "rate": round(tested[0] / max(elapsed, 0.001)),
        "found": found,
    }


def human(n):
    if n >= 1048576:
        return f"{n / 1048576:.1f}MB"
    if n >= 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}B"


def render_text(res, color):
    lines = [f";; {TOOL} {VERSION} <<>> {TEAM}",
             f"Mục tiêu: {color.bold(res['target'])} | "
             f"từ điển: {res['total']} đường dẫn",
             f"Đã thử {res['tested']}/{res['total']} | "
             f"lỗi mạng {res['errors']} | {res['elapsed']:.1f}s "
             f"({res['rate']}/s)",
             ""]
    if res["found"]:
        lines.append(color.green(f"TÌM THẤY {len(res['found'])} đường dẫn:"))
        lines.append("")
        for f in res["found"]:
            url = build_url(res["target"], f["path"])
            sz = human(f["size"]) if f["size"] is not None else "-"
            line = (f"  + {color.cyan(url)}  "
                    f"({color.green(str(f['status']))}, {sz}")
            if f["location"]:
                line += f", -> {f['location']}"
            line += ")"
            lines.append(line)
    else:
        lines.append(color.yellow("KHÔNG tìm thấy đường dẫn nào."))
    lines.append("")
    lines.append(color.bold(f";; {len(res['found'])} đường dẫn trong "
                            f"{res['elapsed']:.1f}s"))
    return "\n".join(lines)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="dirbf",
        description=f"{TOOL} {VERSION} - directory/file brute force "
                    f"({TEAM}). Python thuần, không cần cài đặt.",
        epilog="Vi du:\n"
               "  dirbf.py http://192.168.1.10/\n"
               "  dirbf.py http://192.168.1.10/app/ --top 200\n"
               "  dirbf.py https://site.com -w dirs.txt -x php,bak\n"
               "  dirbf.py https://site.com --code 200,301 -t 30\n"
               "  dirbf.py http://10.0.0.5 --json-output -o report.json")
    ap.add_argument("url", help="URL goc (vi du http://host/ hoac "
                                "http://host/app/)")
    ap.add_argument("-w", "--wordlist", metavar="FILE",
                    help="wordlist duong dan (1 dong 1 duong; dong # la "
                         "comment), cong them vao built-in")
    ap.add_argument("--no-defaults", action="store_true",
                    help="khong dung wordlist tich hop san")
    ap.add_argument("--top", type=int, metavar="N",
                    help="chi dung N duong dan dau tien cua wordlist "
                         "tich hop (mac dinh: full 269 duong dan)")
    ap.add_argument("-x", "--extensions", metavar="EXTS",
                    help="them duoi vao moi tu, phan cach phay "
                         "(vi du: php,html,bak) -> admin, admin.php, ...")
    ap.add_argument("--code", metavar="CODES",
                    help="chi bao status nam trong list (vi du: 200,301)")
    ap.add_argument("--hide", metavar="CODES",
                    help="bo qua them status (404 luon bo qua; "
                         "vi du: 403,500)")
    ap.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                    help=f"so luong thread (mac dinh {DEFAULT_THREADS})")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="do tre giua cac lan thu (giay)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"timeout moi request (mac dinh {DEFAULT_TIMEOUT})")
    ap.add_argument("--retries", type=int, default=0,
                    help="so lan thu lai khi loi mang")
    ap.add_argument("-H", "--header", action="append", default=[],
                    metavar="NAME: VAL",
                    help="header tuy chinh (dung nhieu lan)")
    ap.add_argument("-A", "--user-agent", metavar="UA",
                    help="doi User-Agent")
    ap.add_argument("--cookie", metavar="STR",
                    help="header Cookie (vi du: sid=abc123)")
    ap.add_argument("--proxy", metavar="URL",
                    help="proxy HTTP/HTTPS (vi du: http://127.0.0.1:8080)")
    ap.add_argument("--insecure", action="store_true",
                    help="bo qua xac minh TLS (self-signed)")
    ap.add_argument("--stop-first", action="store_true",
                    help="dung ngay khi tim thay duong dan dau tien")
    ap.add_argument("--json-output", action="store_true",
                    help="xuat JSON thay vi text")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="in tien trinh ra stderr")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    color = Color(enabled=not args.no_color and sys.stdout.isatty()
                  and not args.output)

    if not args.url.lower().startswith(("http://", "https://")):
        print(f"{TOOL}: URL phai bat dau bang http:// hoac https://",
              file=sys.stderr)
        return 2
    if args.threads < 1:
        print(f"{TOOL}: --threads phai >= 1", file=sys.stderr)
        return 2
    if args.top is not None and args.top < 1:
        print(f"{TOOL}: --top phai >= 1", file=sys.stderr)
        return 2
    if args.delay < 0:
        print(f"{TOOL}: --delay khong duoc am", file=sys.stderr)
        return 2

    hide = set(HIDE_DEFAULT)
    if args.hide:
        hide |= parse_codes(args.hide, "--hide")
    args.code = parse_codes(args.code, "--code") if args.code else None

    paths = build_paths(args)
    res = run(args.url, paths, args, hide)

    if args.json_output:
        text = json.dumps({"tool": TOOL, "version": VERSION, "team": TEAM,
                           "queried_at": datetime.now().astimezone()
                           .isoformat(),
                           **res}, indent=2, ensure_ascii=False)
    else:
        text = render_text(res, color)

    print(text)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"{TOOL}: khong ghi duoc file {args.output}: {e}",
                  file=sys.stderr)
            return 2

    if res["tested"] and res["errors"] == res["tested"]:
        return 3
    return 1 if res["found"] else 0


if __name__ == "__main__":
    sys.exit(main())
