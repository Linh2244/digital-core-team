#!/usr/bin/env python3
import argparse
import json
import math
import random
import secrets
import sys
from datetime import datetime

TOOL = "PassGen"
VERSION = "1.0.0"
TEAM = "Digital Core team"

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"
AMBIG = "0O1lI|"

CHARSETS = (("lower", LOWER), ("upper", UPPER), ("digit", DIGITS),
            ("symbol", SYMBOLS))

WORDS = (
    "apple bacon bandit basin beach beacon beetle berry bird blade blanket "    "blimp block blossom boat bolt bonnet bottle brain branch brass breeze "
    "brick bridge brook bubble bucket buggy bullet cabin cable cactus "
    "camera candle canvas canyon cargo castle cedar cellar cement center "
    "chain chair cheese cherry chest chick chisel church circle circus "
    "cliff cloak clock cloud clover coast cobra cobalt coconut coffee "
    "collar comet compass copper coral corgi cotton cottage crater cream "
    "creek crest cricket crystal cube cupcake cushion cyclone dagger daisy "
    "dancer danger dawn deadline debate debris decade defeat defend degree "
    "delay demand desert design detail diamond dinner dolphin donkey "
    "dragon drama dream drift drill drizzle drone drum duck eagle earth "
    "echo elbow emerald engine escape estate fabric falcon fence ferry "
    "fiber field finger flame forest fossil fountain fox frog frost frozen "
    "fruit galaxy garden garlic gazelle glacier glass globe glove goat "
    "golden gopher gorilla grape grass gravel gravity green ground "
    "guardian guitar gypsy habit hammer harbor harvest hawk hazel helmet "
    "herd horizon horse hotel hound hurricane iceberg igloo image impact "
    "island ivy jacket jaguar jelly journey jungle kangaroo ketchup kettle "
    "kingdom kiosk kitten kiwi knight ladder ladybug lantern lavender "
    "lawyer lemon leopard liberty library lightning lily lion lizard "
    "lobster longhorn lotus luggage luxury lynx macaw magnet mallard mango "
    "marble marine meadow medal melon meteor midnight mirror model mole "
    "monkey mountain mouse mushroom mystery napkin nectar needle nest "
    "nickel night notebook ocelot octopus olive onion orange orchid otter "
    "panda panther papaya parsley peacock peanut pelican penguin peony "
    "pepper picnic pineapple planet platypus plum pocket polar popcorn "
    "porcupine potato prairie pumpkin puddle quartz rabbit raccoon radar "
    "rainbow raven rhino ribbon rice river rocket robin rock rooster rose "
    "safari salmon sapphire sardine scallop school scorpion seahorse seal "
    "seaweed shadow shark sheep shell sherbet shrimp silver skeleton sky "
    "sloth snail snowflake soap sparrow spider sponge squirrel star starfish "
    "stone storm strawberry sunflower sunset sunshine swan sword tangerine "
    "temple tiger tomato tornado tortoise toucan tower tree tulip tuna "
    "turkey turtle umbrella unicorn valley velvet volcano walrus wasp "
    "waterfall whale wheat willow winter wolf wombat woodpecker wool "
    "wren zebra zero zipper zone zoo"
).split()

GUESSES_PER_SEC = 1e12


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


def entropy_bits(pool_size, length):
    return length * math.log2(pool_size)


def crack_seconds(bits):
    return (2 ** bits) / GUESSES_PER_SEC


def fmt_duration(secs):
    if secs >= 31557600:
        years = secs / 31557600
        if years >= 1e9:
            return f"{years:.2e} năm"
        if years >= 1e6:
            return f"{years / 1e6:.1f} triệu năm"
        if years >= 1000:
            return f"{years / 1000:.1f} nghìn năm"
        return f"{years:.1f} năm"
    if secs >= 86400:
        return f"{secs / 86400:.1f} ngày"
    if secs >= 3600:
        return f"{secs / 3600:.1f} giờ"
    if secs >= 60:
        return f"{secs / 60:.1f} phút"
    return f"{secs:.1f} giây"


def rating(bits):
    if bits < 40:
        return "YẾU", "red"
    if bits < 60:
        return "TRUNG BÌNH", "yellow"
    if bits < 80:
        return "MẠNH", "cyan"
    return "RẤT MẠNH", "green"


def gen_password(pool, length, required):
    chars = [secrets.choice(pool) for _ in range(length)]
    for cs in required:
        if not any(c in cs for c in chars):
            chars[secrets.randbelow(length)] = secrets.choice(cs)
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def gen_passphrase(words_n, sep, cap):
    picks = [secrets.choice(WORDS) for _ in range(words_n)]
    if cap:
        picks = [w.capitalize() for w in picks]
    return sep.join(picks)


def estimate_pool(password):
    size = 0
    for _, cs in CHARSETS:
        if any(c in cs for c in password):
            size += len(cs)
    return size


def build_password_pool(args):
    pool = ""
    required = []
    for name, cs in CHARSETS:
        if getattr(args, "no_" + name):
            continue
        pool += cs
        required.append(cs)
    if args.no_ambig:
        pool = "".join(c for c in pool if c not in AMBIG)
    if not pool:
        return None, required
    return pool, required


def render_strength(pw, color):
    pool = estimate_pool(pw)
    bits = entropy_bits(pool, len(pw))
    label, method = rating(bits)
    lines = [
        f";; {TOOL} {VERSION} <<>> {TEAM}",
        f"Mật khẩu: {color.bold(pw)}",
        f"Độ dài: {len(pw)} | Pool ký tự: {pool} | "
        f"Entropy: {bits:.1f} bits -> {getattr(color, method)(label)}",
        f"Thời gian bẻ khóa (offline ~{GUESSES_PER_SEC:.0e} phép thử/s): "
        f"{fmt_duration(crack_seconds(bits))}",
    ]
    return "\n".join(lines), {"password": pw, "length": len(pw),
                              "pool_size": pool, "entropy_bits": round(bits, 1),
                              "rating": label,
                              "crack_time": fmt_duration(crack_seconds(bits))}


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="pwgen",
        description=f"{TOOL} {VERSION} - password generator (Digital Core "
                    f"team). Sinh mật khẩu / passphrase an toàn dung secrets.")
    ap.add_argument("-c", "--count", type=int, default=10,
                    help="so luong mat khau (mac dinh 10)")
    ap.add_argument("-l", "--length", type=int, default=16,
                    help="do dai moi mat khau (mac dinh 16)")
    ap.add_argument("--no-lower", action="store_true",
                    help="bo chu thuong")
    ap.add_argument("--no-upper", action="store_true",
                    help="bo chu hoa")
    ap.add_argument("--no-digit", action="store_true",
                    help="bo chu so")
    ap.add_argument("--no-symbol", action="store_true",
                    help="bo ky tu dac biet")
    ap.add_argument("--no-ambig", action="store_true",
                    help="loai ky tu de nham lan (0O1lI|)")
    ap.add_argument("-p", "--passphrase", action="store_true",
                    help="sinh passphrase (nhieu tu noi voi nhau)")
    ap.add_argument("-w", "--words", type=int, default=8,
                    help="so tu trong passphrase (mac dinh 8)")
    ap.add_argument("--sep", default="-",
                    help="ky tu noi giua cac tu (mac dinh '-')")
    ap.add_argument("--cap", action="store_true",
                    help="viet hoa chu cai dau moi tu")
    ap.add_argument("--strength", metavar="PASSWORD",
                    help="kiem tra do manh cua mat khau cho san")
    ap.add_argument("--json", action="store_true",
                    help="output JSON")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="ghi ket qua ra file (them vao man hinh)")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="hien entropy tung mat khau")
    ap.add_argument("--no-color", action="store_true",
                    help="tat mau ANSI")
    args = ap.parse_args()

    color = Color(enabled=not args.no_color and sys.stdout.isatty()
                  and not args.output)

    if args.strength is not None:
        text, data = render_strength(args.strength, color)
        if args.json:
            out = {"tool": TOOL, "version": VERSION, "team": TEAM,
                   "queried_at": datetime.now().astimezone().isoformat(),
                   "mode": "strength", "strength": data}
            text = json.dumps(out, indent=2, ensure_ascii=False)
        print(text)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        return 0

    if args.count < 1:
        print(f"{TOOL}: --count phai >= 1", file=sys.stderr)
        return 2

    if args.passphrase:
        if args.words < 3:
            print(f"{TOOL}: --words phai >= 3", file=sys.stderr)
            return 2
        bits = entropy_bits(len(WORDS), args.words)
        generated = [gen_passphrase(args.words, args.sep, args.cap)
                     for _ in range(args.count)]
        pool_note = f"{len(WORDS)} từ"
        mode = "passphrase"
    else:
        if args.length < 4:
            print(f"{TOOL}: --length phai >= 4", file=sys.stderr)
            return 2
        pool, required = build_password_pool(args)
        if not pool:
            print(f"{TOOL}: khong con ky tu nao de sinh mat khau "
                  f"(da tat het charset)", file=sys.stderr)
            return 2
        if len(required) > args.length:
            print(f"{TOOL}: --length qua ngan cho so charset da chon",
                  file=sys.stderr)
            return 2
        bits = entropy_bits(len(pool), args.length)
        generated = [gen_password(pool, args.length, required)
                     for _ in range(args.count)]
        pool_note = f"pool {len(pool)} ký tự"
        mode = "password"

    if args.json:
        text = json.dumps({
            "tool": TOOL, "version": VERSION, "team": TEAM,
            "queried_at": datetime.now().astimezone().isoformat(),
            "mode": mode,
            "options": {"count": args.count,
                        "length": args.length if not args.passphrase
                        else None,
                        "words": args.words if args.passphrase else None,
                        "separator": args.sep if args.passphrase else None,
                        "cap": args.cap if args.passphrase else None,
                        "no_lower": args.no_lower,
                        "no_upper": args.no_upper,
                        "no_digit": args.no_digit,
                        "no_symbol": args.no_symbol,
                        "no_ambig": args.no_ambig},
            "pool_size": len(pool) if not args.passphrase else len(WORDS),
            "entropy_bits": round(bits, 1),
            "passwords": generated,
        }, indent=2, ensure_ascii=False)
    else:
        width = len(str(args.count))
        lines = [f";; {TOOL} {VERSION} <<>> {TEAM}",
                 f";; {args.count} {mode}, {pool_note} | "
                 f"~{bits:.1f} bits"]
        for i, pw in enumerate(generated, 1):
            line = f"{i:>{width}}. {color.bold(pw)}"
            if args.verbose and not args.passphrase:
                line += color.dim(f"  [{entropy_bits(len(pool), len(pw)):.1f} b]")
            lines.append(line)
        text = "\n".join(lines)

    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
