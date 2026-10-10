#!/usr/bin/env python3

import argparse
import asyncio
import glob
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SOURCES_FILE = Path("sources.txt")
BLOCKLIST_URLS_FILE = Path("blocklist_urls.txt")
DEAD_HASHES_FILE = Path("dead_hashes.txt")
CHANNEL_FILE = Path("channel.txt")

CLEAN_CANDIDATES = Path("clean_candidates.json")
POST_FILE = Path("post_ready.txt")

UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")

TCP_TIMEOUT = 4
TLS_TIMEOUT = 3
TEST_CONCURRENCY = 200

LINK_RE = re.compile(r"(?:tg://proxy|https?://t\.me/proxy)\?[^\s\"'<>]+", re.I)
SECRET_LIKE = re.compile(r"^[0-9a-zA-Z_\-]{16,}$")
DEAD, TCP_OK, TLS_OK = "dead", "tcp", "tls"


def fetch(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def fetch_bytes(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def make_key(server: str, port: int, secret: str) -> str:
    return f"{server.lower()}:{port}:{secret.strip().lower()}"


def build_tg_proxy(server: str, port: int, secret: str) -> str:
    return f"tg://proxy?server={server}&port={port}&secret={secret}"


def load_sources() -> list:
    if SOURCES_FILE.exists():
        urls = []
        for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line.split("?", 1)[0])
        if urls:
            return urls
    print("[WARN] sources.txt missing or empty")
    return []


def load_channel() -> dict:
    cfg = {}
    if CHANNEL_FILE.exists():
        for line in CHANNEL_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    return cfg


def parse_links(text: str, source: str) -> list:
    out = []
    for m in LINK_RE.finditer(text.replace("&amp;", "&")):
        q = parse_qs(urlparse(m.group(0)).query)
        server = (q.get("server") or [""])[0]
        secret = (q.get("secret") or [""])[0]
        try:
            port = int((q.get("port") or ["0"])[0])
        except ValueError:
            continue
        if server and 1 <= port <= 65535 and secret:
            out.append({"server": server, "port": port, "secret": secret, "source": source})
    return out


def parse_plain(text: str, source: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "://" in line or line.startswith("#"):
            continue
        parts = [p for p in re.split(r"[\s,|:]+", line) if p]
        if len(parts) < 3 or not parts[1].isdigit():
            continue
        server, port, secret = parts[0], int(parts[1]), parts[2]
        if 1 <= port <= 65535 and "." in server and SECRET_LIKE.match(secret):
            out.append({"server": server, "port": port, "secret": secret, "source": source})
    return out


def parse_json(text: str, source: str) -> list:
    t = text.strip()
    try:
        if t.startswith("["):
            arr = json.loads(t)
        elif t.startswith("{"):
            obj = json.loads(t)
            arr = next((obj[k] for k in ("proxies", "data", "results", "items")
                        if isinstance(obj.get(k), list)), [obj])
        else:
            return []
        out = []
        for o in arr:
            if not isinstance(o, dict):
                continue
            server = o.get("host") or o.get("server") or o.get("ip") or o.get("address") or ""
            secret = o.get("secret") or o.get("proxy_secret") or ""
            try:
                port = int(o.get("port", -1))
            except (TypeError, ValueError):
                continue
            if server and 1 <= port <= 65535 and secret:
                out.append({"server": str(server), "port": port,
                            "secret": str(secret), "source": source})
        return out
    except (json.JSONDecodeError, AttributeError):
        return []


def parse_any(text: str, source: str) -> list:
    seen, merged = set(), []
    for p in parse_links(text, source) + parse_plain(text, source) + parse_json(text, source):
        pid = make_key(p["server"], p["port"], p["secret"])
        if pid not in seen:
            seen.add(pid)
            merged.append(p)
    return merged


def collect() -> list:
    urls = load_sources()
    print(f"sources: {len(urls)}")

    def safe(u):
        try:
            return u, fetch(u), None
        except Exception as e:
            return u, "", str(e)

    found = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for u, text, err in ex.map(safe, urls):
            if err:
                print(f"  x {u.split('//')[1][:50]} -> {err}")
                continue
            got = parse_any(text, u)
            if got:
                print(f"  ok {u.split('//')[1][:50]} -> {len(got)}")
            else:
                print(f"  !! {u.split('//')[1][:50]} -> 0")
            found += got

    seen, uniq = set(), []
    for p in found:
        pid = make_key(p["server"], p["port"], p["secret"])
        if pid not in seen:
            seen.add(pid)
            uniq.append(p)
    print(f"unique after dedup: {len(uniq)}\n")
    return uniq


def load_dead_hashes() -> set:
    if not DEAD_HASHES_FILE.exists():
        return set()
    return {
        line.strip()
        for line in DEAD_HASHES_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def load_ip_blocklists() -> set:
    import ipaddress
    nets = set()
    if not BLOCKLIST_URLS_FILE.exists():
        print("[WARN] blocklist_urls.txt missing - IP filter skipped")
        return nets
    for url in BLOCKLIST_URLS_FILE.read_text(encoding="utf-8").splitlines():
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        try:
            text = fetch(url)
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        nets.add(ipaddress.ip_network(line, strict=False))
                        count += 1
                    except ValueError:
                        pass
            print(f"  ok blocklist {url.split('//')[1][:45]} -> +{count} nets")
        except Exception as e:
            print(f"  x blocklist {url.split('//')[1][:45]} -> {e}")
    return nets


def ip_blocked(server: str, nets: set) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(server)
        return any(ip in n for n in nets)
    except ValueError:
        return False


def extract_sni(secret: str):
    s = secret.lower()
    if not s.startswith("ee") or len(s) < 35:
        return None
    tail = s[34:]
    if re.fullmatch(r"[0-9a-f]+", tail):
        try:
            d = bytes.fromhex(tail).rstrip(b"\x00").decode("ascii", "ignore")
            if d and "." in d and all(c.isalnum() or c in "-." for c in d):
                return d
        except ValueError:
            pass
    d = tail.rstrip("0")
    if d and "." in d and all(c.isalnum() or c in "-." for c in d):
        return d
    return None


async def test_all(proxies: list, timeout: float, concurrency: int) -> dict:
    sem = asyncio.Semaphore(concurrency)
    done, total = 0, len(proxies)

    async def one(p):
        nonlocal done
        async with sem:
            host, port, secret = p["server"], p["port"], p["secret"]
            t0 = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout)
            except Exception:
                done += 1
                return make_key(host, port, secret), {"alive": False, "tier": DEAD, "latency_ms": None}
            latency = round((time.perf_counter() - t0) * 1000)
            tier = TCP_OK
            sni = extract_sni(secret)
            if sni:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    _, w2 = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
                        timeout)
                    tier = TLS_OK
                    w2.close()
                except Exception:
                    pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            done += 1
            if done % 100 == 0 or done == total:
                print(f"  tested: {done}/{total}")
            return make_key(host, port, secret), {"alive": True, "tier": tier, "latency_ms": latency}

    return dict(await asyncio.gather(*(one(p) for p in proxies)))


def cmd_collect_clean(_):
    proxies = collect()

    dead_hashes = load_dead_hashes()
    if dead_hashes:
        before = len(proxies)
        proxies = [p for p in proxies
                   if make_key(p["server"], p["port"], p["secret"]).split(":", 2)[2]
                      not in dead_hashes]
        print(f"  blocklist (hashes): {before} -> {len(proxies)}")

    nets = load_ip_blocklists()
    if nets:
        before = len(proxies)
        proxies = [p for p in proxies if not ip_blocked(p["server"], nets)]
        print(f"  blocklist (ip): {before} -> {len(proxies)}")

    if not proxies:
        sys.exit("empty after filters")

    print(f"global tcp-check for {len(proxies)} proxies...")
    results = asyncio.run(test_all(proxies, TCP_TIMEOUT, TEST_CONCURRENCY))

    alive = [dict(p, **results[make_key(p["server"], p["port"], p["secret"])])
             for p in proxies
             if results[make_key(p["server"], p["port"], p["secret"])]["alive"]]

    CLEAN_CANDIDATES.write_text(
        json.dumps({"checked": len(proxies), "alive": alive},
                   ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(f"ok: checked={len(proxies)} alive={len(alive)} -> {CLEAN_CANDIDATES}")


def cmd_make_post(_):
    if not CLEAN_CANDIDATES.exists():
        sys.exit("clean_candidates.json missing - run collect-clean first")
    data = json.loads(CLEAN_CANDIDATES.read_text(encoding="utf-8"))
    checked = data.get("checked", 0)
    alive = data.get("alive", [])
    scanned = checked if checked > 0 else len(alive)

    cfg = load_channel()
    apk_url = cfg.get("apk_post_url", "").strip()

    if apk_url:
        operator_lines = (
            f"[**همراه اول | ایرانسل | وایفای | اختصاصی**]({apk_url})\n"
            f"[**همراه اول | ایرانسل | وایفای | اختصاصی**]({apk_url})"
        )
    else:
        operator_lines = (
            "**همراه اول | ایرانسل | وایفای | اختصاصی**\n"
            "**همراه اول | ایرانسل | وایفای | اختصاصی**"
        )

    body = [
        "✦ **گزارش روزانهٔ ProxyStar**",
        "",
        f"**در حال حاضر {scanned:,} سرور بررسی شد و مجموع {len(alive):,} سرور برتر برای شما در دسترس گرفت.**",
        "",
        "**~ پروکسی‌های اختصاصی، متناسب با اپراتور و اینترنت منطقه‌ای شما :**",
        operator_lines,
        "",
        "@Proxystar_Channel",
    ]
    text = "\n".join(body)
    POST_FILE.write_text(text, encoding="utf-8")
    print(text)
    print(f"\n---- saved: {POST_FILE} ----")


def tg_api_call(token: str, method: str, fields: dict, photo_bytes: bytes = None) -> dict:
    """Send via multipart if photo_bytes given, else urlencoded. Returns full Telegram response."""
    api = f"https://api.telegram.org/bot{token}/{method}"
    if photo_bytes is None:
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(api, data=data)
    else:
        boundary = uuid.uuid4().hex
        buf = b""
        for k, v in fields.items():
            buf += (f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode()
        buf += (f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="banner.png"\r\n'
                f"Content-Type: image/png\r\n\r\n").encode() + photo_bytes + b"\r\n"
        buf += f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(api, data=buf, headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}"})

    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def cmd_send_post(_):
    if not POST_FILE.exists():
        sys.exit("post_ready.txt missing - run make-post first")
    token = os.environ.get("TG_BOT_TOKEN", "")
    channel = os.environ.get("TG_CHANNEL_ID", "")
    if not token or not channel:
        sys.exit("TG_BOT_TOKEN / TG_CHANNEL_ID not set")

    cfg = load_channel()
    banner_url = cfg.get("banner_url", "").strip()
    text = POST_FILE.read_text(encoding="utf-8")

    photo_bytes = None
    if banner_url:
        try:
            photo_bytes = fetch_bytes(banner_url)
            print(f"banner downloaded: {len(photo_bytes)} bytes")
        except Exception as e:
            print(f"[WARN] banner download failed, sending text-only: {e}")

    if photo_bytes:
        resp = tg_api_call(token, "sendPhoto",
                           {"chat_id": channel, "caption": text, "parse_mode": "Markdown"},
                           photo_bytes=photo_bytes)
        if resp.get("ok"):
            print("posted (with banner)")
            return
        print(f"[WARN] sendPhoto failed: {resp} - falling back to text")

    resp = tg_api_call(token, "sendMessage",
                       {"chat_id": channel, "text": text,
                        "parse_mode": "Markdown", "disable_web_page_preview": "true"})
    if resp.get("ok"):
        print("posted (text-only)")
    else:
        print(f"TELEGRAM ERROR: {resp}")
        sys.exit(1)


def cmd_run(args):
    proxies = collect()
    if not proxies:
        sys.exit("no proxies parsed")
    print(f"testing on network '{args.operator}'...")
    results = asyncio.run(test_all(proxies, args.timeout, args.concurrency))

    tier_count = defaultdict(int)
    for r in results.values():
        tier_count[r["tier"]] += 1
    print(f"tiers: {dict(tier_count)}")

    Path(f"results_{args.operator}.json").write_text(
        json.dumps({
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "proxies": proxies,
            "results": results,
        }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"saved: results_{args.operator}.json")


def cmd_merge(_):
    files = sorted(glob.glob("results_*.json"))
    if not files:
        sys.exit("results_*.json not found")
    merged = {}
    for f in files:
        d = json.loads(Path(f).read_text(encoding="utf-8"))
        for p in d["proxies"]:
            pid = make_key(p["server"], p["port"], p["secret"])
            r = d["results"].get(pid, {"alive": False})
            e = merged.setdefault(pid, {**p, "alive_count": 0})
            if r["alive"]:
                e["alive_count"] += 1
    kept = [e for e in merged.values() if e["alive_count"] > 0]
    kept.sort(key=lambda e: -e["alive_count"])
    Path("proxies_alive.txt").write_text(
        "\n".join(build_tg_proxy(e["server"], e["port"], e["secret"]) for e in kept),
        encoding="utf-8")
    print(f"alive in at least one network: {len(kept)} of {len(merged)} -> proxies_alive.txt")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("collect-clean")
    sub.add_parser("make-post")
    sub.add_parser("send-post")
    sub.add_parser("merge")
    r = sub.add_parser("run")
    r.add_argument("--operator", "-o", default="net")
    r.add_argument("--timeout", type=float, default=5.0)
    r.add_argument("--concurrency", "-c", type=int, default=200)
    args = ap.parse_args()

    if args.cmd == "collect-clean":
        cmd_collect_clean(args)
    elif args.cmd == "make-post":
        cmd_make_post(args)
    elif args.cmd == "send-post":
        cmd_send_post(args)
    elif args.cmd == "merge":
        cmd_merge(args)
    elif args.cmd == "run":
        cmd_run(args)


if __name__ == "__main__":
    main()
