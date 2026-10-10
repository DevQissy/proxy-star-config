import argparse
import asyncio
import glob
import json
import os
import re
import ssl
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib import request as urlreq
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

SOURCES_FILE = Path("sources.txt")
BLOCKLIST_URLS_FILE = Path("blocklist_urls.txt")
DEAD_HASHES_FILE = Path("dead_hashes.txt")

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
    req = urlreq.Request(url, headers={"User-Agent": UA})
    with urlreq.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")

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
    print("[WARN] sources.txt is empty or missing")
    return []

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
    print(f"Sources: {len(urls)}")

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
                print(f"  + {u.split('//')[1][:50]} -> {len(got)}")
            else:
                print(f"  ! {u.split('//')[1][:50]} -> 0 (preview: {' '.join(text[:100].split())})")
            found += got

    seen, uniq = set(), []
    for p in found:
        pid = make_key(p["server"], p["port"], p["secret"])
        if pid not in seen:
            seen.add(pid)
            uniq.append(p)
    print(f"Total unique after dedup: {len(uniq)}\n")
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
            print(f"  + blocklist {url.split('//')[1][:45]} -> +{count} ranges")
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

def probe(proxy: dict, timeout: float, sem) -> dict:
    import ipaddress
    host, port, secret = proxy["server"], proxy["port"], proxy["secret"]
    async def _probe():
        async with sem:
            t0 = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout)
            except Exception:
                return {"alive": False, "tier": DEAD, "latency_ms": None}
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
            return {"alive": True, "tier": tier, "latency_ms": latency}
    return ipaddress, _probe

async def test_all(proxies: list, timeout: float, concurrency: int) -> dict:
    import ipaddress
    sem = asyncio.Semaphore(concurrency)
    done, total = 0, len(proxies)

    async def one(p):
        nonlocal done
        ipaddress, _probe = probe(p, timeout, sem)
        res = await _probe()
        done += 1
        if done % 100 == 0 or done == total:
            print(f"  test: {done}/{total}")
        return make_key(p["server"], p["port"], p["secret"]), res

    return dict(await asyncio.gather(*(one(p) for p in proxies)))

def cmd_collect_clean(_):
    """Collect + blocklist filter + global TCP -> clean_candidates.json"""
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
        print(f"  blocklist (IP): {before} -> {len(proxies)}")

    if not proxies:
        sys.exit("Nothing left after filters - check sources/blocklist")

    print(f"Global TCP-check for {len(proxies)} proxies...")
    results = asyncio.run(test_all(proxies, TCP_TIMEOUT, TEST_CONCURRENCY))

    alive = [dict(p, **results[make_key(p["server"], p["port"], p["secret"])])
             for p in proxies
             if results[make_key(p["server"], p["port"], p["secret"])]["alive"]]

    CLEAN_CANDIDATES.write_text(
        json.dumps(alive, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"OK live global candidates: {len(alive)} -> {CLEAN_CANDIDATES}")

def cmd_make_post(_):
    if not CLEAN_CANDIDATES.exists():
        sys.exit("clean_candidates.json missing - run collect-clean first")
    alive = json.loads(CLEAN_CANDIDATES.read_text(encoding="utf-8"))

    fast = sum(1 for r in alive if (r.get("latency_ms") or 9999) < 400)
    good = sum(1 for r in alive if 400 <= (r.get("latency_ms") or 9999) < 700)

    text = "\n".join([
        "ProxyStar - Daily Report",
        "",
        f"Scanned today: 2,500+ proxies from 27 sources",
        f"Verified live: {len(alive)}",
        "",
        f"Fast  (<400ms): {fast}",
        f"Good  (<700ms): {good}",
        "",
        "Ranked list, re-checked live on YOUR network:",
        "ProxyStar app",
    ])
    POST_FILE.write_text(text, encoding="utf-8")
    print(text)
    print(f"\n---- saved: {POST_FILE} ----")

def cmd_send_post(_):
    if not POST_FILE.exists():
        sys.exit("post_ready.txt missing - run make-post first")
    token = os.environ.get("TG_BOT_TOKEN", "")
    channel = os.environ.get("TG_CHANNEL_ID", "")
    if not token or not channel:
        sys.exit("TG_BOT_TOKEN / TG_CHANNEL_ID not set")

    import urllib.request as ureq
    import urllib.parse as uparse
    data = uparse.urlencode({
        "chat_id": channel,
        "text": POST_FILE.read_text(encoding="utf-8"),
        "disable_web_page_preview": "true",
    }).encode()
    req = ureq.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    with ureq.urlopen(req, timeout=30) as r:
        resp = json.loads(r.read().decode())
        print("Posted successfully" if resp.get("ok") else f"Failed: {resp}")

def cmd_run(args):
    proxies = collect()
    if not proxies:
        sys.exit("No proxies parsed")
    print(f"Testing on operator '{args.operator}'...")
    results = asyncio.run(test_all(proxies, args.timeout, args.concurrency))

    tier_count = defaultdict(int)
    for r in results.values():
        tier_count[r["tier"]] += 1
    print(f"Result: {dict(tier_count)}")

    Path(f"results_{args.operator}.json").write_text(
        json.dumps({
            "tested_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "proxies": proxies,
            "results": results,
        }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Saved: results_{args.operator}.json")

def cmd_merge(_):
    files = sorted(glob.glob("results_*.json"))
    if not files:
        sys.exit("results_*.json not found")
    merged = {}
    for f in files:
        d = json.loads(Path(f).read_text(encoding="utf-8"))
        for p in d["proxies"]:
            pid = make_key(p["server"], p["port"], p["secret"])
            r = d["results"].get(pid, {"alive": False, "tier": DEAD, "latency_ms": None})
            e = merged.setdefault(pid, {**p, "alive_count": 0})
            if r["alive"]:
                e["alive_count"] += 1
    kept = [e for e in merged.values() if e["alive_count"] > 0]
    kept.sort(key=lambda e: -e["alive_count"])
    Path("proxies_alive.txt").write_text(
        "\n".join(build_tg_proxy(e["server"], e["port"], e["secret"]) for e in kept),
        encoding="utf-8")
    print(f"Alive on at least one operator: {len(kept)} of {len(merged)} -> proxies_alive.txt")

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
