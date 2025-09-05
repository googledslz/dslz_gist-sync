import base64
import requests
import yaml
import re
import asyncio
import time
from pathlib import Path
from urllib.parse import unquote, parse_qs
import subprocess
from tqdm import tqdm

# ================= 配置 =================
INPUT_CANDIDATES = ["tmp/1.TXT", "/tmp/1.TXT"]
EXISTING_YAML = ["tmp/dslz.yaml", "/tmp/dslz.yaml"]
OUTPUT_FILE = "clash.yaml"
FIX_SCRIPT = "fix_clash.py"
CONCURRENCY = 50
TIMEOUT = 3

# ================= 工具函数 =================

def read_url_list() -> list:
    for p in INPUT_CANDIDATES:
        fp = Path(p)
        if fp.exists():
            with open(fp, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            if urls:
                print(f"[+] 读取订阅列表: {fp} ({len(urls)} 条)")
                return urls
    raise FileNotFoundError("未找到订阅列表文件")

def http_get(url: str) -> str:
    r = requests.get(url, timeout=45)
    r.raise_for_status()
    return r.text

def maybe_b64_decode(text: str) -> str:
    if "://" in text or "proxies:" in text:
        return text
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded, validate=False)
        s = decoded.decode("utf-8", errors="ignore")
        if "://" in s or "proxies:" in s:
            return s
    except Exception:
        pass
    return text

# ================= 协议解析 =================

def parse_hysteria2(link: str) -> dict | None:
    try:
        raw = link[len("hysteria2://"):]
        creds, rest = raw.split("@", 1)
        password = creds
        hp_match = re.match(r"([^:/?#]+):(\d+)(.*)", rest)
        if not hp_match: return None
        host, port, tail = hp_match.groups()
        q, name = {}, "HY2"
        if "?" in tail:
            query_part = tail.split("?", 1)[1]
            if "#" in query_part:
                query_part, frag = query_part.split("#", 1)
                name = unquote(frag)
            q = parse_qs(query_part)
        elif "#" in tail:
            name = unquote(tail.split("#", 1)[1])
        return {
            "name": name,
            "type": "hysteria2",
            "server": host,
            "port": int(port),
            **({"sni": q["sni"][0]} if "sni" in q else {}),
            **({"alpn": q["alpn"][0].split(",")} if "alpn" in q else {}),
            **({"skip-cert-verify": True} if (
                ("insecure" in q and q["insecure"][0] in ("1", "true", "True")) or
                ("skip-cert-verify" in q and q["skip-cert-verify"][0] in ("1", "true", "True"))
            ) else {}),
            "password": password
        }
    except Exception:
        return None

def parse_trojan(link: str) -> dict | None:
    try:
        raw = link[len("trojan://"):]
        pwd, rest = raw.split("@", 1)
        host_port, tail = (rest.split("?", 1) + [""])[:2]
        name = "Trojan"
        if "#" in tail:
            tail, frag = tail.split("#", 1)
            name = unquote(frag)
        host, port = host_port.split(":")
        q = parse_qs(tail)
        node = {
            "name": name,
            "type": "trojan",
            "server": host,
            "port": int(port),
            "password": pwd,
        }
        sni = q.get("sni") or q.get("peer")
        if sni: node["sni"] = sni[0]
        if q.get("allowInsecure", ["0"])[0] in ("1","true","True"):
            node["skip-cert-verify"] = True
        return node
    except Exception:
        return None

def parse_ss(link: str) -> dict | None:
    try:
        body = link[len("ss://"):]
        name = "Shadowsocks"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)
        def decode_if_b64(s: str) -> str:
            try:
                padded = s + "=" * (-len(s) % 4)
                return base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                return s
        if "@" not in body:
            body = decode_if_b64(body)
        if "@" in body:
            auth, hp = body.split("@", 1)
        else:
            m = re.match(r"([^:@]+):([^:@]+)@([^:@]+):(\d+)", body)
            if not m: return None
            auth, hp = f"{m.group(1)}:{m.group(2)}", f"{m.group(3)}:{m.group(4)}"
        method, password = auth.split(":", 1)
        host, port = hp.split(":", 1)
        return {
            "name": name,
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None

def parse_uri_line(line: str) -> dict | None:
    if line.startswith("hysteria2://"): return parse_hysteria2(line)
    if line.startswith("trojan://"): return parse_trojan(line)
    if line.startswith("ss://"): return parse_ss(line)
    return None

# ================= 合并逻辑 =================

def parse_subscription_text(text: str) -> list[dict]:
    text = maybe_b64_decode(text).strip()
    proxies: list[dict] = []
    if "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                proxies.extend([p for p in data["proxies"] if isinstance(p, dict)])
                return proxies
        except Exception:
            pass
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        node = parse_uri_line(ln)
        if node: proxies.append(node)
    return proxies

def unique_name(existing: set, name: str) -> str:
    if name not in existing:
        existing.add(name)
        return name
    i = 2
    while True:
        cand = f"{name} ({i})"
        if cand not in existing:
            existing.add(cand)
            return cand
        i += 1

# ================= 并发连通性 =================

async def test_one(server: str, port: int, timeout: int = TIMEOUT) -> int | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout)
        writer.close()
        await writer.wait_closed()
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None

async def filter_alive_async(proxies: list[dict], concurrency: int = CONCURRENCY) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    alive = []
    seen_server_port = set()

    async def check(p):
        server, port = p.get("server"), p.get("port")
        if not server or not port: return
        key = (server, port)
        if key in seen_server_port: return
        seen_server_port.add(key)
        async with sem:
            latency = await test_one(server, int(port))
            if latency is not None:
                p["latency_ms"] = latency
                alive.append(p)

    for p in tqdm(proxies, desc="测试节点连通性"):
        await check(p)

    return alive

# ================= 保存 =================

def save_yaml(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def read_existing_yaml(paths: list) -> list[dict]:
    proxies = []
    for p in paths:
        fp = Path(p)
        if fp.exists():
            try:
                data = yaml.safe_load(fp.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "proxies" in data:
                    proxies.extend(data["proxies"])
            except Exception:
                continue
    return proxies

def build_final_config(all_proxies: list[dict]) -> dict:
    all_proxies.sort(key=lambda x: x.get("latency_ms", 9999))
    seen_names = set()
    normalized = []
    seen_server_port = set()
    for p in all_proxies:
        key = (p.get("server"), p.get("port"))
        if key in seen_server_port: continue
        seen_server_port.add(key)
        p["name"] = unique_name(seen_names, str(p.get("name","Node")))
        normalized.append(p)
    return {"proxies": normalized}

# ================= 主流程 =================

def main():
    urls = read_url_list()
    merged = []

    for url in urls:
        try:
            print(f"[+] 拉取: {url}")
            raw = http_get(url)
            proxies = parse_subscription_text(raw)
            print(f"    - 解析 {len(proxies)} 个节点")
            merged.extend(proxies)
        except Exception as e:
            print(f"[!] 拉取失败: {url} -> {e}")

    print(f"[=] 开始并发测试节点连通性，总计 {len(merged)} 个")
    alive = asyncio.run(filter_alive_async(merged))

    # 读取已有 YAML
    existing_proxies = read_existing_yaml(EXISTING_YAML)
    print(f"[+] 已读取仓库 tmp
