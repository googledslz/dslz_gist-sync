import base64
import requests
import yaml
import re
import asyncio
import time
import subprocess
from pathlib import Path
from urllib.parse import unquote, parse_qs

# ================= 配置 =================
INPUT_CANDIDATES = ["tmp/1.TXT", "/tmp/1.TXT"]
EXISTING_YAML = ["tmp/dslz.yaml", "/tmp/dslz.yaml"]
OUTPUT_FILE = "clash.yaml"
FIX_SCRIPT = "fix_clash.py"

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
    raise FileNotFoundError("未找到 tmp/1.TXT 或 /tmp/1.TXT")

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

def parse_uri_line(line: str) -> dict | None:
    if line.startswith("ss://") or line.startswith("trojan://") or line.startswith("hysteria2://"):
        # 简化解析，具体可扩展
        return {"name": line[:20], "type": "ss", "server": "127.0.0.1", "port": 12345}
    if line.startswith("vless://") or line.startswith("vmess://"):
        return {"name": line[:20], "type": "vless", "server": "127.0.0.1", "port": 12345}
    return None

def parse_subscription_text(text: str) -> list[dict]:
    text = maybe_b64_decode(text).strip()
    proxies: list[dict] = []
    if "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                proxies.extend([p for p in data["proxies"] if isinstance(p, dict)])
                print(f"    - Clash YAML，{len(proxies)} 个节点")
                return proxies
        except Exception:
            pass
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        node = parse_uri_line(ln)
        if node:
            proxies.append(node)
    print(f"    - URI 列表，解析 {len(proxies)} 个节点")
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

# ================= 并发连通性测试 =================

async def test_one(server: str, port: int, timeout: int = 3) -> float | None:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout)
        writer.close()
        await writer.wait_closed()
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None

async def filter_alive_async(proxies: list[dict], concurrency: int = 50) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    alive = []
    seen_server_port = set()
    async def check(p):
        server, port = p.get("server"), p.get("port")
        if not server or not port:
            return
        key = (server, port)
        if key in seen_server_port:
            return
        seen_server_port.add(key)
        async with sem:
            latency = await test_one(server, int(port))
            if latency is not None:
                p["latency_ms"] = latency
                alive.append(p)
    await asyncio.gather(*(check(p) for p in proxies))
    return alive

def build_final_config(all_proxies: list[dict]) -> dict:
    all_proxies.sort(key=lambda x: x.get("latency_ms", 9999))
    seen_names = set()
    normalized = []
    for p in all_proxies:
        if "name" not in p: continue
        p = dict(p)
        p["name"] = unique_name(seen_names, str(p["name"]))
        normalized.append(p)
    return {"proxies": normalized}

def save_yaml(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def read_existing_yaml(paths: list[str]) -> list[dict]:
    proxies = []
    for path in paths:
        fp = Path(path)
        if fp.exists():
            try:
                data = yaml.safe_load(fp.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                    proxies.extend(data["proxies"])
            except Exception:
                pass
    return proxies

def main():
    urls = read_url_list()
    merged = []
    for url in urls:
        try:
            print(f"[+] 拉取: {url}")
            raw = http_get(url)
            proxies = parse_subscription_text(raw)
            merged.extend(proxies)
        except Exception as e:
            print(f"[!] 拉取失败: {url} -> {e}")

    print(f"[=] 开始并发测试节点连通性，总计 {len(merged)} 个")
    alive = asyncio.run(filter_alive_async(merged))

    existing_proxies = read_existing_yaml(EXISTING_YAML)
    all_proxies = alive + existing_proxies
    cfg = build_final_config(all_proxies)
    save_yaml(cfg, OUTPUT_FILE)
    print(f"[+] 已生成 {OUTPUT_FILE}")

    # 调用 fix_clash.py
    try:
        subprocess.run(["python3", FIX_SCRIPT], check=True)
        print(f"[+] 修复完成")
    except subprocess.CalledProcessError as e:
        print(f"[!] fix_clash.py 执行失败: {e}")

if __name__ == "__main__":
    main()
