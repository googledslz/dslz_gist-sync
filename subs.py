import base64
import requests
import yaml
import re
import asyncio
import time
from pathlib import Path
from urllib.parse import unquote, parse_qs
import subprocess

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

def parse_trojan(link: str) -> dict | None:
    try:
        raw = link[len("trojan://"):].strip()
        if "@" not in raw: return None
        pwd, rest = raw.split("@", 1)
        host_port, tail = (rest.split("?", 1) + [""])[:2]
        name = "Trojan"
        if "#" in tail:
            tail, frag = tail.split("#", 1)
            name = unquote(frag)
        host, port = host_port.split(":")
        q = parse_qs(tail)
        node = {"name": name, "type": "trojan", "server": host, "port": int(port), "password": pwd}
        sni = q.get("sni") or q.get("peer")
        if sni: node["sni"] = sni[0]
        if q.get("allowInsecure", ["0"])[0].lower() in ("1","true"):
            node["skip-cert-verify"] = True
        return node
    except Exception:
        return None

def parse_ss(link: str) -> dict | None:
    try:
        body = link[len("ss://"):].strip()
        name = "Shadowsocks"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)
        if "@" not in body:
            try:
                padded = body + "=" * (-len(body) % 4)
                body = base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                return None
        auth, hp = body.split("@", 1)
        method, password = auth.split(":", 1)
        host, port = hp.split(":", 1)
        return {"name": name, "type": "ss", "server": host, "port": int(port), "cipher": method, "password": password}
    except Exception:
        return None

def parse_uri_line(line: str) -> dict | None:
    if line.startswith("trojan://"): return parse_trojan(line)
    if line.startswith("ss://"): return parse_ss(line)
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
        if node: proxies.append(node)
    print(f"    - URI 列表，解析 {len(proxies)} 个节点")
    return proxies

def read_existing_yaml(path_list: list[str]) -> list[dict]:
    for p in path_list:
        fp = Path(p)
        if fp.exists():
            try:
                data = yaml.safe_load(fp.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                    return data["proxies"]
            except Exception as e:
                print(f"[!] 读取已有 YAML 失败: {p} -> {e}")
    return []

# ================= 并发连通性 =================

async def test_one(server: str, port: int, timeout: int = 3) -> int | None:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout)
        writer.close()
        await writer.wait_closed()
        end = time.perf_counter()
        return int((end - start) * 1000)
    except Exception:
        return None

async def filter_alive_async(proxies: list[dict], concurrency: int = 50) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    alive = []
    seen_server_port = set()

    async def check(p):
        server, port = p.get("server"), p.get("port")
        if not server or not port: return
        try:
            port = int(str(port).split()[0].split("#")[0])
        except Exception:
            return
        key = (server, port)
        if key in seen_server_port: return
        seen_server_port.add(key)
        async with sem:
            latency = await test_one(server, port)
            if latency is not None:
                p["port"] = port
                p["latency_ms"] = latency
                alive.append(p)

    await asyncio.gather(*(check(p) for p in proxies))
    return alive

def unique_name(existing: set, name: str) -> str:
    if name not in existing:
        existing.add(name); return name
    i = 2
    while True:
        cand = f"{name} ({i})"
        if cand not in existing:
            existing.add(cand); return cand
        i += 1

def build_final_config(all_proxies: list[dict]) -> dict:
    all_proxies.sort(key=lambda x: x.get("latency_ms", 9999))
    seen_names = set()
    normalized = []
    seen_server_port = set()
    for p in all_proxies:
        try:
            server, port = p.get("server"), p.get("port")
            key = (server, port)
            if key in seen_server_port: continue
            seen_server_port.add(key)
            p = dict(p)
            p["name"] = unique_name(seen_names, str(p.get("name","Node")))
            normalized.append(p)
        except Exception:
            continue
    return {"proxies": normalized}

def save_yaml(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

# ================= 主流程 =================

def main():
    # 1. 拉取节点
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

    # 2. 测试连通性
    print(f"[=] 开始并发测试节点连通性，总计 {len(merged)} 个")
    alive = asyncio.run(filter_alive_async(merged))

    # 3. 合并节点（保留唯一 server+port，节点名称改名）
    existing_proxies = read_existing_yaml(EXISTING_YAML)
    all_proxies = alive + existing_proxies
    cfg = build_final_config(all_proxies)

    # 4. 写入 clash.yaml
    save_yaml(cfg, OUTPUT_FILE)
    print(f"[+] clash.yaml 已生成，节点总数: {len(cfg['proxies'])}")

    # 5. 调用 fix_clash.py 修复端口
    try:
        subprocess.run(["python3", FIX_SCRIPT], check=True)
        print(f"[+] fix_clash.py 执行完成，clash.yaml 已修复")
    except Exception as e:
        print(f"[!] 执行 fix_clash.py 失败 -> {e}")

if __name__ == "__main__":
    main()
