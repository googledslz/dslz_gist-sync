import base64
import requests
import yaml
import re
import asyncio
import time
import subprocess
from pathlib import Path
from urllib.parse import unquote, parse_qs
from tqdm import tqdm

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

def parse_hysteria2(link: str) -> dict | None:
    try:
        raw = link[len("hysteria2://") :]
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
            "password": password,
        }
    except Exception:
        return None

def parse_trojan(link: str) -> dict | None:
    try:
        raw = link[len("trojan://") :]
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
        body = link[len("ss://") :]
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
                if isinstance(data, dict) and "proxies" in data:
                    proxies.extend([p for p in data["proxies"] if isinstance(p, dict)])
            except Exception as e:
                print(f"[!] 读取已有 YAML 失败: {path} -> {e}")
    return proxies

def print_latency_table(proxies: list[dict]):
    if not proxies: return
    print("\n┌" + "─"*72 + "┐")
    print(f"│ {'节点名称':<20} │ {'服务器':<20} │ {'端口':<6} │ {'延迟(ms)':<8} │")
    print("├" + "─"*72 + "┤")
    for p in proxies:
        print(f"│ {p['name']:<20} │ {p['server']:<20} │ {p['port']:<6} │ {p.get('latency_ms', '-'):<8} │")
    print("└" + "─"*72 + "┘\n")

# ================= 主流程 =================

def main():
    urls = read_url_list()
    merged = []

    print(f"[+] 开始拉取订阅节点 ({len(urls)} 个链接)")
    for url in tqdm(urls):
        try:
            text = http_get(url)
            nodes = parse_subscription_text(text)
            merged.extend(nodes)
        except Exception as e:
            print(f"[!] 拉取失败: {url} -> {e}")

    # 合并已有 YAML
    merged.extend(read_existing_yaml(EXISTING_YAML))
    print(f"[+] 合并节点总数: {len(merged)}")

    # 去重 server+port
    seen_sp = set()
    deduped = []
    for p in merged:
        sp = (p.get("server"), p.get("port"))
        if sp not in seen_sp:
            deduped.append(p)
            seen_sp.add(sp)
    print(f"[+] 去重 server+port 后节点总数: {len(deduped)}")

    # 连通性检测
    print(f"[+] 开始并发测试节点连通性...")
    alive = asyncio.run(filter_alive_async(deduped))
    print(f"[+] 连通节点总数: {len(alive)}")
    print_latency_table(alive)

    # 写 clash.yaml
    final_config = build_final_config(alive)
    save_yaml(final_config, OUTPUT_FILE)
    print(f"[+] 已生成 {OUTPUT_FILE}")

    # 调用 fix_clash.py 并捕获异常
    print(f"[+] 调用 {FIX_SCRIPT} 修复端口并剔除错误节点...")
    try:
        subprocess.run(["python3", FIX_SCRIPT], check=True)
        print(f"[+] {FIX_SCRIPT} 执行完成")
    except subprocess.CalledProcessError as e:
        print(f"[!] {FIX_SCRIPT} 执行失败: {e}")

if __name__ == "__main__":
    main()
