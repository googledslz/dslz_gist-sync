import base64
import asyncio
import aiohttp
import requests
import yaml
import re
import subprocess
from pathlib import Path

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

def decode_base64(content: str) -> str:
    try:
        missing_padding = 4 - len(content) % 4
        if missing_padding:
            content += "=" * missing_padding
        return base64.b64decode(content).decode("utf-8", errors="ignore")
    except Exception:
        return content

def parse_subscription(url: str) -> list:
    print(f"[+] 拉取: {url}")
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        content = resp.text.strip()
        if content.startswith("vmess://") or content.startswith("ss://") or content.startswith("vless://"):
            return content.splitlines()
        else:
            decoded = decode_base64(content)
            return decoded.splitlines()
    except Exception as e:
        print(f"[!] 拉取失败: {url} -> {e}")
        return []

# ============ 节点解析 ============
def parse_node(line: str) -> dict:
    if line.startswith("vmess://"):
        return parse_vmess(line)
    elif line.startswith("ss://"):
        return parse_ss(line)
    elif line.startswith("vless://"):
        return parse_vless(line)
    return None

def parse_vmess(line: str) -> dict:
    try:
        data = line[8:]
        js = base64.b64decode(data + "==").decode("utf-8", errors="ignore")
        cfg = yaml.safe_load(js)
        return {
            "name": cfg.get("ps", "vmess"),
            "type": "vmess",
            "server": cfg["add"],
            "port": int(cfg["port"]),
            "uuid": cfg["id"],
            "alterId": int(cfg.get("aid", 0)),
            "cipher": "auto",
            "tls": True if cfg.get("tls") == "tls" else False,
            "network": cfg.get("net", "tcp"),
        }
    except Exception:
        return None

def parse_ss(line: str) -> dict:
    try:
        from urllib.parse import urlparse
        data = line[5:]
        if "#" in data:
            data, name = data.split("#", 1)
            name = requests.utils.unquote(name)
        else:
            name = "ss"
        if "@" not in data:
            raw = base64.b64decode(data + "==").decode("utf-8")
            method, rest = raw.split(":", 1)
            password, server_port = rest.split("@")
            server, port = server_port.split(":")
        else:
            method_pwd, server_port = data.split("@")
            method, password = method_pwd.split(":", 1)
            server, port = server_port.split(":")
        return {
            "name": name,
            "type": "ss",
            "server": server,
            "port": int(re.sub(r"\D", "", port)),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None

def parse_vless(line: str) -> dict:
    try:
        from urllib.parse import urlparse, parse_qs
        data = line[8:]
        if "#" in data:
            data, name = data.split("#", 1)
            name = requests.utils.unquote(name)
        else:
            name = "vless"
        u = urlparse("vless://" + data)
        qs = parse_qs(u.query)
        return {
            "name": name,
            "type": "vless",
            "server": u.hostname,
            "port": int(u.port or 443),
            "uuid": u.username,
            "network": qs.get("type", ["tcp"])[0],
            "tls": True if qs.get("security", ["none"])[0] == "tls" else False,
        }
    except Exception:
        return None

# ============ 并发测试连通性 ============
async def test_one(server: str, port: int, timeout: int = 3) -> float | None:
    try:
        start = asyncio.get_event_loop().time()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return (asyncio.get_event_loop().time() - start) * 1000
    except Exception:
        return None

async def filter_alive_async(proxies: list) -> list:
    print(f"[=] 开始并发测试节点连通性，总计 {len(proxies)} 个")
    results = []

    async def check(p):
        latency = await test_one(p["server"], p["port"])
        if latency is not None:
            p["latency"] = latency
            results.append(p)

    await asyncio.gather(*(check(p) for p in proxies))
    results.sort(key=lambda x: x["latency"])
    print("[=] 存活节点: ", len(results))
    for p in results[:20]:
        print(f"{p['name']:<30} {p['server']}:{p['port']}  {p['latency']:.1f} ms")
    return results

# ============ 去重 & 改名 ============
def dedup_and_rename(proxies: list) -> list:
    seen = set()
    names = {}
    newlist = []
    for p in proxies:
        key = (p["server"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        name = p["name"]
        count = 1
        while name in names:
            count += 1
            name = f"{p['name']}_{count}"
        names[name] = 1
        p["name"] = name
        newlist.append(p)
    return newlist

# ============ 主逻辑 ============
def main():
    urls = read_url_list()
    all_nodes = []
    for url in urls:
        lines = parse_subscription(url)
        for line in lines:
            node = parse_node(line)
            if node:
                all_nodes.append(node)

    print(f"[+] 共解析到 {len(all_nodes)} 个节点")

    # 测试可用性
    alive = asyncio.run(filter_alive_async(all_nodes))

    # 去重 & 改名
    merged = dedup_and_rename(alive)

    # 写入 clash.yaml
    clash_config = {"proxies": merged}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)

    # 追加 dslz.yaml
    for p in EXISTING_YAML:
        fp = Path(p)
        if fp.exists():
            with open(fp, "r", encoding="utf-8") as src, open(OUTPUT_FILE, "a", encoding="utf-8") as dst:
                dst.write("\n")
                dst.write(src.read())
            print(f"[+] 已追加 {fp} 到 clash.yaml")

    # 调用 fix_clash.py
    subprocess.run(["python", FIX_SCRIPT], check=True)
    print("[+] clash.yaml 已修复完成")

if __name__ == "__main__":
    main()
