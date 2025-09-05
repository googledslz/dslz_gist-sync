import asyncio
import base64
import os
import subprocess
from urllib.parse import unquote
import aiohttp
import yaml

# 订阅链接
SUBS = [
    "https://raw.githubusercontent.com/theGreatPeter/v2rayNodes/main/nodes.txt",
    # 可以继续添加
]

# 输出文件
CLASH_FILE = "clash.yaml"
TMP_FILE = "/tmp/dslz.yaml"

# ============ 节点解析 ============

def parse_vmess(link: str) -> dict | None:
    try:
        body = link[len("vmess://"):]
        padded = body + "=" * (-len(body) % 4)
        raw = base64.urlsafe_b64decode(padded).decode("utf-8")
        data = yaml.safe_load(raw)
        return {
            "name": data.get("ps", "vmess"),
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port", 0)),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "tls": "tls" if data.get("tls") else "",
            "network": data.get("net", "tcp"),
            "ws-opts": {"path": data.get("path", ""), "headers": {"Host": data.get("host", "")}}
            if data.get("net") == "ws" else {}
        }
    except Exception:
        return None


def parse_vless(link: str) -> dict | None:
    try:
        body = link[len("vless://"):]
        name = "VLESS"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)
        if "@" not in body or ":" not in body:
            return None
        userinfo, serverinfo = body.split("@", 1)
        uuid = userinfo
        if "?" in serverinfo:
            serverinfo, params = serverinfo.split("?", 1)
            params = dict(p.split("=") for p in params.split("&") if "=" in p)
        else:
            params = {}
        host, port = serverinfo.split(":", 1)
        return {
            "name": name,
            "type": "vless",
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "network": params.get("type", "tcp"),
            "tls": params.get("security", ""),
            "udp": True
        }
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
            # 新格式：Base64 解码
            try:
                padded = body + "=" * (-len(body) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                return None
            body = decoded

        if "@" not in body or ":" not in body:
            return None

        auth, hp = body.split("@", 1)
        method, password = auth.split(":", 1)
        host, port = hp.split(":", 1)

        return {
            "name": name,
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password
        }
    except Exception:
        return None


def parse_link(link: str) -> dict | None:
    if link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("ss://"):
        return parse_ss(link)
    return None

# ============ 下载订阅 ============

async def fetch_sub(session: aiohttp.ClientSession, url: str) -> list[str]:
    try:
        async with session.get(url, timeout=20) as resp:
            text = await resp.text()
            return [line.strip() for line in text.splitlines() if line.strip()]
    except Exception:
        return []

async def load_all_subs() -> list[str]:
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_sub(session, url) for url in SUBS]
        results = await asyncio.gather(*tasks)
        return sum(results, [])

# ============ 节点测试 ============

async def test_proxy(proxy: dict) -> bool:
    host, port = proxy["server"], proxy["port"]
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def filter_working(proxies: list[dict]) -> list[dict]:
    tasks = [test_proxy(p) for p in proxies]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [p for p, ok in zip(proxies, results) if ok is True]

# ============ 合并去重 ============

def dedup_proxies(proxies: list[dict]) -> list[dict]:
    seen = set()
    names = set()
    result = []
    for p in proxies:
        key = (p["server"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        name = p["name"]
        idx = 1
        while name in names:
            name = f"{p['name']}_{idx}"
            idx += 1
        p["name"] = name
        names.add(name)
        result.append(p)
    return result

# ============ 主逻辑 ============

async def main():
    print("加载订阅...")
    raw_links = await load_all_subs()
    proxies = [parse_link(link) for link in raw_links]
    proxies = [p for p in proxies if p]

    print(f"总共解析节点: {len(proxies)}")

    print("测试可用性...")
    proxies = await filter_working(proxies)
    print(f"可用节点: {len(proxies)}")

    print("去重和重命名...")
    proxies = dedup_proxies(proxies)

    # 写入 clash.yaml
    data = {"proxies": proxies, "proxy-groups": [], "rules": []}

    # 合并 /tmp/dslz.yaml
    if os.path.exists(TMP_FILE):
        with open(TMP_FILE, "r", encoding="utf-8") as f:
            extra = yaml.safe_load(f)
        if isinstance(extra, dict):
            for k, v in extra.items():
                if k in data and isinstance(data[k], list) and isinstance(v, list):
                    data[k].extend(v)
                else:
                    data[k] = v

    with open(CLASH_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)

    print("已生成 clash.yaml")

    # 自动调用 fix_clash.py
    print("运行 fix_clash.py 修复 clash.yaml...")
    subprocess.run(["python", "fix_clash.py"], check=True)

if __name__ == "__main__":
    asyncio.run(main())
