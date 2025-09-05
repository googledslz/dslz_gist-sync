import asyncio
import aiohttp
import base64
import json
import re
import subprocess
import yaml
from pathlib import Path

# ================= 配置 =================
INPUT_CANDIDATES = ["tmp/1.TXT", "/tmp/1.TXT"]
EXISTING_YAML = ["tmp/dslz.yaml", "/tmp/dslz.yaml"]
OUTPUT_FILE = "clash.yaml"
FIX_SCRIPT = "fix_clash.py"
TEST_URL = "http://cp.cloudflare.com"  # 节点连通性测试 URL

# ================= 工具函数 =================

def read_url_list() -> list:
    """读取订阅列表"""
    for p in INPUT_CANDIDATES:
        fp = Path(p)
        if fp.exists():
            with open(fp, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            if urls:
                print(f"[+] 读取订阅列表: {fp} ({len(urls)} 条)")
                return urls
    raise FileNotFoundError("未找到 tmp/1.TXT 或 /tmp/1.TXT")

def decode_base64(data: str) -> str:
    """解码 base64（补齐 padding）"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data).decode("utf-8")

# ================= 节点解析 =================

def parse_vmess(data: str) -> dict:
    raw = decode_base64(data)
    js = json.loads(raw)
    return {
        "name": js.get("ps", "vmess"),
        "type": "vmess",
        "server": js["add"],
        "port": int(js["port"]),
        "uuid": js["id"],
        "alterId": int(js.get("aid", 0)),
        "cipher": "auto",
        "tls": True if js.get("tls") == "tls" else False,
        "network": js.get("net", "tcp"),
        "ws-opts": {
            "path": js.get("path", ""),
            "headers": {"Host": js.get("host", "")}
        },
    }

def parse_vless(url: str) -> dict:
    m = re.match(r"^vless://([^@]+)@([^:]+):(\d+)\??(.*)", url)
    if not m:
        return None
    uuid, host, port, params = m.groups()
    opts = dict(re.findall(r"([^=&]+)=([^&]*)", params))
    name = url.split("#")[-1] if "#" in url else "vless"
    return {
        "name": name,
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "tls": True if opts.get("security") == "tls" else False,
        "network": opts.get("type", "tcp"),
        "ws-opts": {
            "path": opts.get("path", ""),
            "headers": {"Host": opts.get("host", "")}
        },
    }

def parse_trojan(url: str) -> dict:
    m = re.match(r"^trojan://([^@]+)@([^:]+):(\d+)\??", url)
    if not m:
        return None
    password, host, port = m.groups()
    name = url.split("#")[-1] if "#" in url else "trojan"
    return {
        "name": name,
        "type": "trojan",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": host,
        "tls": True,
    }

def parse_ss(url: str) -> dict:
    m = re.match(r"^ss://([^@]+)@([^:]+):(\d+)", url)
    if not m:
        return None
    userinfo, host, port = m.groups()
    if ":" in userinfo:
        method, password = userinfo.split(":", 1)
    else:
        decoded = decode_base64(userinfo)
        method, password = decoded.split(":", 1)
    name = url.split("#")[-1] if "#" in url else "ss"
    return {
        "name": name,
        "type": "ss",
        "server": host,
        "port": int(port),
        "cipher": method,
        "password": password,
    }

def parse_url(url: str) -> dict:
    if url.startswith("vmess://"):
        return parse_vmess(url[8:])
    elif url.startswith("vless://"):
        return parse_vless(url)
    elif url.startswith("trojan://"):
        return parse_trojan(url)
    elif url.startswith("ss://"):
        return parse_ss(url)
    return None

# ================= 节点测试 =================

async def test_proxy(session, proxy: dict) -> bool:
    test_conf = {
        "proxies": [proxy],
        "proxy-groups": [
            {"name": "test", "type": "select", "proxies": [proxy["name"]]}
        ],
        "rules": ["MATCH,test"],
    }
    tmp_file = Path("/tmp/clash_test.yaml")
    tmp_file.write_text(yaml.dump(test_conf, allow_unicode=True), encoding="utf-8")
    cmd = ["curl", "--proxy", f"socks5://127.0.0.1:7890", TEST_URL, "--max-time", "5"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.communicate(), timeout=6)
        return proc.returncode == 0
    except Exception:
        return False

async def filter_working_proxies(proxies: list) -> list:
    async with aiohttp.ClientSession() as session:
        tasks = [test_proxy(session, p) for p in proxies]
        results = await asyncio.gather(*tasks)
    working = [p for p, ok in zip(proxies, results) if ok]
    print(f"[+] 可用节点数量: {len(working)}/{len(proxies)}")
    return working

# ================= 主流程 =================

async def main():
    urls = read_url_list()

    # 解析节点
    proxies = []
    for url in urls:
        proxy = parse_url(url)
        if proxy:
            proxies.append(proxy)

    # 去重 (server+port)
    seen = set()
    unique_proxies = []
    for p in proxies:
        key = (p["server"], p["port"])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(p)

    # 名称去重
    names = set()
    for p in unique_proxies:
        name = p["name"]
        i = 1
        while name in names:
            i += 1
            name = f"{p['name']}_{i}"
        p["name"] = name
        names.add(name)

    # 测试连通性
    working = await filter_working_proxies(unique_proxies)

    # 合并现有 yaml
    merged = {"proxies": working}
    for path in EXISTING_YAML:
        fp = Path(path)
        if fp.exists():
            with open(fp, "r", encoding="utf-8") as f:
                extra_yaml = yaml.safe_load(f)
            if extra_yaml and "proxies" in extra_yaml:
                merged["proxies"].extend(extra_yaml["proxies"])

    # 写入 clash.yaml
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(merged, f, allow_unicode=True)
    print(f"[+] 已生成 {OUTPUT_FILE}")

    # 调用 fix_clash.py
    subprocess.run(["python", FIX_SCRIPT], check=True)

if __name__ == "__main__":
    asyncio.run(main())
