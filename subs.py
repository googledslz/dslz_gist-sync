import base64
import asyncio
import aiohttp
import yaml
import subprocess
from pathlib import Path
from urllib.parse import unquote

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


def decode_base64(data: str) -> str:
    """解码 base64 并自动补全缺失的 ="""
    try:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return data


# ================= 协议解析 =================
def parse_ss(link: str) -> dict | None:
    try:
        body = link[len("ss://"):].strip()
        name = "Shadowsocks"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)

        # 如果 body 中没有 @，说明是 base64(method:password@host:port)
        if "@" not in body:
            body = decode_base64(body)

        if "@" not in body:
            return None
        auth, hp = body.split("@", 1)
        if ":" not in auth or ":" not in hp:
            return None

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


def parse_vmess(link: str) -> dict | None:
    try:
        import json
        body = decode_base64(link[len("vmess://"):])
        js = json.loads(body)
        return {
            "name": js.get("ps", "vmess"),
            "type": "vmess",
            "server": js["add"],
            "port": int(js["port"]),
            "uuid": js["id"],
            "alterId": int(js.get("aid", 0)),
            "cipher": "auto",
            "tls": "tls" if js.get("tls") == "tls" else "",
            "network": js.get("net", "tcp"),
            "ws-opts": {"path": js.get("path", ""), "headers": {"Host": js.get("host", "")}},
        }
    except Exception:
        return None


def parse_vless(link: str) -> dict | None:
    try:
        body = link[len("vless://") :]
        name = "VLESS"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)

        userinfo, hpq = body.split("@", 1)
        uuid = userinfo
        host, *rest = hpq.split(":")
        port_proto = ":".join(rest)
        if "?" in port_proto:
            port, query = port_proto.split("?", 1)
        else:
            port, query = port_proto, ""

        opts = {}
        for kv in query.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                opts[k] = v

        return {
            "name": name,
            "type": "vless",
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "tls": "tls" if opts.get("security") == "tls" else "",
            "network": opts.get("type", "tcp"),
            "ws-opts": {"path": opts.get("path", ""), "headers": {"Host": opts.get("host", "")}},
        }
    except Exception:
        return None


def parse_trojan(link: str) -> dict | None:
    try:
        body = link[len("trojan://") :]
        password, hp = body.split("@", 1)
        host, *rest = hp.split(":")
        port = int(rest[0]) if rest else 443
        name = "Trojan"
        if "#" in body:
            _, frag = body.split("#", 1)
            name = unquote(frag)
        return {
            "name": name,
            "type": "trojan",
            "server": host,
            "port": port,
            "password": password,
            "sni": host,
        }
    except Exception:
        return None


def parse_link(link: str) -> dict | None:
    if link.startswith("ss://"):
        return parse_ss(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    else:
        return None


# ================= 节点连通性测试 =================
async def test_one(server: str, port: int, timeout: float = 3.0) -> float | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, port), timeout)
        writer.close()
        await writer.wait_closed()
        return timeout * 1000  # 简单返回固定延迟
    except Exception:
        return None


async def filter_alive_async(proxies: list) -> list:
    results = []

    async def check(p):
        latency = await test_one(p["server"], p["port"])
        if latency is not None:
            results.append((p, latency))

    await asyncio.gather(*(check(p) for p in proxies))
    results.sort(key=lambda x: x[1])  # 按延迟排序
    return [p for p, _ in results]


# ================= 主流程 =================
def merge_proxies(all_proxies: list) -> list:
    seen = set()
    names = set()
    merged = []
    for p in all_proxies:
        key = (p["server"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        base_name = p.get("name", p["type"])
        name = base_name
        i = 1
        while name in names:
            i += 1
            name = f"{base_name}_{i}"
        p["name"] = name
        names.add(name)
        merged.append(p)
    return merged


def load_existing_yaml() -> dict:
    for p in EXISTING_YAML:
        fp = Path(p)
        if fp.exists():
            with open(fp, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
    return {}


def save_clash_yaml(proxies: list, extra: dict):
    data = {"proxies": proxies}
    if extra:
        data.update(extra)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)
    print(f"[+] 写入 {OUTPUT_FILE}, 共 {len(proxies)} 个节点")


def run_fix_script():
    if Path(FIX_SCRIPT).exists():
        subprocess.run(["python", FIX_SCRIPT], check=True)
        print("[+] 已调用 fix_clash.py 修复端口")


def main():
    urls = read_url_list()
    all_proxies = []

    for url in urls:
        print(f"[+] 拉取: {url}")
        try:
            import requests
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            content = r.text.strip()

            # 可能是 base64 批量节点
            if content.startswith("ss://") or content.startswith("vmess://") or \
               content.startswith("vless://") or content.startswith("trojan://"):
                lines = content.splitlines()
            else:
                try:
                    decoded = decode_base64(content)
                    lines = decoded.splitlines()
                except Exception:
                    lines = content.splitlines()

            for line in lines:
                node = parse_link(line.strip())
                if node:
                    all_proxies.append(node)
        except Exception as e:
            print(f"[!] 拉取失败: {url} -> {e}")

    print(f"[=] 开始并发测试节点连通性，总计 {len(all_proxies)} 个")
    alive = asyncio.run(filter_alive_async(all_proxies))
    print(f"[+] 可用节点数: {len(alive)}")

    merged = merge_proxies(alive)
    extra = load_existing_yaml()
    save_clash_yaml(merged, extra)
    run_fix_script()


if __name__ == "__main__":
    main()
