import base64
import requests
import yaml
import re
import asyncio
import time
from pathlib import Path
from urllib.parse import unquote, parse_qs

# ================= 配置 =================
INPUT_CANDIDATES = ["tmp/1.TXT", "/tmp/1.TXT"]
EXISTING_YAML = ["tmp/dslz.yaml", "/tmp/dslz.yaml"]
OUTPUT_FILE = "clash.yaml"
FIXED_OUTPUT_FILE = "clash_fixed.yaml"

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
            "password": password,
            **({"sni": q["sni"][0]} if "sni" in q else {}),
            **({"alpn": q["alpn"][0].split(",")} if "alpn" in q else {}),
            **({"skip-cert-verify": True} if (
                ("insecure" in q and q["insecure"][0] in ("1", "true", "True")) or
                ("skip-cert-verify" in q and q["skip-cert-verify"][0] in ("1", "true", "True"))
            ) else {}),
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
            "port": port,
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
            "port": port,
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

def unique_name(existing: set, name: str) -> str:
    if name not in existing:
        existing.add(name); return name
    i = 2
    while True:
        cand = f"{name} ({i})"
        if cand not in existing:
            existing.add(cand); return cand
        i += 1

# ================= 并发连通性 + 延迟 =================

async def test_one(server: str, port: int, timeout: int = 3) -> float | None:
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
        if not server or not port:
            return
        if isinstance(port, str):
            m = re.match(r"(\d+)", port)
            if m:
                port = int(m.group(1))
            else:
                return
        key = (server, port)
        if key in seen_server_port:
            return
        seen_server_port.add(key)
        async with sem:
            latency = await test_one(server, port)
            if latency is not None:
                p["latency_ms"] = latency
                p["port"] = port  # 确保端口是整数
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

def print_latency_table(proxies: list[dict]):
    if not proxies:
        return
    print("\n┌" + "─"*72 + "┐")
    print(f"│ {'节点名称':<20} │ {'服务器':<20} │ {'端口':<6} │ {'延迟(ms)':<8} │")
    print("├" + "─"*72 + "┤")
    for p in proxies:
        print(f"│ {p['name']:<20} │ {p['server']:<20} │ {p['port']:<6} │ {p.get('latency_ms', '-'):<8} │")
    print("└" + "─"*72 + "┘\n")

# ================= 保存最终 YAML（合并 dslz.yaml 内容） =================

def save_final_yaml(alive_proxies: list[dict], existing_yaml_paths: list[str], output_file: str):
    final_data = {"proxies": alive_proxies}
    for p in existing_yaml_paths:
        fp = Path(p)
        if fp.exists():
            try:
                data = yaml.safe_load(fp.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for k, v in data.items():
                        if k != "proxies":
                            final_data[k] = v
            except Exception as e:
                print(f"[!] 读取已有 YAML 失败: {p} -> {e}")
    save_yaml(final_data, output_file)
    print(f"[√] 已生成 {output_file}")

# ================= 端口清理 =================

def fix_ports(input_file: str, output_file: str):
    fp = Path(input_file)
    if not fp.exists():
        print(f"[!] 文件不存在: {input_file}")
        return
    data = yaml.safe_load(fp.read_text(encoding="utf-8"))
    fixed_count = 0
    if "proxies" in data and isinstance(data["proxies"], list):
        new_proxies = []
        for p in data["proxies"]:
            if "port" in p:
                port_value = p["port"]
                if isinstance(port_value, int):
                    new_proxies.append(p)
                    continue
                if isinstance(port_value, str):
                    m = re.match(r"(\d+)", port_value)
                    if m:
                        p["port"] = int(m.group(1))
                        fixed_count += 1
                        new_proxies.append(p)
                    else:
                        print(f"[!] 节点 {p.get('name')} port 无法解析，跳过")
            else:
                new_proxies.append(p)
        data["proxies"] = new_proxies
    save_yaml(data, output_file)
    print(f"[√] 端口修正完成，处理 {fixed_count} 个端口，输出 {output_file}")

# ================= 主流程 =================

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

    cfg = build_final_config(alive)
    print_latency_table(cfg["proxies"])

    save_final_yaml(cfg["proxies"], EXISTING_YAML, OUTPUT_FILE)

    # 自动调用端口修复，生成最终 clash_fixed.yaml
    fix_ports(OUTPUT_FILE, FIXED_OUTPUT_FILE)

if __name__ == "__main__":
    main()
