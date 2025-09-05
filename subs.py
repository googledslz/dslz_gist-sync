#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
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
APPEND_MARKER = "# ===== tmp/dslz.yaml 原始内容 =====\n"

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

def parse_vmess(link: str) -> dict | None:
    try:
        body = link[len("vmess://"):].strip()
        padded = body + "=" * (-len(body) % 4)
        raw = base64.b64decode(padded).decode("utf-8", errors="ignore")
        data = json.loads(raw)
        return {
            "name": data.get("ps", "vmess"),
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port") or 0),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid") or 0),
            "cipher": data.get("scy") or data.get("cipher") or "auto",
            "tls": True if data.get("tls") else False,
            "network": data.get("net", "tcp"),
            # ws opts if needed
            **({"ws-path": data.get("path", ""), "ws-headers": {"Host": data.get("host", "")}} if data.get("net") == "ws" else {})
        }
    except Exception:
        return None

def parse_vless(link: str) -> dict | None:
    try:
        raw = link[len("vless://"):].strip()
        name = "VLESS"
        if "#" in raw:
            raw, frag = raw.split("#", 1)
            name = unquote(frag)
        if "@" not in raw:
            return None
        userinfo, rest = raw.split("@", 1)
        serverinfo, qstr = (rest.split("?", 1) + [""])[:2]
        if ":" not in serverinfo:
            return None
        host, port = serverinfo.split(":", 1)
        q = parse_qs(qstr)
        node = {"name": name, "type": "vless", "server": host, "port": int(port), "uuid": userinfo}
        if q.get("sni"): node["sni"] = q["sni"][0]
        if q.get("security") and q["security"][0].lower() in ("tls", "xtls"):
            node["tls"] = True
        if q.get("path"):
            node["network"] = q.get("type", ["tcp"])[0]
            node["ws-path"] = q["path"][0]
        if q.get("host"):
            node["ws-headers"] = {"Host": q["host"][0]}
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

        # 如果没有 @ ，此为 base64 整段编码
        if "@" not in body:
            try:
                padded = body + "=" * (-len(body) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                # 尝试普通 base64
                try:
                    padded = body + "=" * (-len(body) % 4)
                    decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                except Exception:
                    return None
            body = decoded

        if "@" not in body:
            return None
        auth, hp = body.split("@", 1)
        if ":" not in auth or ":" not in hp:
            return None
        method, password = auth.split(":", 1)
        host, port = hp.split(":", 1)
        return {"name": name, "type": "ss", "server": host, "port": int(port), "cipher": method, "password": password}
    except Exception:
        return None

def parse_trojan(link: str) -> dict | None:
    try:
        raw = link[len("trojan://"):].strip()
        if "@" not in raw:
            return None
        pwd, rest = raw.split("@", 1)
        host_port, tail = (rest.split("?", 1) + [""])[:2]
        name = "Trojan"
        if "#" in tail:
            tail, frag = tail.split("#", 1)
            name = unquote(frag)
        if ":" not in host_port:
            return None
        host, port = host_port.split(":", 1)
        q = parse_qs(tail)
        node = {"name": name, "type": "trojan", "server": host, "port": int(port), "password": pwd}
        if q.get("sni"): node["sni"] = q["sni"][0]
        if q.get("allowInsecure", ["0"])[0].lower() in ("1", "true"):
            node["skip-cert-verify"] = True
        return node
    except Exception:
        return None

def parse_hysteria2(link: str) -> dict | None:
    try:
        raw = link[len("hysteria2://"):].strip()
        if "@" not in raw:
            return None
        creds, rest = raw.split("@", 1)
        password = creds
        m = re.match(r"([^:/?#]+):(\d+)(.*)", rest)
        if not m:
            return None
        host, port, tail = m.groups()
        q, name = {}, "HY2"
        if "?" in tail:
            qstr = tail.split("?", 1)[1]
            if "#" in qstr:
                qstr, frag = qstr.split("#", 1)
                name = unquote(frag)
            q = parse_qs(qstr)
        elif "#" in tail:
            name = unquote(tail.split("#", 1)[1])
        node = {"name": name, "type": "hysteria2", "server": host, "port": int(port), "password": password}
        if "sni" in q: node["sni"] = q["sni"][0]
        return node
    except Exception:
        return None

def parse_uri_line(line: str) -> dict | None:
    line = line.strip()
    if not line: return None
    if line.startswith("vmess://"): return parse_vmess(line)
    if line.startswith("vless://"): return parse_vless(line)
    if line.startswith("ss://"): return parse_ss(line)
    if line.startswith("trojan://"): return parse_trojan(line)
    if line.startswith("hysteria2://"): return parse_hysteria2(line)
    return None

# ================= 合并逻辑 =================

def parse_subscription_text(text: str) -> list[dict]:
    text = maybe_b64_decode(text).strip()
    proxies: list[dict] = []
    # 如果是 clash YAML 结构
    if "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                proxies.extend([p for p in data["proxies"] if isinstance(p, dict)])
                print(f"    - Clash YAML，{len(proxies)} 个节点")
                return proxies
        except Exception:
            pass
    # 否则按行解析 URI
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        node = parse_uri_line(ln)
        if node:
            proxies.append(node)
    print(f"    - URI 列表，解析 {len(proxies)} 个节点")
    return proxies

def read_existing_yaml(paths: list[str]) -> list[dict]:
    """读取已有 dslz.yaml 中的 proxies（用于合并）"""
    merged = []
    for p in paths:
        fp = Path(p)
        if not fp.exists(): continue
        try:
            data = yaml.safe_load(fp.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                merged.extend([n for n in data["proxies"] if isinstance(n, dict)])
        except Exception as e:
            print(f"[!] 读取已有 YAML 失败: {p} -> {e}")
    return merged

def read_raw_yaml(paths: list[str]) -> str:
    """读取 tmp/dslz.yaml 原始内容以便追加（返回原始文本，不做解析）"""
    for p in paths:
        fp = Path(p)
        if fp.exists():
            try:
                return fp.read_text(encoding="utf-8")
            except Exception as e:
                print(f"[!] 读取原始文件失败: {p} -> {e}")
    return ""

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

# ================= 并发连通性 + 测试 =================

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
        server, port_raw = p.get("server"), p.get("port")
        if not server or not port_raw:
            return
        # 尝试从 port 字段中提取整数端口（兼容 "443#备注", "443/?plugin=..."）
        try:
            port = int(re.match(r"(\d+)", str(port_raw)).group(1))
        except Exception:
            return
        key = (server, port)
        if key in seen_server_port:
            return
        seen_server_port.add(key)
        async with sem:
            latency = await test_one(server, port)
            if latency is not None:
                p["port"] = port
                p["latency_ms"] = latency
                alive.append(p)

    await asyncio.gather(*(check(p) for p in proxies))
    return alive

def build_final_config(all_proxies: list[dict]) -> dict:
    # 按延迟排序并保证 server+port 唯一与 name 唯一
    all_proxies.sort(key=lambda x: x.get("latency_ms", 9999))
    seen_sp = set()
    seen_names = set()
    normalized = []
    for p in all_proxies:
        server, port = p.get("server"), p.get("port")
        if not server or not port:
            continue
        key = (server, port)
        if key in seen_sp:
            continue
        seen_sp.add(key)
        p = dict(p)
        name = str(p.get("name", f"{server}:{port}"))
        p["name"] = unique_name(seen_names, name)
        normalized.append(p)
    return {"proxies": normalized}

def save_yaml(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

def print_latency_table(proxies: list[dict]):
    if not proxies:
        return
    print("\n┌" + "─"*72 + "┐")
    print(f"│ {'节点名称':<20} │ {'服务器':<20} │ {'端口':<6} │ {'延迟(ms)':<8} │")
    print("├" + "─"*72 + "┤")
    for p in proxies:
        print(f"│ {p['name']:<20} │ {p['server']:<20} │ {p['port']:<6} │ {p.get('latency_ms','-'):<8} │")
    print("└" + "─"*72 + "┘\n")

# ================= 主流程 =================

def main():
    # 1. 读取订阅链接并拉取节点
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
    # 2. 并发测试连通性，返回 alive 列表
    alive = asyncio.run(filter_alive_async(merged))

    # 3. 合并节点（加入已有 tmp/dslz.yaml 中的 proxies）
    existing_proxies = read_existing_yaml(EXISTING_YAML)
    all_proxies = alive + existing_proxies

    cfg = build_final_config(all_proxies)

    # 4. 写入 clash.yaml（先写 proxies）
    save_yaml(cfg, OUTPUT_FILE)
    print(f"[+] 已写入 {OUTPUT_FILE}，有效节点: {len(cfg['proxies'])}")

    # 4b. 追加 tmp/dslz.yaml 原始内容（不做处理）
    raw_extra = read_raw_yaml(EXISTING_YAML)
    if raw_extra:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write("\n" + APPEND_MARKER)
            f.write(raw_extra)
        print(f"[+] 已追加 tmp/dslz.yaml 原始内容到 {OUTPUT_FILE}")

    # 5. 自动调用 fix_clash.py（会修复 YAML 部分端口并覆盖 clash.yaml，同时保留追加内容）
    try:
        subprocess.run(["python3", FIX_SCRIPT], check=True)
        print("[+] fix_clash.py 执行完成（clash.yaml 已修复并覆盖）")
    except subprocess.CalledProcessError as e:
        print(f"[!] 调用 {FIX_SCRIPT} 失败: {e}")
    except Exception as e:
        print(f"[!] 调用 {FIX_SCRIPT} 出错: {e}")

if __name__ == "__main__":
    main()
