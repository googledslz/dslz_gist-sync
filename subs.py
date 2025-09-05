import base64
import requests
import yaml
import re
from pathlib import Path
from urllib.parse import unquote, parse_qs

INPUT_CANDIDATES = ["tmp/1.TXT", "/tmp/1.TXT"]  # 两个路径都尝试
OUTPUT_FILE = "clash.yaml"

def read_url_list() -> list:
    for p in INPUT_CANDIDATES:
        fp = Path(p)
        if fp.exists():
            with open(fp, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            if urls:
                print(f"[+] 读取订阅列表: {fp} ({len(urls)} 条)")
                return urls
    raise FileNotFoundError("未找到 tmp/1.TXT 或 /tmp/1.TXT（每行一个订阅地址）")

def http_get(url: str) -> str:
    r = requests.get(url, timeout=45)
    r.raise_for_status()
    return r.text

def maybe_b64_decode(text: str) -> str:
    # 如果文本看起来已是明文（含 :// 或 proxies:），直接返回
    if "://" in text or "proxies:" in text or "proxy-groups:" in text:
        return text
    # 尝试 Base64 解码
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded, validate=False)
        s = decoded.decode("utf-8", errors="ignore")
        if "://" in s or "proxies:" in s or "proxy-groups:" in s:
            return s
    except Exception:
        pass
    # 解不出有效内容就当作原文
    return text

# ---------------- URI 解析 ----------------

def parse_hysteria2(link: str) -> dict | None:
    # hysteria2://password@host:port/?insecure=1&sni=xxx&alpn=h3,h2#name
    try:
        raw = link[len("hysteria2://") :]
        creds, rest = raw.split("@", 1)
        password = creds
        host_port_and_more = rest
        # host:port 之后可能有 /? 或 ? 或 #，先把 host:port 拿出来
        hp_match = re.match(r"([^:/?#]+):(\d+)(.*)", host_port_and_more)
        if not hp_match:
            return None
        host, port, tail = hp_match.groups()
        q = {}
        name = "HY2"
        if "?" in tail:
            query_part = tail.split("?", 1)[1]
            if "#" in query_part:
                query_part, frag = query_part.split("#", 1)
                name = unquote(frag)
            q = parse_qs(query_part)
        elif "#" in tail:
            name = unquote(tail.split("#", 1)[1])

        node = {
            "name": name,
            "type": "hysteria2",
            "server": host,
            "port": int(port),
            "password": password,
        }
        if "sni" in q and q["sni"]:
            node["sni"] = q["sni"][0]
        if "alpn" in q and q["alpn"]:
            node["alpn"] = [s for s in q["alpn"][0].split(",") if s]
        if ("insecure" in q and q["insecure"] and q["insecure"][0] in ("1", "true", "True")) or \
           ("skip-cert-verify" in q and q["skip-cert-verify"][0] in ("1","true","True")):
            node["skip-cert-verify"] = True
        return node
    except Exception:
        return None

def parse_trojan(link: str) -> dict | None:
    # trojan://password@host:port?peer=xxx&sni=xxx#name
    try:
        raw = link[len("trojan://") :]
        pwd, rest = raw.split("@", 1)
        host_port, tail = (rest.split("?", 1) + [""])[:2]
        if "#" in tail:
            tail, frag = tail.split("#", 1)
            name = unquote(frag)
        else:
            name = "Trojan"
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
        if sni:
            node["sni"] = sni[0]
        if q.get("allowInsecure", ["0"])[0] in ("1","true","True"):
            node["skip-cert-verify"] = True
        return node
    except Exception:
        return None

def parse_ss(link: str) -> dict | None:
    # 兼容常见 ss:// 形式（尽量解析，不保证覆盖全部边角）
    try:
        body = link[len("ss://") :]
        name = "Shadowsocks"
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)

        # 可能是 base64(method:password@host:port) 或 method:password@host:port
        def decode_if_b64(s: str) -> str:
            try:
                padded = s + "=" * (-len(s) % 4)
                out = base64.b64decode(padded).decode("utf-8", errors="ignore")
                return out
            except Exception:
                return s

        if "@" not in body:
            body = decode_if_b64(body)

        # 再次尝试拆分
        if "@" in body:
            auth, hp = body.split("@", 1)
        else:
            # 有些是 method:password:host:port 之类的奇形怪状，尽量兜底
            m = re.match(r"([^:@]+):([^:@]+)@([^:@]+):(\d+)", body)
            if not m:
                return None
            auth = f"{m.group(1)}:{m.group(2)}"
            hp = f"{m.group(3)}:{m.group(4)}"

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

def parse_uri_line(line: str) -> dict | None:
    if line.startswith("hysteria2://"):
        return parse_hysteria2(line)
    if line.startswith("trojan://"):
        return parse_trojan(line)
    if line.startswith("ss://"):
        return parse_ss(line)
    # 其他协议（vmess/vless/tuic/hysteria1等）此处先跳过，避免出错
    return None

# --------------- 订阅解析与合并 ----------------

def parse_subscription_text(text: str) -> list[dict]:
    """返回 Clash 代理节点字典列表"""
    text = maybe_b64_decode(text).strip()
    proxies: list[dict] = []

    # 情况 A：Clash YAML
    if "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                for p in data["proxies"]:
                    if isinstance(p, dict) and "name" in p and "type" in p:
                        proxies.append(p)
                print(f"    - 识别为 Clash YAML，提取 proxies: {len(proxies)} 个")
                return proxies
        except Exception:
            pass  # 解析失败则当作 URI 列表继续

    # 情况 B：明文/解码后的 URI 列表
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    added = 0
    for ln in lines:
        node = parse_uri_line(ln)
        if node:
            proxies.append(node)
            added += 1
    print(f"    - 识别为 URI 列表，成功解析: {added}/{len(lines)}")
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

def build_final_config(all_proxies: list[dict]) -> dict:
    # 去重：按 name 去重（重复则自动加后缀）
    seen = set()
    normalized = []
    for p in all_proxies:
        if "name" not in p:
            continue
        p = dict(p)  # 复制
        p["name"] = unique_name(seen, str(p["name"]))
        normalized.append(p)

    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "Rule",
        "proxies": normalized,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "proxies": [p["name"] for p in normalized],
            }
        ],
        "rules": ["MATCH,AUTO"],
    }
    return config

def save_yaml(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def main():
    urls = read_url_list()
    merged: list[dict] = []
    total_from_each = []

    for url in urls:
        try:
            print(f"[+] 拉取: {url}")
            raw = http_get(url)
            proxies = parse_subscription_text(raw)
            merged.extend(proxies)
            total_from_each.append(len(proxies))
        except Exception as e:
            print(f"[!] 拉取失败: {url} -> {e}")

    cfg = build_final_config(merged)
    save_yaml(cfg, OUTPUT_FILE)
    print(f"[√] 已生成 {OUTPUT_FILE}：合并 {len(urls)} 个订阅，共 {len(merged)} 个节点（各订阅分别解析：{total_from_each}）")

if __name__ == "__main__":
    main()
