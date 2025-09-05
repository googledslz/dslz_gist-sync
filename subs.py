import base64
import requests
import yaml
import subprocess
import os
from urllib.parse import unquote, urlparse, parse_qs


import base64
import requests
import yaml
from urllib.parse import unquote, parse_qs

# === 配置区 ===
SUB_URL = "https://foldjc.top/api/v1/client/subscribe?token=412e0b0168a844cadf332a634b5a52d4"
OUTPUT_FILE = "clash.yaml"


# === 下载订阅 ===
def download_subscribe(url: str) -> str:
    print("[+] 下载订阅中...")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text.strip()


# === Base64 解码 ===
def decode_base64(data: str) -> str:
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)
    return base64.b64decode(data).decode("utf-8", errors="ignore")


# === 解析 hysteria2 链接为 Clash 节点 ===
def parse_hysteria2(link: str) -> dict:
    # 格式: hysteria2://uuid@host:port/?param=xxx#name
    url = link.replace("hysteria2://", "")
    creds, rest = url.split("@", 1)
    uuid = creds
    host_port, *rest2 = rest.split("/", 1)
    host, port = host_port.split(":")
    query = {}
    name = "Hysteria"

    if "?" in rest:
        q = rest.split("?", 1)[1]
        if "#" in q:
            q, frag = q.split("#", 1)
            name = unquote(frag)
        query = parse_qs(q)
    elif "#" in rest:
        name = unquote(rest.split("#", 1)[1])

    node = {
        "name": name,
        "type": "hysteria",
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "tls": True,
        "alpn": [],
    }
    if "sni" in query:
        node["sni"] = query["sni"][0]
    return node


# === 转换为 Clash YAML ===
def convert_to_clash(links: list) -> dict:
    proxies = []
    for link in links:
        if link.startswith("hysteria2://"):
            proxies.append(parse_hysteria2(link))
        else:
            print(f"[!] 未支持的协议: {link[:20]}")

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "Rule",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "proxies": [p["name"] for p in proxies],
            }
        ],
        "rules": ["MATCH,AUTO"],
    }
    return clash_config


# === 保存文件 ===
def save_yaml(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)


def main():
    raw = download_subscribe(SUB_URL)
    decoded = decode_base64(raw)
    links = [line.strip() for line in decoded.splitlines() if line.strip()]
    clash_config = convert_to_clash(links)
    save_yaml(clash_config, OUTPUT_FILE)
    print(f"[+] 已生成 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

