import base64
import requests
import yaml
from urllib.parse import unquote, parse_qs
from pathlib import Path

# === 配置区 ===
INPUT_FILE = "tmp/1.TXT"   # 存放订阅链接的文件
OUTPUT_FILE = "clash.yaml"


# === 下载订阅 ===
def download_subscribe(url: str) -> str:
    print(f"[+] 下载订阅: {url}")
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
    # 读取订阅链接列表
    sub_file = Path(INPUT_FILE)
    if not sub_file.exists():
        print(f"[!] 输入文件不存在: {INPUT_FILE}")
        return

    with open(sub_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    all_links = []
    for url in urls:
        try:
            raw = download_subscribe(url)
            decoded = decode_base64(raw)
            links = [line.strip() for line in decoded.splitlines() if line.strip()]
            all_links.extend(links)
        except Exception as e:
            print(f"[!] 拉取失败: {url}, 错误: {e}")

    clash_config = convert_to_clash(all_links)
    save_yaml(clash_config, OUTPUT_FILE)
    print(f"[+] 已生成 {OUTPUT_FILE}，包含 {len(all_links)} 个节点")


if __name__ == "__main__":
    main()
