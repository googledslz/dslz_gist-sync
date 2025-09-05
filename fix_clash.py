import yaml
from pathlib import Path
from tqdm import tqdm
import requests
import socket

INPUT_FILE = "clash.yaml"

# 国家IP库 API（示例免费IP查询服务）
IPAPI_URL = "https://ipapi.co/{}/json/"

# 简单的 IP -> 国家缩写映射缓存
ip_country_cache = {}

def get_country_emoji(ip: str) -> str:
    if ip in ip_country_cache:
        return ip_country_cache[ip]
    try:
        r = requests.get(IPAPI_URL.format(ip), timeout=5)
        r.raise_for_status()
        data = r.json()
        code = data.get("country_code", "")
        if not code: return ""
        emoji = f"🇨🇳" if code=="CN" else f"🇺🇸" if code=="US" else f"🇪🇺" if code=="EU" else f"🌐"
        ip_country_cache[ip] = f"{emoji}{code}"
        return f"{emoji}{code}"
    except Exception:
        return ""

def is_valid_node(node: dict) -> bool:
    """检查节点是否含有必要字段"""
    required = ["name","server","port","type"]
    for k in required:
        if k not in node:
            return False
    if not isinstance(node["port"], int):
        return False
    return True

def main():
    fp = Path(INPUT_FILE)
    if not fp.exists():
        print(f"[!] {INPUT_FILE} 不存在")
        return

    with open(fp, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "proxies" not in data:
        print("[!] clash.yaml 格式错误")
        return

    nodes = data["proxies"]
    fixed_nodes = []

    for node in tqdm(nodes, desc="[>] 处理节点"):
        if not is_valid_node(node):
            continue
        # 修复端口（保证整数）
        try:
            node["port"] = int(node["port"])
        except Exception:
            continue
        # 添加国家缩写前缀
        server = node.get("server","")
        try:
            ip = socket.gethostbyname(server)
            country = get_country_emoji(ip)
            if country:
                node["name"] = f"{country} {node['name']}"
        except Exception:
            pass
        fixed_nodes.append(node)

    print(f"[+] 原始节点数: {len(nodes)}")
    print(f"[+] 修复后节点数: {len(fixed_nodes)}")

    data["proxies"] = fixed_nodes
    with open(INPUT_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)

    print(f"[+] 已覆盖生成 {INPUT_FILE} 成功")

if __name__ == "__main__":
    main()
