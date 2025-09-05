import yaml
import ipaddress
import requests
from tqdm import tqdm
from pathlib import Path

INPUT_FILE = "clash.yaml"

# 国家名映射（可扩展）
COUNTRY_EMOJI_MAP = {
    "CN": "🇨🇳CN", "US": "🇺🇸US", "JP": "🇯🇵JP", "KR": "🇰🇷KR", "SG": "🇸🇬SG",
    "DE": "🇩🇪DE", "FR": "🇫🇷FR", "GB": "🇬🇧GB", "RU": "🇷🇺RU", "IN": "🇮🇳IN"
}

def get_country_code(ip: str) -> str:
    try:
        r = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
        if r.status_code == 200:
            return COUNTRY_EMOJI_MAP.get(r.text.strip(), r.text.strip())
    except Exception:
        pass
    return "🌐"

def fix_node(p: dict) -> dict | None:
    # 端口必须是整数
    try:
        port = int(p.get("port"))
        if not (0 < port < 65536):
            return None
        p["port"] = port
    except Exception:
        return None

    # 字段合法性检查
    if "type" not in p or "server" not in p or "name" not in p:
        return None

    # IP 国家前缀
    try:
        ipaddress.ip_address(p["server"])
        country = get_country_code(p["server"])
        p["name"] = f"{country} {p['name']}"
    except Exception:
        p["name"] = f"🌐 {p['name']}"

    return p

def main():
    fp = Path(INPUT_FILE)
    if not fp.exists():
        print(f"[!] 文件不存在: {INPUT_FILE}")
        return

    data = yaml.safe_load(fp.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "proxies" not in data:
        print("[!] YAML 格式错误")
        return

    proxies = data["proxies"]
    fixed = []

    for p in tqdm(proxies, desc="修复节点"):
        node = fix_node(p)
        if node:
            fixed.append(node)

    print(f"[+] 原节点数量: {len(proxies)}, 修复后节点数量: {len(fixed)}")

    data["proxies"] = fixed
    fp.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print("[√] 已覆盖原 clash.yaml")

if __name__ == "__main__":
    main()
