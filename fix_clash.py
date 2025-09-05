import yaml
import ipaddress
import requests
from pathlib import Path
import sys

INPUT_FILE = "clash.yaml"

# 简单的国家码映射
COUNTRY_MAP = {
    "CN": "🇨🇳CN",
    "US": "🇺🇸US",
    "JP": "🇯🇵JP",
    "KR": "🇰🇷KR",
    "SG": "🇸🇬SG",
    "DE": "🇩🇪DE",
    "FR": "🇫🇷FR",
    "RU": "🇷🇺RU",
}

def get_country_code(ip: str) -> str:
    try:
        r = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
        if r.status_code == 200:
            return COUNTRY_MAP.get(r.text.strip(), r.text.strip())
    except Exception:
        pass
    return "🌐"

def fix_node(p: dict) -> dict | None:
    try:
        port = int(p.get("port"))
        if port <= 0 or port > 65535:
            return None
        node = dict(p)
        node["port"] = port
        # 将 TLS 从字符串转为 bool
        if "tls" in node:
            val = node["tls"]
            if isinstance(val, str):
                node["tls"] = val.lower() in ("1","true","yes")
        # 添加国家缩写
        server = node.get("server")
        if server:
            try:
                ipaddress.ip_address(server)
                cc = get_country_code(server)
                node["name"] = f"{cc} {node['name']}"
            except Exception:
                pass
        return node
    except Exception:
        return None

def main():
    fp = Path(INPUT_FILE)
    if not fp.exists():
        print(f"[!] {INPUT_FILE} 不存在")
        sys.exit(0)
    try:
        data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        if not data or "proxies" not in data:
            print("[!] 无 proxies 节点")
            sys.exit(0)
        proxies_fixed = []
        for p in data["proxies"]:
            node = fix_node(p)
            if node:
                proxies_fixed.append(node)
        data["proxies"] = proxies_fixed
        fp.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"[√] 已修复 clash.yaml，剔除无效节点，节点数 {len(proxies_fixed)}")
    except Exception as e:
        print(f"[!] 修复失败: {e}")
    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()
