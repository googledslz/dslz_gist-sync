import yaml
from pathlib import Path
from tqdm import tqdm
import geoip2.database

INPUT_FILE = "clash.yaml"

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def save_yaml(data, path):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)

def fix_node(node):
    try:
        if "port" not in node or not isinstance(node["port"], int):
            return None
        if "server" not in node or not node["server"]:
            return None
        # 修复 tls 字段为布尔
        if "tls" in node and isinstance(node["tls"], str):
            node["tls"] = node["tls"].lower() in ("1","true","yes")
        return node
    except Exception:
        return None

def add_country(node, reader):
    try:
        ip = node.get("server")
        if not ip:
            return node
        rec = reader.city(ip)
        iso = rec.country.iso_code or ""
        emoji = {
            "CN":"🇨🇳","US":"🇺🇸","JP":"🇯🇵","KR":"🇰🇷","SG":"🇸🇬","DE":"🇩🇪","FR":"🇫🇷"
        }.get(iso, "")
        if emoji:
            node["name"] = f"{emoji}{iso} {node.get('name','')}"
        return node
    except Exception:
        return node

def main():
    fp = Path(INPUT_FILE)
    if not fp.exists():
        print(f"[!] {INPUT_FILE} 不存在")
        return
    data = load_yaml(fp)
    if "proxies" not in data:
        print("[!] 无 proxies 字段")
        return
    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    except Exception:
        reader = None
    new_proxies = []
    print("[+] 开始修复节点...")
    for p in tqdm(data["proxies"], desc="修复节点"):
        p2 = fix_node(p)
        if p2 is None:
            continue
        if reader:
            p2 = add_country(p2, reader)
        new_proxies.append(p2)
    data["proxies"] = new_proxies
    save_yaml(data, INPUT_FILE)
    print(f"[+] 已修复 {len(new_proxies)} 个节点，覆盖 {INPUT_FILE}")

if __name__ == "__main__":
    main()
