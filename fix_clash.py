import yaml
import requests
from tqdm import tqdm
from pathlib import Path

INPUT_FILE = "clash.yaml"
OUTPUT_FILE = "clash.yaml"

# ================= 国家查询 =================
COUNTRY_CACHE = {}

def get_country_flag(ip: str) -> str:
    if ip in COUNTRY_CACHE: return COUNTRY_CACHE[ip]
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        r.raise_for_status()
        data = r.json()
        country = data.get("country", "")
        flag = country_to_emoji(country)
        COUNTRY_CACHE[ip] = flag
        return flag
    except Exception:
        return ""
    
def country_to_emoji(code: str) -> str:
    mapping = {
        "CN":"🇨🇳CN", "US":"🇺🇸US", "JP":"🇯🇵JP", "KR":"🇰🇷KR",
        "SG":"🇸🇬SG", "HK":"🇭🇰HK", "TW":"🇹🇼TW"
    }
    return mapping.get(code.upper(), code)

# ================= 修复 =================

def fix_node(node: dict) -> dict | None:
    # 检查 server port
    server = node.get("server")
    port = node.get("port")
    if not server or not isinstance(port,int):
        return None
    # 国家标识
    flag = get_country_flag(server)
    node["name"] = f"{flag} {node['name']}" if flag else node["name"]
    return node

def main():
    fp = Path(INPUT_FILE)
    if not fp.exists():
        print(f"[!] 文件不存在: {INPUT_FILE}")
        return

    try:
        data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        proxies = data.get("proxies", [])
        fixed = []
        for p in tqdm(proxies, desc="修复节点"):
            node = fix_node(p)
            if node: fixed.append(node)
        data["proxies"] = fixed
        fp.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"[+] 修复完成, 有效节点 {len(fixed)}/{len(proxies)}")
    except Exception as e:
        print(f"[!] 修复失败: {e}")

if __name__ == "__main__":
    main()
