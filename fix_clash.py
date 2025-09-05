import yaml
import ipaddress
import requests
from pathlib import Path

INPUT_FILE = "clash.yaml"

# 简单国家映射
IP_COUNTRY = {
    "CN": "🇨🇳CN",
    "US": "🇺🇸US",
    "JP": "🇯🇵JP",
    "KR": "🇰🇷KR",
    "SG": "🇸🇬SG",
}

def get_country_code(ip: str) -> str:
    try:
        r = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
        if r.status_code == 200:
            code = r.text.strip()
            return IP_COUNTRY.get(code, code)
    except Exception:
        pass
    return ""

def fix_node(p: dict) -> dict | None:
    try:
        server = p.get("server")
        port = p.get("port")
        if not server or not port:
            return None
        # port 强制 int
        p["port"] = int(str(port).split()[0])
        # tls 强制布尔
        if "tls" in p:
            p["tls"] = str(p["tls"]).lower() in ("1","true","yes")
        # 节点名称前加国家缩写
        country = get_country_code(server)
        if country:
            p["name"] = f"{country} {p['name']}"
        return p
    except Exception:
        return None

def main():
    fp = Path(INPUT_FILE)
    if not fp.exists():
        print(f"[!] 文件不存在: {INPUT_FILE}")
        return
    try:
        data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        proxies = data.get("proxies", [])
        fixed = []
        for p in proxies:
            p_fixed = fix_node(p)
            if p_fixed:
                fixed.append(p_fixed)
        data["proxies"] = fixed
        fp.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"[+] 修复完成，节点数: {len(fixed)}")
    except Exception as e:
        print(f"[!] 修复失败: {e}")

if __name__ == "__main__":
    main()
