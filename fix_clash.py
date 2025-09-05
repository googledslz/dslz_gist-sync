import yaml
import requests
from tqdm import tqdm
from pathlib import Path

OUTPUT_FILE = "clash.yaml"

VALID_SS_CIPHERS = [
    "aes-128-gcm","aes-192-gcm","aes-256-gcm",
    "chacha20-ietf-poly1305","xchacha20-ietf-poly1305"
]

IPAPI_URL = "https://ipapi.co/{}/country_code/"

def get_country_emoji(ip: str) -> str:
    try:
        r = requests.get(IPAPI_URL.format(ip), timeout=5)
        r.raise_for_status()
        code = r.text.strip().upper()
        if code:
            return f"🇨🇳CN" if code=="CN" else f"🇺🇸US" if code=="US" else f"🌐{code}"
    except Exception:
        pass
    return "🌐??"

def fix_node(p: dict) -> dict | None:
    t = p.get("type")
    if t == "ss":
        if not p.get("server") or not p.get("port") or not p.get("cipher") or p["cipher"] not in VALID_SS_CIPHERS:
            return None
    elif t in ("trojan","hysteria2","vmess","vless"):
        if not p.get("server") or not p.get("port"):
            return None
    else:
        return None
    # 加国家前缀
    server_ip = p.get("server")
    prefix = get_country_emoji(server_ip)
    p["name"] = f"{prefix} {p.get('name','node')}"
    return p

def main():
    fp = Path(OUTPUT_FILE)
    if not fp.exists():
        print("[!] clash.yaml 不存在")
        return
    with open(fp, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    proxies = data.get("proxies", [])
    fixed = []
    for p in tqdm(proxies, desc="[>] 修复节点"):
        np = fix_node(p)
        if np:
            fixed.append(np)
    data["proxies"] = fixed
    with open(fp, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)
    print(f"[+] 修复完成，节点总数: {len(fixed)}")

if __name__ == "__main__":
    main()
