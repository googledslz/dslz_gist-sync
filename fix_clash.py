import yaml
import re

INPUT = "clash.yaml"
OUTPUT = "clash.yaml"

def fix_ports_and_bools(proxies):
    fixed = []
    for p in proxies:
        # 修复端口 (去掉多余字符)
        if isinstance(p.get("port"), str):
            match = re.match(r"(\d+)", p["port"])
            if match:
                p["port"] = int(match.group(1))
            else:
                continue  # 丢弃无法解析的端口
        # 修复 tls 字段
        if "tls" in p and isinstance(p["tls"], str):
            p["tls"] = True if p["tls"].lower() in ["true", "tls", "1"] else False
        fixed.append(p)
    return fixed

def main():
    with open(INPUT, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    proxies = data.get("proxies", [])
    proxies = fix_ports_and_bools(proxies)
    data["proxies"] = proxies

    with open(OUTPUT, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

    print(f"[+] 已修复并覆盖写回 {OUTPUT}")

if __name__ == "__main__":
    main()
