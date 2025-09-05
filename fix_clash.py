import yaml

CLASH_FILE = "clash.yaml"

def fix_ports(data: dict) -> dict:
    for proxy in data.get("proxies", []):
        if isinstance(proxy.get("port"), str):
            try:
                proxy["port"] = int("".join([c for c in proxy["port"] if c.isdigit()]))
            except Exception:
                proxy["port"] = 0
    return data

def main():
    with open(CLASH_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    data = fix_ports(data)
    with open(CLASH_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True)
    print("已修复 clash.yaml 并覆盖原文件")

if __name__ == "__main__":
    main()
