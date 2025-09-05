import yaml
from pathlib import Path

CLASH_FILE = "clash.yaml"

def load_yaml(path):
    fp = Path(path)
    if not fp.exists(): return None
    try:
        return yaml.safe_load(fp.read_text(encoding="utf-8"))
    except Exception:
        return None

def save_yaml(data, path):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def fix_ports_and_dedup(data):
    if "proxies" not in data: return data
    new_list = []
    seen_server_port = set()
    for p in data["proxies"]:
        server = p.get("server")
        port = p.get("port")
        if not server or not port: continue
        try:
            port_int = int(str(port).split()[0].split("#")[0])
        except Exception:
            continue
        key = (server, port_int)
        if key in seen_server_port: continue
        seen_server_port.add(key)
        p["port"] = port_int
        new_list.append(p)
    data["proxies"] = new_list
    return data

def main():
    data = load_yaml(CLASH_FILE)
    if not data: return
    data = fix_ports_and_dedup(data)
    save_yaml(data, CLASH_FILE)
    print(f"[+] clash.yaml 已修复，节点总数: {len(data['proxies'])}")

if __name__ == "__main__":
    main()
