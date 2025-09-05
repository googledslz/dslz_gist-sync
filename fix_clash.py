import yaml
import re
import requests
import pycountry

INPUT = "clash.yaml"
OUTPUT = "clash.yaml"

# 缓存，避免重复请求
_geo_cache = {}
# 国家名 -> ISO2 缩写 + emoji
_country_flag_cache = {}

def country_to_emoji(country_name: str) -> str:
    """国家名转 ISO2 + emoji"""
    if country_name in _country_flag_cache:
        return _country_flag_cache[country_name]

    try:
        country = pycountry.countries.lookup(country_name)
        code = country.alpha_2.upper()
        # emoji flag
        emoji = "".join(chr(ord(c) + 127397) for c in code)
        res = f"{emoji}{code}"
    except Exception:
        res = f"🌐??"
    _country_flag_cache[country_name] = res
    return res

def get_country(ip_or_host: str) -> str:
    """查询 IP/域名归属国家"""
    if ip_or_host in _geo_cache:
        return _geo_cache[ip_or_host]

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_or_host}?fields=status,country",
            timeout=5,
        )
        data = resp.json()
        if data.get("status") == "success":
            country_name = data.get("country", "未知")
        else:
            country_name = "未知"
    except Exception:
        country_name = "未知"

    _geo_cache[ip_or_host] = country_name
    return country_name


def fix_ports_and_bools(proxies):
    fixed = []
    for p in proxies:
        try:
            # 检查 server
            if not p.get("server"):
                continue

            # 修复端口 (必须是 int)
            if isinstance(p.get("port"), str):
                match = re.match(r"(\d+)", p["port"])
                if match:
                    p["port"] = int(match.group(1))
                else:
                    continue
            elif isinstance(p.get("port"), int):
                if not (0 < p["port"] < 65536):
                    continue
            else:
                continue

            # 修复 tls 字段
            if "tls" in p and isinstance(p["tls"], str):
                p["tls"] = True if p["tls"].lower() in ["true", "tls", "1"] else False

            # 获取国家并加到 name 前面
            country_name = get_country(p["server"])
            country_prefix = country_to_emoji(country_name)

            if not p.get("name"):
                p["name"] = "proxy"
            if not p["name"].startswith(country_prefix):
                p["name"] = f"{country_prefix}_{p['name']}"

            fixed.append(p)

        except Exception:
            # 出错的节点剔除
            continue

    return fixed


def main():
    with open(INPUT, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    proxies = data.get("proxies", [])
    proxies = fix_ports_and_bools(proxies)
    data["proxies"] = proxies

    with open(OUTPUT, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

    print(f"[+] 已修复并覆盖写回 {OUTPUT}, 最终节点数: {len(proxies)}")


if __name__ == "__main__":
    main()
