#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import re
from pathlib import Path

CLASH_FILE = "clash.yaml"
APPEND_MARKER = "# ===== tmp/dslz.yaml 原始内容 =====\n"

def split_file_parts(text: str):
    """
    如果 subs.py 在 clash.yaml 末尾追加了 APPEND_MARKER，则 split 为 (yaml_text, appended_text)
    否则 appended_text 为 ''。
    """
    idx = text.find("\n" + APPEND_MARKER)
    if idx == -1:
        # 也尝试不带前导换行的情况
        idx2 = text.find(APPEND_MARKER)
        if idx2 == -1:
            return text, ""
        else:
            return text[:idx2], text[idx2 + len(APPEND_MARKER):]
    else:
        return text[:idx], text[idx + 1 + len(APPEND_MARKER):]

def fix_ports_and_dedup(data: dict) -> dict:
    if not isinstance(data, dict):
        return data
    proxies = data.get("proxies", [])
    new_list = []
    seen = set()
    for p in proxies:
        server = p.get("server")
        port_raw = p.get("port")
        if not server or not port_raw:
            continue
        # 提取端口中的数字
        s = str(port_raw)
        m = re.match(r"(\d+)", s)
        if not m:
            # 无法解析端口 -> 跳过该节点
            continue
        port = int(m.group(1))
        key = (server, port)
        if key in seen:
            continue
        seen.add(key)
        p["port"] = port
        new_list.append(p)
    data["proxies"] = new_list
    return data

def main():
    fp = Path(CLASH_FILE)
    if not fp.exists():
        print(f"[!] {CLASH_FILE} 不存在，跳过修复")
        return
    text = fp.read_text(encoding="utf-8")
    yaml_text, appended = split_file_parts(text)

    # 解析 yaml_text
    try:
        data = yaml.safe_load(yaml_text) or {}
    except Exception as e:
        print(f"[!] 解析 clash.yaml 时失败: {e}")
        # 如果解析失败，尝试将整个文件当作 YAML（退而求其次）
        try:
            data = yaml.safe_load(text) or {}
            appended = ""
            yaml_text = text
        except Exception as e2:
            print(f"[!] 无法解析整个文件为 YAML: {e2}")
            return

    # 修复 ports 并去重
    data = fix_ports_and_dedup(data)

    # 写回：先把修复后的 YAML 写回，然后追加原始追加内容（如果存在）
    try:
        out = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        with open(CLASH_FILE, "w", encoding="utf-8") as f:
            f.write(out)
            if appended:
                f.write("\n" + APPEND_MARKER)
                f.write(appended)
        print(f"[+] 修复完成并覆盖 {CLASH_FILE}，节点数: {len(data.get('proxies', []))}")
    except Exception as e:
        print(f"[!] 写回文件失败: {e}")

if __name__ == "__main__":
    main()
