import sys
import yaml
from pathlib import Path

def fix_port(port):
    """将端口字符串中的非数字字符去掉，只保留数字"""
    if isinstance(port, int):
        return port
    if isinstance(port, str):
        num = ''.join(filter(str.isdigit, port))
        return int(num) if num else 0
    return 0

def fix_clash_yaml(input_path, output_path):
    fp = Path(input_path)
    if not fp.exists():
        print(f"[!] 文件不存在: {input_path}")
        return
    try:
        data = yaml.safe_load(fp.read_text(encoding="utf-8"))
        if "proxies" not in data or not isinstance(data["proxies"], list):
            print("[!] proxies 节点不存在或格式错误")
            return
        fixed = []
        seen = set()
        for p in data["proxies"]:
            # 修复端口
            p["port"] = fix_port(p.get("port"))
            # 避免重复 server+port
            key = (p.get("server"), p.get("port"))
            if key in seen:
                continue
            seen.add(key)
            fixed.append(p)
        data["proxies"] = fixed
        Path(output_path).write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"[√] 已生成修复文件: {output_path}, 节点数: {len(fixed)}")
    except Exception as e:
        print(f"[!] 处理失败: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python fix_clash.py 输入.yaml 输出.yaml")
    else:
        fix_clash_yaml(sys.argv[1], sys.argv[2])
