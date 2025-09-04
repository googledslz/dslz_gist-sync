# check_copy.py
import os, requests, pathlib, yaml


# check_copy.py
import os, sys, requests, pathlib, yaml

# 必需的环境变量
required_envs = ["GIST_TOKEN", "GIST_ID", "GIST_USER"]
missing = [name for name in required_envs if name not in os.environ]

if missing:
    print(f"❌ 缺少必要的环境变量: {', '.join(missing)}")
    print("请在 GitHub 仓库的 Settings → Secrets → Actions 中配置这些变量。")
    sys.exit(1)

# 环境变量存在才继续
token = os.environ["GIST_TOKEN"]
gist_id = os.environ["GIST_ID"]
gist_user = os.environ["GIST_USER"]




# 确保 tmp 目录存在（固定在仓库根目录）
repo_root = pathlib.Path(__file__).parent
tmp_dir = repo_root / "tmp"
tmp_dir.mkdir(parents=True, exist_ok=True)

cache_file = tmp_dir / "zhu_he_last.txt"
pc_file = tmp_dir / "pc.yaml"

# 构造 Gist 文件 URL
base_url = f"https://gist.githubusercontent.com/{gist_user}/{gist_id}/raw"
zhu_he_url = f"{base_url}/ZHU_HE"
fu_xie_a_url = f"{base_url}/fu_xie_A"

# 下载文件
zhu_he_content = requests.get(zhu_he_url).text.strip()
fu_xie_a_content = requests.get(fu_xie_a_url).text.strip()

# ===========================
# 判断是否第一次运行 / ZHU_HE 是否变化
# ===========================
first_run = not cache_file.exists()
old_content = cache_file.read_text(encoding="utf-8") if not first_run else ""

if first_run:
    print("🆕 第一次运行，强制生成 pc.yaml")
elif zhu_he_content != old_content:
    print("🔄 ZHU_HE 内容变化，更新并写入 pc.yaml")
else:
    print("✅ ZHU_HE 内容未变化，跳过更新 pc.yaml")
    exit(0)  # 不生成

# ===========================
# 更新缓存
# ===========================
cache_file.write_text(zhu_he_content, encoding="utf-8")

# ===========================
# YAML 处理（保证 proxies 重命名）
# ===========================
try:
    data = yaml.safe_load(zhu_he_content)
except Exception:
    print("⚠️ ZHU_HE 内容不是有效 YAML，直接原样写入 pc.yaml")
    data = {}

if isinstance(data, dict) and "proxies" in data:
    proxies = data["proxies"]
    seen = {}
    for proxy in proxies:
        base_name = proxy.get("name", "")
        if base_name not in seen:
            seen[base_name] = 1
        else:
            count = seen[base_name]
            new_name = f"{base_name}-{count}"
            while new_name in seen:
                count += 1
                new_name = f"{base_name}-{count}"
            proxy["name"] = new_name
            seen[base_name] += 1
            seen[new_name] = 1
    data["proxies"] = proxies
    zhu_he_fixed = yaml.dump(data, allow_unicode=True)
else:
    zhu_he_fixed = zhu_he_content

# ===========================
# 写入 tmp/pc.yaml（先删除）
# ===========================
if pc_file.exists():
    pc_file.unlink()
pc_file.write_text(zhu_he_fixed + "\n" + fu_xie_a_content, encoding="utf-8")

print(f"✅ 已写入合并内容到 {pc_file}")
