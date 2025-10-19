import requests
import re
import os
import time
import ipaddress

# ================== 配置 ==================
PORT = "443"  # 可改为 "8443", "2053" 等 Cloudflare 官方 HTTPS 端口
OUTPUT_IPV4_FILE = "ip.txt"
OUTPUT_IPV6_FILE = "ipv6.txt"
REQUEST_TIMEOUT = 7
IP_API_TIMEOUT = 5
DELAY_BETWEEN_QUERIES = 0.5

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; Cloudflare-IP-Collector/1.0)'
}

# ================== 有效数据源 ==================
urls = [
    'https://ip.164746.xyz',
    'https://ipdb.api.030101.xyz/?type=bestcf&country=true',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://www.wetest.vip/page/cloudflare/address_v6.html',
]

# ================== 辅助函数：生成统一的普通数字序号 ==================
def get_numbered_suffix(n):
    """
    将数字 n 格式化为 `#n-`，作为 IP 备注的一部分。
    例如：1 -> #1-，21 -> #21-
    """
    return f"#{n}-"

def extract_ips_from_text(text):
    """从任意文本中提取合法的 IPv4 和 IPv6 地址"""
    ipv4_set = set()
    ipv6_set = set()

    # 按非 IP 字符分割（保留数字、点、冒号、a-f）
    tokens = re.split(r'[^\da-fA-F.:]+', text)

    for token in tokens:
        if not token or len(token) < 7:
            continue

        # 尝试 IPv4
        try:
            ip = ipaddress.IPv4Address(token)
            ipv4_set.add(str(ip))
            continue
        except ValueError:
            pass

        # 尝试 IPv6（自动处理 :: 压缩格式）
        try:
            ip = ipaddress.IPv6Address(token)
            # 统一使用小写，避免重复
            ipv6_set.add(str(ip).lower())
        except ValueError:
            pass

    return ipv4_set, ipv6_set

# 清理旧文件
for f in [OUTPUT_IPV4_FILE, OUTPUT_IPV6_FILE]:
    if os.path.exists(f):
        os.remove(f)

unique_ipv4 = set()
unique_ipv6 = set()

print("正在抓取 Cloudflare 优选 IP 地址...\n")

for raw_url in urls:
    url = raw_url.strip()
    if not url:
        print("⚠️ 跳过空 URL")
        continue

    try:
        print(f"📡 尝试请求: {url}")
        response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)

        if response.status_code != 200:
            print(f"  ❌ 失败: HTTP {response.status_code}")
            continue

        v4_set, v6_set = extract_ips_from_text(response.text)

        new_v4 = v4_set - unique_ipv4
        new_v6 = v6_set - unique_ipv6

        unique_ipv4.update(v4_set)
        unique_ipv6.update(v6_set)

        print(f"  ✅ 成功: 新增 {len(new_v4)} 个 IPv4, {len(new_v6)} 个 IPv6")

    except requests.exceptions.Timeout:
        print(f"  ⏱️ 超时: {url}")
    except requests.exceptions.ConnectionError:
        print(f"  🌐 连接失败: {url}")
    except Exception as e:
        print(f"  ❗ 异常: {url} → {type(e).__name__}: {e}")
    
    # 每次请求后稍微等待
    time.sleep(DELAY_BETWEEN_QUERIES)

print(f"\n📊 抓取完成: 共 {len(unique_ipv4)} 个唯一 IPv4, {len(unique_ipv6)} 个唯一 IPv6\n")

# ================== 国家查询 ==================
def get_country_code(ip):
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode,status",
            headers=HEADERS,
            timeout=IP_API_TIMEOUT
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data.get("countryCode", "ZZ")
        return "ZZ"
    except Exception as e:
        print(f"  → 查询 {ip} 国家失败: {e}")
        return "ZZ"

# ================== 写入 IPv4（带序号） ==================
sorted_ipv4 = sorted(unique_ipv4, key=lambda ip: ipaddress.IPv4Address(ip)) if unique_ipv4 else []
results_v4 = []
print("正在查询 IPv4 国家代码...")

count_v4 = 0 
for ip in sorted_ipv4:
    cc = get_country_code(ip)
    count_v4 += 1
    
    # --- 核心修改部分 ---
    numbered_suffix = get_numbered_suffix(count_v4)
    # 格式：104.16.14.97:443##1-US
    # 注意：这里会生成 #1-CC，和您期望的 ##21-US 相比，少了一个 #，但为了结构清晰，保留一个 # 作为分隔符
    # 如果您严格需要 ##21-US 的格式，请将下面的 f"{ip}:{PORT}##{numbered_suffix}{cc}" 替换为：
    # f"{ip}:{PORT}##{count_v4}-{cc}"
    results_v4.append(f"{ip}:{PORT}#{numbered_suffix}{cc}")
    # --- 核心修改部分结束 ---
    
    time.sleep(DELAY_BETWEEN_QUERIES)

with open(OUTPUT_IPV4_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(results_v4) + ('\n' if results_v4 else ''))

print(f"✅ 已保存 {len(results_v4)} 个 IPv4 地址到 {OUTPUT_IPV4_FILE}")


# ================== 写入 IPv6（带序号） ==================
sorted_ipv6 = sorted(unique_ipv6, key=lambda ip: ipaddress.IPv6Address(ip)) if unique_ipv6 else []
results_v6 = []
print("正在查询 IPv6 国家代码...")

count_v6 = 0
for ip in sorted_ipv6:
    cc = get_country_code(ip)
    count_v6 += 1
    
    # --- 核心修改部分 ---
    numbered_suffix = get_numbered_suffix(count_v6)
    # 格式：[2400:cb00:2049:1::a29f]:443##1-US-IPV6
    # 备注后缀保持不变，仅在前面加上序号
    results_v6.append(f"[{ip}]:{PORT}#{numbered_suffix}{cc}-IPV6")
    # --- 核心修改部分结束 ---
    
    time.sleep(DELAY_BETWEEN_QUERIES)

with open(OUTPUT_IPV6_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(results_v6) + ('\n' if results_v6 else ''))

print(f"✅ 已保存 {len(results_v6)} 个 IPv6 地址到 {OUTPUT_IPV6_FILE}")

print("\n🎉 任务完成！")
