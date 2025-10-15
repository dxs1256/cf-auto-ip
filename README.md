# cf-auto-ip

自动抓取多个公开源的 Cloudflare 优选 IPv4/IPv6 地址，自动去重、校验、排序，并查询国家代码，输出为代理工具可用格式。

## ✨ 特性
- 支持 IPv4 / IPv6 双栈
- 自动国家识别（使用 ip-api.com，无需 token）
- 输出格式：`ip:port#CC`（IPv6 自动加方括号）
- 默认端口 `443`（可修改为 `8443` 等 Cloudflare 官方 HTTPS 端口）

## 📦 输出文件
- `ip.txt`：IPv4 列表  
- `ipv6.txt`：IPv6 列表（带 `-IPV6` 标识）

## ▶️ 使用
```bash
pip install requests
python autoip6.py
