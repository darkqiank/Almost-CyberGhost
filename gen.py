import shodan
import os
import re
import yaml

API_KEY = os.getenv("SHODAN_API_KEY")

api = shodan.Shodan(API_KEY)

query = 'http.html:"nodes.gen4.ninja"'

proxies = []
proxy_names = []

try:
    count = 0
    results = api.search(
        query,
        fields="ip_str,http.html",
        limit=1000
    )

    print(f"Total results: {results['total']}")

    for match in results["matches"]:
        ip = match.get("ip_str", "")
        html = match.get("http", {}).get("html", "")
        print("=" * 60)
        print("IP:", ip)
        print("HTML snippet:", html[:300])  # 防止太长
        match = re.search(r'([^"\s<>]+)\.nodes\.gen4\.ninja:9002', html)
        if match and ip:
            node_name = match.group(1)
            # 去重：如果已存在同名节点则跳过
            if node_name in proxy_names:
                print(f"[-] 跳过重复节点: {node_name} -> {ip}")
                continue
            # 构建单个代理节点配置
            proxy_item = {
                "name": node_name,
                "type": "http",
                "server": ip,
                "port": 9002,
                "tls": True,
                "skip-cert-verify": True,
                "sni": "www.icloud.com"
            }
            proxies.append(proxy_item)
            proxy_names.append(node_name)
            count += 1
                
            print(f"[+] 找到节点: {node_name} -> {ip}")

except shodan.APIError as e:
    print("Error:", e)

# 输出文件名
OUTPUT_FILE = "clash_config.yaml"

# Clash 基础配置头部 (保持你提供的模版)
CLASH_HEADER = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": False,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "secret": "",
    "dns": {
        "enable": True,
        "ipv6": False,
        "listen": "0.0.0.0:53",
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": ["8.8.8.8", "1.1.1.1"],
        "fallback": ["8.8.4.4", "1.0.0.1"]
    }
}

# 组装最终配置
full_config = CLASH_HEADER.copy()
full_config['proxies'] = proxies

# 添加代理组 (Proxy Groups) - 必不可少，否则 Clash 无法选择节点
full_config['proxy-groups'] = [
    {
        "name": "Auto Select",
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "proxies": proxy_names
    },
    {
        "name": "Proxy",
        "type": "select",
        "proxies": ["Auto Select"] + proxy_names
    }
]

# 添加基础规则
full_config['rules'] = [
    "MATCH,Proxy"
]

# 写入文件
# allow_unicode=True 确保中文注释不乱码 (虽然这里主要是英文)
# sort_keys=False 保持字典顺序，更易读
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    yaml.dump(full_config, f, allow_unicode=True, sort_keys=False)

print(f"[*] 共获取节点数量: {len(proxies)}")