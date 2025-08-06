import requests

def clean_domain(domain):
    """清洗域名：去除前后多余的点、转为小写"""
    return domain.strip().lower().strip('.')

def fetch_and_extract_domains(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        domains = set()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 清洗后加入集合（确保目标域名格式统一）
            cleaned = clean_domain(line)
            if cleaned:  # 避免空字符串
                domains.add(cleaned)
        return domains
    except Exception as e:
        print(f"获取域名列表失败：{str(e)}")
        return set()

def is_subdomain_or_match(host_domain, target_domain):
    """判断 host_domain 是否是 target_domain 的子域名或完全匹配"""
    if host_domain == target_domain:
        return True  # 完全匹配
    # 子域名判断：host_domain 必须以 ".target_domain" 结尾
    return host_domain.endswith(f".{target_domain}")

def filter_hosts_by_domains(hosts_url, target_domains):
    try:
        response = requests.get(hosts_url, timeout=30)
        response.raise_for_status()
        filtered_lines = []
        for line in response.text.splitlines():
            original_line = line
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            content_without_comment = line.split('#', 1)[0].strip()
            parts = content_without_comment.split()
            if len(parts) < 2:
                continue  # 不符合 hosts 格式
            
            # 提取并清洗 hosts 中的所有域名（排除 IP 部分）
            hosts_domains = [clean_domain(part) for part in parts[1:] if clean_domain(part)]
            if not hosts_domains:
                continue  # 没有有效域名
            
            # 检查是否有任何域名是目标域名的子域名或完全匹配
            match = False
            for host_domain in hosts_domains:
                for target_domain in target_domains:
                    if is_subdomain_or_match(host_domain, target_domain):
                        match = True
                        break  # 找到匹配的目标域名，跳出内层循环
                if match:
                    break  # 找到匹配的域名，跳出外层循环
            
            if match:
                filtered_lines.append(original_line)
        
        return filtered_lines
    except Exception as e:
        print(f"获取/处理 Hosts 失败：{str(e)}")
        return []

if __name__ == "__main__":
    DOMAINS_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/active.list-aa"
    HOSTS_URL = "https://raw.githubusercontent.com/ykvhjnn/ad-filters-subscriber/refs/heads/release/hosts.txt"
    
    target_domains = fetch_and_extract_domains(DOMAINS_URL)
    if not target_domains:
        print("无有效目标域名，退出")
        exit(1)
    
    filtered_hosts = filter_hosts_by_domains(HOSTS_URL, target_domains)
    
    with open("filtered_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_hosts) + "\n")
