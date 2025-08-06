import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def clean_domain(domain):
    """仅清洗域名首尾空格和点，保留原始格式"""
    return domain.strip().strip('.') if domain else ''

def create_session():
    """创建轻量会话：3秒超时+3次重试（适配GitHub网络）"""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504]
    )
    session.mount('https://', HTTPAdapter(max_retries=retry))
    return session

def fetch_domains(url, session):
    """获取原始域名列表（保留顺序和重复项）"""
    try:
        resp = session.get(url, timeout=3)
        resp.raise_for_status()
        domains = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line and not line.lstrip().startswith('#'):
                cleaned = clean_domain(line)
                if cleaned:
                    domains.append(cleaned)
        return domains
    except Exception as e:
        print(f"下载 {url} 失败：{str(e)}")
        return []

def get_parent_domains(domain):
    """生成父域名集合（含自身）"""
    if not domain:
        return set()
    parts = [p for p in domain.split('.') if p]
    return {'.'.join(parts[i:]) for i in range(len(parts))}

def filter_hosts(hosts_url, whitelist, blacklist, session):
    """筛选hosts：仅保留域名规则，保留原始格式和重复项"""
    try:
        resp = session.get(hosts_url, timeout=3)
        resp.raise_for_status()
        filtered = []
        
        for line in resp.text.splitlines():
            original_line = line
            line_clean = line.strip()
            
            if not line_clean or line_clean.startswith('#'):
                continue
            
            # 提取域名部分（忽略注释）
            content = line_clean.split('#', 1)[0].strip()
            if not content:
                continue
            
            # 直接视为域名列表（无需拆分IP）
            domains = [clean_domain(p) for p in content.split() if clean_domain(p)]
            if not domains:
                continue
            
            # 白名单检查（使用集合快速查找）
            white_set = set(whitelist)
            in_white = any(get_parent_domains(d) & white_set for d in domains)
            if not in_white:
                continue
            
            # 黑名单检查（使用集合快速查找）
            black_set = set(blacklist)
            in_black = any(get_parent_domains(d) & black_set for d in domains)
            if in_black:
                continue
            
            filtered.append(original_line)
        
        return filtered
    except Exception as e:
        print(f"处理hosts失败：{str(e)}")
        return []

if __name__ == "__main__":
    # 配置链接
    WHITELIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/active.list-aa"
    BLACKLIST_URL1 = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/main/release/china-list.txt"
    BLACKLIST_URL2 = "https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/config/add_rules/useless_ad_domain.txt"
    HOSTS_URL = "https://raw.githubusercontent.com/ykvhjnn/ad-filters-subscriber/refs/heads/release/hosts.txt"
    
    session = create_session()
    
    # 获取白名单（列表，保留重复项）
    print("获取白名单...")
    whitelist = fetch_domains(WHITELIST_URL, session)
    if not whitelist:
        print("白名单为空，退出")
        session.close()
        exit(1)
    
    # 获取黑名单（列表，保留重复项）
    print("获取黑名单1...")
    blacklist1 = fetch_domains(BLACKLIST_URL1, session)
    print("获取黑名单2...")
    blacklist2 = fetch_domains(BLACKLIST_URL2, session)
    blacklist = blacklist1 + blacklist2  # 合并列表，保留顺序和重复项
    
    # 筛选hosts
    print("筛选hosts...")
    result = filter_hosts(HOSTS_URL, whitelist, blacklist, session)
    
    # 保存结果（保留原始格式和重复项）
    with open("filtered_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(result) + "\n")
    
    print(f"完成，保留 {len(result)} 条记录")
    session.close()
