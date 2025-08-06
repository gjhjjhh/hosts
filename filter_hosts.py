import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def clean_domain(domain):
    """清洗域名：去除首尾点、转小写，确保格式统一"""
    return domain.strip().lower().strip('.')

def create_session_with_retries():
    """创建带重试机制的requests会话，提高网络稳定性"""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    return session

def fetch_domain_set(url, session):
    """从URL获取域名列表并返回清洗后的集合（去重）"""
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        domains = set()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):  # 跳过空行和注释
                continue
            cleaned = clean_domain(line)
            if cleaned:  # 避免空字符串
                domains.add(cleaned)
        return domains
    except Exception as e:
        print(f"获取 {url} 失败：{str(e)}")
        return set()

def get_parent_domains(domain):
    """生成域名的所有父域名（含自身）集合，用于快速匹配"""
    parts = domain.split('.')
    parent_domains = set()
    for i in range(len(parts)):
        parent = '.'.join(parts[i:])  # 从第i段开始拼接父域名
        parent_domains.add(parent)
    return parent_domains

def filter_hosts(hosts_url, whitelist, blacklist, session):
    """
    筛选hosts文件：
    1. 保留在白名单中（含子域名）的条目
    2. 移除在黑名单中（含子域名）的条目
    """
    try:
        response = session.get(hosts_url, timeout=30)
        response.raise_for_status()
        filtered_lines = []
        
        for line in response.text.splitlines():
            original_line = line
            line_clean = line.strip()
            
            # 跳过空行和纯注释行（逻辑修复：保留带内容的注释行）
            if not line_clean or line_clean.startswith('#'):
                continue
            
            # 分离IP和域名部分（忽略行尾注释）
            content_part = line_clean.split('#', 1)[0].strip()
            parts = content_part.split()
            if len(parts) < 2:  # 无效hosts格式（至少需IP+1个域名）
                continue
            
            # 提取并清洗当前行所有域名（排除IP部分）
            hosts_domains = [clean_domain(part) for part in parts[1:] if clean_domain(part)]
            if not hosts_domains:
                continue
            
            # 检查是否匹配白名单（任一域名在白名单中或为其子域名）
            in_whitelist = False
            for domain in hosts_domains:
                # 生成当前域名的所有父域名，与白名单求交集
                if get_parent_domains(domain) & whitelist:
                    in_whitelist = True
                    break  # 找到匹配立即终止
            if not in_whitelist:
                continue  # 不匹配白名单，直接跳过
            
            # 检查是否匹配黑名单（任一域名在黑名单中或为其子域名）
            in_blacklist = False
            for domain in hosts_domains:
                if get_parent_domains(domain) & blacklist:
                    in_blacklist = True
                    break  # 找到匹配立即终止
            if in_blacklist:
                continue  # 匹配黑名单，跳过
            
            # 同时通过白名单和黑名单检查，保留原始行
            filtered_lines.append(original_line)
        
        return filtered_lines
    except Exception as e:
        print(f"处理hosts失败：{str(e)}")
        return []

if __name__ == "__main__":
    # 配置URL
    WHITELIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/active.list-aa"
    BLACKLIST_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/china-list.txt"
    HOSTS_URL = "https://raw.githubusercontent.com/ykvhjnn/ad-filters-subscriber/refs/heads/release/hosts.txt"
    
    # 创建带重试的会话，复用连接提高效率
    session = create_session_with_retries()
    
    # 获取白名单和黑名单（集合格式，支持O(1)查找）
    print("获取白名单...")
    whitelist = fetch_domain_set(WHITELIST_URL)
    print("获取黑名单...")
    blacklist = fetch_domain_set(BLACKLIST_URL)
    
    # 检查白名单有效性
    if not whitelist:
        print("白名单为空，无法继续")
        exit(1)
    
    # 筛选hosts
    print("开始筛选hosts...")
    filtered_hosts = filter_hosts(HOSTS_URL, whitelist, blacklist, session)
    
    # 保存结果
    with open("filtered_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_hosts) + "\n")
    
    print(f"筛选完成，保留 {len(filtered_hosts)} 条记录")
