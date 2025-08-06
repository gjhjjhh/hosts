import requests
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def clean_domain(domain):
    """清洗域名：处理格式问题，保留原始大小写（纯域名场景无需强制小写）"""
    if not domain:
        return ""
    # 仅去除首尾空格和连续点，保留原始大小写（纯域名可能需要大小写区分）
    cleaned = domain.strip().strip('.')
    cleaned = re.sub(r'\.{2,}', '.', cleaned)  # 修复 example..com 格式
    return cleaned

def create_session_with_retries():
    """创建适配纯域名列表的会话，优化网络稳定性"""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

def fetch_domain_set(url, session, name):
    """获取域名集合（纯域名列表专用，保留原始格式相关清洗）"""
    try:
        response = session.get(url, timeout=15)
        response.raise_for_status()
        domains = set()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.lstrip().startswith('#'):
                continue
            cleaned = clean_domain(line)
            if cleaned:
                domains.add(cleaned)
        print(f"[{name}] 有效域名数量：{len(domains)}")
        return domains
    except Exception as e:
        print(f"获取 {name} 失败：{str(e)}")
        return set()

def get_parent_domains(domain):
    """生成所有父域名（含自身），支持纯域名子域匹配"""
    if not domain:
        return set()
    parts = domain.split('.')
    parts = [p for p in parts if p]  # 过滤空片段（处理连续点）
    if not parts:
        return set()
    return {'.'.join(parts[i:]) for i in range(len(parts))}

def filter_hosts(hosts_url, whitelist, blacklist, session):
    """筛选纯域名hosts：保留白名单（含子域）且不在黑名单（含子域）的行，不去重"""
    try:
        response = session.get(hosts_url, timeout=15)
        response.raise_for_status()
        filtered_lines = []
        total_lines = 0
        matched_white = 0
        matched_black = 0
        
        for line in response.text.splitlines():
            total_lines += 1
            original_line = line  # 保留原始行（含格式、空格、注释）
            line_clean = line.strip()
            
            # 跳过空行和纯注释行（保留带内容的注释行，如 "example.com # 注释"）
            if not line_clean or line_clean.startswith('#'):
                continue
            
            # 分离域名部分与注释（纯域名场景，无IP，直接取内容）
            content_part = line_clean.split('#', 1)[0].strip()
            if not content_part:
                continue  # 仅含注释，无实际域名
            
            # 提取所有域名（纯域名场景：整行均为域名，无IP，不排除任何部分）
            # 支持多行多域名（如 "a.com b.com" 视为两个域名）
            hosts_domains = [clean_domain(part) for part in content_part.split() if clean_domain(part)]
            if not hosts_domains:
                continue  # 无有效域名
            
            # 白名单匹配（任一域名的父域在白名单中）
            in_white = False
            for domain in hosts_domains:
                if get_parent_domains(domain) & whitelist:
                    in_white = True
                    break
            if not in_white:
                continue
            matched_white += 1
            
            # 黑名单匹配（任一域名的父域在黑名单中则排除）
            in_black = False
            for domain in hosts_domains:
                if get_parent_domains(domain) & blacklist:
                    in_black = True
                    break
            if in_black:
                matched_black += 1
                continue
            
            # 保留原始行（不去重，完全保留格式）
            filtered_lines.append(original_line)
        
        # 输出统计，便于排查数量问题
        print(f"处理总行数：{total_lines}")
        print(f"匹配白名单行数：{matched_white}")
        print(f"匹配黑名单行数（从白名单中排除）：{matched_black}")
        return filtered_lines
    except Exception as e:
        print(f"处理hosts失败：{str(e)}")
        return []

if __name__ == "__main__":
    # 配置URL（新增第二个黑名单）
    WHITELIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt"
    BLACKLIST_URL1 = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/main/release/china-list.txt"
    BLACKLIST_URL2 = "https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/config/add_rules/useless_ad_domain.txt"  # 新增黑名单
    HOSTS_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.plus.txt"
    
    session = create_session_with_retries()
    
    # 获取白名单
    print("获取白名单...")
    whitelist = fetch_domain_set(WHITELIST_URL, session, "白名单")
    if not whitelist:
        print("错误：白名单为空，无法继续")
        session.close()
        exit(1)
    
    # 获取并合并两个黑名单
    print("获取黑名单1...")
    blacklist1 = fetch_domain_set(BLACKLIST_URL1, session, "黑名单1")
    print("获取黑名单2...")
    blacklist2 = fetch_domain_set(BLACKLIST_URL2, session, "黑名单2")
    blacklist = blacklist1.union(blacklist2)  # 合并去重（仅黑名单自身去重，不影响hosts重复行）
    print(f"合并后黑名单总数量：{len(blacklist)}")
    
    # 筛选hosts（纯域名模式）
    print("开始筛选hosts...")
    filtered_hosts = filter_hosts(HOSTS_URL, whitelist, blacklist, session)
    
    # 保存结果（完全保留原始格式和重复行）
    with open("filtered_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_hosts) + "\n")
    
    print(f"筛选完成，保留 {len(filtered_hosts)} 条记录（含重复行，结果已保存）")
    session.close()
