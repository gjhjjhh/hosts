import requests
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def clean_domain(domain):
    """清洗域名：处理空格、大小写、首尾点及中间连续点，确保格式规范"""
    if not domain:
        return ""
    # 去除前后空格、转小写、去除首尾点
    cleaned = domain.strip().lower().strip('.')
    # 替换中间连续的点为单个点（修复 example..com 这类格式）
    cleaned = re.sub(r'\.{2,}', '.', cleaned)
    return cleaned

def create_session_with_retries():
    """创建带重试机制的requests会话，提升网络稳定性"""
    session = requests.Session()
    # 增加重试次数和状态码覆盖，处理更多网络异常
    retry = Retry(
        total=5,  # 总重试次数
        backoff_factor=1,  # 重试间隔（1s, 2s, 4s...）
        status_forcelist=[429, 500, 502, 503, 504]  # 需重试的状态码（含429限流）
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)  # 兼容http
    return session

def fetch_domain_set(url, session):
    """从URL获取域名列表并返回清洗后的集合（去重）"""
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()  # 触发HTTP错误（4xx/5xx）
        domains = set()
        for line in response.text.splitlines():
            line = line.strip()
            # 跳过空行、纯注释行（支持#后带空格的注释）
            if not line or line.lstrip().startswith('#'):
                continue
            cleaned = clean_domain(line)
            if cleaned:  # 仅保留有效域名
                domains.add(cleaned)
        return domains
    except requests.exceptions.HTTPError as e:
        print(f"获取 {url} 失败（HTTP错误）：{str(e)}")
    except requests.exceptions.Timeout:
        print(f"获取 {url} 超时")
    except Exception as e:
        print(f"获取 {url} 失败：{str(e)}")
    return set()

def get_parent_domains(domain):
    """生成域名的所有父域名（含自身）集合，处理异常格式"""
    if not domain:
        return set()
    parts = domain.split('.')
    # 过滤空字符串（处理因连续点导致的空分割结果，如 example..com → ['example', '', 'com']）
    parts = [p for p in parts if p]
    if not parts:  # 无效域名（如空字符串或仅点）
        return set()
    parent_domains = set()
    for i in range(len(parts)):
        parent = '.'.join(parts[i:])
        parent_domains.add(parent)
    return parent_domains

def filter_hosts(hosts_url, whitelist, blacklist, session):
    """筛选hosts文件，保留白名单（含子域）且不在黑名单（含子域）的条目"""
    try:
        response = session.get(hosts_url, timeout=30)
        response.raise_for_status()
        filtered_lines = []
        
        for line in response.text.splitlines():
            original_line = line
            line_clean = line.strip()
            
            # 跳过空行和纯注释行（允许带内容的注释行，如 127.0.0.1 example.com # 注释）
            if not line_clean or line_clean.startswith('#'):
                continue
            
            # 分离IP+域名部分与行尾注释
            content_part = line_clean.split('#', 1)[0].strip()
            if not content_part:  # 仅有注释，无实际内容
                continue
            
            # 分割IP和域名（支持多个空格分隔）
            parts = content_part.split()
            if len(parts) < 2:  # 无效格式（无IP或无域名）
                continue
            
            # 提取并清洗域名（排除IP部分）
            hosts_domains = [clean_domain(part) for part in parts[1:] if clean_domain(part)]
            if not hosts_domains:  # 无有效域名
                continue
            
            # 检查是否匹配白名单（任一域名的父域在白名单中）
            in_whitelist = False
            for domain in hosts_domains:
                if get_parent_domains(domain) & whitelist:
                    in_whitelist = True
                    break
            if not in_whitelist:
                continue
            
            # 检查是否匹配黑名单（任一域名的父域在黑名单中）
            in_blacklist = False
            for domain in hosts_domains:
                if get_parent_domains(domain) & blacklist:
                    in_blacklist = True
                    break
            if in_blacklist:
                continue
            
            # 保留符合条件的行
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
    
    # 创建带重试的会话
    session = create_session_with_retries()
    
    # 获取白名单和黑名单
    print("获取白名单...")
    whitelist = fetch_domain_set(WHITELIST_URL, session)
    print("获取黑名单...")
    blacklist = fetch_domain_set(BLACKLIST_URL, session)
    
    # 检查白名单有效性
    if not whitelist:
        print("错误：白名单为空，无法继续筛选")
        exit(1)
    # 黑名单为空时仍可继续（仅白名单筛选）
    if not blacklist:
        print("警告：黑名单为空，仅执行白名单筛选")
    
    # 筛选hosts
    print("开始筛选hosts...")
    filtered_hosts = filter_hosts(HOSTS_URL, whitelist, blacklist, session)
    
    # 保存结果
    with open("filtered_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_hosts) + "\n")
    
    print(f"筛选完成，共保留 {len(filtered_hosts)} 条记录（结果已保存至 filtered_hosts.txt）")
    
    # 关闭会话（释放资源）
    session.close()
