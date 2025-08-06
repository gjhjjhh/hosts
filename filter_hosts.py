import requests
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DomainTrie:
    """域名前缀树（Trie）实现，用于高效子域名匹配
    
    核心功能：
    - 存储域名及其所有父域名（如"a.b.com"包含"a.b.com"、"b.com"、"com"）
    - 快速判断目标域名是否为存储域名的子域名或完全匹配
    """
    def __init__(self):
        self.root = {}  # 根节点（字典结构，键为域名片段，值为子节点）
        self._end_mark = '$'  # 标记域名结束的特殊键

    def add_domain(self, domain):
        """添加域名及其所有父域名到Trie树
        
        Args:
            domain: 清洗后的域名（如"a.b.com"）
        """
        if not domain:
            return
        
        # 拆分域名并反向排序（如"a.b.com" → ["com", "b", "a"]）
        parts = domain.split('.')[::-1]
        current_node = self.root
        
        for part in parts:
            if part not in current_node:
                current_node[part] = {}
            current_node = current_node[part]
        
        # 标记当前路径为一个完整域名（用于匹配完全一致的情况）
        current_node[self._end_mark] = True

    def is_subdomain_or_match(self, domain):
        """判断目标域名是否为Trie树中某域名的子域名或完全匹配
        
        Args:
            domain: 待匹配的清洗后域名（如"sub.a.b.com"）
        
        Returns:
            bool: 若匹配则返回True，否则返回False
        """
        if not domain:
            return False
        
        # 拆分域名并反向排序（与存储格式一致）
        parts = domain.split('.')[::-1]
        current_node = self.root
        
        for part in parts:
            if part not in current_node:
                return False  # 域名片段不匹配，直接返回
            current_node = current_node[part]
            # 若当前节点是某个域名的结束，说明匹配成功（找到父域名）
            if self._end_mark in current_node:
                return True
        
        # 遍历完所有片段后，检查是否为某个域名的完全匹配
        return self._end_mark in current_node


def clean_domain(domain):
    """清洗域名：仅去除首尾空格和点，保留原始格式（大小写、中间符号等）
    
    Args:
        domain: 原始域名字符串
    
    Returns:
        str: 清洗后的域名（空字符串表示无效）
    """
    if not isinstance(domain, str):
        return ""
    return domain.strip().strip('.')  # 仅处理首尾，保留中间格式


def create_http_session():
    """创建带重试机制的HTTP会话，适配大文件下载
    
    Returns:
        requests.Session: 配置好的会话对象
    """
    session = requests.Session()
    # 配置重试策略：处理网络波动和限流
    retry_strategy = Retry(
        total=3,  # 总重试次数
        backoff_factor=0.3,  # 重试间隔：0.3s, 0.6s, 1.2s
        status_forcelist=[429, 500, 502, 503, 504]  # 需要重试的状态码
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,  # 连接池大小
        pool_maxsize=10
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session


def build_trie_from_url(url, session):
    """从URL构建域名Trie树（包含所有域名及其父域名）
    
    Args:
        url: 域名列表URL
        session: HTTP会话对象
    
    Returns:
        DomainTrie: 构建完成的Trie树（None表示失败）
    """
    trie = DomainTrie()
    try:
        # 流式读取大文件（避免一次性加载到内存）
        with session.get(url, timeout=3, stream=True) as response:
            response.raise_for_status()  # 触发HTTP错误（4xx/5xx）
            # 逐行处理域名
            for line in response.iter_lines(decode_unicode=True):
                line = line.strip()
                # 跳过空行和注释行（支持#后带空格的注释）
                if not line or line.lstrip().startswith('#'):
                    continue
                # 清洗域名并添加到Trie（包含所有父域名）
                cleaned_domain = clean_domain(line)
                if cleaned_domain:
                    trie.add_domain(cleaned_domain)
        return trie
    except Exception as e:
        print(f"构建Trie树失败（URL: {url}）：{str(e)}", file=sys.stderr)
        return None


def merge_tries(trie1, trie2):
    """合并两个Trie树（将trie2的节点合并到trie1）
    
    Args:
        trie1: 目标Trie树（合并后结果）
        trie2: 待合并的Trie树
    """
    def _merge_nodes(src_node, dest_node):
        """递归合并节点"""
        for key, child_node in src_node.items():
            if key == trie1._end_mark:
                # 标记为域名结束
                dest_node[key] = True
            else:
                # 若子节点不存在则创建，否则递归合并
                if key not in dest_node:
                    dest_node[key] = {}
                _merge_nodes(child_node, dest_node[key])
    
    if trie1 and trie2:
        _merge_nodes(trie2.root, trie1.root)


def filter_hosts_file(hosts_url, white_trie, black_trie, session):
    """筛选hosts文件，保留符合条件的行
    
    筛选规则：
    1. 行中至少包含一个域名在白名单中（或为其子域名）
    2. 行中所有域名均不在黑名单中（或为其子域名）
    3. 保留原始格式和重复行
    
    Args:
        hosts_url: hosts文件URL
        white_trie: 白名单Trie树
        black_trie: 黑名单Trie树
        session: HTTP会话对象
    
    Returns:
        list: 筛选后的行列表
    """
    filtered_lines = []
    try:
        # 流式读取hosts文件（处理大文件）
        with session.get(hosts_url, timeout=3, stream=True) as response:
            response.raise_for_status()
            for line in response.iter_lines(decode_unicode=True):
                original_line = line
                line_clean = line.strip()
                
                # 跳过空行和纯注释行（保留带内容的注释行）
                if not line_clean or line_clean.startswith('#'):
                    continue
                
                # 分离域名部分和注释（保留原始行格式）
                content_part = line_clean.split('#', 1)[0].strip()
                if not content_part:
                    continue  # 仅含注释，无实际内容
                
                # 提取当前行的所有域名（按空格拆分）
                line_domains = [clean_domain(d) for d in content_part.split() if clean_domain(d)]
                if not line_domains:
                    continue  # 无有效域名
                
                # 检查白名单：至少一个域名匹配白名单（或子域）
                match_white = False
                for domain in line_domains:
                    if white_trie.is_subdomain_or_match(domain):
                        match_white = True
                        break
                if not match_white:
                    continue
                
                # 检查黑名单：任何域名匹配黑名单（或子域）则排除
                match_black = False
                for domain in line_domains:
                    if black_trie.is_subdomain_or_match(domain):
                        match_black = True
                        break
                if match_black:
                    continue
                
                # 保留原始行（不去重）
                filtered_lines.append(original_line)
        
        return filtered_lines
    except Exception as e:
        print(f"筛选hosts失败（URL: {hosts_url}）：{str(e)}", file=sys.stderr)
        return []


def main():
    # 配置目标URL
    WHITELIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/active.list-aa"
    BLACKLIST_URL1 = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/main/release/china-list.txt"
    BLACKLIST_URL2 = "https://raw.githubusercontent.com/ykvhjnn/Rules/refs/heads/main/config/add_rules/useless_ad_domain.txt"
    HOSTS_URL = "https://raw.githubusercontent.com/ykvhjnn/ad-filters-subscriber/refs/heads/release/hosts.txt"
    
    # 初始化会话
    session = create_http_session()
    
    # 1. 构建白名单Trie树
    print("构建白名单Trie树...")
    white_trie = build_trie_from_url(WHITELIST_URL, session)
    if not white_trie:
        print("白名单构建失败，退出程序", file=sys.stderr)
        session.close()
        sys.exit(1)
    
    # 2. 构建并合并黑名单Trie树
    print("构建黑名单Trie树（1/2）...")
    black_trie1 = build_trie_from_url(BLACKLIST_URL1, session) or DomainTrie()
    
    print("构建黑名单Trie树（2/2）...")
    black_trie2 = build_trie_from_url(BLACKLIST_URL2, session) or DomainTrie()
    
    print("合并黑名单Trie树...")
    merge_tries(black_trie1, black_trie2)
    black_trie = black_trie1
    
    # 3. 筛选hosts文件
    print("筛选hosts文件...")
    result_lines = filter_hosts_file(HOSTS_URL, white_trie, black_trie, session)
    
    # 4. 保存结果
    with open("filtered_hosts.txt", "w", encoding="utf-8", newline='\n') as f:
        f.write('\n'.join(result_lines))
    
    print(f"处理完成，共保留 {len(result_lines)} 条记录")
    session.close()


if __name__ == "__main__":
    main()
