import requests

def fetch_and_extract_domains(url):
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        domains = set()
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            domains.add(line.lower())
        return domains
    except:
        return set()

def filter_hosts_by_domains(hosts_url, target_domains):
    try:
        response = requests.get(hosts_url, timeout=15)
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
                continue
            domains_in_line = [part.lower() for part in parts[1:]]
            if any(domain in target_domains for domain in domains_in_line):
                filtered_lines.append(original_line)
        return filtered_lines
    except:
        return []

if __name__ == "__main__":
    DOMAINS_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/active.list-aa"
    HOSTS_URL = "https://raw.githubusercontent.com/ykvhjnn/ad-filters-subscriber/refs/heads/release/hosts.txt"
    
    target_domains = fetch_and_extract_domains(DOMAINS_URL)
    if not target_domains:
        exit(1)
    
    filtered_hosts = filter_hosts_by_domains(HOSTS_URL, target_domains)
    if filtered_hosts:
        with open("filtered_hosts.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(filtered_hosts) + "\n")
