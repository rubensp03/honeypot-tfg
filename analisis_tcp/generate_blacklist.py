import sqlite3
import requests
import time
import subprocess
import re
import sys

# Whitelists (Ignored completely)
# Note: Chinese providers (Alibaba, Tencent, UCLOUD, Huawei, Chinanet, etc.) are NOT here, so they WILL be blocked.
BIG_PROVIDERS = [
    'google', 'microsoft', 'amazon', 'digitalocean', 'akamai', 
    'cloudflare', 'fastly', 'oracle', 'godaddy'
]

SCANNERS = [
    'censys', 'onyphe', 'shodan', 'shadowserver', 
    'alpha strike', 'securitytrails', 'stretchoid'
]

def is_whitelisted(datacenter):
    if not datacenter:
        return False
    datacenter_lower = datacenter.lower()
    for wp in BIG_PROVIDERS + SCANNERS:
        if wp in datacenter_lower:
            return True
    return False

def add_asn_column(cursor):
    try:
        cursor.execute("ALTER TABLE malicious_ips ADD COLUMN asn TEXT")
    except sqlite3.OperationalError:
        pass # Column already exists

def update_asns(conn, cursor):
    cursor.execute("SELECT ip FROM malicious_ips WHERE asn IS NULL")
    ips_without_asn = [row[0] for row in cursor.fetchall()]
    
    if not ips_without_asn:
        print("All IPs already have ASN information.")
        return

    print(f"Fetching ASN for {len(ips_without_asn)} IPs...")
    batch_size = 100
    for i in range(0, len(ips_without_asn), batch_size):
        batch = ips_without_asn[i:i+batch_size]
        print(f"Fetching batch {i//batch_size + 1}/{(len(ips_without_asn) + batch_size - 1)//batch_size}...")
        
        try:
            payload = [{"query": ip, "fields": "query,as"} for ip in batch]
            response = requests.post("http://ip-api.com/batch", json=payload, timeout=10)
            data = response.json()
            
            for result in data:
                ip = result.get('query')
                # 'as' field format is usually "AS15169 Google LLC", we just need the AS15169 part
                asn_full = result.get('as', '')
                asn = asn_full.split(' ')[0] if asn_full else 'Unknown'
                cursor.execute("UPDATE malicious_ips SET asn = ? WHERE ip = ?", (asn, ip))
            conn.commit()
        except Exception as e:
            print(f"Error querying batch: {e}")
        
        time.sleep(4)

def get_cidrs_for_asn(asn):
    if asn == 'Unknown' or not asn.startswith('AS'):
        return set()
    
    asn_num = asn[2:]
    cidrs = set()
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_num}"
        response = requests.get(url, timeout=10)
        data = response.json()
        if 'data' in data and 'prefixes' in data['data']:
            for prefix_info in data['data']['prefixes']:
                cidrs.add(prefix_info['prefix'])
    except Exception as e:
        print(f"Error fetching CIDRs for {asn}: {e}")
    
    return set(cidrs)

def main():
    conn = sqlite3.connect('blacklist.db')
    cursor = conn.cursor()
    
    add_asn_column(cursor)
    update_asns(conn, cursor)
    
    # Get all datacenters and ASNs
    cursor.execute("SELECT DISTINCT datacenter, asn FROM malicious_ips")
    rows = cursor.fetchall()
    
    malicious_asns = set()
    blocked_datacenters = set()
    ignored_datacenters = set()
    
    print("\nFiltering datacenters...")
    for datacenter, asn in rows:
        if is_whitelisted(datacenter):
            ignored_datacenters.add(datacenter)
        else:
            if asn and asn.startswith('AS'):
                malicious_asns.add(asn)
                blocked_datacenters.add(datacenter)

    print(f"\nIgnored {len(ignored_datacenters)} whitelisted datacenters (Big Providers / Scanners).")
    print(f"Found {len(malicious_asns)} unique malicious ASNs to block.")
    
    print("\nFetching CIDR ranges for malicious ASNs (this might take a few minutes)...")
    all_cidrs = set()
    output_file = 'firewall_blacklist.txt'
    with open(output_file, 'w') as f:
        f.write("# Firewall Blacklist generated from Honeypot data\n")
        f.write("# Ignored Big Providers and Scanners.\n")
        f.write("# Included Chinese and other potentially malicious providers.\n")
        
    for i, asn in enumerate(malicious_asns):
        sys.stdout.write(f"\rProcessing ASN {i+1}/{len(malicious_asns)}: {asn}")
        sys.stdout.flush()
        cidrs = get_cidrs_for_asn(asn)
        if cidrs:
            all_cidrs.update(cidrs)
            with open(output_file, 'a') as f:
                for cidr in sorted(list(cidrs)):
                    f.write(f"{cidr}\n")
        # Small sleep to avoid bombing the whois server
        time.sleep(0.1)
        
    print(f"\n\nTotal unique CIDR ranges obtained: {len(all_cidrs)}")
    print(f"\nBlacklist successfully generated and saved to: {output_file}")
    
    conn.close()

if __name__ == "__main__":
    main()
