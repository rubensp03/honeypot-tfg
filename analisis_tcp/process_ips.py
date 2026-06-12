import re
import sqlite3
import requests
import time
import json

HONEYPOT_IP = "159.223.6.94"

def get_db_connection():
    conn = sqlite3.connect('blacklist.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip TEXT PRIMARY KEY,
            datacenter TEXT
        )
    ''')
    conn.commit()
    return conn

def extract_ips(filename):
    ips = set()
    pattern = re.compile(r'IP\s+(\d{1,3}(?:\.\d{1,3}){3})\.\d+\s+>')
    with open(filename, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                if ip != HONEYPOT_IP and not ip.startswith('169.254.'):
                    ips.add(ip)
    return ips

def main():
    print("Extracting IPs from data.txt...")
    ips = extract_ips('data.txt')
    print(f"Found {len(ips)} unique malicious IPs.")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT ip FROM malicious_ips")
    existing_ips = {row[0] for row in cursor.fetchall()}
    
    ips_to_process = list(ips - existing_ips)
    print(f"Processing {len(ips_to_process)} new IPs using batch API...")
    
    batch_size = 100
    for i in range(0, len(ips_to_process), batch_size):
        batch = ips_to_process[i:i+batch_size]
        print(f"Querying batch {i//batch_size + 1}/{(len(ips_to_process) + batch_size - 1)//batch_size}...")
        
        try:
            # Prepare payload for batch request
            payload = [{"query": ip, "fields": "query,isp,org"} for ip in batch]
            response = requests.post("http://ip-api.com/batch", json=payload, timeout=10)
            data = response.json()
            
            for result in data:
                ip = result.get('query')
                isp = result.get('isp', 'Unknown')
                if not isp:
                    isp = result.get('org', 'Unknown')
                cursor.execute("INSERT OR IGNORE INTO malicious_ips (ip, datacenter) VALUES (?, ?)", (ip, isp))
            conn.commit()
        except Exception as e:
            print(f"Error querying batch: {e}")
        
        # Free tier: 15 batch requests per minute -> Wait 4 seconds between requests
        time.sleep(4)
        
    conn.close()
    print("Process complete. Results saved to blacklist.db")

if __name__ == "__main__":
    main()
