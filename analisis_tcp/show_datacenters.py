import sqlite3

def main():
    conn = sqlite3.connect('blacklist.db')
    cursor = conn.cursor()
    
    query = '''
        SELECT datacenter, COUNT(ip) as count 
        FROM malicious_ips 
        GROUP BY datacenter 
        ORDER BY count DESC
    '''
    
    cursor.execute(query)
    results = cursor.fetchall()
    
    print(f"{'Datacenter / ISP':<50} | {'Total IPs'}")
    print("-" * 65)
    
    total_ips = 0
    for datacenter, count in results:
        datacenter_name = datacenter if datacenter else "Unknown"
        print(f"{datacenter_name:<50} | {count}")
        total_ips += count
        
    print("-" * 65)
    print(f"{'TOTAL':<50} | {total_ips}")
    
    conn.close()

if __name__ == "__main__":
    main()
