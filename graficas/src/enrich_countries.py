"""
Enriquecimiento de blacklist.db con campo 'country' via ip-api.com batch API.
Respetamos la misma metodología de lotes de process_ips.py.
"""
import os
import sys
import sqlite3
import requests
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT_DIR

DB_PATH = os.path.join(ROOT_DIR, 'blacklisting', 'blacklist.db')

def add_country_column(cursor):
    try:
        cursor.execute("ALTER TABLE malicious_ips ADD COLUMN country TEXT")
    except sqlite3.OperationalError:
        pass  # ya existe

def main():
    if not os.path.exists(DB_PATH):
        print(f"[SKIP] No se encuentra {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    add_country_column(cursor)
    
    cursor.execute("SELECT ip FROM malicious_ips WHERE country IS NULL OR country = ''")
    ips = [row[0] for row in cursor.fetchall()]
    total = len(ips)
    
    if not ips:
        print("[5.20-prep] Todas las IPs ya tienen campo country.")
        conn.close()
        return
    
    print(f"[5.20-prep] Consultando país para {total} IPs en ip-api.com (batch API)...")
    batch_size = 100
    processed = 0
    
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i+batch_size]
        try:
            payload = [{"query": ip, "fields": "query,country"} for ip in batch]
            response = requests.post("http://ip-api.com/batch", json=payload, timeout=30)
            data = response.json()
            
            for result in data:
                ip = result.get('query')
                country = result.get('country', 'Unknown')
                cursor.execute("UPDATE malicious_ips SET country = ? WHERE ip = ?", (country, ip))
            conn.commit()
            processed += len(batch)
            print(f"  ... {processed}/{total} IPs procesadas")
        except Exception as e:
            print(f"[WARN] Error en lote {i//batch_size + 1}: {e}")
        
        # Rate limit: 15 batch requests per minute -> 4s between batches
        time.sleep(4)
    
    conn.close()
    print("[5.20-prep] Enriquecimiento completado.")

if __name__ == '__main__':
    main()
