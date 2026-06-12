"""
Figura 5.7: Categorización de proveedores de origen del tráfico malicioso (donut chart).
Datos: blacklist.db + heurística de whitelisting de generate_blacklist.py
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

BIG_PROVIDERS = [
    'google', 'microsoft', 'amazon', 'digitalocean', 'akamai',
    'cloudflare', 'fastly', 'oracle', 'godaddy'
]
SCANNERS = [
    'censys', 'onyphe', 'shodan', 'shadowserver',
    'alpha strike', 'securitytrails', 'stretchoid'
]

def categorize(datacenter):
    if not datacenter:
        return 'unknown'
    dc = datacenter.lower()
    for p in BIG_PROVIDERS:
        if p in dc:
            return 'hyperscaler'
    for s in SCANNERS:
        if s in dc:
            return 'scanner'
    # Offshore heuristic: providers with very lax abuse policies often have short names or specific keywords
    # For this project, anything not whitelisted that has >10 IPs or is from known bulletproof regions
    # We classify as 'offshore' if it is not hyperscaler/scanner and has >10 IPs, else 'other'
    return 'offshore'

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_7']
    db_path = os.path.join(ROOT_DIR, 'blacklisting', 'blacklist.db')
    
    if not os.path.exists(db_path):
        print(f"[SKIP] No se encuentra {db_path}")
        return
    
    print("[5.7] Categorizando proveedores ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT datacenter, COUNT(ip) as count FROM malicious_ips GROUP BY datacenter", conn)
    conn.close()
    
    df['cat'] = df['datacenter'].apply(categorize)
    # For offshore, filter those with count >= 10 to avoid noise, else send to other
    def finalize(row):
        if row['cat'] == 'offshore' and row['count'] < 10:
            return 'other'
        return row['cat']
    df['cat'] = df.apply(finalize, axis=1)
    
    counts = df.groupby('cat')['count'].sum()
    mapping = {
        'hyperscaler': 0,
        'scanner': 1,
        'offshore': 2,
        'other': 3
    }
    
    for lang in ['es', 'en']:
        labels = trans['labels'][lang]
        sizes = [counts.get(mapping_inv, 0) for mapping_inv in ['hyperscaler', 'scanner', 'offshore', 'other']]
        # If some category is zero, still keep label but size 0
        colors_donut = [COLORS[0], COLORS[1], COLORS[4], COLORS[6]]
        fig, ax = plt.subplots(figsize=(8, 6))
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, autopct='%1.1f%%', startangle=140,
            colors=colors_donut, wedgeprops=dict(width=0.4, edgecolor='white'),
            pctdistance=0.75, labeldistance=1.15
        )
        for autotext in autotexts:
            autotext.set_fontsize(10)
            autotext.set_color('#333333')
        for text in texts:
            text.set_fontsize(10)
        ax.set_title(trans['title'][lang])
        fig.tight_layout()
        save_fig(fig, 'fig_5_7_categorizacion_proveedores', lang)
        plt.close(fig)
    print("[5.7] OK")

if __name__ == '__main__':
    main()
