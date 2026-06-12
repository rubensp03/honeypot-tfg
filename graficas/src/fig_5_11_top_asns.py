"""
Figura 5.11: Top 15 ASNs por número de IPs únicas atacantes.
Datos: blacklist.db (campo asn)
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_11']
    db_path = os.path.join(ROOT_DIR, 'blacklisting', 'blacklist.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB no encontrada")
        return
    
    print("[5.11] Leyendo ASNs ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT asn, COUNT(ip) as count FROM malicious_ips WHERE asn IS NOT NULL AND asn != '' AND asn != 'Unknown' GROUP BY asn ORDER BY count DESC LIMIT 15",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos ASN")
        return
    
    df = df.sort_values('count', ascending=True)
    total = df['count'].sum()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        bars = ax.barh(df['asn'], df['count'], color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            w = bar.get_width()
            pct = w/total*100
            ax.text(w + total*0.005, bar.get_y() + bar.get_height()/2,
                    f'{pct:.1f}%', va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(df['count'])*1.25)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_11_top_asns', lang)
        plt.close(fig)
    print("[5.11] OK")

if __name__ == '__main__':
    main()
