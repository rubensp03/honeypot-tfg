"""
Figura 5.6: Top 15 datacenters / ISPs por IPs únicas atacantes.
Datos: blacklist.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_6']
    db_path = os.path.join(ROOT_DIR, 'blacklisting', 'blacklist.db')
    
    if not os.path.exists(db_path):
        print(f"[SKIP] No se encuentra {db_path}")
        return
    
    print("[5.6] Leyendo datacenters ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT datacenter, COUNT(ip) as count FROM malicious_ips GROUP BY datacenter ORDER BY count DESC LIMIT 15",
        conn
    )
    conn.close()
    
    df = df.sort_values('count', ascending=True)
    # Limpiar nombres muy largos
    df['datacenter'] = df['datacenter'].str[:45]
    total = df['count'].sum()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 7))
        bars = ax.barh(df['datacenter'], df['count'], color=COLORS[:len(df)], edgecolor='white', linewidth=0.5)
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
        save_fig(fig, 'fig_5_6_top_datacenters', lang)
        plt.close(fig)
    print("[5.6] OK")

if __name__ == '__main__':
    main()
