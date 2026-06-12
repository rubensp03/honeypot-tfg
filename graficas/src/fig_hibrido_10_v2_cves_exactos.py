"""
Figura Híbrida 10: Top 10 CVEs con matching exacto (pipeline v2).
Datos: honeypot_hibrido_v2.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_10']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return
    
    print("[hibrido_10] Leyendo CVEs exactos v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT cve, COUNT(*) as count FROM alertas_hibrido WHERE cve != 'Desconocido' AND cve IS NOT NULL AND cve != '' GROUP BY cve ORDER BY count DESC LIMIT 10",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay CVEs en v2")
        return
    
    df = df.sort_values('count', ascending=True)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        bars = ax.barh(df['cve'], df['count'], color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(df['count'])*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=9, color='#333333')
        
        ax.set_xlim(0, max(df['count'])*1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_10_v2_cves_exactos', lang)
        plt.close(fig)
    print("[hibrido_10] OK")

if __name__ == '__main__':
    main()
