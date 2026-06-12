"""
Figura Híbrida 3: Top 15 CVEs comparativa Nuclei vs DeepSeek.
Datos: honeypot_hibrido_deepseek.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_3']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_deepseek.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida no encontrada")
        return
    
    print("[hibrido_3] Leyendo CVEs comparativos ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT cve, motor_deteccion, COUNT(*) as count FROM alertas_hibrido WHERE cve != 'Desconocido' AND cve IS NOT NULL AND cve != '' GROUP BY cve, motor_deteccion ORDER BY count DESC",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay CVEs")
        return
    
    # Top 15 CVEs globales
    top_cves = df.groupby('cve')['count'].sum().sort_values(ascending=False).head(15).index.tolist()
    
    pivot = df[df['cve'].isin(top_cves)].pivot(index='cve', columns='motor_deteccion', values='count').fillna(0).astype(int)
    pivot = pivot.reindex(top_cves)
    
    for col in ['nuclei', 'deepseek-v4-pro']:
        if col not in pivot.columns:
            pivot[col] = 0
    
    pivot = pivot.sort_values('nuclei', ascending=True)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 8))
        y = np.arange(len(pivot))
        width = 0.35
        
        bars1 = ax.barh(y - width/2, pivot['nuclei'], width, label='Nuclei', color=COLORS[0], edgecolor='white')
        bars2 = ax.barh(y + width/2, pivot['deepseek-v4-pro'], width, label='DeepSeek v4-pro', color=COLORS[1], edgecolor='white')
        
        ax.set_yticks(y)
        ax.set_yticklabels(pivot.index)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_3_cves_comparativa', lang)
        plt.close(fig)
    print("[hibrido_3] OK")

if __name__ == '__main__':
    main()
