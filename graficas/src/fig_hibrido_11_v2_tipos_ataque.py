"""
Figura Híbrida 11: Tipos de ataque en pipeline v2 (matching exacto).
Datos: honeypot_hibrido_v2.db
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
    trans = TRANSLATIONS['fig_hibrido_11']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return
    
    print("[hibrido_11] Leyendo tipos de ataque v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT tipo_ataque, COUNT(*) as count FROM alertas_hibrido GROUP BY tipo_ataque ORDER BY count DESC",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    top_types = df.nlargest(8, 'count')
    top_types = top_types.sort_values('count', ascending=True)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        bars = ax.barh(top_types['tipo_ataque'], top_types['count'], color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top_types['count'])*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=9, color='#333333')
        
        ax.set_xlim(0, max(top_types['count'])*1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_11_v2_tipos_ataque', lang)
        plt.close(fig)
    print("[hibrido_11] OK")

if __name__ == '__main__':
    main()
