"""
Figura Híbrida 4: Tipos de ataque por motor de detección (barras apiladas).
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
    trans = TRANSLATIONS['fig_hibrido_4']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_deepseek.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida no encontrada")
        return
    
    print("[hibrido_4] Leyendo tipos de ataque ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT tipo_ataque, motor_deteccion, COUNT(*) as count FROM alertas_hibrido GROUP BY tipo_ataque, motor_deteccion ORDER BY count DESC",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    # Top 8 tipos globales
    top_types = df.groupby('tipo_ataque')['count'].sum().sort_values(ascending=False).head(8).index.tolist()
    pivot = df[df['tipo_ataque'].isin(top_types)].pivot(index='tipo_ataque', columns='motor_deteccion', values='count').fillna(0).astype(int)
    pivot = pivot.reindex(top_types)
    
    for col in ['nuclei', 'deepseek-v4-pro']:
        if col not in pivot.columns:
            pivot[col] = 0
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(11, 6))
        x = np.arange(len(pivot))
        width = 0.35
        
        ax.bar(x - width/2, pivot['nuclei'], width, label='Nuclei', color=COLORS[0], edgecolor='white')
        ax.bar(x + width/2, pivot['deepseek-v4-pro'], width, label='DeepSeek v4-pro', color=COLORS[1], edgecolor='white')
        
        ax.set_xticks(x)
        ax.set_xticklabels(pivot.index, rotation=20, ha='right')
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_4_tipos_ataque', lang)
        plt.close(fig)
    print("[hibrido_4] OK")

if __name__ == '__main__':
    main()
