"""
Figura Híbrida 5: Distribución de severidad por motor de detección.
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
    trans = TRANSLATIONS['fig_hibrido_5']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_deepseek.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida no encontrada")
        return
    
    print("[hibrido_5] Leyendo severidad ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT gravedad, motor_deteccion, COUNT(*) as count FROM alertas_hibrido WHERE gravedad IS NOT NULL AND gravedad != '' GROUP BY gravedad, motor_deteccion ORDER BY count DESC",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    # Normalizar gravedad
    df['gravedad'] = df['gravedad'].replace({'Critica': 'Crítica', 'Crítica': 'Crítica', 'Ninguna': 'Ninguna', 'Desconocida': 'Desconocida'})
    # Solo niveles relevantes
    valid = ['Baja', 'Media', 'Alta', 'Crítica', 'Ninguna', 'Desconocida']
    df = df[df['gravedad'].isin(valid)]
    
    pivot = df.groupby(['gravedad', 'motor_deteccion'])['count'].sum().unstack(fill_value=0).astype(int)
    
    for col in ['nuclei', 'deepseek-v4-pro']:
        if col not in pivot.columns:
            pivot[col] = 0
    
    # Orden logico
    order = ['Ninguna', 'Baja', 'Media', 'Alta', 'Crítica', 'Desconocida']
    pivot = pivot.reindex([o for o in order if o in pivot.index])
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        x = np.arange(len(pivot))
        width = 0.35
        
        ax.bar(x - width/2, pivot['nuclei'], width, label='Nuclei', color=COLORS[0], edgecolor='white')
        ax.bar(x + width/2, pivot['deepseek-v4-pro'], width, label='DeepSeek v4-pro', color=COLORS[1], edgecolor='white')
        
        ax.set_xticks(x)
        ax.set_xticklabels(pivot.index)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_5_severidad', lang)
        plt.close(fig)
    print("[hibrido_5] OK")

if __name__ == '__main__':
    main()
