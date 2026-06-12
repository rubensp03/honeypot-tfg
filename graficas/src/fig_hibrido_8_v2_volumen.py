"""
Figura Híbrida 8: Volumen del pipeline híbrido v2 (matching exacto).
Datos: honeypot_hibrido_v2.db (tabla alertas_hibrido)
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
    trans = TRANSLATIONS['fig_hibrido_8']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return
    
    print("[hibrido_8] Leyendo volumen del pipeline v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT motor_deteccion, COUNT(*) as count FROM alertas_hibrido GROUP BY motor_deteccion", conn)
    conn.close()
    
    order = {'nuclei': 0, 'deepseek-v4-pro': 1}
    df['ord'] = df['motor_deteccion'].map(order).fillna(2)
    df = df.sort_values('ord')
    total = df['count'].sum()
    
    bar_colors = [COLORS[0], COLORS[1]]
    
    for lang in ['es', 'en']:
        labels = trans['labels'][lang]
        label_map = {
            'nuclei': labels[0],
            'deepseek-v4-pro': labels[1]
        }
        plot_labels = [label_map.get(m, m) for m in df['motor_deteccion']]
        
        fig, ax = plt.subplots(figsize=(10, 5))
        y_pos = np.arange(len(df))
        bars = ax.barh(y_pos, df['count'], color=bar_colors[:len(df)], edgecolor='white', linewidth=0.5, height=0.6)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(plot_labels)
        ax.set_xlabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        
        for i, bar in enumerate(bars):
            w = bar.get_width()
            pct = w/total*100
            ax.text(w + total*0.01, bar.get_y() + bar.get_height()/2,
                    f'{int(w)} ({pct:.1f}%)', va='center', fontsize=10, color='#333333')
        ax.set_xlim(0, max(df['count'])*1.3)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_8_v2_volumen', lang)
        plt.close(fig)
    print("[hibrido_8] OK")

if __name__ == '__main__':
    main()
