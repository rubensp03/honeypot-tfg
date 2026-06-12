"""
Figura 5.8: Distribución de severidad de ataques web (DeepSeek).
Datos: honeypot_ataques_deepseek.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_8']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    
    if not os.path.exists(db_path):
        print(f"[SKIP] No se encuentra {db_path}")
        return
    
    print("[5.8] Leyendo severidad ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT gravedad, COUNT(*) as count FROM alertas_ia WHERE gravedad IS NOT NULL AND gravedad != '' GROUP BY gravedad ORDER BY count DESC",
        conn
    )
    conn.close()
    
    # Orden logico
    order = {'Baja':0, 'Media':1, 'Alta':2, 'Crítica':3, 'Ninguna':4}
    df['ord'] = df['gravedad'].map(order).fillna(5)
    df = df.sort_values('ord')
    total = df['count'].sum()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 5))
        colors_sev = [COLORS[5], COLORS[3], COLORS[0], COLORS[4], COLORS[6]]
        bars = ax.bar(df['gravedad'], df['count'], color=colors_sev[:len(df)], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            h = bar.get_height()
            pct = h/total*100
            ax.text(bar.get_x() + bar.get_width()/2, h + total*0.01,
                    f'{h}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=9, color='#333333')
        ax.set_ylim(0, max(df['count'])*1.2)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_8_distribucion_gravedad', lang)
        plt.close(fig)
    print("[5.8] OK")

if __name__ == '__main__':
    main()
