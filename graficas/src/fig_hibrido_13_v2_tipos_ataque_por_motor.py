"""
Figura Híbrida 13: Tipos de ataque por motor de detección (v2 - matching exacto).
Datos: honeypot_hibrido_v2.db (tabla alertas_hibrido)
Muestra la especialización de cada motor: qué tipos detecta Nuclei vs DeepSeek.
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
    trans = TRANSLATIONS['fig_hibrido_13']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')

    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return

    print("[hibrido_13] Analizando tipos de ataque por motor v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT motor_deteccion, tipo_ataque, COUNT(*) as count FROM alertas_hibrido "
        "GROUP BY motor_deteccion, tipo_ataque ORDER BY count DESC",
        conn
    )
    conn.close()

    engines = ['nuclei', 'deepseek-v4-pro']
    top_types = df.groupby('tipo_ataque')['count'].sum().nlargest(8).index.tolist()
    df_top = df[df['tipo_ataque'].isin(top_types)]

    pivot = df_top.pivot_table(index='tipo_ataque', columns='motor_deteccion',
                                values='count', fill_value=0)
    for eng in engines:
        if eng not in pivot.columns:
            pivot[eng] = 0
    pivot = pivot[engines]
    pivot['total'] = pivot.sum(axis=1)
    pivot = pivot.sort_values('total', ascending=True)

    colors_eng = [COLORS[0], COLORS[1]]

    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 6))
        y = np.arange(len(pivot))
        bar_h = 0.35

        bars_n = ax.barh(y - bar_h/2, pivot['nuclei'], bar_h, label=trans['legend_nuclei'][lang],
                         color=colors_eng[0], edgecolor='white', linewidth=0.3)
        bars_d = ax.barh(y + bar_h/2, pivot['deepseek-v4-pro'], bar_h,
                         label=trans['legend_deepseek'][lang],
                         color=colors_eng[1], edgecolor='white', linewidth=0.3)

        ax.set_yticks(y)
        ax.set_yticklabels(pivot.index)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.xaxis.grid(True, linestyle='--', alpha=0.3)
        ax.set_axisbelow(True)

        totals = pivot[['nuclei', 'deepseek-v4-pro']].values
        max_total = totals.sum(axis=1).max()
        ax.set_xlim(0, max_total * 1.2)

        for i, (n_val, d_val) in enumerate(totals):
            total_t = n_val + d_val
            if total_t > 0:
                ax.text(n_val + 2, i - bar_h/2, str(n_val) if n_val > 0 else '',
                        va='center', fontsize=7, color='#333333')
                ax.text(d_val + 2, i + bar_h/2, str(d_val) if d_val > 0 else '',
                        va='center', fontsize=7, color='#333333')

        ax.legend(loc='lower right', framealpha=0.9, edgecolor='#cccccc')
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_13_v2_tipos_ataque_por_motor', lang)
        plt.close(fig)
    print("[hibrido_13] OK")

if __name__ == '__main__':
    main()
