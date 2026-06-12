"""
Figura Híbrida 16: Top CVEs detectados por motor (v2).
Datos: honeypot_hibrido_v2.db
Muestra que solo CVE-2017-9841 fue detectado por ambos motores,
evidenciando la complementariedad determinista-heurística.
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
    trans = TRANSLATIONS['fig_hibrido_16']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')

    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return

    print("[hibrido_16] Analizando CVEs por motor v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT motor_deteccion, cve, COUNT(*) as count FROM alertas_hibrido "
        "WHERE cve != 'Desconocido' AND cve IS NOT NULL AND cve != '' "
        "AND (motor_deteccion='nuclei' OR motor_deteccion='deepseek-v4-pro') "
        "GROUP BY motor_deteccion, cve",
        conn
    )
    conn.close()

    engines = ['nuclei', 'deepseek-v4-pro']
    top_cves = df.groupby('cve')['count'].sum().nlargest(12).index.tolist()
    df_top = df[df['cve'].isin(top_cves)]

    pivot = df_top.pivot_table(index='cve', columns='motor_deteccion', values='count', fill_value=0)
    for eng in engines:
        if eng not in pivot.columns:
            pivot[eng] = 0
    pivot = pivot[engines]
    pivot['total'] = pivot.sum(axis=1)
    pivot = pivot.sort_values('total', ascending=True)

    colors_eng = [COLORS[0], COLORS[1]]

    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(11, 6))
        y = np.arange(len(pivot))
        bar_h = 0.35

        ax.barh(y - bar_h/2, pivot['nuclei'], bar_h, label=trans['legend_nuclei'][lang],
                color=colors_eng[0], edgecolor='white', linewidth=0.3)
        ax.barh(y + bar_h/2, pivot['deepseek-v4-pro'], bar_h,
                label=trans['legend_deepseek'][lang],
                color=colors_eng[1], edgecolor='white', linewidth=0.3)

        ax.set_yticks(y)
        ax.set_yticklabels(pivot.index, fontsize=8)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang], fontsize=11)
        ax.xaxis.grid(True, linestyle='--', alpha=0.3)
        ax.set_axisbelow(True)

        totals = pivot[['nuclei', 'deepseek-v4-pro']].values
        max_total = totals.sum(axis=1).max()
        ax.set_xlim(0, max_total * 1.3)

        for i, (n_val, d_val) in enumerate(totals):
            if n_val > 0:
                ax.text(n_val + 0.5, i - bar_h/2, str(n_val), va='center', fontsize=7, color=COLORS[0])
            if d_val > 0:
                ax.text(d_val + 0.5, i + bar_h/2, str(d_val), va='center', fontsize=7, color=COLORS[1])

        ax.legend(loc='lower right', framealpha=0.9, edgecolor='#cccccc')
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_16_v2_cves_por_motor', lang)
        plt.close(fig)
    print("[hibrido_16] OK")

if __name__ == '__main__':
    main()
