"""
Figura Híbrida 18: Top 10 IPs atacantes con desglose por tipo de ataque (v2).
Datos: honeypot_hibrido_v2.db
Limpia trailing commas en IPs. Muestra patrones: escáneres masivos vs atacantes dirigidos.
Usa los top 5 tipos de ataque para la leyenda, agrupa el resto como 'Otros'.
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
    trans = TRANSLATIONS['fig_hibrido_18']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')

    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return

    print("[hibrido_18] Analizando top IPs por tipo de ataque v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT ip_origen, tipo_ataque, COUNT(*) as count FROM alertas_hibrido "
        "GROUP BY ip_origen, tipo_ataque",
        conn
    )
    conn.close()

    df['ip_origen'] = df['ip_origen'].str.strip().str.rstrip(',')
    top_ips = df.groupby('ip_origen')['count'].sum().nlargest(10).index.tolist()
    df_top = df[df['ip_origen'].isin(top_ips)]

    top_all_types = df_top.groupby('tipo_ataque')['count'].sum().nlargest(5).index.tolist()
    df_top['attack_cat'] = df_top['tipo_ataque'].apply(lambda x: x if x in top_all_types else 'Otros')

    pivot = df_top.pivot_table(index='ip_origen', columns='attack_cat', values='count', fill_value=0)
    cat_order = top_all_types + (['Otros'] if 'Otros' in pivot.columns else [])
    pivot = pivot.reindex(columns=[c for c in cat_order if c in pivot.columns])
    pivot['total'] = pivot.sum(axis=1)
    pivot = pivot.sort_values('total', ascending=True)

    colors_list = COLORS[:len(pivot.columns) - 1]

    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(11, 6))
        y = np.arange(len(pivot))
        bar_h = 0.6
        left = np.zeros(len(pivot))

        for ci, col in enumerate([c for c in pivot.columns if c != 'total']):
            ax.barh(y, pivot[col], bar_h, left=left, label=col,
                    color=colors_list[ci % len(colors_list)],
                    edgecolor='white', linewidth=0.3)
            for i, val in enumerate(pivot[col].values):
                if val > 0:
                    ax.text(left[i] + val/2, i, str(val) if val >= 5 else '',
                            ha='center', va='center', fontsize=6.5, color='white' if val > 30 else '#333333')
            left += pivot[col].values

        ax.set_yticks(y)
        ax.set_yticklabels(pivot.index, fontsize=8)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.xaxis.grid(True, linestyle='--', alpha=0.3)
        ax.set_axisbelow(True)
        ax.set_xlim(0, pivot['total'].max() * 1.15)
        ax.legend(loc='lower right', fontsize=7, framealpha=0.9, edgecolor='#cccccc')
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_18_v2_top_ips', lang)
        plt.close(fig)
    print("[hibrido_18] OK")

if __name__ == '__main__':
    main()
