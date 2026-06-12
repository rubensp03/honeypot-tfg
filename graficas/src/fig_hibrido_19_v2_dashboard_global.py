"""
Figura Híbrida 19: Dashboard global del pipeline híbrido v2.
Panel 2x2: (a) Proporción por motor, (b) Severidad por motor,
(c) Top tipos de ataque, (d) Top tecnologías objetivo.
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

SEVERITY_NORM = {
    'Ninguna': 'Ninguna', 'Baja': 'Baja', 'Media': 'Media', 'Alta': 'Alta',
    'Critica': 'Crítica', 'Crítica': 'Crítica', 'Info': 'Media', 'Desconocida': 'Baja',
}

SEVERITY_ORDER_ES = ['Ninguna', 'Baja', 'Media', 'Alta', 'Crítica']
SEVERITY_ORDER_EN = ['None', 'Low', 'Medium', 'High', 'Critical']
SEV_TO_EN = {'Ninguna': 'None', 'Baja': 'Low', 'Media': 'Medium', 'Alta': 'High', 'Crítica': 'Critical'}
SEV_TO_ES = {'Ninguna': 'Ninguna', 'Baja': 'Baja', 'Media': 'Media', 'Alta': 'Alta', 'Crítica': 'Crítica'}


def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_19']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')

    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return

    print("[hibrido_19] Generando dashboard global v2 ...")
    conn = sqlite3.connect(db_path)

    df_engine = pd.read_sql_query(
        "SELECT motor_deteccion, COUNT(*) as count FROM alertas_hibrido GROUP BY motor_deteccion", conn)

    df_sev = pd.read_sql_query(
        "SELECT motor_deteccion, gravedad, COUNT(*) as count FROM alertas_hibrido GROUP BY motor_deteccion, gravedad", conn)

    df_types = pd.read_sql_query(
        "SELECT tipo_ataque, COUNT(*) as count FROM alertas_hibrido GROUP BY tipo_ataque ORDER BY count DESC LIMIT 8", conn)

    df_tech = pd.read_sql_query(
        "SELECT tecnologia_objetivo, COUNT(*) as count FROM alertas_hibrido "
        "WHERE tecnologia_objetivo IS NOT NULL AND tecnologia_objetivo != '' "
        "AND tecnologia_objetivo != 'Desconocida' AND tecnologia_objetivo != 'Desconocido' "
        "GROUP BY tecnologia_objetivo ORDER BY count DESC LIMIT 8", conn)

    conn.close()

    df_sev['severity_norm'] = df_sev['gravedad'].apply(lambda x: SEVERITY_NORM.get(x, x))
    engines = ['nuclei', 'deepseek-v4-pro']

    for lang in ['es', 'en']:
        fig, axes = plt.subplots(2, 2, figsize=(14, 12))
        labels_eng = trans['labels'][lang]
        colors_eng = [COLORS[0], COLORS[1]]

        # --- (a) Proporción por motor (donut) ---
        ax = axes[0, 0]
        order = {'nuclei': 0, 'deepseek-v4-pro': 1}
        df_eng_sorted = df_engine.copy()
        df_eng_sorted['ord'] = df_eng_sorted['motor_deteccion'].map(order).fillna(2)
        df_eng_sorted = df_eng_sorted.sort_values('ord')
        total = df_eng_sorted['count'].sum()
        label_map = {'nuclei': labels_eng[0], 'deepseek-v4-pro': labels_eng[1]}
        plot_labels = [label_map.get(m, m) for m in df_eng_sorted['motor_deteccion']]
        wedges, texts, autotexts = ax.pie(
            df_eng_sorted['count'], labels=None,
            colors=[colors_eng[0], colors_eng[1]],
            autopct='%1.1f%%', startangle=90, pctdistance=0.75,
            wedgeprops={'edgecolor': 'white', 'linewidth': 1})
        for at in autotexts:
            at.set_fontsize(10)
        ax.legend(wedges, [f'{l}\n({int(c)})' for l, c in zip(plot_labels, df_eng_sorted['count'])],
                  loc='lower center', bbox_to_anchor=(0.5, -0.15), fontsize=9, ncol=2)
        ax.set_title(trans['subtitle_a'][lang], fontsize=11, fontweight='bold')

        # --- (b) Severidad por motor (barras agrupadas) ---
        ax = axes[0, 1]
        sev_order = SEVERITY_ORDER_ES if lang == 'es' else SEVERITY_ORDER_EN
        sev_lookup = SEV_TO_ES if lang == 'es' else SEV_TO_EN
        sev_pivot = df_sev.pivot_table(index='severity_norm', columns='motor_deteccion', values='count', fill_value=0)
        for eng in engines:
            if eng not in sev_pivot.columns:
                sev_pivot[eng] = 0
        sev_pivot = sev_pivot.reindex([s for s in sev_order if s in sev_pivot.index])
        if sev_pivot.empty:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes)
        else:
            x = np.arange(len(sev_pivot))
            bar_w = 0.3
            ax.bar(x - bar_w/2, sev_pivot['nuclei'], bar_w, label=labels_eng[0], color=colors_eng[0],
                   edgecolor='white', linewidth=0.3)
            ax.bar(x + bar_w/2, sev_pivot['deepseek-v4-pro'], bar_w, label=labels_eng[1],
                   color=colors_eng[1], edgecolor='white', linewidth=0.3)
            ax.set_xticks(x)
            ax.set_xticklabels([sev_lookup.get(s, s) for s in sev_pivot.index], fontsize=8)
            ax.legend(fontsize=8, framealpha=0.9, edgecolor='#cccccc')
            ax.grid(axis='y', linestyle='--', alpha=0.3)
            ax.set_axisbelow(True)
        ax.set_title(trans['subtitle_b'][lang], fontsize=11, fontweight='bold')

        # --- (c) Top tipos de ataque ---
        ax = axes[1, 0]
        df_types_plot = df_types.sort_values('count', ascending=True)
        ax.barh(df_types_plot['tipo_ataque'], df_types_plot['count'], color=COLORS[2], edgecolor='white', linewidth=0.3)
        for i, (_, row) in enumerate(df_types_plot.iterrows()):
            ax.text(row['count'] + max(df_types['count']) * 0.01, i, str(row['count']),
                    va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(df_types['count']) * 1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        ax.set_axisbelow(True)
        ax.set_title(trans['subtitle_c'][lang], fontsize=11, fontweight='bold')

        # --- (d) Top tecnologias ---
        ax = axes[1, 1]
        df_tech_plot = df_tech.sort_values('count', ascending=True)
        bars = ax.barh(df_tech_plot['tecnologia_objetivo'], df_tech_plot['count'], color=COLORS[3],
                       edgecolor='white', linewidth=0.3)
        for i, (_, row) in enumerate(df_tech_plot.iterrows()):
            ax.text(row['count'] + max(df_tech['count']) * 0.01, i, str(row['count']),
                    va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(df_tech['count']) * 1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        ax.set_axisbelow(True)
        ax.set_title(trans['subtitle_d'][lang], fontsize=11, fontweight='bold')

        fig.suptitle(trans['title'][lang] + '\n' + trans['subtitle'][lang], fontsize=14, fontweight='bold', y=1.01)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_19_v2_dashboard_global', lang)
        plt.close(fig)
    print("[hibrido_19] OK")

if __name__ == '__main__':
    main()
