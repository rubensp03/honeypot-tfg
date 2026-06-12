"""
Figura Híbrida 14: Distribución de severidad por motor de detección (v2).
Datos: honeypot_hibrido_v2.db
Nuclei se concentra en severidades altas/críticas; DeepSeek distribuye.
Normaliza etiquetas inconsistentes (Critica/Crítica).
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

SEVERITY_ORDER_ES = ['Ninguna', 'Baja', 'Media', 'Alta', 'Crítica']
SEVERITY_ORDER_EN = ['None', 'Low', 'Medium', 'High', 'Critical']

SEVERITY_MAP = {
    'Ninguna':    'es:Ninguna',  'None':      'en:None',
    'Baja':       'es:Baja',     'Low':       'en:Low',
    'Media':      'es:Media',    'Medium':    'en:Medium',
    'Alta':       'es:Alta',     'High':      'en:High',
    'Critica':    'es:Crítica',  'Critica':   'es:Crítica',
    'Crítica':    'es:Crítica',  'Critical':  'en:Critical',
    'Info':       'es:Media',    'Desconocida':'es:Baja',
}

def normalize_severity(raw, lang):
    mapped = SEVERITY_MAP.get(raw, None)
    if mapped:
        prefix, label = mapped.split(':')
        if prefix == lang:
            return label
    if lang == 'es':
        fallback = {'Ninguna': 'Ninguna', 'None': 'Ninguna', 'Baja': 'Baja', 'Low': 'Baja',
                     'Media': 'Media', 'Medium': 'Media', 'Alta': 'Alta', 'High': 'Alta',
                     'Critica': 'Crítica', 'Crítica': 'Crítica', 'Critical': 'Crítica',
                     'Info': 'Media', 'Desconocida': 'Baja'}
    else:
        fallback = {'Ninguna': 'None', 'None': 'None', 'Baja': 'Low', 'Low': 'Low',
                     'Media': 'Medium', 'Medium': 'Medium', 'Alta': 'High', 'High': 'High',
                     'Critica': 'Critical', 'Crítica': 'Critical', 'Critical': 'Critical',
                     'Info': 'Medium', 'Desconocida': 'Low'}
    return fallback.get(raw, raw)

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_14']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')

    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return

    print("[hibrido_14] Analizando severidad por motor v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT motor_deteccion, gravedad, COUNT(*) as count FROM alertas_hibrido "
        "GROUP BY motor_deteccion, gravedad",
        conn
    )
    conn.close()

    engines = ['nuclei', 'deepseek-v4-pro']
    colors_eng = [COLORS[0], COLORS[1]]

    for lang in ['es', 'en']:
        severity_order = SEVERITY_ORDER_ES if lang == 'es' else SEVERITY_ORDER_EN
        df['severity_norm'] = df['gravedad'].apply(lambda x: normalize_severity(x, lang))
        pivot = df.pivot_table(index='severity_norm', columns='motor_deteccion',
                                values='count', fill_value=0)
        for eng in engines:
            if eng not in pivot.columns:
                pivot[eng] = 0
        pivot = pivot.reindex([s for s in severity_order if s in pivot.index])

        fig, ax = plt.subplots(figsize=(10, 5))
        x = np.arange(len(pivot))
        bar_w = 0.35

        ax.bar(x - bar_w/2, pivot['nuclei'], bar_w, label=trans['legend_nuclei'][lang],
               color=colors_eng[0], edgecolor='white', linewidth=0.3)
        ax.bar(x + bar_w/2, pivot['deepseek-v4-pro'], bar_w,
               label=trans['legend_deepseek'][lang],
               color=colors_eng[1], edgecolor='white', linewidth=0.3)

        ax.set_xticks(x)
        ax.set_xticklabels(pivot.index)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])  # actually ylabel is severity, swap
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        ax.legend(loc='upper right', framealpha=0.9, edgecolor='#cccccc')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        ax.set_axisbelow(True)

        totals = pivot[['nuclei', 'deepseek-v4-pro']].values
        for i, (n_val, d_val) in enumerate(totals):
            if n_val > 0:
                ax.text(i - bar_w/2, n_val + totals.max() * 0.02, str(n_val),
                        ha='center', va='bottom', fontsize=8, color='#333333')
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_14_v2_severidad_por_motor', lang)
        plt.close(fig)
    print("[hibrido_14] OK")

if __name__ == '__main__':
    main()
