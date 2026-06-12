"""
Figura Híbrida 17: Mapa de calor - Tipo de ataque vs Severidad en DeepSeek v4 Pro (v2).
Datos: honeypot_hibrido_v2.db (solo deepseek-v4-pro, que es el 98.9% de los datos)
Muestra la correlación entre categorías de ataque y niveles de gravedad.
Normaliza etiquetas inconsistentes de severidad.
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

SEVERITY_NORM = {
    'Ninguna': 'Ninguna', 'Baja': 'Baja', 'Media': 'Media', 'Alta': 'Alta',
    'Critica': 'Crítica', 'Crítica': 'Crítica', 'Info': 'Media', 'Desconocida': 'Baja',
}

def normalize_sev(raw):
    return SEVERITY_NORM.get(raw, raw)

SEVERITY_ORDER_ES = ['Ninguna', 'Baja', 'Media', 'Alta', 'Crítica']
SEVERITY_ORDER_EN = ['None', 'Low', 'Medium', 'High', 'Critical']

SEV_TRANSLATE_ES = {'Ninguna': 'Ninguna', 'Baja': 'Baja', 'Media': 'Media', 'Alta': 'Alta', 'Crítica': 'Crítica'}
SEV_TRANSLATE_EN = {'Ninguna': 'None', 'Baja': 'Low', 'Media': 'Medium', 'Alta': 'High', 'Crítica': 'Critical'}

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_17']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')

    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return

    print("[hibrido_17] Generando heatmap tipo vs severidad v2 ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT tipo_ataque, gravedad, COUNT(*) as count FROM alertas_hibrido "
        "WHERE motor_deteccion='deepseek-v4-pro' "
        "GROUP BY tipo_ataque, gravedad",
        conn
    )
    conn.close()

    df['severity_norm'] = df['gravedad'].apply(normalize_sev)
    pivot_raw = df.pivot_table(index='tipo_ataque', columns='severity_norm', values='count', fill_value=0)
    top_types = pivot_raw.sum(axis=1).nlargest(8).index.tolist()
    pivot_raw = pivot_raw.loc[top_types]
    pivot_raw = pivot_raw.reindex(columns=SEVERITY_ORDER_ES, fill_value=0)
    pivot_raw = pivot_raw.astype(int)

    for lang in ['es', 'en']:
        if lang == 'es':
            sev_labels = [SEV_TRANSLATE_ES.get(s, s) for s in SEVERITY_ORDER_ES]
        else:
            sev_labels = [SEV_TRANSLATE_EN.get(s, s) for s in SEVERITY_ORDER_ES]

        fig, ax = plt.subplots(figsize=(10, 6))
        sns.heatmap(pivot_raw, annot=True, fmt='d', cmap='YlOrRd',
                    xticklabels=sev_labels, yticklabels=pivot_raw.index,
                    linewidths=0.5, linecolor='white', cbar_kws={'label': trans['cbar_label'][lang]},
                    ax=ax, annot_kws={'fontsize': 9})

        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang], fontsize=11)
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.tick_params(axis='both', labelsize=9)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_17_v2_heatmap_tipo_severidad', lang)
        plt.close(fig)
    print("[hibrido_17] OK")

if __name__ == '__main__':
    main()
