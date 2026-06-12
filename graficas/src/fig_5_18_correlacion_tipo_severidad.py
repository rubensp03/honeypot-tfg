"""
Figura 5.18: Matriz de correlación: Tipo de Ataque vs Severidad (DeepSeek).
Datos: honeypot_ataques_deepseek.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_18']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB no encontrada")
        return
    
    print("[5.18] Generando matriz de correlacion ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT tipo_ataque, gravedad FROM alertas_ia WHERE tipo_ataque IS NOT NULL AND gravedad IS NOT NULL AND gravedad != '' AND gravedad != 'Ninguna'", conn)
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos suficientes")
        return
    
    # Simplify types
    df['tipo_ataque'] = df['tipo_ataque'].replace({'Legitimo u otro': 'Legítimo', 'Ninguno': 'Legítimo'})
    # Keep top 6 types
    top_types = df['tipo_ataque'].value_counts().head(6).index.tolist()
    df = df[df['tipo_ataque'].isin(top_types)]
    
    pivot = pd.crosstab(df['tipo_ataque'], df['gravedad'])
    # Order columns logically
    col_order = ['Baja', 'Media', 'Alta', 'Crítica']
    pivot = pivot[[c for c in col_order if c in pivot.columns]]
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        sns.heatmap(pivot, cmap='YlOrRd', linewidths=0.5, ax=ax, annot=True, fmt='d',
                    cbar_kws={'label': 'Número de casos' if lang=='es' else 'Number of cases'})
        ax.set_title(trans['title'][lang])
        ax.set_xlabel('Severidad' if lang=='es' else 'Severity')
        ax.set_ylabel('Tipo de ataque' if lang=='es' else 'Attack type')
        fig.tight_layout()
        save_fig(fig, 'fig_5_18_correlacion_tipo_severidad', lang)
        plt.close(fig)
    print("[5.18] OK")

if __name__ == '__main__':
    main()
