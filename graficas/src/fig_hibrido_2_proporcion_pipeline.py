"""
Figura Híbrida 2: Proporción del pipeline híbrido (donut chart).
Datos: honeypot_hibrido_deepseek.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_2']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_deepseek.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida no encontrada")
        return
    
    print("[hibrido_2] Leyendo proporciones ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT motor_deteccion, COUNT(*) as count FROM alertas_hibrido GROUP BY motor_deteccion", conn)
    conn.close()
    
    # Ordenar
    order = {'nuclei': 0, 'deepseek-v4-pro': 1}
    df['ord'] = df['motor_deteccion'].map(order).fillna(2)
    df = df.sort_values('ord')
    total = df['count'].sum()
    
    colors_donut = [COLORS[0], COLORS[1], COLORS[6]]
    
    for lang in ['es', 'en']:
        labels = trans['labels'][lang]
        label_map = {
            'nuclei': labels[0],
            'deepseek-v4-pro': labels[1]
        }
        plot_labels = [label_map.get(m, m) for m in df['motor_deteccion']]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        wedges, texts, autotexts = ax.pie(
            df['count'], labels=plot_labels, autopct='%1.1f%%', startangle=140,
            colors=colors_donut[:len(df)], wedgeprops=dict(width=0.4, edgecolor='white'),
            pctdistance=0.75, labeldistance=1.15
        )
        for autotext in autotexts:
            autotext.set_fontsize(10)
            autotext.set_color('#333333')
        for text in texts:
            text.set_fontsize(10)
        ax.set_title(trans['title'][lang] + f'\n(Total: {total} logs)')
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_2_proporcion_pipeline', lang)
        plt.close(fig)
    print("[hibrido_2] OK")

if __name__ == '__main__':
    main()
