"""
Figura 5.3: Tipologia de ataques en honeypot web.
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
    trans = TRANSLATIONS['fig_5_3']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    
    if not os.path.exists(db_path):
        print(f"[SKIP] No se encuentra {db_path}")
        return
    
    print("[5.3] Leyendo tipos de ataque DeepSeek ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT tipo_ataque, COUNT(*) as count FROM alertas_ia GROUP BY tipo_ataque ORDER BY count DESC", conn)
    conn.close()
    
    # Normalizar nombres combinados
    df['tipo_ataque'] = df['tipo_ataque'].replace({
        'Legítimo': 'Legítimo / Ruido',
        'Legitimo u otro': 'Legítimo / Ruido',
        'Ninguno': 'Legítimo / Ruido'
    })
    df = df.groupby('tipo_ataque')['count'].sum().sort_values(ascending=True)
    total = df.sum()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        bars = ax.barh(df.index, df.values, color=COLORS[:len(df)], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            w = bar.get_width()
            pct = w/total*100
            ax.text(w + total*0.005, bar.get_y() + bar.get_height()/2,
                    f'{pct:.1f}%', va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(df.values)*1.25)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_3_tipos_ataque_web', lang)
        plt.close(fig)
    print("[5.3] OK")

if __name__ == '__main__':
    main()
