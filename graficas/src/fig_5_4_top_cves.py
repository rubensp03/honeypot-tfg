"""
Figura 5.4: Top 10 CVEs más explotadas.
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
    trans = TRANSLATIONS['fig_5_4']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    
    if not os.path.exists(db_path):
        print(f"[SKIP] No se encuentra {db_path}")
        return
    
    print("[5.4] Leyendo CVEs DeepSeek ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT cve, COUNT(*) as count FROM alertas_ia WHERE cve IS NOT NULL AND cve != '' AND cve != 'Desconocido' AND cve != 'Ninguna' GROUP BY cve ORDER BY count DESC LIMIT 10",
        conn
    )
    # Ataques genericos
    generic = pd.read_sql_query(
        "SELECT COUNT(*) as count FROM alertas_ia WHERE cve IS NULL OR cve = '' OR cve = 'Ninguna'",
        conn
    )
    conn.close()
    
    rows = list(zip(df['cve'], df['count']))
    if not generic.empty and generic.iloc[0]['count'] > 0:
        rows.append(('Ataques Genéricos', generic.iloc[0]['count']))
    
    df_plot = pd.DataFrame(rows, columns=['cve', 'count']).sort_values('count', ascending=True)
    total = df_plot['count'].sum()
    
    for lang in ['es', 'en']:
        labels = df_plot['cve'].tolist()
        if lang == 'en':
            labels = [l if not l.startswith('Ataques') else 'Generic Attacks' for l in labels]
        fig, ax = plt.subplots(figsize=(9, 6))
        bars = ax.barh(labels, df_plot['count'].values, color=COLORS[:len(labels)], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            w = bar.get_width()
            pct = w/total*100
            ax.text(w + total*0.005, bar.get_y() + bar.get_height()/2,
                    f'{pct:.1f}%', va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(df_plot['count'].values)*1.25)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_4_top_cves', lang)
        plt.close(fig)
    print("[5.4] OK")

if __name__ == '__main__':
    main()
