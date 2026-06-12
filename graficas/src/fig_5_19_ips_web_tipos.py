"""
Figura 5.19: Top 10 IPs atacantes web y tipos de ataque asociados.
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
    trans = TRANSLATIONS['fig_5_19']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB no encontrada")
        return
    
    print("[5.19] Analizando IPs y tipos ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT ip_origen, tipo_ataque FROM alertas_ia WHERE ip_origen IS NOT NULL AND tipo_ataque IS NOT NULL", conn)
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    df['tipo_ataque'] = df['tipo_ataque'].replace({'Legitimo u otro': 'Legítimo', 'Ninguno': 'Legítimo'})
    top_ips = df['ip_origen'].value_counts().head(10).index.tolist()
    
    pivot = df[df['ip_origen'].isin(top_ips)].groupby(['ip_origen', 'tipo_ataque']).size().unstack(fill_value=0)
    pivot = pivot.reindex(top_ips)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 6))
        pivot.plot(kind='barh', stacked=True, ax=ax, color=COLORS[:len(pivot.columns)], edgecolor='white', linewidth=0.3)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.legend(title='Tipo' if lang=='es' else 'Type', frameon=True, fancybox=False, edgecolor='#333333', loc='lower right')
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_19_ips_web_tipos', lang)
        plt.close(fig)
    print("[5.19] OK")

if __name__ == '__main__':
    main()
