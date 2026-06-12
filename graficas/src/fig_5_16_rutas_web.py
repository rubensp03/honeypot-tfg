"""
Figura 5.16: Top 10 rutas (paths) más solicitadas en el honeypot web.
Datos: honeypot_march.log (nginx)
"""
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_16']
    log_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'logs', 'honeypot_march.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log web no encontrado")
        return
    
    print("[5.16] Parseando rutas ...")
    paths = []
    path_re = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP')
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = path_re.search(line)
            if m:
                paths.append(m.group(1))
    
    if not paths:
        print("[SKIP] No se encontraron rutas")
        return
    
    top = pd.Series(paths).value_counts().head(10).sort_values(ascending=True)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.barh(top.index, top.values, color=COLORS[1], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top.values)*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(top.values)*1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_16_rutas_web', lang)
        plt.close(fig)
    print("[5.16] OK")

if __name__ == '__main__':
    main()
