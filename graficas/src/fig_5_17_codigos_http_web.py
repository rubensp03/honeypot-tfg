"""
Figura 5.17: Distribución de códigos de respuesta HTTP.
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
    trans = TRANSLATIONS['fig_5_17']
    log_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'logs', 'honeypot_march.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log web no encontrado")
        return
    
    print("[5.17] Parseando códigos HTTP ...")
    codes = []
    # Pattern after the HTTP version: " GET / HTTP/1.1" 200 3407
    code_re = re.compile(r'"\s+(\d{3})\s+\d+\s+"')
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = code_re.search(line)
            if m:
                codes.append(m.group(1))
            else:
                # fallback: find 3-digit code before "-" or end
                parts = line.strip().split()
                for p in parts:
                    if p.isdigit() and len(p) == 3 and p.startswith(('2','3','4','5')):
                        codes.append(p)
                        break
    
    if not codes:
        print("[SKIP] No se encontraron códigos")
        return
    
    counts = pd.Series(codes).value_counts().sort_index()
    total = counts.sum()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 5))
        colors_map = {'200': COLORS[0], '404': COLORS[1], '405': COLORS[4], '400': COLORS[6], '500': COLORS[7]}
        bar_colors = [colors_map.get(c, COLORS[5]) for c in counts.index]
        bars = ax.bar(counts.index.astype(str), counts.values, color=bar_colors, edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            h = bar.get_height()
            pct = h/total*100
            ax.text(bar.get_x() + bar.get_width()/2, h + total*0.01,
                    f'{h}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=9, color='#333333')
        ax.set_ylim(0, max(counts.values)*1.2)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_17_codigos_http_web', lang)
        plt.close(fig)
    print("[5.17] OK")

if __name__ == '__main__':
    main()
