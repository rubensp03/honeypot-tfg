"""
Figura 5.13: Diagrama de Pareto de puertos escaneados.
Datos: data.txt (tcpdump)
"""
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_13']
    data_path = os.path.join(ROOT_DIR, 'data.txt')
    
    if not os.path.exists(data_path):
        print("[SKIP] data.txt no encontrado")
        return
    
    print("[5.13] Calculando Pareto ...")
    ports = []
    regex = re.compile(r'^(?:\d{2}:\d{2}:\d{2})\.\d+ IP (?:[\d\.]+)\.\d+ > (?:[\d\.]+)\.(\d+): tcp')
    with open(data_path, 'r') as f:
        for line in f:
            m = regex.search(line)
            if m:
                ports.append(m.group(1))
    
    counts = pd.Series(ports).value_counts()
    total = counts.sum()
    cum_pct = counts.cumsum() / total * 100
    top15 = counts.head(15)
    top15_cum = cum_pct.head(15)
    
    for lang in ['es', 'en']:
        fig, ax1 = plt.subplots(figsize=(10, 5))
        x = range(len(top15))
        bars = ax1.bar(x, top15.values, color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax1.set_xticks(x)
        ax1.set_xticklabels(top15.index, rotation=45, ha='right')
        ax1.set_ylabel(trans['ylabel_left'][lang])
        ax1.set_xlabel(trans['xlabel'][lang])
        ax1.set_title(trans['title'][lang])
        ax1.grid(axis='y', linestyle='--', alpha=0.3)
        
        ax2 = ax1.twinx()
        ax2.plot(x, top15_cum.values, color=COLORS[1], marker='o', linewidth=2, label='Cumulative %')
        ax2.axhline(y=80, color=COLORS[4], linestyle='--', linewidth=1, label='80%')
        ax2.set_ylabel(trans['ylabel_right'][lang])
        ax2.set_ylim(0, 105)
        ax2.legend(loc='lower right', frameon=True, fancybox=False, edgecolor='#333333')
        
        fig.tight_layout()
        save_fig(fig, 'fig_5_13_pareto_puertos', lang)
        plt.close(fig)
    print("[5.13] OK")

if __name__ == '__main__':
    main()
