"""
Figura 5.2: Top 15 puertos TCP más escaneados.
Datos: data.txt (tcpdump)
"""
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_2']
    data_path = os.path.join(ROOT_DIR, 'data.txt')
    
    if not os.path.exists(data_path):
        print(f"[SKIP] No se encuentra {data_path}")
        return
    
    print("[5.2] Leyendo puertos de data.txt ...")
    ports = []
    regex = re.compile(r'^(?:\d{2}:\d{2}:\d{2})\.\d+ IP (?:[\d\.]+)\.\d+ > (?:[\d\.]+)\.(\d+): tcp')
    
    with open(data_path, 'r') as f:
        for line in f:
            m = regex.search(line)
            if m:
                ports.append(m.group(1))
    
    port_counts = pd.Series(ports).value_counts().head(15)
    port_counts = port_counts.sort_values(ascending=True)
    total = sum(port_counts.values)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        colors = ['#0072B2', '#E69F00', '#CC79A7', '#F0E442', '#D55E00', '#56B4E9', '#999999', '#884EA0',
                  '#117A65', '#D68910', '#0072B2', '#E69F00', '#CC79A7', '#F0E442', '#D55E00']
        bars = ax.barh(port_counts.index.astype(str), port_counts.values, color=colors[:len(port_counts)], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        # Anotaciones de porcentaje
        for bar in bars:
            width = bar.get_width()
            pct = width / total * 100
            ax.text(width + total*0.005, bar.get_y() + bar.get_height()/2,
                    f'{pct:.1f}%', va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(port_counts.values)*1.25)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_2_top_puertos_tcp', lang)
        plt.close(fig)
    print("[5.2] OK")

if __name__ == '__main__':
    main()
