"""
Figura Híbrida 7: Eficiencia económica del pipeline híbrido.
Datos: hardcoded (coste real = $2.00, coste hipotetico = todo a DeepSeek)
"""
import os
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

# Coste real proporcionado por el usuario
COSTE_REAL = 2.00
# Total logs resueltos por DeepSeek
TOTAL_DEEPSEEK = 2820
# Coste estimado por log (aproximado)
COSTE_POR_LOG = COSTE_REAL / TOTAL_DEEPSEEK
# Coste hipotetico si todo el dataset (4402) se enviara a DeepSeek
COSTE_HIPOTETICO = COSTE_POR_LOG * 4402

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_7']
    
    print("[hibrido_7] Generando eficiencia económica ...")
    
    categories = ['hipotetico', 'real']
    values = [COSTE_HIPOTETICO, COSTE_REAL]
    colors = [COLORS[6], COLORS[0]]  # gris para hipotetico, azul para real
    
    for lang in ['es', 'en']:
        labels = trans['labels'][lang]
        fig, ax = plt.subplots(figsize=(8, 5))
        x = np.arange(2)
        bars = ax.bar(x, values, color=colors, edgecolor='white', linewidth=0.5, width=0.5)
        ax.set_xticks(x)
        ax.set_xticklabels([labels[0], labels[1]])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        
        for i, bar in enumerate(bars):
            h = bar.get_height()
            label = f'${h:.2f}'
            if i == 1:
                ahorro = COSTE_HIPOTETICO - COSTE_REAL
                label += f'\n(Ahorro: ${ahorro:.2f})'
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.05,
                    label, ha='center', va='bottom', fontsize=10, color='#333333')
        
        ax.set_ylim(0, max(values)*1.2)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_7_eficiencia_economica', lang)
        plt.close(fig)
    print("[hibrido_7] OK")

if __name__ == '__main__':
    main()
