"""
Figura Híbrida 9: Precisión del matching de Nuclei: fuzzy vs exacto.
Compara las detecciones de Nuclei entre v1 (fuzzy matching) y v2 (exact matching).
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_9']
    
    db_v1 = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_deepseek.db')
    db_v2 = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')
    
    if not os.path.exists(db_v1) or not os.path.exists(db_v2):
        print("[SKIP] DBs hibridas no encontradas")
        return
    
    print("[hibrido_9] Comparando v1 (fuzzy) vs v2 (exacto) ...")
    
    conn_v1 = sqlite3.connect(db_v1)
    nuclei_v1 = pd.read_sql_query("SELECT COUNT(*) as count FROM alertas_hibrido WHERE motor_deteccion='nuclei'", conn_v1).iloc[0]['count']
    total_v1 = pd.read_sql_query("SELECT COUNT(*) as count FROM alertas_hibrido", conn_v1).iloc[0]['count']
    conn_v1.close()
    
    conn_v2 = sqlite3.connect(db_v2)
    nuclei_v2 = pd.read_sql_query("SELECT COUNT(*) as count FROM alertas_hibrido WHERE motor_deteccion='nuclei'", conn_v2).iloc[0]['count']
    total_v2 = pd.read_sql_query("SELECT COUNT(*) as count FROM alertas_hibrido", conn_v2).iloc[0]['count']
    conn_v2.close()
    
    for lang in ['es', 'en']:
        labels = trans['labels'][lang]
        fig, ax = plt.subplots(figsize=(9, 6))
        
        x = np.arange(2)
        values = [nuclei_v1, nuclei_v2]
        colors = [COLORS[1], COLORS[0]]  # naranja para fuzzy, azul para exacto
        
        bars = ax.bar(x, values, color=colors, edgecolor='white', linewidth=0.5, width=0.5)
        ax.set_xticks(x)
        ax.set_xticklabels([labels[0], labels[1]])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        
        for i, bar in enumerate(bars):
            h = bar.get_height()
            pct_total = h / [total_v1, total_v2][i] * 100
            ax.text(bar.get_x() + bar.get_width()/2, h + max(values)*0.02,
                    f'{int(h)}\n({pct_total:.1f}%)', ha='center', va='bottom', fontsize=10, color='#333333')
        
        # Diferencia relativa
        reduction = (nuclei_v1 - nuclei_v2) / nuclei_v1 * 100
        ax.text(0.5, max(values)*0.5, f'Reducción: {reduction:.1f}%', ha='center', va='center',
                fontsize=11, color='#D55E00', fontweight='bold',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='#FFF3CD', edgecolor='#D55E00', alpha=0.8))
        
        ax.set_ylim(0, max(values)*1.2)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_9_comparativa_v1_v2_nuclei', lang)
        plt.close(fig)
    print("[hibrido_9] OK")

if __name__ == '__main__':
    main()
