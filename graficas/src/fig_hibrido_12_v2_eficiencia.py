"""
Figura Híbrida 12: Eficiencia económica del pipeline v2 (matching exacto).
Datos: metricas de v2 + coste real
"""
import os
import sqlite3
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_hibrido_12']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_hibrido_v2.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] DB hibrida v2 no encontrada")
        return
    
    print("[hibrido_12] Generando eficiencia económica v2 ...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT total_logs, resueltos_nuclei, resueltos_deepseek FROM metricas ORDER BY fecha DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        total_logs, nuclei_count, deepseek_count = row
    else:
        # Fallback a conteo directo
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alertas_hibrido")
        total_logs = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alertas_hibrido WHERE motor_deteccion='nuclei'")
        nuclei_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alertas_hibrido WHERE motor_deteccion='deepseek-v4-pro'")
        deepseek_count = cursor.fetchone()[0]
        conn.close()
    
    # Coste real del usuario para v2 (misma API key, solo deepseek logs)
    # Asumimos mismo precio por token
    coste_real = 2.00  # Coste total del proyecto
    # Ajustar proporcionalmente para v2: deepseek_count/total * coste_real
    # O mejor: calcular coste por log y aplicar a v2
    coste_por_log = coste_real / 2820  # coste por log de deepseek (v1 real)
    coste_v2_real = coste_por_log * deepseek_count
    coste_v2_hipotetico = coste_por_log * total_logs
    
    for lang in ['es', 'en']:
        labels = trans['labels'][lang]
        fig, ax = plt.subplots(figsize=(8, 5))
        x = np.arange(2)
        values = [coste_v2_hipotetico, coste_v2_real]
        colors = [COLORS[6], COLORS[0]]
        
        bars = ax.bar(x, values, color=colors, edgecolor='white', linewidth=0.5, width=0.5)
        ax.set_xticks(x)
        ax.set_xticklabels([labels[0], labels[1]])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang] + '\n' + trans['subtitle'][lang])
        
        for i, bar in enumerate(bars):
            h = bar.get_height()
            label = f'${h:.2f}'
            if i == 1:
                ahorro = coste_v2_hipotetico - coste_v2_real
                label += f'\n(Ahorro: ${ahorro:.2f})'
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.05,
                    label, ha='center', va='bottom', fontsize=10, color='#333333')
        
        ax.set_ylim(0, max(values)*1.2)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_hibrido_12_v2_eficiencia', lang)
        plt.close(fig)
    print("[hibrido_12] OK")

if __name__ == '__main__':
    main()
