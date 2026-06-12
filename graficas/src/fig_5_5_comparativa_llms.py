"""
Figura 5.5: Comparativa de rendimiento entre modelos LLM.
Datos: honeypot_ataques_deepseek.db, honeypot_ataques_qwen.db, honeypot_ataques_llama3.1.db
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def get_stats(db_path):
    conn = sqlite3.connect(db_path)
    total = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_ia", conn).iloc[0]['c']
    # CVE fallidos = Desconocido o vacio
    cve_fail = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_ia WHERE cve IS NULL OR cve = '' OR cve = 'Desconocido' OR cve = 'Ninguna' OR cve = 'Ninguno'", conn).iloc[0]['c']
    # Top tipos
    tipos = pd.read_sql_query("SELECT tipo_ataque, COUNT(*) as count FROM alertas_ia GROUP BY tipo_ataque ORDER BY count DESC LIMIT 5", conn)
    conn.close()
    fail_rate = cve_fail / total * 100 if total > 0 else 0
    return total, fail_rate, tipos

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_5']
    
    models = {
        'DeepSeek (Flash)': os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db'),
        'Qwen (Local)': os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_qwen.db'),
        'LLaMA 3.1 (Local)': os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_llama3.1.db')
    }
    
    stats = {}
    for name, path in models.items():
        if os.path.exists(path):
            stats[name] = get_stats(path)
        else:
            print(f"[WARN] No se encuentra {path}")
    
    if not stats:
        print("[SKIP] No hay bases de datos disponibles")
        return
    
    print("[5.5] Generando comparativa LLMs ...")
    for lang in ['es', 'en']:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        # Subplot A: volumen + tasa fallo
        names = list(stats.keys())
        volumes = [stats[n][0] for n in names]
        fail_rates = [stats[n][1] for n in names]
        
        ax = axes[0]
        x = np.arange(len(names))
        width = 0.35
        bars1 = ax.bar(x - width/2, volumes, width, label=trans['legend_vol'][lang], color=COLORS[0], edgecolor='white')
        ax2 = ax.twinx()
        bars2 = ax2.bar(x + width/2, fail_rates, width, label=trans['legend_fail'][lang], color=COLORS[1], edgecolor='white')
        ax.set_xticks(x)
        ax.set_xticklabels(names, rotation=15, ha='right')
        ax.set_ylabel(trans['xlabel_vol'][lang])
        ax2.set_ylabel(trans['ylabel_fail'][lang])
        ax.set_title(trans['subtitle_a'][lang])
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        # Leyenda combinada
        lines1, labels1 = ax.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax.legend(lines1 + lines2, labels1 + labels2, loc='upper left', frameon=True, fancybox=False, edgecolor='#333333')
        
        # Subplot B: distribucion de tipos principales por modelo
        ax = axes[1]
        # Recopilar top 4 categorias globales
        all_types = {}
        for n in names:
            tipos = stats[n][2]
            for _, row in tipos.iterrows():
                t = row['tipo_ataque']
                # Normalizar
                t = t.replace('Legitimo u otro','Legítimo').replace('Ninguno','Legítimo').replace('Desconocido','Desconocido')
                all_types[t] = all_types.get(t, 0) + row['count']
        top_types = sorted(all_types.items(), key=lambda x: -x[1])[:4]
        type_names = [t[0] for t in top_types]
        
        x = np.arange(len(type_names))
        width = 0.25
        for i, n in enumerate(names):
            tipos = stats[n][2].copy()
            tipos['tipo_ataque'] = tipos['tipo_ataque'].replace({'Legitimo u otro':'Legítimo','Ninguno':'Legítimo'})
            tipos = tipos.groupby('tipo_ataque')['count'].sum().reindex(type_names, fill_value=0)
            ax.bar(x + i*width, tipos.values, width, label=n, color=COLORS[i], edgecolor='white')
        ax.set_xticks(x + width)
        ax.set_xticklabels(type_names, rotation=15, ha='right')
        ax.set_ylabel(trans['xlabel_vol'][lang])
        ax.set_title(trans['subtitle_b'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        
        fig.suptitle(trans['title'][lang], fontsize=13, fontweight='bold')
        fig.tight_layout(rect=[0, 0, 1, 0.96])
        save_fig(fig, 'fig_5_5_comparativa_llms', lang)
        plt.close(fig)
    print("[5.5] OK")

if __name__ == '__main__':
    main()
