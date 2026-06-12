"""
Figura 5.9: Evolución temporal de ataques web por día.
Datos: honeypot_ataques_deepseek.db (columna fecha)
"""
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_9']
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    
    if not os.path.exists(db_path):
        print(f"[SKIP] No se encuentra {db_path}")
        return
    
    print("[5.9] Leyendo fechas de ataques web ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT fecha FROM alertas_ia", conn)
    conn.close()
    
    if df.empty:
        print("[SKIP] Tabla vacía")
        return
    
    # Parsear fecha: puede ser ISO o similar
    df['fecha_dt'] = pd.to_datetime(df['fecha'], errors='coerce', utc=True)
    df = df.dropna(subset=['fecha_dt'])
    df['date'] = df['fecha_dt'].dt.date
    daily = df.groupby('date').size().sort_index()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.fill_between(daily.index, daily.values, color=COLORS[0], alpha=0.2)
        ax.plot(daily.index, daily.values, color=COLORS[0], linewidth=1.5, marker='o', markersize=3)
        if len(daily) > 3:
            rolling = daily.rolling(window=3, center=True, min_periods=1).mean()
            ax.plot(rolling.index, rolling.values, color=COLORS[1], linewidth=2, label='MA 3d')
            ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.grid(True, linestyle='--', alpha=0.3)
        fig.autofmt_xdate()
        fig.tight_layout()
        save_fig(fig, 'fig_5_9_evolucion_ataques_web_tiempo', lang)
        plt.close(fig)
    print("[5.9] OK")

if __name__ == '__main__':
    main()
