"""
Figura 5.10: Mapa de calor de actividad maliciosa (día de la semana vs hora).
Datos: data.txt (tcpdump)
"""
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_10']
    data_path = os.path.join(ROOT_DIR, 'data.txt')
    
    if not os.path.exists(data_path):
        print(f"[SKIP] No se encuentra {data_path}")
        return
    
    print("[5.10] Leyendo data.txt para heatmap ...")
    times = []
    regex = re.compile(r'^(\d{2}:\d{2}:\d{2})\.\d+ IP (?:[\d\.]+)\.\d+ > (?:[\d\.]+)\.(\d+): tcp')
    with open(data_path, 'r') as f:
        for line in f:
            m = regex.search(line)
            if m:
                times.append(m.group(1))
    
    # data.txt solo tiene hora, no fecha completa.
    # Usamos la base de datos web para fechas completas.
    db_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'databases', 'honeypot_ataques_deepseek.db')
    if os.path.exists(db_path):
        conn = pd.io.sql.read_sql
        import sqlite3
        con = sqlite3.connect(db_path)
        df_web = pd.read_sql_query("SELECT fecha FROM alertas_ia", con)
        con.close()
        df_web['fecha_dt'] = pd.to_datetime(df_web['fecha'], errors='coerce', utc=True)
        df_web = df_web.dropna(subset=['fecha_dt'])
        if len(df_web) > 0:
            df_web['hour'] = df_web['fecha_dt'].dt.hour
            df_web['dow'] = df_web['fecha_dt'].dt.day_name()
            pivot = df_web.groupby(['dow', 'hour']).size().unstack(fill_value=0)
            # Asegurar todas las horas 0-23 y todos los dias
            all_hours = list(range(24))
            pivot = pivot.reindex(columns=all_hours, fill_value=0)
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            dow_es = {'Monday':'Lunes','Tuesday':'Martes','Wednesday':'Miércoles','Thursday':'Jueves','Friday':'Viernes','Saturday':'Sábado','Sunday':'Domingo'}
            pivot = pivot.reindex(day_order, fill_value=0)
            
            for lang in ['es', 'en']:
                fig, ax = plt.subplots(figsize=(14, 5))
                plot_pivot = pivot.copy()
                if lang == 'es':
                    plot_pivot.index = [dow_es.get(i, i) for i in plot_pivot.index]
                sns.heatmap(plot_pivot, cmap='plasma', linewidths=0.5, ax=ax, cbar_kws={'label': 'Peticiones' if lang=='es' else 'Requests'})
                ax.set_title(trans['title'][lang])
                ax.set_xlabel(trans['xlabel'][lang])
                ax.set_ylabel(trans['ylabel'][lang])
                # Mostrar etiquetas de hora cada 2 horas para claridad
                ax.set_xticks(range(0, 24, 2))
                ax.set_xticklabels(range(0, 24, 2))
                fig.tight_layout()
                save_fig(fig, 'fig_5_10_mapa_calor_dia_hora', lang)
                plt.close(fig)
            print("[5.10] OK (web DB)")
            return
    
    print("[SKIP] No hay datos de fecha suficientes para heatmap")

if __name__ == '__main__':
    main()
