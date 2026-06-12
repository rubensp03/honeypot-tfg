"""
Figura 5.12: Evolución acumulada de IPs únicas atacantes.
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
    trans = TRANSLATIONS['fig_5_12']
    data_path = os.path.join(ROOT_DIR, 'data.txt')
    
    if not os.path.exists(data_path):
        print("[SKIP] data.txt no encontrado")
        return
    
    print("[5.12] Calculando IPs acumuladas ...")
    records = []
    regex = re.compile(r'^(\d{2}:\d{2}:\d{2})\.\d+ IP (\d{1,3}(?:\.\d{1,3}){3})\.\d+ >')
    with open(data_path, 'r') as f:
        for line in f:
            m = regex.search(line)
            if m:
                records.append((m.group(1), m.group(2)))
    
    df = pd.DataFrame(records, columns=['time', 'ip'])
    df['time'] = pd.to_datetime(df['time'], format='%H:%M:%S')
    df = df.sort_values('time')
    
    seen = set()
    cumulative = []
    for _, row in df.iterrows():
        seen.add(row['ip'])
        cumulative.append((row['time'], len(seen)))
    
    cum_df = pd.DataFrame(cumulative, columns=['time', 'count']).set_index('time')
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(cum_df.index, cum_df['count'], color=COLORS[0], linewidth=1.5)
        ax.fill_between(cum_df.index, cum_df['count'], color=COLORS[0], alpha=0.15)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.grid(True, linestyle='--', alpha=0.3)
        fig.autofmt_xdate()
        fig.tight_layout()
        save_fig(fig, 'fig_5_12_evolucion_ips_acumulada', lang)
        plt.close(fig)
    print("[5.12] OK")

if __name__ == '__main__':
    main()
