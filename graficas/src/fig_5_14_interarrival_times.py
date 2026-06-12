"""
Figura 5.14: Distribución de tiempos inter-llegada de paquetes.
Datos: data.txt (tcpdump)
"""
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_14']
    data_path = os.path.join(ROOT_DIR, 'data.txt')
    
    if not os.path.exists(data_path):
        print("[SKIP] data.txt no encontrado")
        return
    
    print("[5.14] Calculando inter-arrival times ...")
    times = []
    regex = re.compile(r'^(\d{2}:\d{2}:\d{2})\.\d+ IP (?:[\d\.]+)\.\d+ > (?:[\d\.]+)\.(\d+): tcp')
    with open(data_path, 'r') as f:
        for line in f:
            m = regex.search(line)
            if m:
                times.append(m.group(1))
    
    df = pd.DataFrame({'time': times})
    df['time'] = pd.to_datetime(df['time'], format='%H:%M:%S')
    df = df.sort_values('time').reset_index(drop=True)
    df['delta'] = df['time'].diff().dt.total_seconds()
    df = df.dropna()
    # Filtrar outliers para visualizacion (deltas > 60s probablemente son gaps de captura)
    df = df[df['delta'] <= 60]
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.hist(df['delta'], bins=100, color=COLORS[0], edgecolor='white', linewidth=0.3, density=True, alpha=0.8)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        ax.set_xlim(0, 10)  # Focus on first 10 seconds
        fig.tight_layout()
        save_fig(fig, 'fig_5_14_interarrival_times', lang)
        plt.close(fig)
    print("[5.14] OK")

if __name__ == '__main__':
    main()
