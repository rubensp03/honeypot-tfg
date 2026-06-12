"""
Figura 5.1: Volumen de paquetes TCP entrantes a lo largo del tiempo.
Datos: data.txt (tcpdump)
"""
import os
import sys
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_1']
    data_path = os.path.join(ROOT_DIR, 'data.txt')
    
    if not os.path.exists(data_path):
        print(f"[SKIP] No se encuentra {data_path}")
        return
    
    print("[5.1] Leyendo data.txt ...")
    times = []
    regex = re.compile(r'^(\d{2}:\d{2}:\d{2})\.\d+ IP (?:[\d\.]+)\.\d+ > (?:[\d\.]+)\.(\d+): tcp')
    
    with open(data_path, 'r') as f:
        for line in f:
            m = regex.search(line)
            if m:
                times.append(m.group(1))
    
    df = pd.DataFrame({'time': times})
    df['time'] = pd.to_datetime(df['time'], format='%H:%M:%S')
    df_volume = df.set_index('time').resample('10s').size()
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(df_volume.index, df_volume.values, color='#0072B2', linewidth=1.2, label='Raw')
        # Media movil 1 hora (360 intervalos de 10s)
        if len(df_volume) > 360:
            rolling = df_volume.rolling(window=360, center=True, min_periods=1).mean()
            ax.plot(rolling.index, rolling.values, color='#D55E00', linewidth=2, label='MA 1h')
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel2'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(True, linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_1_trafico_tcp_volumen', lang)
        plt.close(fig)
    print("[5.1] OK")

if __name__ == '__main__':
    main()
