"""
Figura 4.3: Histograma horario de intentos de login SSH.
Datos: logs_cowrie_60dias.log (JSON + fallback texto)
"""
import os
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def parse_logins(path):
    records = []
    login_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{4}).*login attempt \[b\'([^\']*)\'/b\'([^\']*)\'\]\s+(succeeded|failed)'
    )
    json_re = re.compile(r'^\s*\{')
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if json_re.match(line):
                try:
                    d = json.loads(line)
                    if d.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed'):
                        records.append({'timestamp': d.get('timestamp',''), 'status': d.get('eventid')})
                except: pass
                continue
            m = login_re.search(line)
            if m:
                ts, _, _, result = m.groups()
                records.append({'timestamp': ts, 'status': 'cowrie.login.success' if result=='succeeded' else 'cowrie.login.failed'})
    return pd.DataFrame(records)

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_4_3']
    log_path = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log Cowrie no encontrado")
        return
    
    print("[4.3] Parseando horarios SSH ...")
    df = parse_logins(log_path)
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    df['dt'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
    df = df.dropna(subset=['dt'])
    df['hour'] = df['dt'].dt.hour
    
    hourly = df.groupby(['hour', 'status']).size().unstack(fill_value=0)
    if 'cowrie.login.success' not in hourly.columns: hourly['cowrie.login.success'] = 0
    if 'cowrie.login.failed' not in hourly.columns: hourly['cowrie.login.failed'] = 0
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        x = hourly.index
        width = 0.35
        ax.bar(x - width/2, hourly['cowrie.login.failed'], width, label='Fallidos' if lang=='es' else 'Failed', color=COLORS[0], edgecolor='white')
        if hourly['cowrie.login.success'].sum() > 0:
            ax.bar(x + width/2, hourly['cowrie.login.success'], width, label='Exitosos' if lang=='es' else 'Successful', color=COLORS[4], edgecolor='white')
        ax.set_xticks(range(24))
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.set_title(trans['title'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_4_3_horario_ssh', lang)
        plt.close(fig)
    print("[4.3] OK")

if __name__ == '__main__':
    main()
