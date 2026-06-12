"""
Figura 4.1: Análisis de intentos de login SSH.
Datos: analisis_ssh/logs_cowrie_60dias.log (JSON + fallback texto)
"""
import os
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def parse_cowrie_log(path):
    """Parsea log de Cowrie soportando JSON y formato texto de Twisted."""
    records = []
    # Patron para login attempt en formato texto
    # Ej: 2026-02-18T16:03:45+0000 [HoneyPotSSHTransport,33048,68.183.198.231] login attempt [b'oracle'/b'qwerty123'] failed
    login_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{4}).*login attempt \[b\'([^\']*)\'/b\'([^\']*)\'\]\s+(succeeded|failed)'
    )
    # Tambien buscar eventid JSON
    json_re = re.compile(r'^\s*\{')
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Intentar JSON primero
            if json_re.match(line):
                try:
                    d = json.loads(line)
                    eid = d.get('eventid')
                    ts = d.get('timestamp', '')
                    if eid in ('cowrie.login.success', 'cowrie.login.failed'):
                        records.append({
                            'timestamp': ts,
                            'eventid': eid,
                            'username': d.get('username', ''),
                            'password': d.get('password', ''),
                            'src_ip': d.get('src_ip', '')
                        })
                    continue
                except json.JSONDecodeError:
                    pass
            # Fallback texto
            m = login_re.search(line)
            if m:
                ts_raw, user, pw, result = m.groups()
                status = 'cowrie.login.success' if result == 'succeeded' else 'cowrie.login.failed'
                records.append({
                    'timestamp': ts_raw,
                    'eventid': status,
                    'username': user,
                    'password': pw,
                    'src_ip': ''
                })
    return pd.DataFrame(records)

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_4_1']
    log_path = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
    
    if not os.path.exists(log_path):
        print(f"[SKIP] No se encuentra {log_path}")
        return
    
    print("[4.1] Parseando logs Cowrie ...")
    df = parse_cowrie_log(log_path)
    
    if df.empty:
        print("[SKIP] No se encontraron registros de login en Cowrie")
        return
    
    df['dt'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
    df = df.dropna(subset=['dt'])
    df['date'] = df['dt'].dt.date
    
    daily = df.groupby(['date', 'eventid']).size().unstack(fill_value=0)
    if 'cowrie.login.success' not in daily.columns:
        daily['cowrie.login.success'] = 0
    if 'cowrie.login.failed' not in daily.columns:
        daily['cowrie.login.failed'] = 0
    
    # Top 10 combinaciones
    combos = df.groupby(['username', 'password']).size().reset_index(name='count').sort_values('count', ascending=False).head(10)
    combos['combo'] = combos['username'] + ' / ' + combos['password']
    combos = combos.sort_values('count', ascending=True)
    
    for lang in ['es', 'en']:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        ax = axes[0]
        ax.plot(daily.index, daily['cowrie.login.failed'], color=COLORS[0], linewidth=1.5, label='Failed' if lang=='en' else 'Fallidos')
        if daily['cowrie.login.success'].sum() > 0:
            ax.plot(daily.index, daily['cowrie.login.success'], color=COLORS[4], linewidth=1.5, label='Success' if lang=='en' else 'Exitosos')
        ax.set_title(trans['subtitle_a'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(True, linestyle='--', alpha=0.3)
        fig.autofmt_xdate()
        
        ax = axes[1]
        bars = ax.barh(combos['combo'], combos['count'], color=COLORS[2], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['subtitle_b'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        
        fig.suptitle(trans['title'][lang], fontsize=13, fontweight='bold')
        fig.tight_layout(rect=[0, 0, 1, 0.96])
        save_fig(fig, 'fig_4_1_ssh_intentos_login', lang)
        plt.close(fig)
    print("[4.1] OK")

if __name__ == '__main__':
    main()
