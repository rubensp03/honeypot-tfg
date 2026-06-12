"""
Figura 4.5: Duración de sesiones SSH.
Datos: logs_cowrie_60dias.log (JSON + fallback)
"""
import os
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def parse_sessions(path):
    sessions = {}
    # Pattern: "Connection lost after X.Y seconds"
    lost_re = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{4}).*Connection lost after ([\d\.]+) seconds')
    json_re = re.compile(r'^\s*\{')
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            if json_re.match(line):
                try:
                    d = json.loads(line)
                    eid = d.get('eventid')
                    if eid == 'cowrie.session.closed':
                        sid = d.get('session', '')
                        dur = d.get('duration', None)
                        if dur is not None:
                            sessions[sid] = float(dur)
                except: pass
                continue
            m = lost_re.search(line)
            if m:
                ts, dur = m.groups()
                # We can't map to session ID easily in text mode, so just collect duration
                sessions[ts] = float(dur)
    return pd.DataFrame(list(sessions.items()), columns=['key', 'duration'])

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_4_5']
    log_path = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log Cowrie no encontrado")
        return
    
    print("[4.5] Parseando duraciones ...")
    df = parse_sessions(log_path)
    if df.empty:
        print("[SKIP] No hay datos de duración")
        return
    
    # Filter outliers for visualization (>300s = 5min)
    durations = df['duration'][df['duration'] <= 300]
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.hist(durations, bins=50, color=COLORS[0], edgecolor='white', linewidth=0.3, density=True, alpha=0.8)
        ax.axvline(durations.median(), color=COLORS[1], linestyle='--', linewidth=2, label=f"Median: {durations.median():.1f}s")
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        ax.legend(frameon=True, fancybox=False, edgecolor='#333333')
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_4_5_duracion_sesiones_ssh', lang)
        plt.close(fig)
    print("[4.5] OK")

if __name__ == '__main__':
    main()
