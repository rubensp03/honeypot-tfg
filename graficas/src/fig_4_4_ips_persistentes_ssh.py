"""
Figura 4.4: Top 15 IPs origen más persistentes en ataques SSH.
Datos: logs_cowrie_60dias.log (JSON + fallback)
"""
import os
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def parse_logins_ip(path):
    records = []
    login_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{4}).*login attempt \[b\'([^\']*)\'/b\'([^\']*)\'\]\s+(succeeded|failed)'
    )
    ip_re = re.compile(r'New connection:\s+(\d{1,3}(?:\.\d{1,3}){3}):')
    json_re = re.compile(r'^\s*\{')
    current_ip = ''
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            # Try to capture IP from New connection line
            ip_m = ip_re.search(line)
            if ip_m:
                current_ip = ip_m.group(1)
            if json_re.match(line):
                try:
                    d = json.loads(line)
                    eid = d.get('eventid')
                    if eid in ('cowrie.login.success', 'cowrie.login.failed'):
                        src_ip = d.get('src_ip', current_ip)
                        records.append({'ip': src_ip, 'status': eid})
                    elif eid == 'cowrie.session.connecting':
                        current_ip = d.get('src_ip', '')
                except: pass
                continue
            m = login_re.search(line)
            if m:
                records.append({'ip': current_ip, 'status': 'cowrie.login.failed'})
    return pd.DataFrame(records)

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_4_4']
    log_path = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log Cowrie no encontrado")
        return
    
    print("[4.4] Parseando IPs persistentes ...")
    df = parse_logins_ip(log_path)
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    top_ips = df['ip'].value_counts().head(15).sort_values(ascending=True)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(9, 6))
        bars = ax.barh(top_ips.index, top_ips.values, color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top_ips.values)*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(top_ips.values)*1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_4_4_ips_persistentes_ssh', lang)
        plt.close(fig)
    print("[4.4] OK")

if __name__ == '__main__':
    main()
