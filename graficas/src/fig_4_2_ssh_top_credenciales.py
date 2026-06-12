"""
Figura 4.2: Top credenciales en ataques de fuerza bruta SSH.
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
    login_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{4}).*login attempt \[b\'([^\']*)\'/b\'([^\']*)\'\]\s+(succeeded|failed)'
    )
    json_re = re.compile(r'^\s*\{')
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if json_re.match(line):
                try:
                    d = json.loads(line)
                    eid = d.get('eventid')
                    if eid in ('cowrie.login.success', 'cowrie.login.failed'):
                        records.append({
                            'username': d.get('username', ''),
                            'password': d.get('password', '')
                        })
                    continue
                except json.JSONDecodeError:
                    pass
            m = login_re.search(line)
            if m:
                _, user, pw, _ = m.groups()
                records.append({'username': user, 'password': pw})
    return pd.DataFrame(records)

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_4_2']
    log_path = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
    
    if not os.path.exists(log_path):
        print(f"[SKIP] No se encuentra {log_path}")
        return
    
    print("[4.2] Parseando credenciales Cowrie ...")
    df = parse_cowrie_log(log_path)
    
    if df.empty:
        print("[SKIP] No se encontraron credenciales en Cowrie")
        return
    
    top_users = df['username'].value_counts().head(10).sort_values(ascending=True)
    top_pass = df['password'].value_counts().head(10).sort_values(ascending=True)
    
    for lang in ['es', 'en']:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        
        ax = axes[0]
        bars = ax.barh(top_users.index.astype(str), top_users.values, color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['subtitle_a'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top_users.values)*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(top_users.values)*1.15)
        
        ax = axes[1]
        bars = ax.barh(top_pass.index.astype(str), top_pass.values, color=COLORS[1], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['subtitle_b'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top_pass.values)*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(top_pass.values)*1.15)
        
        fig.suptitle(trans['title'][lang], fontsize=13, fontweight='bold')
        fig.tight_layout(rect=[0, 0, 1, 0.96])
        save_fig(fig, 'fig_4_2_ssh_top_credenciales', lang)
        plt.close(fig)
    print("[4.2] OK")

if __name__ == '__main__':
    main()
