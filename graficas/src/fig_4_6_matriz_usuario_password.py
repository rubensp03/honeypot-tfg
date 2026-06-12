"""
Figura 4.6: Matriz de calor Usuario vs Contraseña (Top 10x10).
Datos: logs_cowrie_60dias.log
"""
import os
import json
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR

def parse_credentials(path):
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
                        records.append({'u': d.get('username',''), 'p': d.get('password','')})
                except: pass
                continue
            m = login_re.search(line)
            if m:
                _, u, p, _ = m.groups()
                records.append({'u': u, 'p': p})
    return pd.DataFrame(records)

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_4_6']
    log_path = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log Cowrie no encontrado")
        return
    
    print("[4.6] Parseando credenciales para matriz ...")
    df = parse_credentials(log_path)
    if df.empty:
        print("[SKIP] No hay datos")
        return
    
    top_u = df['u'].value_counts().head(10).index.tolist()
    top_p = df['p'].value_counts().head(10).index.tolist()
    
    pivot = df[df['u'].isin(top_u) & df['p'].isin(top_p)].groupby(['u', 'p']).size().unstack(fill_value=0)
    pivot = pivot.reindex(index=top_u, columns=top_p, fill_value=0)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(pivot, cmap='YlOrRd', linewidths=0.5, ax=ax, annot=True, fmt='d', cbar_kws={'label': 'Frecuencia' if lang=='es' else 'Frequency'})
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        fig.tight_layout()
        save_fig(fig, 'fig_4_6_matriz_usuario_password', lang)
        plt.close(fig)
    print("[4.6] OK")

if __name__ == '__main__':
    main()
