"""
Figura 5.15: Top 10 User-Agents en peticiones al honeypot web.
Datos: honeypot_march.log (nginx)
"""
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_15']
    log_path = os.path.join(ROOT_DIR, 'ai-classifier', 'data', 'logs', 'honeypot_march.log')
    
    if not os.path.exists(log_path):
        print("[SKIP] log web no encontrado")
        return
    
    print("[5.15] Parseando User-Agents ...")
    # Nginx log pattern: IP - - [date] "METHOD PATH PROTO" STATUS SIZE "REFERER" "USER_AGENT"
    ua_re = re.compile(r'"[^"]*"\s+"([^"]*)"')
    agents = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            # Try regex for user-agent at end of line
            parts = line.strip().split('"')
            if len(parts) >= 6:
                ua = parts[-2] if parts[-1] == '-' else parts[-1]
                if not ua or ua == '-':
                    ua = parts[-2] if len(parts) >= 2 else '-'
                agents.append(ua)
    
    if not agents:
        print("[SKIP] No se encontraron User-Agents")
        return
    
    df = pd.DataFrame({'ua': agents})
    # Clean: limit length and group similar
    df['ua_short'] = df['ua'].str[:60]
    top = df['ua_short'].value_counts().head(10).sort_values(ascending=True)
    
    for lang in ['es', 'en']:
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.barh(top.index, top.values, color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['title'][lang])
        ax.set_xlabel(trans['xlabel'][lang])
        ax.set_ylabel(trans['ylabel'][lang])
        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top.values)*0.01, bar.get_y() + bar.get_height()/2,
                    str(int(w)), va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(top.values)*1.15)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        fig.tight_layout()
        save_fig(fig, 'fig_5_15_user_agents_web', lang)
        plt.close(fig)
    print("[5.15] OK")

if __name__ == '__main__':
    main()
