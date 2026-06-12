"""
Figura 5.20: Mapa mundial de origen geográfico del tráfico malicioso + Top 15 países.
Datos: blacklist.db (campo country)
"""
import os
import sys
import sqlite3
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import geopandas as gpd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import setup_style, save_fig, TRANSLATIONS, ensure_dirs, ROOT_DIR, COLORS

# Normalizaciones de nombres de países en ip-api vs Natural Earth (50m)
COUNTRY_REMAP = {
    'The Netherlands': 'Netherlands',
    'Russian Federation': 'Russia',
    'Korea, Republic of': 'South Korea',
    'Viet Nam': 'Vietnam',
    "Lao People's Democratic Republic": 'Laos',
    'Brunei Darussalam': 'Brunei',
    'Czechia': 'Czech Republic',
    'Moldova, Republic of': 'Moldova',
    'Bolivia, Plurinational State of': 'Bolivia',
    'Venezuela, Bolivarian Republic of': 'Venezuela',
    'Tanzania': 'United Republic of Tanzania',
    'Tanzania, United Republic of': 'United Republic of Tanzania',
    'Macedonia, the former Yugoslav Republic of': 'North Macedonia',
    'Iran, Islamic Republic of': 'Iran',
    'Syrian Arab Republic': 'Syria',
    'Palestine, State of': 'Palestine',
    'Congo, the Democratic Republic of the': 'Democratic Republic of the Congo',
    'Congo': 'Republic of the Congo',
    'Libyan Arab Jamahiriya': 'Libya',
    "Cote d'Ivoire": 'Ivory Coast',
    'United States': 'United States of America',
    'Hong Kong': 'Hong Kong S.A.R.',
    'Türkiye': 'Turkey',
    'Serbia': 'Republic of Serbia',
    'Eswatini': 'eSwatini',
}

def load_world():
    """Descarga shapefile Natural Earth 50m via URL."""
    url = "https://naturalearth.s3.amazonaws.com/50m_cultural/ne_50m_admin_0_countries.zip"
    try:
        world = gpd.read_file(url)
        print("[5.20] Shapefile 50m descargado correctamente.")
        return world
    except Exception as e:
        print(f"[WARN] Fallo descarga 50m: {e}. Intentando 110m...")
        try:
            url110 = "https://naturalearth.s3.amazonaws.com/110m_cultural/ne_110m_admin_0_countries.zip"
            world = gpd.read_file(url110)
            print("[5.20] Shapefile 110m descargado correctamente.")
            return world
        except Exception as e2:
            print(f"[ERROR] No se pudo obtener shapefile: {e2}")
            return None

def main():
    setup_style()
    ensure_dirs()
    trans = TRANSLATIONS['fig_5_20']
    db_path = os.path.join(ROOT_DIR, 'blacklisting', 'blacklist.db')
    
    if not os.path.exists(db_path):
        print("[SKIP] blacklist.db no encontrado")
        return
    
    # 1. Leer datos por país
    print("[5.20] Leyendo datos por país ...")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT country, COUNT(ip) as ips FROM malicious_ips WHERE country IS NOT NULL AND country != '' AND country != 'Unknown' GROUP BY country",
        conn
    )
    conn.close()
    
    if df.empty:
        print("[SKIP] No hay datos de país")
        return
    
    # Normalizar nombres
    df['country'] = df['country'].replace(COUNTRY_REMAP)
    # Agregar tras normalización (ej. Netherlands + The Netherlands)
    df = df.groupby('country')['ips'].sum().reset_index()
    
    # 2. Cargar shapefile mundial
    world = load_world()
    if world is None:
        print("[SKIP] No se pudo cargar shapefile mundial")
        return
    
    # 3. Merge
    # Natural Earth usa 'ADMIN' o 'SOVEREIGNT' para nombre del país
    merge_col = 'ADMIN' if 'ADMIN' in world.columns else 'SOVEREIGNT' if 'SOVEREIGNT' in world.columns else 'name'
    world[merge_col] = world[merge_col].replace(COUNTRY_REMAP)
    merged = world.merge(df, left_on=merge_col, right_on='country', how='left')
    merged['ips'] = merged['ips'].fillna(0).astype(int)
    merged['log_ips'] = np.log1p(merged['ips'])

    # Diagnosticar países sin correspondencia
    unmatched = set(df['country']) - set(world[merge_col].unique())
    if unmatched:
        unmatched_info = df[df['country'].isin(unmatched)].sort_values('ips', ascending=False)
        print(f"[5.20] ADVERTENCIA: {len(unmatched)} países sin geometría en el shapefile:")
        for _, row in unmatched_info.iterrows():
            print(f"       - {row['country']:40s} {int(row['ips']):>6} IPs")
    
    # 4. Top 15 para barras
    top15 = df.sort_values('ips', ascending=False).head(15).sort_values('ips', ascending=True)
    total_ips = df['ips'].sum()
    
    for lang in ['es', 'en']:
        fig, axes = plt.subplots(1, 2, figsize=(18, 8), gridspec_kw={'width_ratios': [3, 1]})
        
        # --- Subplot (a): Mapa ---
        ax = axes[0]
        merged.plot(column='log_ips', cmap='plasma', linewidth=0.3, ax=ax,
                    edgecolor='#666666', missing_kwds={'color': '#F5F5F5', 'edgecolor': '#CCCCCC'})
        ax.set_title(trans['subtitle_map'][lang], fontsize=11)
        ax.set_axis_off()
        
        # Colorbar personalizada con ticks en escala log
        sm = plt.cm.ScalarMappable(cmap='plasma', norm=plt.Normalize(vmin=0, vmax=merged['log_ips'].max()))
        cbar = fig.colorbar(sm, ax=ax, fraction=0.03, pad=0.04)
        cbar.set_label(trans['cbar_label'][lang])
        # Ticks en valores log que correspondan a IPs reales
        log_max = int(np.floor(merged['log_ips'].max())) + 1
        ticks = list(range(0, log_max + 1))
        cbar.set_ticks(ticks)
        cbar.set_ticklabels([f'{int(np.expm1(t))}' for t in ticks])
        
        # --- Subplot (b): Barras ---
        ax = axes[1]
        bars = ax.barh(top15['country'], top15['ips'], color=COLORS[0], edgecolor='white', linewidth=0.5)
        ax.set_title(trans['subtitle_bars'][lang], fontsize=11)
        ax.set_xlabel(trans['xlabel_bars'][lang])
        ax.set_ylabel(trans['ylabel_bars'][lang])
        for bar in bars:
            w = bar.get_width()
            pct = w / total_ips * 100
            ax.text(w + total_ips * 0.005, bar.get_y() + bar.get_height() / 2,
                    f'{int(w)} ({pct:.1f}%)', va='center', fontsize=8, color='#333333')
        ax.set_xlim(0, max(top15['ips']) * 1.3)
        ax.grid(axis='x', linestyle='--', alpha=0.3)
        
        fig.suptitle(trans['title'][lang], fontsize=13, fontweight='bold')
        fig.tight_layout(rect=[0, 0, 1, 0.96])
        save_fig(fig, 'fig_5_20_mapa_mundial_paises', lang)
        plt.close(fig)
    
    print("[5.20] OK")

if __name__ == '__main__':
    main()
