import sqlite3
import random
import os

from config import DB_HONEYPOT_HIBRIDO, OUTPUT_MUESTRA_MANUAL

DB_PATH = str(DB_HONEYPOT_HIBRIDO)
OUTPUT_FILE = str(OUTPUT_MUESTRA_MANUAL)

def extraer_muestra(motor, cantidad_total=15, max_por_cve=3):
    """
    Extrae una muestra aleatoria de logs analizados por un motor específico.
    Garantiza que ningún CVE se repita más de 'max_por_cve' veces.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Obtener todos los registros candidatos para ese motor
    if motor == 'nuclei':
        cursor.execute("""
            SELECT payload, cve, tipo_ataque, gravedad, tecnologia_objetivo
            FROM alertas_hibrido
            WHERE motor_deteccion = 'nuclei'
        """)
    else:
        cursor.execute("""
            SELECT payload, cve, tipo_ataque, gravedad, tecnologia_objetivo
            FROM alertas_hibrido
            WHERE motor_deteccion = 'deepseek-v4-pro' AND confidence = 'heuristica'
        """)
    
    all_rows = cursor.fetchall()
    conn.close()
    
    # Agrupar por CVE para controlar el límite de repeticiones
    cve_groups = {}
    for row in all_rows:
        cve = row[1]
        if cve not in cve_groups:
            cve_groups[cve] = []
        cve_groups[cve].append(row)
    
    # Barajar cada grupo internamente y luego la lista de CVEs
    for cve in cve_groups:
        random.shuffle(cve_groups[cve])
    
    cve_keys = list(cve_groups.keys())
    random.shuffle(cve_keys)
    
    # Seleccionar hasta max_por_cve de cada CVE hasta alcanzar cantidad_total
    seleccionados = []
    conteo_cves = {}
    
    # Primera pasada: intentar diversificar (1 de cada CVE antes de repetir)
    for cve in cve_keys:
        if len(seleccionados) >= cantidad_total:
            break
        if cve_groups[cve]:
            seleccionados.append(cve_groups[cve].pop(0))
            conteo_cves[cve] = 1
    
    # Segunda pasada: permitir hasta max_por_cve repeticiones por CVE
    for cve in cve_keys:
        while len(seleccionados) < cantidad_total and cve_groups[cve] and conteo_cves.get(cve, 0) < max_por_cve:
            seleccionados.append(cve_groups[cve].pop(0))
            conteo_cves[cve] = conteo_cves.get(cve, 0) + 1
    
    random.shuffle(seleccionados)
    return seleccionados

def generar_muestra():
    muestra_nuclei = extraer_muestra('nuclei', 15, 3)
    muestra_deepseek = extraer_muestra('deepseek-v4-pro', 15, 3)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # Encabezado general
        f.write("MUESTRA ALEATORIA PARA VALIDACIÓN MANUAL - Pipeline Híbrido\n")
        f.write("=" * 80 + "\n")
        f.write(f"Total de registros solicitados: 30 (15 Nuclei + 15 DeepSeek)\n")
        f.write(f"Regla: máximo 3 repeticiones por CVE dentro de cada grupo\n")
        f.write(f"Formato: id, payload, cve, tipo_ataque, gravedad, tecnologia_objetivo\n\n")
        
        # SECCIÓN NUCLEI
        f.write("\n" + "=" * 80 + "\n")
        f.write("  SECCIÓN 1: NUCLEI (Motor Determinista - 0€ API)\n")
        f.write("=" * 80 + "\n\n")
        
        i = 1
        for payload, cve, tipo, gravedad, tech in muestra_nuclei:
            f.write(f"{'─' * 80}\n")
            f.write(f"  [{i}] ─────────────────────────────────────────────\n")
            f.write(f"  CVE:       {cve}\n")
            f.write(f"  Tipo:      {tipo}\n")
            f.write(f"  Gravedad:  {gravedad}\n")
            f.write(f"  Tecnología: {tech}\n")
            f.write(f"  Payload:   {payload}\n")
            f.write(f"  ────────────────────────────────────────────────\n\n")
            i += 1
        
        # SECCIÓN DEEPSEEK
        f.write("\n" + "=" * 80 + "\n")
        f.write("  SECCIÓN 2: DEEPEEK V4-PRO (Motor Heurístico - Chain of Thought)\n")
        f.write("=" * 80 + "\n\n")
        
        i = 1
        for payload, cve, tipo, gravedad, tech in muestra_deepseek:
            f.write(f"{'─' * 80}\n")
            f.write(f"  [{i}] ─────────────────────────────────────────────\n")
            f.write(f"  CVE:       {cve}\n")
            f.write(f"  Tipo:      {tipo}\n")
            f.write(f"  Gravedad:  {gravedad}\n")
            f.write(f"  Tecnología: {tech}\n")
            f.write(f"  Payload:   {payload}\n")
            f.write(f"  ────────────────────────────────────────────────\n\n")
            i += 1
        
        # Resumen
        f.write("\n" + "=" * 80 + "\n")
        f.write("RESUMEN DE LA MUESTRA\n")
        f.write("=" * 80 + "\n")
        
        cves_nuclei = [row[1] for row in muestra_nuclei]
        cves_deepseek = [row[1] for row in muestra_deepseek]
        
        f.write(f"\nNuclei: {len(muestra_nuclei)} registros, {len(set(cves_nuclei))} CVEs únicos\n")
        for cve in sorted(set(cves_nuclei)):
            count = cves_nuclei.count(cve)
            f.write(f"  {cve}: {count}\n")
        
        f.write(f"\nDeepSeek: {len(muestra_deepseek)} registros, {len(set(cves_deepseek))} CVEs únicos\n")
        for cve in sorted(set(cves_deepseek)):
            count = cves_deepseek.count(cve)
            f.write(f"  {cve}: {count}\n")
        
        f.write(f"\n{'=' * 80}\n")
        f.write(f"TOTAL de registros extraidos: {len(muestra_nuclei) + len(muestra_deepseek)}\n")
        f.write("=" * 80 + "\n")
    
    print(f"[*] Archivo generado: {OUTPUT_FILE}")
    print(f"[*] Nuclei: {len(muestra_nuclei)} registros, {len(set(cves_nuclei))} CVEs únicos")
    print(f"[*] DeepSeek: {len(muestra_deepseek)} registros, {len(set(cves_deepseek))} CVEs únicos")
    
    # Verificar restricción de máximo 3 por CVE
    for cve, count in [(c, cves_nuclei.count(c)) for c in set(cves_nuclei)]:
        if count > 3:
            print(f"[!] ADVERTENCIA: {cve} aparece {count} veces en Nuclei (límite: 3)")
    for cve, count in [(c, cves_deepseek.count(c)) for c in set(cves_deepseek)]:
        if count > 3:
            print(f"[!] ADVERTENCIA: {cve} aparece {count} veces en DeepSeek (límite: 3)")

if __name__ == '__main__':
    generar_muestra()
