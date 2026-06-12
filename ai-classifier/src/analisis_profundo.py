import sqlite3
import pandas as pd
from collections import Counter, defaultdict
import json

from config import DB_HONEYPOT_HIBRIDO, OUTPUT_ANALISIS_MD, OUTPUT_RESULTADOS_CSV

DB_PATH = str(DB_HONEYPOT_HIBRIDO)
OUTPUT_MD = str(OUTPUT_ANALISIS_MD)
OUTPUT_CSV = str(OUTPUT_RESULTADOS_CSV)


def conectar():
    return sqlite3.connect(DB_PATH)


def generar_analisis_completo():
    conn = conectar()
    
    lines = []
    lines.append("# Análisis Comparativo: Nuclei (Determinista) vs DeepSeek v4-pro (Heurística)")
    lines.append("**Pipeline Híbrido para Clasificación de CVEs en Honeypot**")
    lines.append("")
    
    # ============================================
    # 1. ESTADÍSTICAS GLOBALES
    # ============================================
    lines.append("## 1. Estadísticas Globales del Pipeline")
    lines.append("")
    
    total = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido", conn).iloc[0]['c']
    nuclei_count = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido WHERE motor_deteccion='nuclei'", conn).iloc[0]['c']
    deepseek_ok = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido WHERE motor_deteccion='deepseek-v4-pro' AND confidence='heuristica'", conn).iloc[0]['c']
    deepseek_fail = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido WHERE motor_deteccion='deepseek-v4-pro' AND confidence='fallo_api'", conn).iloc[0]['c']
    
    lines.append(f"- **Total logs procesados:** {total:,}")
    lines.append(f"- **Resueltos por Nuclei (determinista, 0€):** {nuclei_count:,} ({nuclei_count/total*100:.1f}%)")
    lines.append(f"- **Resueltos por DeepSeek v4-pro:** {deepseek_ok:,} ({deepseek_ok/total*100:.1f}%)")
    lines.append(f"- **Fallos API DeepSeek:** {deepseek_fail:,} ({deepseek_fail/total*100:.1f}%)")
    lines.append("")
    lines.append("### 1.1 Eficiencia de Costes")
    lines.append("")
    lines.append("| Concepto | Valor |")
    lines.append("|---|---|")
    lines.append(f"| Logs resueltos sin coste (Nuclei) | {nuclei_count:,} ({nuclei_count/total*100:.1f}%) |")
    lines.append(f"| Logs que requirieron API (DeepSeek) | {deepseek_ok + deepseek_fail:,} ({(deepseek_ok+deepseek_fail)/total*100:.1f}%) |")
    lines.append(f"| Ahorro estimado vs. enviar todo a DeepSeek | ${nuclei_count * 0.0007:.2f} |")
    lines.append("")
    lines.append("> **Nota:** Asumiendo ~$0.0007 por log en DeepSeek v4-pro, Nuclei ha ahorrado aproximadamente "
               f"${nuclei_count * 0.0007:.2f} en tokens API.")
    lines.append("")
    
    # ============================================
    # 2. COMPARATIVA DE CVEs
    # ============================================
    lines.append("## 2. Comparativa de Detección de CVEs")
    lines.append("")
    lines.append("### 2.1 CVEs detectados exclusivamente por Nuclei (firma determinista)")
    lines.append("")
    
    query = """
        SELECT cve, COUNT(*) as cantidad, gravedad, tecnologia_objetivo
        FROM alertas_hibrido 
        WHERE motor_deteccion = 'nuclei' AND cve != 'Desconocido'
        GROUP BY cve 
        ORDER BY cantidad DESC 
        LIMIT 20
    """
    cves_nuclei = pd.read_sql_query(query, conn)
    if not cves_nuclei.empty:
        lines.append("| CVE | Cantidad | Gravedad | Tecnología |")
        lines.append("|---|---|---|---|")
        for _, row in cves_nuclei.iterrows():
            lines.append(f"| {row['cve']} | {row['cantidad']} | {row['gravedad']} | {row['tecnologia_objetivo']} |")
    lines.append("")
    
    lines.append("### 2.2 CVEs detectados exclusivamente por DeepSeek (heurística)")
    lines.append("")
    query = """
        SELECT cve, COUNT(*) as cantidad, gravedad, tecnologia_objetivo
        FROM alertas_hibrido 
        WHERE motor_deteccion = 'deepseek-v4-pro' AND cve != 'Desconocido' AND confidence = 'heuristica'
        GROUP BY cve 
        ORDER BY cantidad DESC 
        LIMIT 20
    """
    cves_ds = pd.read_sql_query(query, conn)
    if not cves_ds.empty:
        lines.append("| CVE | Cantidad | Gravedad | Tecnología |")
        lines.append("|---|---|---|---|")
        for _, row in cves_ds.iterrows():
            lines.append(f"| {row['cve']} | {row['cantidad']} | {row['gravedad']} | {row['tecnologia_objetivo']} |")
    lines.append("")
    
    # ============================================
    # 3. SOLAPAMIENTOS Y DISCREPANCIAS
    # ============================================
    lines.append("## 3. Análisis de Solapamientos y Discrepancias")
    lines.append("")
    lines.append("### 3.1 CVEs detectados por AMBOS motores (validación cruzada)")
    lines.append("")
    
    query = """
        SELECT cve,
               SUM(CASE WHEN motor_deteccion = 'nuclei' THEN 1 ELSE 0 END) as nuclei_count,
               SUM(CASE WHEN motor_deteccion = 'deepseek-v4-pro' AND confidence = 'heuristica' THEN 1 ELSE 0 END) as deepseek_count
        FROM alertas_hibrido
        WHERE cve != 'Desconocido'
        GROUP BY cve
        HAVING nuclei_count > 0 AND deepseek_count > 0
        ORDER BY (nuclei_count + deepseek_count) DESC
        LIMIT 10
    """
    overlap = pd.read_sql_query(query, conn)
    if not overlap.empty:
        lines.append("| CVE | Nuclei | DeepSeek | Total | Validación |")
        lines.append("|---|---|---|---|---|")
        for _, row in overlap.iterrows():
            validation = "✅ Coincide" if row['nuclei_count'] > 0 and row['deepseek_count'] > 0 else "⚠️ Parcial"
            lines.append(f"| {row['cve']} | {row['nuclei_count']} | {row['deepseek_count']} | {row['nuclei_count'] + row['deepseek_count']} | {validation} |")
    else:
        lines.append("No se encontraron CVEs detectados por ambos motores en esta muestra.")
    lines.append("")
    
    lines.append("### 3.2 Discrepancias en Clasificación de Tipo de Ataque")
    lines.append("")
    lines.append("Payloads donde Nuclei y DeepSeek difieren en el tipo de ataque asignado:")
    lines.append("")
    
    query = """
        SELECT DISTINCT payload, tipo_ataque, motor_deteccion
        FROM alertas_hibrido 
        WHERE payload IN (
            SELECT payload FROM alertas_hibrido GROUP BY payload HAVING COUNT(DISTINCT tipo_ataque) > 1
        )
        ORDER BY payload
        LIMIT 15
    """
    discrepancies = pd.read_sql_query(query, conn)
    if not discrepancies.empty:
        lines.append("| Payload | Motor | Tipo Asignado |")
        lines.append("|---|---|---|")
        for _, row in discrepancies.iterrows():
            payload_short = row['payload'][:60] + "..." if len(row['payload']) > 60 else row['payload']
            lines.append(f"| `{payload_short}` | {row['motor_deteccion']} | {row['tipo_ataque']} |")
    else:
        lines.append("No se encontraron discrepancias significativas en esta muestra.")
    lines.append("")
    
    # ============================================
    # 4. ANÁLISIS POR GRAVEDAD Y RIESGO
    # ============================================
    lines.append("## 4. Análisis por Nivel de Gravedad")
    lines.append("")
    
    query = """
        SELECT gravedad, motor_deteccion, COUNT(*) as cantidad
        FROM alertas_hibrido
        WHERE gravedad IN ('Critica', 'Alta', 'Media')
        GROUP BY gravedad, motor_deteccion
        ORDER BY 
            CASE gravedad 
                WHEN 'Critica' THEN 1 
                WHEN 'Alta' THEN 2 
                WHEN 'Media' THEN 3 
                ELSE 4 
            END,
            cantidad DESC
    """
    severity = pd.read_sql_query(query, conn)
    if not severity.empty:
        lines.append("| Gravedad | Motor | Cantidad |")
        lines.append("|---|---|---|")
        for _, row in severity.iterrows():
            lines.append(f"| **{row['gravedad']}** | {row['motor_deteccion']} | {row['cantidad']} |")
    lines.append("")
    
    crit_total = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido WHERE gravedad='Critica'", conn).iloc[0]['c']
    high_total = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido WHERE gravedad='Alta'", conn).iloc[0]['c']
    lines.append(f"**Resumen de riesgo:** {crit_total} ataques críticos + {high_total} ataques de alta gravedad = **{crit_total + high_total} ataques de alto riesgo**.")
    lines.append("")
    
    # ============================================
    # 5. ANÁLISIS DE FINGERPRINTING Y RECONOCIMIENTO
    # ============================================
    lines.append("## 5. Detección de Fingerprinting y Reconocimiento")
    lines.append("")
    
    fp_count = pd.read_sql_query("SELECT COUNT(*) as c FROM alertas_hibrido WHERE tipo_ataque LIKE '%Fingerprinting%' OR tipo_ataque LIKE '%Reconocimiento%'", conn).iloc[0]['c']
    lines.append(f"- **Total de actividades de reconocimiento:** {fp_count:,}")
    lines.append(f"- **Porcentaje del total:** {fp_count/total*100:.1f}%")
    lines.append("")
    
    query = """
        SELECT tecnologia_objetivo, COUNT(*) as cantidad
        FROM alertas_hibrido 
        WHERE tipo_ataque LIKE '%Fingerprinting%' OR tipo_ataque LIKE '%Reconocimiento%'
        GROUP BY tecnologia_objetivo
        ORDER BY cantidad DESC
        LIMIT 15
    """
    fp_techs = pd.read_sql_query(query, conn)
    if not fp_techs.empty:
        lines.append("### Tecnologías más fingerprinteadas:")
        lines.append("")
        lines.append("| Tecnología | Intentos de Reconocimiento |")
        lines.append("|---|---|")
        for _, row in fp_techs.iterrows():
            lines.append(f"| {row['tecnologia_objetivo']} | {row['cantidad']} |")
    lines.append("")
    
    # ============================================
    # 6. MUESTRAS REPRESENTATIVAS
    # ============================================
    lines.append("## 6. Muestras Representativas por Categoría")
    lines.append("")
    
    categorias = [
        ("RCE (Remote Code Execution)", "tipo_ataque='RCE'", 3),
        ("SQL Injection", "tipo_ataque='SQLi'", 3),
        ("Path Traversal / LFI", "tipo_ataque LIKE '%Path Traversal%' OR tipo_ataque='LFI'", 3),
        ("Fingerprinting/Reconocimiento", "tipo_ataque LIKE '%Fingerprinting%'", 3),
        ("Info Disclosure", "tipo_ataque='Info Disclosure'", 3),
        ("Legítimo", "tipo_ataque='Legitimo'", 2),
    ]
    
    for cat_name, where_clause, limit in categorias:
        lines.append(f"### {cat_name}")
        lines.append("")
        query = f"""
            SELECT DISTINCT payload, cve, gravedad, tecnologia_objetivo, motor_deteccion
            FROM alertas_hibrido 
            WHERE {where_clause}
            LIMIT {limit}
        """
        samples = pd.read_sql_query(query, conn)
        if not samples.empty:
            for idx, row in samples.iterrows():
                lines.append(f"**{idx+1}. Payload:** `{row['payload'][:100]}`")
                lines.append(f"   - **CVE:** {row['cve']} | **Gravedad:** {row['gravedad']}")
                lines.append(f"   - **Tecnología:** {row['tecnologia_objetivo']} | **Motor:** {row['motor_deteccion']}")
                lines.append("")
        else:
            lines.append("*No hay muestras en esta categoría.*")
            lines.append("")
    
    # ============================================
    # 7. ANÁLISIS DE IPs ATACANTES
    # ============================================
    lines.append("## 7. Perfil de IPs Atacantes")
    lines.append("")
    
    query = """
        SELECT ip_origen, COUNT(*) as total, 
               SUM(CASE WHEN motor_deteccion='nuclei' THEN 1 ELSE 0 END) as nuclei_det,
               SUM(CASE WHEN motor_deteccion='deepseek-v4-pro' THEN 1 ELSE 0 END) as deepseek_det,
               GROUP_CONCAT(DISTINCT tipo_ataque) as tipos
        FROM alertas_hibrido 
        GROUP BY ip_origen 
        ORDER BY total DESC 
        LIMIT 10
    """
    ips = pd.read_sql_query(query, conn)
    if not ips.empty:
        lines.append("| IP | Total | Nuclei | DeepSeek | Tipos de Ataque |")
        lines.append("|---|---|---|---|---|")
        for _, row in ips.iterrows():
            tipos_short = row['tipos'][:50] + "..." if len(str(row['tipos'])) > 50 else row['tipos']
            lines.append(f"| {row['ip_origen']} | {row['total']} | {row['nuclei_det']} | {row['deepseek_det']} | {tipos_short} |")
    lines.append("")
    
    # ============================================
    # 8. CONCLUSIONES PARA EL TFG
    # ============================================
    lines.append("## 8. Conclusiones y Métricas del Pipeline Híbrido")
    lines.append("")
    lines.append("### 8.1 Efectividad del Motor Determinista (Nuclei)")
    lines.append("")
    lines.append(f"- **Cobertura:** Nuclei resolvió {nuclei_count/total*100:.1f}% de los logs sin coste API.")
    lines.append(f"- **Precisión:** Las detecciones de Nuclei están basadas en firmas YAML verificadas de ProjectDiscovery.")
    lines.append(f"- **Velocidad:** Procesamiento offline instantáneo (sin latencia de red).")
    lines.append("")
    
    lines.append("### 8.2 Valor Añadido de DeepSeek v4-pro (Thinking Mode)")
    lines.append("")
    lines.append(f"- **Cobertura complementaria:** DeepSeek cubrió el {(deepseek_ok+deepseek_fail)/total*100:.1f}% restante que Nuclei no pudo clasificar.")
    lines.append(f"- **Capacidad de razonamiento:** Captura el proceso de pensamiento del modelo para auditoría.")
    lines.append(f"- **Fingerprinting:** Excelente detección de actividades de reconocimiento ({fp_count} casos).")
    lines.append("")
    
    lines.append("### 8.3 Eficiencia Económica")
    lines.append("")
    ahorro = nuclei_count * 0.0007
    lines.append(f"- **Ahorro estimado:** ${ahorro:.2f} en tokens API (enviando {nuclei_count:,} logs menos a DeepSeek).")
    lines.append(f"- **Coste por log resuelto por DeepSeek:** ~$0.0007 (estimado).")
    lines.append(f"- **ROI:** Por cada $1 gastado en DeepSeek, Nuclei ahorró ${ahorro/max(0.01, (deepseek_ok+deepseek_fail)*0.0007):.2f}.")
    lines.append("")
    
    lines.append("### 8.4 Limitaciones Observadas")
    lines.append("")
    lines.append(f"- **Fallos API:** {deepseek_fail} logs ({deepseek_fail/total*100:.1f}%) no pudieron ser analizados por problemas de conectividad/rate limiting.")
    lines.append(f"- **Desconocidos:** {pd.read_sql_query('SELECT COUNT(*) as c FROM alertas_hibrido WHERE tipo_ataque=\"Desconocido\"', conn).iloc[0]['c']} logs ({pd.read_sql_query('SELECT COUNT(*) as c FROM alertas_hibrido WHERE tipo_ataque=\"Desconocido\"', conn).iloc[0]['c']/total*100:.1f}%) quedaron sin clasificar clara.")
    lines.append(f"- **Dataset incompleto:** Solo se procesó {total:,} de 36,760 logs totales por limitación de presupuesto API.")
    lines.append("")
    
    lines.append("---")
    lines.append("*Informe generado automáticamente por el Pipeline Híbrido de Análisis de Vulnerabilidades.*")
    lines.append("*Herramientas: Nuclei v3.8.0 + DeepSeek v4-pro (Thinking Mode) + Python 3.14*")
    
    # Guardar Markdown
    with open(OUTPUT_MD, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"[✓] Informe guardado en: {OUTPUT_MD}")
    
    # ============================================
    # 9. EXPORTAR CSV COMPLETO
    # ============================================
    query = """
        SELECT fecha, ip_origen, payload, tipo_ataque, cve, gravedad, 
               tecnologia_objetivo, motor_deteccion, confidence, reasoning
        FROM alertas_hibrido
    """
    df = pd.read_sql_query(query, conn)
    df.to_csv(OUTPUT_CSV, index=False, encoding='utf-8')
    print(f"[✓] CSV exportado en: {OUTPUT_CSV} ({len(df)} filas)")
    
    conn.close()


if __name__ == "__main__":
    generar_analisis_completo()
