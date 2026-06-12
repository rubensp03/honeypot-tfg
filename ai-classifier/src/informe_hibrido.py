import sqlite3
import pandas as pd
from collections import Counter

from config import DB_HONEYPOT_HIBRIDO

DB_PATH = str(DB_HONEYPOT_HIBRIDO)


def generar_informe():
    conn = sqlite3.connect(DB_PATH)
    
    print("=" * 70)
    print("INFORME COMPARATIVO: Motor Determinista (Nuclei) vs. DeepSeek v4-pro")
    print("=" * 70)
    
    # 1. Métricas globales de la última ejecución
    print("\n### MÉTRICAS GLOBALES (última ejecución) ###")
    metricas = pd.read_sql_query(
        "SELECT * FROM metricas ORDER BY fecha DESC LIMIT 1", conn
    )
    if not metricas.empty:
        row = metricas.iloc[0]
        print(f"Fecha ejecución:         {row['fecha']}")
        print(f"Total logs analizados:   {row['total_logs']}")
        print(f"Resueltos por Nuclei:    {row['resueltos_nuclei']} ({row['resueltos_nuclei']/row['total_logs']*100:.1f}%)")
        print(f"Resueltos por DeepSeek:  {row['resueltos_deepseek']} ({row['resueltos_deepseek']/row['total_logs']*100:.1f}%)")
        print(f"Fallos de DeepSeek:      {row['fallos_deepseek']}")
        print(f"Tiempo total:            {row['tiempo_total_s']:.1f}s")
        print(f"Tokens input estimados:  {row['coste_estimado_input_tokens']}")
        print(f"Tokens output estimados: {row['coste_estimado_output_tokens']}")
    else:
        print("[!] No hay métricas registradas todavía.")
    
    # 2. Distribución por motor de detección
    print("\n### DISTRIBUCIÓN POR MOTOR DE DETECCIÓN ###")
    query = """
        SELECT motor_deteccion, confidence, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        GROUP BY motor_deteccion, confidence 
        ORDER BY cantidad DESC
    """
    dist = pd.read_sql_query(query, conn)
    if not dist.empty:
        print(dist.to_string(index=False))
    else:
        print("[!] No hay datos en la base de datos.")
    
    # 3. Top CVEs detectados por cada motor
    print("\n### TOP 15 CVEs (Nuclei - Determinista) ###")
    query = """
        SELECT cve, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        WHERE motor_deteccion = 'nuclei' AND cve != 'Desconocido' 
        GROUP BY cve 
        ORDER BY cantidad DESC 
        LIMIT 15
    """
    cves_nuclei = pd.read_sql_query(query, conn)
    if not cves_nuclei.empty:
        print(cves_nuclei.to_string(index=False))
    else:
        print("No se encontraron CVEs deterministas.")
    
    print("\n### TOP 15 CVEs (DeepSeek v4-pro - Heurística) ###")
    query = """
        SELECT cve, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        WHERE motor_deteccion = 'deepseek-v4-pro' AND cve != 'Desconocido' 
        GROUP BY cve 
        ORDER BY cantidad DESC 
        LIMIT 15
    """
    cves_deep = pd.read_sql_query(query, conn)
    if not cves_deep.empty:
        print(cves_deep.to_string(index=False))
    else:
        print("No se encontraron CVEs por DeepSeek.")
    
    # 4. Distribución de tipos de ataque
    print("\n### DISTRIBUCIÓN DE TIPOS DE ATAQUE ###")
    query = """
        SELECT tipo_ataque, motor_deteccion, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        GROUP BY tipo_ataque, motor_deteccion 
        ORDER BY cantidad DESC
    """
    tipos = pd.read_sql_query(query, conn)
    if not tipos.empty:
        print(tipos.to_string(index=False))
    else:
        print("No hay tipos de ataque registrados.")
    
    # 5. Tecnologías objetivo más atacadas
    print("\n### TOP 10 TECNOLOGÍAS OBJETIVO ###")
    query = """
        SELECT tecnologia_objetivo, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        WHERE tecnologia_objetivo != 'Desconocida' 
        GROUP BY tecnologia_objetivo 
        ORDER BY cantidad DESC 
        LIMIT 10
    """
    techs = pd.read_sql_query(query, conn)
    if not techs.empty:
        print(techs.to_string(index=False))
    else:
        print("No hay tecnologías identificadas.")
    
    # 6. IPs más atacantes
    print("\n### TOP 10 IPs ATACANTES ###")
    query = """
        SELECT ip_origen, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        GROUP BY ip_origen 
        ORDER BY cantidad DESC 
        LIMIT 10
    """
    ips = pd.read_sql_query(query, conn)
    if not ips.empty:
        print(ips.to_string(index=False))
    
    # 7. Análisis de gravedad
    print("\n### DISTRIBUCIÓN POR GRAVEDAD ###")
    query = """
        SELECT gravedad, motor_deteccion, COUNT(*) as cantidad 
        FROM alertas_hibrido 
        GROUP BY gravedad, motor_deteccion 
        ORDER BY cantidad DESC
    """
    gravedad = pd.read_sql_query(query, conn)
    if not gravedad.empty:
        print(gravedad.to_string(index=False))
    
    # 8. Muestra de reasoning de DeepSeek
    print("\n### MUESTRA DE REASONING (DeepSeek v4-pro) ###")
    query = """
        SELECT payload, tipo_ataque, cve, tecnologia_objetivo, reasoning 
        FROM alertas_hibrido 
        WHERE motor_deteccion = 'deepseek-v4-pro' AND reasoning IS NOT NULL AND reasoning != '' 
        LIMIT 3
    """
    reasoning = pd.read_sql_query(query, conn)
    if not reasoning.empty:
        for _, row in reasoning.iterrows():
            print(f"\nPayload: {row['payload'][:100]}...")
            print(f"  Tipo: {row['tipo_ataque']} | CVE: {row['cve']} | Tech: {row['tecnologia_objetivo']}")
            print(f"  Reasoning: {row['reasoning'][:300]}...")
    else:
        print("No hay reasoning disponible todavía.")
    
    print("\n" + "=" * 70)
    print("Fin del informe")
    print("=" * 70)
    
    conn.close()


if __name__ == "__main__":
    generar_informe()
