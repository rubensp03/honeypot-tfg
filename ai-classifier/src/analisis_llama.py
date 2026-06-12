import sqlite3
import pandas as pd
import sys

from config import DB_HONEYPOT_LLAMA

DB_PATH = str(DB_HONEYPOT_LLAMA)

def analizar_base_datos():
    try:
        conn = sqlite3.connect(DB_PATH)
    except Exception as e:
        print(f"Error conectando a la base de datos: {e}")
        return

    # 1. Explorar el esquema
    query_tablas = "SELECT name FROM sqlite_master WHERE type='table';"
    tablas = pd.read_sql_query(query_tablas, conn)
    
    if tablas.empty:
        print("La base de datos no contiene tablas.")
        conn.close()
        return

    print("=== Tablas en la Base de Datos ===")
    for tabla in tablas['name']:
        print(f"- {tabla}")
    
    # Asumimos que la tabla principal se llama 'ataques' o algo similar.
    # Buscaremos la tabla que posiblemente contenga los datos
    tabla_principal = tablas['name'].iloc[0]
    for t in tablas['name']:
        if 'ataque' in t.lower() or 'log' in t.lower():
            tabla_principal = t
            break
            
    print(f"\nUsando '{tabla_principal}' como tabla principal para el análisis.")

    # Ver columnas
    query_columnas = f"PRAGMA table_info({tabla_principal});"
    columnas = pd.read_sql_query(query_columnas, conn)
    nombres_cols = columnas['name'].tolist()
    print(f"Columnas detectadas: {', '.join(nombres_cols)}\n")

    # 2. Estadísticas generales
    total_registros = pd.read_sql_query(f"SELECT COUNT(*) as total FROM {tabla_principal}", conn).iloc[0]['total']
    print("=== ESTADÍSTICAS GENERALES ===")
    print(f"Total de registros/ataques: {total_registros}")

    # 3. Clasificados vs No Clasificados
    # Buscamos una columna de clasificación, etiqueta o predicción
    col_clase = None
    for col in ['clasificado', 'clasificacion', 'etiqueta', 'label', 'prediccion', 'es_ataque', 'tipo_ataque']:
        if col in nombres_cols:
            col_clase = col
            break
            
    if col_clase:
        print("\n=== CLASIFICACIÓN ===")
        distribucion = pd.read_sql_query(f"SELECT {col_clase}, COUNT(*) as cantidad FROM {tabla_principal} GROUP BY {col_clase} ORDER BY cantidad DESC", conn)
        print(distribucion.to_string(index=False))
    else:
        print("\n[!] No se pudo determinar la columna de clasificación. Las columnas disponibles son:", nombres_cols)

    # 4. CVEs más comunes
    # Buscamos una columna que contenga CVEs
    col_cve = None
    for col in ['cve', 'vulnerabilidad', 'id_cve', 'cves']:
        if col in nombres_cols:
            col_cve = col
            break
            
    if col_cve:
        print("\n=== TOP 10 CVEs ===")
        top_cves = pd.read_sql_query(f"SELECT {col_cve}, COUNT(*) as cantidad FROM {tabla_principal} WHERE {col_cve} IS NOT NULL AND {col_cve} != '' GROUP BY {col_cve} ORDER BY cantidad DESC LIMIT 10", conn)
        if not top_cves.empty:
            print(top_cves.to_string(index=False))
        else:
            print("No se encontraron registros con CVEs.")
    else:
        # Intento de buscar CVEs dentro del payload o mensaje
        print("\n[!] No hay columna directa de 'CVE'. Intentando buscar CVEs en otras columnas de texto...")
        
        # Buscamos la columna de payload, peticion, request o data
        col_texto = None
        for col in ['payload', 'peticion', 'request', 'data', 'mensaje']:
            if col in [c.lower() for c in nombres_cols]:
                col_texto = col
                break
                
        if col_texto:
            # Consulta para sacar textos y buscar con regex en pandas
            query_text = f"SELECT {col_texto} FROM {tabla_principal} WHERE {col_texto} LIKE '%CVE-%'"
            try:
                textos = pd.read_sql_query(query_text, conn)
                # Extraemos patrón CVE-XXXX-XXXXX
                cves_extraidos = textos[col_texto].str.extract(r'(CVE-\d{4}-\d+)')[0]
                conteo_cves = cves_extraidos.value_counts().head(10)
                if not conteo_cves.empty:
                    print("\n=== TOP 10 CVEs ENCONTRADOS EN EL TEXTO ===")
                    print(conteo_cves.to_string())
                else:
                    print("No se encontraron menciones a CVEs en los detalles.")
            except Exception as e:
                pass

    # 5. IPs más atacantes (si existe columna de IP)
    col_ip = next((col for col in ['ip', 'ip_origen', 'source_ip', 'src_ip'] if col in nombres_cols), None)
    if col_ip:
        print("\n=== TOP 5 IPs ATACANTES ===")
        top_ips = pd.read_sql_query(f"SELECT {col_ip}, COUNT(*) as cantidad FROM {tabla_principal} GROUP BY {col_ip} ORDER BY cantidad DESC LIMIT 5", conn)
        print(top_ips.to_string(index=False))

    conn.close()

if __name__ == "__main__":
    analizar_base_datos()
