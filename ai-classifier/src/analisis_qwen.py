import sqlite3
import pandas as pd

from config import DB_HONEYPOT_QWEN

DB_PATH = str(DB_HONEYPOT_QWEN)

def analizar_base_datos():
    try:
        conn = sqlite3.connect(DB_PATH)
        
        # Obtener nombres de las tablas
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tablas = cursor.fetchall()
        print("=== Tablas en la Base de Datos ===")
        for tabla in tablas:
            print(f"- {tabla[0]}")
        print()
        
        # Verificar que la tabla exista
        if ('alertas_ia',) not in tablas:
            print("[!] La tabla 'alertas_ia' no existe en la base de datos.")
            return

        print("Usando 'alertas_ia' como tabla principal para el análisis.")
        
        # Obtener nombres de las columnas
        cursor.execute("PRAGMA table_info(alertas_ia);")
        columnas = [columna[1] for columna in cursor.fetchall()]
        print(f"Columnas detectadas: {', '.join(columnas)}\n")
        
        df = pd.read_sql_query("SELECT * FROM alertas_ia", conn)
        
    except sqlite3.Error as e:
        print(f"Error al conectar con la base de datos: {e}")
        return
    finally:
        if 'conn' in locals() and conn:
            conn.close()

    if df.empty:
        print("[!] La tabla está vacía. No hay datos para analizar.")
        return

    print("=== ESTADÍSTICAS GENERALES ===")
    print(f"Total de registros/ataques: {len(df)}")
    print()

    # Tipos de Ataque
    if 'tipo_ataque' in df.columns:
        print("=== CLASIFICACIÓN ===")
        print(df['tipo_ataque'].value_counts().head(10).to_string())
        print()
    else:
        print("[!] No se pudo determinar la columna de clasificación.")
        
    # Top CVEs
    if 'cve' in df.columns:
        print("=== TOP 10 CVEs ===")
        print(df['cve'].value_counts().head(10).reset_index().rename(columns={'index': 'cve', 'cve': 'cantidad'}).to_string(index=False))
        print()
    
    # Orígenes de IP
    if 'ip_origen' in df.columns:
        print("=== TOP 5 IPs ATACANTES ===")
        print(df['ip_origen'].value_counts().head(5).reset_index().rename(columns={'index': 'ip_origen', 'ip_origen': 'cantidad'}).to_string(index=False))
        print()

if __name__ == "__main__":
    analizar_base_datos()
