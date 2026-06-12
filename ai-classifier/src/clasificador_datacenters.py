import re
import time
from collections import Counter
import requests
import json

from config import LOG_FILE

LOG_FILE = str(LOG_FILE)

def extraer_ips_de_logs(ruta_archivo):
    """
    Extrae las IPs de los logs de acceso y error y cuenta cuántas peticiones ha realizado cada una.
    """
    conteo_ips = Counter()
    regex_access = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    regex_error = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')
    
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            for linea in f:
                match_access = regex_access.search(linea)
                if match_access:
                    conteo_ips[match_access.group(1)] += 1
                    continue
                
                match_error = regex_error.search(linea)
                if match_error:
                    conteo_ips[match_error.group(1)] += 1
                    continue
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo de log en la ruta {ruta_archivo}")
        return None

    return conteo_ips

def obtener_datacenters_batch(ips):
    """
    Utiliza el endpoint batch de ip-api.com para obtener la información del ISP/Datacenter de múltiples IPs.
    Agrupa en lotes de 100 IPs para maximizar la eficiencia y respeta los rate limits.
    """
    url = "http://ip-api.com/batch"
    resultados_ips = {}
    
    ips_list = list(ips)
    total_lotes = (len(ips_list) + 99) // 100
    
    print(f"Consultando información para {len(ips_list)} IPs únicas en {total_lotes} lotes...")

    for i in range(0, len(ips_list), 100):
        lote = ips_list[i:i+100]
        # Petición batch, solo pedimos el campo 'isp' (que suele indicar el centro de datos/proveedor) y 'query' (la IP)
        payload = [{"query": ip, "fields": "query,isp,org"} for ip in lote]
        
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            
            for info in response.json():
                ip = info.get("query")
                # A veces 'org' es más preciso para Datacenters, pero 'isp' es más consistente
                datacenter = info.get("isp", "Desconocido")
                resultados_ips[ip] = datacenter
                
        except Exception as e:
            print(f"Error consultando el lote {i//100 + 1}: {e}")
            
        # Respetar el Rate Limit de ip-api (15 peticiones batch por minuto = 1 petición cada 4 segundos)
        if i + 100 < len(ips_list):
            time.sleep(4)
            
    return resultados_ips

def analizar_datacenters(log_file):
    print("Analizando logs para extraer IPs atacantes...")
    conteo_ips = extraer_ips_de_logs(log_file)
    
    if not conteo_ips:
        return
        
    print(f"Se han encontrado {len(conteo_ips)} IPs atacantes únicas.")
    
    # Obtener información del datacenter
    info_ips = obtener_datacenters_batch(conteo_ips.keys())
    
    # Contar ataques por centro de datos
    ataques_por_datacenter = Counter()
    ips_unicas_por_datacenter = Counter()
    
    for ip, conteo in conteo_ips.items():
        datacenter = info_ips.get(ip, "Desconocido")
        # Sumar el volumen total de peticiones/ataques
        ataques_por_datacenter[datacenter] += conteo
        # Sumar 1 a la cantidad de IPs únicas de este datacenter
        ips_unicas_por_datacenter[datacenter] += 1
        
    # Mostrar Resultados
    print("\n" + "="*50)
    print("TOP 15 CENTROS DE DATOS POR VOLUMEN DE ATAQUES (Peticiones)")
    print("="*50)
    for dc, count in ataques_por_datacenter.most_common(15):
        print(f"{dc}: {count} peticiones")

    print("\n" + "="*50)
    print("TOP 15 CENTROS DE DATOS POR NÚMERO DE IPs ÚNICAS")
    print("="*50)
    for dc, count in ips_unicas_por_datacenter.most_common(15):
        print(f"{dc}: {count} IPs diferentes")

if __name__ == "__main__":
    analizar_datacenters(LOG_FILE)
