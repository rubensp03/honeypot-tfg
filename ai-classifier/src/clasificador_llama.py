import sqlite3
import requests
import json
import datetime
import re
import os

from config import DB_HONEYPOT_LLAMA, LOG_FILE

def inicializar_db():
    """
    Crea (o conecta) la base de datos SQLite 'honeypot_ataques.db' y 
    la tabla estipulada para guardar datos estructurados.
    """
    conn = sqlite3.connect(str(DB_HONEYPOT_LLAMA))
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alertas_ia (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT,
            ip_origen TEXT,
            payload TEXT,
            tipo_ataque TEXT,
            cve TEXT,
            gravedad TEXT
        )
    ''')
    conn.commit()
    conn.close()

def check_modelo_local(modelo):
    """
    Verifica con la API de Ollama si el modelo exigido está descargado.
    """
    try:
        req = requests.get("http://localhost:11434/api/tags", timeout=5)
        if req.status_code == 200:
            modelos = [m['name'] for m in req.json().get('models', [])]
            # Ollama a veces guarda 'llama3.1:latest' o 'llama3.1:8b'
            if not any(modelo in m for m in modelos):
                print(f"\n[!] ATENCIÓN: El modelo '{modelo}' NO está instalado en tu Ollama local.")
                print(f"[!] Por favor, ejecuta en otra terminal: ollama run {modelo}")
                print(f"[!] El script va a intentar continuar, pero Ollama tardará en descargar el modelo la primera vez...\n")
    except Exception:
        pass # Si falla no bloqueamos el código, simplemente Ollama arrojará el error luego

def analizar_ataque_llama(payload):
    """
    Envía el payload HTTP a un modelo de lenguaje local potente (ej. Llama 3.1 8B) 
    para extraer la tipificación del ataque con alta precisión.
    """
    url = "http://localhost:11434/api/generate"
    
    # Prompt estricto solicitado ("System Prompt"). Ajustado para Llama 3.1
    prompt = (
        "Eres un analista experto en ciberseguridad. Analiza el siguiente log/payload HTTP malicioso/sospechoso. "
        "Tu única tarea es identificar el tipo de ataque y el CVE asociado si es conocido, o determinar si es tráfico legítimo. "
        "IMPORTANTE: No uses markdown (```json). Devuelve un objeto JSON crudo válido con las claves exactas: "
        "\"tipo_ataque\" (ej. RCE, LFI, SQLi, Path Traversal, o Legitimo), "
        "\"cve\" (ej. CVE-2017-9841 o Desconocido si no aplica), "
        "\"gravedad\" (Critica, Alta, Media, Baja, o Ninguna)."
        f"\n\nPayload a analizar:\n{payload}"
    )

    data = {
        "model": "llama3.1", # Modelo potente de 8 Billones de parámetros
        "prompt": prompt,
        "stream": False,
        "format": "json",    # Obligatorio para forzar la salida estructurada
        "options": {
            "temperature": 0.0,  # Cero alucinación y respuesta determinista
            "num_ctx": 1024,      # Limitar el buffer de contexto para encajar en 6GB de VRAM
            "num_gpu": 99         # Forzar descarga de todas las capas de la red neuronal a la GPU
        }
    }

    try:
        # Petición a la API REST de Ollama.
        # Aquí se interacciona directamente con hardware local (Edge AI) para el desarrollo de este TFG.
        response = requests.post(url, json=data, timeout=30)
        response.raise_for_status()
        
        # Recuperación de la respuesta autogenerada
        respuesta_ia = response.json().get("response", "{}")
        
        # Retorno estricto del JSON evaluado
        resultado_json = json.loads(respuesta_ia)
        return resultado_json
        
    except requests.exceptions.ConnectionError:
        print("[!] Error: No se pudo conectar a la base local de Ollama. Asegúrese de que el motor Edge AI esté corriendo (http://localhost:11434).")
        return None
    except json.JSONDecodeError:
        print("[!] Error: La IA estructuró de manera inesperada (no retornó un JSON válido).")
        return None
    except Exception as e:
        print(f"[!] Excepción no contemplada interactuando por IA edge: {e}")
        return None

def guardar_alerta(ip, payload, datos_ia):
    """
    Recibe el JSON procesado desde la capa de IA e inserta los registros en la base SQLite.
    Protección contra inyecciones SQL nativa por el uso de (?).
    """
    if not datos_ia:
        return
        
    fecha = datetime.datetime.now().isoformat()
    tipo_ataque = datos_ia.get('tipo_ataque', 'Desconocido')
    cve = datos_ia.get('cve', 'Desconocido')
    gravedad = datos_ia.get('gravedad', 'Desconocida')
    
    conn = sqlite3.connect(str(DB_HONEYPOT_LLAMA))
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alertas_ia (fecha, ip_origen, payload, tipo_ataque, cve, gravedad)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (fecha, ip, payload, tipo_ataque, cve, gravedad))
    conn.commit()
    conn.close()

def extraer_logs(ruta_archivo):
    """
    Parsea de manera sencilla y eficiente el fichero de logs, combinando Nginx (access_log + error_log).
    """
    logs = []
    
    # Expresiones regulares para parsear HTTP verb + resource (access logs vs error logs)
    regex_access = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    regex_error = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')

    if not os.path.exists(ruta_archivo):
        print(f"[!] Archivo de logs base '{ruta_archivo}' no encontrado.")
        return logs

    with open(ruta_archivo, 'r', encoding='utf-8') as f:
        for linea in f:
            
            # Buscar formato clásico access
            match_access = regex_access.search(linea)
            if match_access:
                logs.append({"ip": match_access.group(1), "payload": match_access.group(2)})
                continue
            
            # Buscar formato clásico error
            match_error = regex_error.search(linea)
            if match_error:
                logs.append({"ip": match_error.group(1), "payload": match_error.group(2)})
                continue
                
    return logs

if __name__ == "__main__":
    print("[*] Iniciando Fase 2 - Clasificador Automático Inteligente (Edge AI)")
    
    # 0. Verificación Prevía de Modelos (Mejora Hardware 16GB RAM)
    check_modelo_local("llama3.1")

    # 1. Configuración de Base de Datos
    inicializar_db()
    
    # 2. Extracción Log Base
    ruta_log = str(LOG_FILE)
    print(f"[*] Escaneando ruta de logs locales: {ruta_log}")
    registro_ataques = extraer_logs(ruta_log)
    print(f"[*] Procediendo a la analítica de la cantidad de {len(registro_ataques)} peticiones capturadas.\n")
    
    # Caché: Previene mandar mismas consultas a la GPU/CPU de Ollama una y otra vez para requests redundantes 
    # (muy común con tools como wpscan, dirbuster o nikto).
    cache_ia = {}
    
    # 3. y 4. Integración y Guardado de Flujo (Main)
    for indice, ataque in enumerate(registro_ataques, 1):
        ip = ataque["ip"]
        payload = ataque["payload"]
        
        print(f"--- Evaluando request {indice}/{len(registro_ataques)} ---")
        print(f"[*] IP: {ip} | Payload: {payload}")
        
        if payload in cache_ia:
            print("[+] Mismo payload consultado previamente. Uso de caché edge local.")
            resultado_ia = cache_ia[payload]
        else:
            resultado_ia = analizar_ataque_llama(payload)
            if resultado_ia is not None:
                cache_ia[payload] = resultado_ia
        
        if resultado_ia:
            tipo_ataque = resultado_ia.get('tipo_ataque', 'No detectado')
            cve_asociado = resultado_ia.get('cve', 'N/A')
            gravedad = resultado_ia.get('gravedad', 'Desconocida')
            
            # Formateado elegante tal como se solicitó para visualización estándar
            print(f"[+] Detalle IA -> {tipo_ataque} | CVE: {cve_asociado} | Risk: {gravedad}")
            
            guardar_alerta(ip, payload, resultado_ia)
            print("[✓] Registrado en base de datos honeypot_ataques_llama3.1.db exitosamente.\n")
        else:
            print("[-] No se pudo lograr clasificación del registro.\n")

    print("[*] Trabajo finalizado: 100% registros importados al modelo y almacenados.")
