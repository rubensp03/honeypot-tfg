import sqlite3
import json
import datetime
import re
import os
import asyncio
import aiohttp
import time

from config import DB_HONEYPOT_QWEN, LOG_FILE

DB_PATH = str(DB_HONEYPOT_QWEN)
MODEL_NAME = "qwen2.5:7b"

def inicializar_db():
    conn = sqlite3.connect(DB_PATH)
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

def obtener_procesados():
    """Retorna un set con todos los payloads que ya han sido analizados y guardados en la BD."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT payload FROM alertas_ia')
    procesados = {row[0] for row in cursor.fetchall()}
    conn.close()
    return procesados

def extraer_logs(ruta_archivo):
    logs = []
    regex_access = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    regex_error = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')

    if not os.path.exists(ruta_archivo):
        print(f"[!] Archivo de logs base '{ruta_archivo}' no encontrado.")
        return logs

    with open(ruta_archivo, 'r', encoding='utf-8') as f:
        for linea in f:
            match_access = regex_access.search(linea)
            if match_access:
                logs.append({"ip": match_access.group(1), "payload": match_access.group(2)})
                continue
            
            match_error = regex_error.search(linea)
            if match_error:
                logs.append({"ip": match_error.group(1), "payload": match_error.group(2)})
                continue
                
    return logs

async def analizar_ataque_qwen(session, payload, semaphore, retries=3):
    """
    Envía el payload HTTP a la API local de Ollama de forma asíncrona.
    """
    url = "http://localhost:11434/api/generate"
    prompt = (
        "Eres un analista experto en ciberseguridad. Analiza el siguiente log/payload HTTP malicioso/sospechoso. "
        "Tu única tarea es identificar el tipo de ataque y el CVE asociado si es conocido, o determinar si es tráfico legítimo. "
        "IMPORTANTE: Devuelve ÚNICAMENTE un objeto JSON válido con las claves exactas, sin texto adicional ni bloques preformateados:\n"
        "{\"tipo_ataque\": \"RCE o LFI o SQLi o Path Traversal o Legitimo u otro\", \"cve\": \"CVE-XXXX-XXXX o Desconocido\", \"gravedad\": \"Critica o Alta o Media o Baja o Ninguna\"}"
        f"\n\nPayload a analizar:\n{payload}"
    )

    data = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json",    # Obligatorio para forzar formato JSON en Ollama
        "options": {
            "temperature": 0.0,
            "num_ctx": 1024
        }
    }

    async with semaphore:
        for attempt in range(retries):
            try:
                # Local ollama queueing might take time depending on concurrency, higher timeout needed
                async with session.post(url, json=data, timeout=120) as response:
                    # Si falla, hacer backoff local
                    if response.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                        
                    response.raise_for_status()
                    
                    try:
                        result = await response.json()
                    except aiohttp.client_exceptions.ContentTypeError:
                        text = await response.text()
                        result = json.loads(text)
                    
                    respuesta_ia = result.get("response", "{}").strip()
                    
                    # Limpiar markdown tag en caso de que lo devuelva a pesar del format json
                    if respuesta_ia.startswith("```json"): respuesta_ia = respuesta_ia[7:]
                    if respuesta_ia.startswith("```"): respuesta_ia = respuesta_ia[3:]
                    if respuesta_ia.endswith("```"): respuesta_ia = respuesta_ia[:-3]
                        
                    return json.loads(respuesta_ia.strip())
                    
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt)
            except json.JSONDecodeError:
                return None
            except Exception as e:
                return None
        return None

def guardar_alertas_batch(nuevos_registros):
    """Guarda una lista de tuplas (ip, payload, datos_ia) en lote en la BD"""
    if not nuevos_registros:
        return
        
    fecha = datetime.datetime.now().isoformat()
    datos_insert = []
    
    for ip, payload, datos_ia in nuevos_registros:
        tipo_ataque = datos_ia.get('tipo_ataque', 'Desconocido')
        cve = datos_ia.get('cve', 'Desconocido')
        gravedad = datos_ia.get('gravedad', 'Desconocida')
        datos_insert.append((fecha, ip, payload, tipo_ataque, cve, gravedad))
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.executemany('''
        INSERT INTO alertas_ia (fecha, ip_origen, payload, tipo_ataque, cve, gravedad)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', datos_insert)
    conn.commit()
    conn.close()

async def procesar_lote(lote_actual, session, semaphore, procesados_cache):
    """
    Toma un lote de ataques. Filtra procesados/repetidos.
    Envía peticiones y guarda en BD.
    """
    tareas = []
    payload_a_ip = {} 
    
    for ataque in lote_actual:
        ip = ataque["ip"]
        payload = ataque["payload"]
        
        if payload in procesados_cache:
            continue
            
        if payload not in payload_a_ip:
            payload_a_ip[payload] = ip
            tareas.append(analizar_ataque_qwen(session, payload, semaphore))

    if not tareas:
        return 0

    # Ejecutar peticiones concurrentes a la IA Edge
    resultados = await asyncio.gather(*tareas)
    
    registros_a_guardar = []
    for payload, resultado_ia in zip(payload_a_ip.keys(), resultados):
        procesados_cache.add(payload)
        if resultado_ia:
            ip = payload_a_ip[payload]
            registros_a_guardar.append((ip, payload, resultado_ia))

    guardar_alertas_batch(registros_a_guardar)
    return len(registros_a_guardar)

async def main():
    print(f"[*] Iniciando Fase 2 - Clasificador Local ASÍNCRONO ({MODEL_NAME})")
    inicializar_db()
    
    ruta_log = str(LOG_FILE)
    print(f"[*] Escaneando ruta de logs locales: {ruta_log}")
    registro_ataques = extraer_logs(ruta_log)
    total_logs = len(registro_ataques)
    print(f"[*] Total capturas locales: {total_logs}")
    
    procesados = obtener_procesados()
    print(f"[*] Payloads únicos ya procesados anteriormente en BD: {len(procesados)}")
    
    # Parámetros de concurrencia ajustados para hardware Edge (GPU local)
    LOTE_SIZE = 50          
    MAX_CONCURRENCY = 5     # Menor concurrencia para no acaparar cola de Ollama (> timeout)
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    
    t_inicio = time.time()
    procesados_exito = 0
    omitidos = 0
    
    # Local requiere un conector sin límite fuerte (Ollama encola lo que no procesa al instante)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, total_logs, LOTE_SIZE):
            lote = registro_ataques[i:i+LOTE_SIZE]
            
            if all(ataque["payload"] in procesados for ataque in lote):
                omitidos += len(lote)
                continue
                
            guardados = await procesar_lote(lote, session, semaphore, procesados)
            procesados_exito += guardados
            
            progreso_actual = min(i+LOTE_SIZE, total_logs)
            t_transcurrido = time.time() - t_inicio
            vel = progreso_actual / t_transcurrido if t_transcurrido > 0 else 0
            
            print(f"Progreso: {progreso_actual}/{total_logs} logs ({progreso_actual/total_logs*100:.1f}%) | "
                  f"Velocidad: {vel:.1f} req/s | Añadidos: {guardados}")

    t_total = time.time() - t_inicio
    print(f"\n[*] Trabajo finalizado en {t_total:.1f}s.")
    print(f"[*] Total guardados en BD esta iteración: {procesados_exito}")

if __name__ == "__main__":
    asyncio.run(main())
