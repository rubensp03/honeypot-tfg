import sqlite3
import json
import datetime
import re
import os
import asyncio
import aiohttp
import time

from config import DB_HONEYPOT_DEEPSEEK, LOG_FILE, obtener_api_key

DB_PATH = str(DB_HONEYPOT_DEEPSEEK)

DEEPSEEK_API_KEY = obtener_api_key()

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

async def analizar_ataque_deepseek(session, payload, semaphore, retries=3):
    """
    Envía el payload HTTP a la API de DeepSeek de forma asíncrona.
    Usa un semaphore para limitar la concurrencia y un sistema de reintentos.
    """
    url = "https://api.deepseek.com/chat/completions"
    prompt = (
        "Eres un analista experto en ciberseguridad. Analiza el siguiente log/payload HTTP malicioso/sospechoso. "
        "Tu única tarea es identificar el tipo de ataque y el CVE asociado si es conocido, o determinar si es tráfico legítimo. "
        "Devuelve ÚNICAMENTE un objeto JSON válido con las claves exactas: "
        "'tipo_ataque' (ej. RCE, LFI, SQLi, Path Traversal, o Legitimo), "
        "'cve' (ej. CVE-2017-9841 o 'Desconocido' si no aplica), "
        "'gravedad' (Critica, Alta, Media, Baja, o Ninguna)."
        f"\n\nPayload a analizar:\n{payload}"
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Accept-Encoding": "gzip, deflate"
    }

    data = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": "Eres un asistente de ciberseguridad. Responde únicamente con un objeto JSON válido, sin usar bloques de código Markdown ni texto adicional."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.0
    }

    async with semaphore:
        for attempt in range(retries):
            try:
                async with session.post(url, headers=headers, json=data, timeout=30) as response:
                    # Rate limiting (429) o errores del servidor (500+)
                    if response.status == 429 or response.status >= 500:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                        
                    response.raise_for_status()
                    
                    try:
                        result = await response.json()
                    except aiohttp.client_exceptions.ContentTypeError:
                        text = await response.text()
                        result = json.loads(text)
                    
                    respuesta_ia = result["choices"][0]["message"]["content"].strip()
                    
                    # Limpiar markdown tag en caso de que lo devuelva
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
    Toma un lote de ataques (dicts con ip y payload).
    Filtra los que ya están procesados y los repetidos internamente (usando un cache local por lote).
    Envía peticiones simultáneas, y los guarda en base de datos al terminar el lote.
    """
    tareas = []
    # Usamos un diccionario para no lanzar la petición 2 veces para el mismo payload dentro del mismo lote
    payload_a_ip = {} 
    
    for ataque in lote_actual:
        ip = ataque["ip"]
        payload = ataque["payload"]
        
        # Saltamos si ya existe en la BD
        if payload in procesados_cache:
            continue
            
        # Si este lote ya tiene este payload, simplemente nos quedamos con una IP representativa
        if payload not in payload_a_ip:
            payload_a_ip[payload] = ip
            tareas.append(analizar_ataque_deepseek(session, payload, semaphore))

    if not tareas:
        return 0

    # Ejecutar peticiones concurrentes
    resultados = await asyncio.gather(*tareas)
    
    # Preparar datos a guardar
    registros_a_guardar = []
    for payload, resultado_ia in zip(payload_a_ip.keys(), resultados):
        procesados_cache.add(payload) # Agregamos al cache global para futuros lotes
        if resultado_ia:
            ip = payload_a_ip[payload]
            registros_a_guardar.append((ip, payload, resultado_ia))

    # Guardar en BD
    guardar_alertas_batch(registros_a_guardar)
    return len(registros_a_guardar)

async def main():
    print("[*] Iniciando Fase 2 - Clasificador Automático Inteligente ASÍNCRONO (DeepSeek API)")
    inicializar_db()
    
    ruta_log = str(LOG_FILE)
    print(f"[*] Escaneando ruta de logs locales: {ruta_log}")
    registro_ataques = extraer_logs(ruta_log)
    total_logs = len(registro_ataques)
    print(f"[*] Total capturas locales: {total_logs}")
    
    procesados = obtener_procesados()
    print(f"[*] Payloads únicos ya procesados anteriormente en BD: {len(procesados)}")
    
    # Parámetros de concurrencia
    LOTE_SIZE = 100         # Cada cuántos registros encolamos para hacer el gather y guardar a DB
    MAX_CONCURRENCY = 20    # Cuántas peticiones simultaneas enviamos a DeepSeek a la vez
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    
    t_inicio = time.time()
    procesados_exito = 0
    omitidos = 0
    
    async with aiohttp.ClientSession() as session:
        for i in range(0, total_logs, LOTE_SIZE):
            lote = registro_ataques[i:i+LOTE_SIZE]
            
            # Chequeo rápido para logs
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
