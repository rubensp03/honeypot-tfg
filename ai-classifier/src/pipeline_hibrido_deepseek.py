import sqlite3
import json
import datetime
import re
import os
import asyncio
import aiohttp
import time
from urllib.parse import urlparse, parse_qs

# Importar firmas generadas por nuclei_template_parser.py
from nuclei_signatures import NUCLEI_SIGNATURES
from config import DB_HONEYPOT_HIBRIDO, LOG_FILE, obtener_api_key

DB_PATH = str(DB_HONEYPOT_HIBRIDO)
LOG_PATH = str(LOG_FILE)

DEEPSEEK_API_KEY = obtener_api_key()


def inicializar_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alertas_hibrido (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT,
            ip_origen TEXT,
            payload TEXT,
            tipo_ataque TEXT,
            cve TEXT,
            gravedad TEXT,
            tecnologia_objetivo TEXT,
            motor_deteccion TEXT,
            confidence TEXT,
            reasoning TEXT,
            procesado INTEGER DEFAULT 0
        )
    ''')
    # Tabla de métricas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metricas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT,
            total_logs INTEGER,
            resueltos_nuclei INTEGER,
            resueltos_deepseek INTEGER,
            fallos_deepseek INTEGER,
            tiempo_total_s REAL,
            coste_estimado_input_tokens INTEGER,
            coste_estimado_output_tokens INTEGER
        )
    ''')
    conn.commit()
    conn.close()


def obtener_procesados():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT payload FROM alertas_hibrido')
    procesados = {row[0] for row in cursor.fetchall()}
    conn.close()
    return procesados


def extraer_logs(ruta_archivo):
    logs = []
    regex_access = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    regex_error = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')

    if not os.path.exists(ruta_archivo):
        print(f"[!] Archivo de logs '{ruta_archivo}' no encontrado.")
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


def parse_payload(payload):
    """Extrae método, path y query de un payload HTTP."""
    parts = payload.split(' ')
    if len(parts) < 2:
        return None, None, None
    method = parts[0]
    path = parts[1]
    # Quitar HTTP/1.x
    path = re.sub(r'\s+HTTP/\d\.\d$', '', path)
    parsed = urlparse(path)
    return method, parsed.path, parsed.query


def inferir_tipo_ataque(tags, description, name):
    """Infiere tipo de ataque a partir de tags/descripción del template."""
    tags_lower = (tags or "").lower()
    desc_lower = (description or "").lower()
    name_lower = (name or "").lower()
    
    if "rce" in tags_lower or "rce" in desc_lower or "remote code execution" in desc_lower:
        return "RCE"
    if "sqli" in tags_lower or "sql injection" in desc_lower or "sql" in tags_lower:
        return "SQLi"
    if "lfi" in tags_lower or "local file inclusion" in desc_lower or "path traversal" in desc_lower or "traversal" in tags_lower:
        return "Path Traversal / LFI"
    if "xss" in tags_lower or "cross-site scripting" in desc_lower:
        return "XSS"
    if "ssrf" in tags_lower:
        return "SSRF"
    if "csrf" in tags_lower:
        return "CSRF"
    if "xxe" in tags_lower:
        return "XXE"
    if "auth bypass" in tags_lower or "authentication bypass" in desc_lower:
        return "Auth Bypass"
    if "information disclosure" in tags_lower or "exposure" in tags_lower:
        return "Info Disclosure"
    if "backdoor" in tags_lower or "shell" in tags_lower:
        return "Backdoor"
    if "fingerprint" in tags_lower or "detect" in tags_lower or "version" in desc_lower:
        return "Fingerprinting"
    return "Desconocido"


def inferir_tecnologia(name, description, tags):
    """Extrae tecnología/software objetivo del template."""
    combined = f"{name} {description} {tags}".lower()
    
    techs = {
        "apache": "Apache HTTP Server",
        "nginx": "Nginx",
        "php": "PHP",
        "phpunit": "PHPUnit",
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "laravel": "Laravel",
        "thinkphp": "ThinkPHP",
        "netgear": "Netgear",
        "cisco": "Cisco",
        "f5": "F5 BIG-IP",
        "gitlab": "GitLab",
        "jenkins": "Jenkins",
        "tomcat": "Apache Tomcat",
        "weblogic": "Oracle WebLogic",
        "websphere": "IBM WebSphere",
        "spring": "Spring Framework",
        "exchange": "Microsoft Exchange",
        "sharepoint": "Microsoft SharePoint",
        "iis": "Microsoft IIS",
        "asp.net": "ASP.NET",
        "jquery": "jQuery",
        "struts": "Apache Struts",
        "mongodb": "MongoDB",
        "redis": "Redis",
        "elastic": "Elasticsearch",
        "kibana": "Kibana",
        "grafana": "Grafana",
        "zabbix": "Zabbix",
        "nagios": "Nagios",
        "vsphere": "VMware vSphere",
        "sonicwall": "SonicWall",
        "fortinet": "Fortinet",
        "palo alto": "Palo Alto Networks",
        "checkpoint": "Check Point",
        "juniper": "Juniper",
        "huawei": "Huawei",
        "dlink": "D-Link",
        "tplink": "TP-Link",
        "asus": "ASUS",
        "ubiquiti": "Ubiquiti",
        "mikrotik": "MikroTik",
        "zimbra": "Zimbra",
        "confluence": "Atlassian Confluence",
        "jira": "Atlassian Jira",
        "bamboo": "Atlassian Bamboo",
        "bitbucket": "Atlassian Bitbucket",
        "woocommerce": "WooCommerce",
        "magento": "Magento",
        "prestashop": "PrestaShop",
        "opencart": "OpenCart",
        "django": "Django",
        "flask": "Flask",
        "rails": "Ruby on Rails",
        "nodejs": "Node.js",
        "express": "Express.js",
        "nextjs": "Next.js",
        "nuxt": "Nuxt.js",
        "vue": "Vue.js",
        "react": "React",
        "angular": "Angular",
        "bootstrap": "Bootstrap",
        "ckeditor": "CKEditor",
        "tinymce": "TinyMCE",
        "fckeditor": "FCKEditor",
        "uebimiau": "Uebimiau",
        "roundcube": "Roundcube",
        "horde": "Horde",
        "squirrelmail": "SquirrelMail",
        "phpmyadmin": "phpMyAdmin",
        "adminer": "Adminer",
        "pgadmin": "pgAdmin",
        "webmin": "Webmin",
        "cpanel": "cPanel",
        "plesk": "Plesk",
        "directadmin": "DirectAdmin",
        "ispconfig": "ISPConfig",
        "centos": "CentOS",
        "ubuntu": "Ubuntu",
        "debian": "Debian",
        "windows": "Windows",
        "linux": "Linux",
        "unix": "Unix",
        "git": "Git",
        "svn": "Subversion",
        "mercurial": "Mercurial",
        "cvs": "CVS",
        "docker": "Docker",
        "kubernetes": "Kubernetes",
        "openshift": "OpenShift",
        "rancher": "Rancher",
        "istio": "Istio",
        "envoy": "Envoy",
        "traefik": "Traefik",
        "haproxy": "HAProxy",
        "varnish": "Varnish",
        "squid": "Squid",
        "naxsi": "Naxsi",
        "modsecurity": "ModSecurity",
        "snort": "Snort",
        "suricata": "Suricata",
        "zeek": "Zeek",
        "wireshark": "Wireshark",
        "nmap": "Nmap",
        "nessus": "Nessus",
        "openvas": "OpenVAS",
        "qualys": "Qualys",
        "rapid7": "Rapid7",
        "metasploit": "Metasploit",
        "cobalt strike": "Cobalt Strike",
        "empire": "Empire",
        " covenant": "Covenant",
        "sliver": "Sliver",
        "havoc": "Havoc",
        "brute ratel": "Brute Ratel",
        "mythic": "Mythic",
        "posh": "PoshC2",
        "shad0w": "Shad0w",
        "silentrinity": "SilentTrinity",
        "koadic": "Koadic",
    }
    
    for keyword, tech_name in techs.items():
        if keyword in combined:
            return tech_name
    return "Desconocida"


def match_nuclei(payload):
    """Intenta matchear un payload contra las firmas de Nuclei."""
    method, path, query = parse_payload(payload)
    if not method or not path:
        return None
    
    # Normalizar path (quitar URL encoding simple para matching más flexible)
    path_norm = path.lower()
    
    best_match = None
    best_score = 0
    
    for sig in NUCLEI_SIGNATURES:
        # Coincidencia exacta de método
        if sig["method"] != method:
            continue
        
        sig_path = sig["path"].lower()
        
        # IGNORAR firmas extremadamente genéricas (path exacto '/' o vacío)
        # Estos templates de Nuclei dependen de matchear la RESPUESTA, no la petición.
        sig_path_clean = sig_path.strip("/")
        if not sig_path_clean or sig_path_clean == "":
            continue
        
        # Matching: path exacto, prefijo, o contenido
        score = 0
        if sig_path == path_norm:
            score = 100
        elif path_norm.startswith(sig_path) and len(sig_path) > 3:
            score = 90
        elif sig_path in path_norm and len(sig_path) > 5:
            score = 70
        elif path_norm.endswith(sig_path) and len(sig_path) > 3:
            score = 80
        
        # Bonus si el query string también coincide en parte
        if query and any(qpart in sig_path for qpart in query.split("&")):
            score += 10
        
        if score > best_score:
            best_score = score
            best_match = sig
    
    # Requerir un 100% de coincidencia (match exacto) para evitar falsos positivos categóricos
    if best_match and best_score == 100:
        best_path_clean = best_match["path"].strip("/")
        # Si el path de la firma es muy corto (< 4 chars), requerimos match exacto (score 100)
        if len(best_path_clean) < 4 and best_score < 100:
            return None
        
        tipo = inferir_tipo_ataque(best_match["tags"], best_match["description"], best_match["name"])
        tech = inferir_tecnologia(best_match["name"], best_match["description"], best_match["tags"])
        gravedad_map = {
            "critical": "Critica",
            "high": "Alta",
            "medium": "Media",
            "low": "Baja",
            "info": "Info"
        }
        gravedad = gravedad_map.get(best_match["severity"].lower(), best_match["severity"])
        return {
            "tipo_ataque": tipo,
            "cve": best_match["cve"] or "Desconocido",
            "gravedad": gravedad,
            "tecnologia_objetivo": tech,
            "confidence": "determinista",
            "motor": "nuclei",
            "reasoning": None,
            "match_score": best_score
        }
    
    return None


async def analizar_deepseek(session, payload, semaphore, retries=3):
    """Envía payload a DeepSeek v4-pro con thinking mode."""
    url = "https://api.deepseek.com/chat/completions"
    
    prompt = (
        "Eres un analista experto en ciberseguridad y threat intelligence. "
        "Analiza el siguiente log/payload HTTP malicioso o sospechoso capturado en un honeypot.\n\n"
        "Tu tarea es producir un análisis profundo siguiendo ESTRICTAMENTE este formato JSON:\n"
        "{\n"
        "  'tipo_ataque': 'RCE | LFI | SQLi | XSS | SSRF | Path Traversal | Info Disclosure | "
        "Fingerprinting/Reconocimiento | Backdoor | Auth Bypass | Legitimo | Desconocido',\n"
        "  'cve': 'CVE-XXXX-XXXXX o Desconocido',\n"
        "  'gravedad': 'Critica | Alta | Media | Baja | Ninguna',\n"
        "  'tecnologia_objetivo': 'Nombre del software/framework/servicio que el atacante intenta explotar o fingerprintar (ej: Apache Struts, WordPress, PHPUnit, Netgear Router, Laravel, etc.). Si no se puede determinar, indica Desconocida.',\n"
        "  'explicacion': 'Breve explicación del razonamiento (1-2 frases)'\n"
        "}\n\n"
        "REGLAS:\n"
        "1. Si el payload es un simple GET a una ruta común (/, /index.html) con User-Agent normal, clasifica como 'Legitimo'.\n"
        "2. Si el payload contiene rutas de administración, archivos de configuración (.env, config.php), o rutas típicas de frameworks, clasifica como 'Fingerprinting/Reconocimiento'.\n"
        "3. Si detectas intento de ejecución de comandos, inclusion de archivos, o inyección de código, indica el CVE específico si es conocido.\n"
        "4. La tecnología objetivo debe inferirse del path, parámetros o patrones del payload.\n"
        "5. Responde ÚNICAMENTE con el objeto JSON válido, sin bloques markdown ni texto adicional.\n\n"
        f"Payload a analizar:\n{payload}"
    )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Accept-Encoding": "gzip, deflate"
    }

    data = {
        "model": "deepseek-v4-pro",
        "messages": [
            {
                "role": "system",
                "content": "Eres un asistente de ciberseguridad especializado en análisis de payloads HTTP. Responde únicamente con un objeto JSON válido, sin usar bloques de código Markdown ni texto adicional."
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
                async with session.post(url, headers=headers, json=data, timeout=60) as response:
                    if response.status == 429 or response.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    
                    response.raise_for_status()
                    result = await response.json()
                    
                    msg = result["choices"][0]["message"]
                    respuesta_ia = msg.get("content", "").strip()
                    reasoning = msg.get("reasoning_content", "")
                    
                    # Limpiar markdown
                    if respuesta_ia.startswith("```json"): respuesta_ia = respuesta_ia[7:]
                    if respuesta_ia.startswith("```"): respuesta_ia = respuesta_ia[3:]
                    if respuesta_ia.endswith("```"): respuesta_ia = respuesta_ia[:-3]
                    
                    parsed = json.loads(respuesta_ia.strip())
                    parsed["_reasoning"] = reasoning
                    return parsed
                    
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt)
            except json.JSONDecodeError:
                return None
            except Exception:
                return None
        return None


def guardar_alertas_batch(nuevos_registros):
    if not nuevos_registros:
        return
    
    fecha = datetime.datetime.now().isoformat()
    datos_insert = []
    
    for ip, payload, datos in nuevos_registros:
        tipo_ataque = datos.get('tipo_ataque', 'Desconocido')
        cve = datos.get('cve', 'Desconocido')
        gravedad = datos.get('gravedad', 'Desconocida')
        tecnologia = datos.get('tecnologia_objetivo', 'Desconocida')
        motor = datos.get('motor', 'deepseek')
        confidence = datos.get('confidence', 'heuristica')
        reasoning = datos.get('_reasoning', datos.get('reasoning', ''))
        datos_insert.append((fecha, ip, payload, tipo_ataque, cve, gravedad, tecnologia, motor, confidence, reasoning))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.executemany('''
        INSERT INTO alertas_hibrido 
        (fecha, ip_origen, payload, tipo_ataque, cve, gravedad, tecnologia_objetivo, motor_deteccion, confidence, reasoning)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', datos_insert)
    conn.commit()
    conn.close()


def guardar_metricas(total, nuclei_count, deepseek_count, deepseek_fails, tiempo_total, input_tokens, output_tokens):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    fecha = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO metricas 
        (fecha, total_logs, resueltos_nuclei, resueltos_deepseek, fallos_deepseek, tiempo_total_s, coste_estimado_input_tokens, coste_estimado_output_tokens)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (fecha, total, nuclei_count, deepseek_count, deepseek_fails, tiempo_total, input_tokens, output_tokens))
    conn.commit()
    conn.close()


async def procesar_lote(lote_actual, session, semaphore, procesados_cache):
    tareas = []
    payload_a_ip = {}
    nuclei_hits = 0
    deepseek_hits = 0
    deepseek_fails = 0
    total_input_tokens = 0
    total_output_tokens = 0
    
    for ataque in lote_actual:
        ip = ataque["ip"]
        payload = ataque["payload"]
        
        if payload in procesados_cache:
            continue
        
        if payload not in payload_a_ip:
            payload_a_ip[payload] = ip
    
    registros_a_guardar = []
    payloads_deepseek = []
    
    # Fase 1: Matcher Nuclei (offline, determinista)
    for payload, ip in payload_a_ip.items():
        procesados_cache.add(payload)
        match = match_nuclei(payload)
        if match:
            nuclei_hits += 1
            match["motor"] = "nuclei"
            match["confidence"] = "determinista"
            registros_a_guardar.append((ip, payload, match))
        else:
            payloads_deepseek.append((ip, payload))
    
    # Fase 2: DeepSeek para los no resueltos
    if payloads_deepseek:
        tareas = [analizar_deepseek(session, payload, semaphore) for _, payload in payloads_deepseek]
        resultados = await asyncio.gather(*tareas)
        
        for (ip, payload), resultado_ia in zip(payloads_deepseek, resultados):
            if resultado_ia:
                deepseek_hits += 1
                resultado_ia["motor"] = "deepseek-v4-pro"
                resultado_ia["confidence"] = "heuristica"
                # Estimar tokens (aproximado)
                total_input_tokens += len(payload.split()) + 200
                total_output_tokens += len(str(resultado_ia).split())
                registros_a_guardar.append((ip, payload, resultado_ia))
            else:
                deepseek_fails += 1
                # Guardar como fallo/desconocido
                registros_a_guardar.append((ip, payload, {
                    "tipo_ataque": "Desconocido",
                    "cve": "Desconocido",
                    "gravedad": "Desconocida",
                    "tecnologia_objetivo": "Desconocida",
                    "motor": "deepseek-v4-pro",
                    "confidence": "fallo_api",
                    "_reasoning": ""
                }))
    
    guardar_alertas_batch(registros_a_guardar)
    return nuclei_hits, deepseek_hits, deepseek_fails, total_input_tokens, total_output_tokens


async def main():
    print("[*] Iniciando Pipeline Híbrido: Nuclei (Determinista) + DeepSeek v4-pro (Thinking)")
    print("[*] Nueva Base de Datos:", DB_PATH)
    inicializar_db()
    
    if not os.path.exists(LOG_PATH):
        print(f"[!] Archivo de logs no encontrado: {LOG_PATH}")
        return
    
    registro_ataques = extraer_logs(LOG_PATH)
    total_logs = len(registro_ataques)
    print(f"[*] Total logs parseados: {total_logs}")
    
    procesados = obtener_procesados()
    print(f"[*] Payloads ya procesados en BD: {len(procesados)}")
    
    LOTE_SIZE = 100
    MAX_CONCURRENCY = 25
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    
    # Presupuesto API: ~$1.37 restantes. Precios v4-pro: $0.435/1M input, $0.87/1M output
    PRESUPUESTO_USD = 1.30
    COST_INPUT_POR_TOKEN = 0.435 / 1_000_000
    COST_OUTPUT_POR_TOKEN = 0.87 / 1_000_000
    gasto_acumulado = 0.0
    
    t_inicio = time.time()
    total_nuclei = 0
    total_deepseek = 0
    total_fallos = 0
    total_input = 0
    total_output = 0
    
    async with aiohttp.ClientSession() as session:
        for i in range(0, total_logs, LOTE_SIZE):
            lote = registro_ataques[i:i+LOTE_SIZE]
            
            if all(ataque["payload"] in procesados for ataque in lote):
                continue
            
            # Verificar presupuesto antes de cada lote
            if gasto_acumulado >= PRESUPUESTO_USD:
                print(f"\n[!] PRESUPUESTO AGOTADO: ${gasto_acumulado:.4f} / ${PRESUPUESTO_USD:.2f}")
                print("[!] Deteniendo pipeline para evitar sobregasto.")
                break
            
            n_hits, d_hits, d_fails, inp, out = await procesar_lote(lote, session, semaphore, procesados)
            total_nuclei += n_hits
            total_deepseek += d_hits
            total_fallos += d_fails
            total_input += inp
            total_output += out
            
            # Calcular gasto en tiempo real
            gasto_lote = (inp * COST_INPUT_POR_TOKEN) + (out * COST_OUTPUT_POR_TOKEN)
            gasto_acumulado += gasto_lote
            
            progreso = min(i + LOTE_SIZE, total_logs)
            t_transcurrido = time.time() - t_inicio
            vel = progreso / t_transcurrido if t_transcurrido > 0 else 0
            
            print(f"Progreso: {progreso}/{total_logs} ({progreso/total_logs*100:.1f}%) | "
                  f"Vel: {vel:.1f} req/s | Nuclei: {total_nuclei} | DeepSeek: {total_deepseek} | "
                  f"Gasto: ${gasto_acumulado:.4f}/${PRESUPUESTO_USD:.2f}")
    
    t_total = time.time() - t_inicio
    
    guardar_metricas(
        total_logs, total_nuclei, total_deepseek, total_fallos, 
        t_total, total_input, total_output
    )
    
    print(f"\n{'='*60}")
    print(f"[*] Pipeline finalizado en {t_total:.1f}s")
    print(f"[*] Resueltos por Nuclei (determinista, 0€): {total_nuclei}")
    print(f"[*] Resueltos por DeepSeek v4-pro: {total_deepseek}")
    print(f"[*] Fallos de DeepSeek: {total_fallos}")
    print(f"[*] Total procesado: {total_nuclei + total_deepseek + total_fallos}")
    print(f"[*] Tokens estimados (input/output): {total_input}/{total_output}")
    print(f"[*] Gasto API estimado: ${gasto_acumulado:.4f}")
    print(f"[*] Base de datos: {DB_PATH}")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
