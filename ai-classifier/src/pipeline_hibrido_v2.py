import sqlite3
import json
import datetime
import re
import os
import asyncio
import aiohttp
import time
from urllib.parse import urlparse

from nuclei_signatures import NUCLEI_SIGNATURES
from config import DB_HONEYPOT_HIBRIDO_V2, LOG_FILE, obtener_api_key

DB_PATH = str(DB_HONEYPOT_HIBRIDO_V2)
LOG_PATH = str(LOG_FILE)

DEEPSEEK_API_KEY = obtener_api_key()

def inicializar_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alertas_hibrido (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT, ip_origen TEXT, payload TEXT,
            tipo_ataque TEXT, cve TEXT, gravedad TEXT,
            tecnologia_objetivo TEXT, motor_deteccion TEXT, confidence TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS metricas (
            id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT,
            total_logs INTEGER, resueltos_nuclei INTEGER,
            resueltos_deepseek INTEGER, fallos_deepseek INTEGER,
            tiempo_total_s REAL, coste_estimado_input_tokens INTEGER,
            coste_estimado_output_tokens INTEGER
        )
    ''')
    conn.commit(); conn.close()

def obtener_procesados():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT payload FROM alertas_hibrido')
    res = {row[0] for row in c.fetchall()}
    conn.close(); return res

def extraer_logs(ruta):
    logs = []
    r1 = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    r2 = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')
    if not os.path.exists(ruta): return logs
    with open(ruta, 'r', encoding='utf-8') as f:
        for line in f:
            m = r1.search(line)
            if m: logs.append({"ip": m.group(1), "payload": m.group(2)}); continue
            m = r2.search(line)
            if m: logs.append({"ip": m.group(1), "payload": m.group(2)})
    return logs

def parse_payload(p):
    parts = p.split(' ')
    if len(parts) < 2: return None, None
    method = parts[0]
    path = re.sub(r'\s+HTTP/\d\.\d$', '', parts[1])
    parsed = urlparse(path)
    return method, parsed.path + ("?" + parsed.query if parsed.query else "")

def match_nuclei(payload):
    method, full_path = parse_payload(payload)
    if not method or not full_path: return None
    key = (method, full_path)
    sig = NUCLEI_SIGNATURES.get(key)
    if not sig: return None
    # Mapear severidad
    sm = {"critical": "Critica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Info"}
    gravedad = sm.get(sig["severity"].lower(), sig["severity"])
    # Inferir tipo
    tl = (sig.get("tags","") + " " + sig.get("description","")).lower()
    tipo = "Desconocido"
    if "rce" in tl: tipo = "RCE"
    elif "sqli" in tl or "sql injection" in tl: tipo = "SQLi"
    elif "lfi" in tl or "path traversal" in tl or "traversal" in tl: tipo = "Path Traversal / LFI"
    elif "xss" in tl: tipo = "XSS"
    elif "ssrf" in tl: tipo = "SSRF"
    elif "info disclosure" in tl or "exposure" in tl: tipo = "Info Disclosure"
    elif "fingerprint" in tl or "detect" in tl: tipo = "Fingerprinting"
    # Inferir tecnología
    combined = f"{sig.get('name','')} {sig.get('description','')} {sig.get('tags','')}".lower()
    techs = {
        "apache": "Apache HTTP Server", "nginx": "Nginx", "php": "PHP",
        "phpunit": "PHPUnit", "wordpress": "WordPress", "drupal": "Drupal",
        "laravel": "Laravel", "thinkphp": "ThinkPHP", "netgear": "Netgear",
        "cisco": "Cisco", "f5": "F5 BIG-IP", "gitlab": "GitLab",
        "jenkins": "Jenkins", "tomcat": "Apache Tomcat", "weblogic": "Oracle WebLogic",
        "spring": "Spring Framework", "exchange": "Microsoft Exchange",
        "sharepoint": "Microsoft SharePoint", "iis": "Microsoft IIS",
        "struts": "Apache Struts", "mongodb": "MongoDB", "redis": "Redis",
        "elastic": "Elasticsearch", "kibana": "Kibana", "grafana": "Grafana",
        "zabbix": "Zabbix", "sonicwall": "SonicWall", "fortinet": "Fortinet",
        "fortios": "Fortinet FortiOS", "fortigate": "Fortinet FortiGate",
        "palo alto": "Palo Alto Networks", "checkpoint": "Check Point",
        "juniper": "Juniper", "huawei": "Huawei", "dlink": "D-Link",
        "tplink": "TP-Link", "asus": "ASUS", "ubiquiti": "Ubiquiti",
        "mikrotik": "MikroTik", "zimbra": "Zimbra", "confluence": "Atlassian Confluence",
        "jira": "Atlassian Jira", "bamboo": "Atlassian Bamboo",
        "bitbucket": "Atlassian Bitbucket", "woocommerce": "WooCommerce",
        "magento": "Magento", "prestashop": "PrestaShop", "opencart": "OpenCart",
        "django": "Django", "flask": "Flask", "rails": "Ruby on Rails",
        "nodejs": "Node.js", "express": "Express.js", "next.js": "Next.js",
        "nuxt": "Nuxt.js", "vue": "Vue.js", "react": "React", "angular": "Angular",
        "bootstrap": "Bootstrap", "ckeditor": "CKEditor", "tinymce": "TinyMCE",
        "fckeditor": "FCKEditor", "roundcube": "Roundcube", "horde": "Horde",
        "squirrelmail": "SquirrelMail", "phpmyadmin": "phpMyAdmin",
        "adminer": "Adminer", "pgadmin": "pgAdmin", "webmin": "Webmin",
        "cpanel": "cPanel", "plesk": "Plesk", "directadmin": "DirectAdmin",
        "ispconfig": "ISPConfig", "centos": "CentOS", "ubuntu": "Ubuntu",
        "debian": "Debian", "windows": "Windows", "linux": "Linux",
        "git": "Git", "svn": "Subversion", "docker": "Docker",
        "kubernetes": "Kubernetes", "openshift": "OpenShift",
        "rancher": "Rancher", "istio": "Istio", "envoy": "Envoy",
        "traefik": "Traefik", "haproxy": "HAProxy", "varnish": "Varnish",
        "squid": "Squid", "naxsi": "Naxsi", "modsecurity": "ModSecurity",
        "snort": "Snort", "suricata": "Suricata", "zeek": "Zeek",
        "wireshark": "Wireshark", "nmap": "Nmap", "nessus": "Nessus",
        "openvas": "OpenVAS", "qualys": "Qualys", "rapid7": "Rapid7",
        "metasploit": "Metasploit", "cobalt strike": "Cobalt Strike",
        "empire": "Empire", "sliver": "Sliver", "havoc": "Havoc",
        "brute ratel": "Brute Ratel", "mythic": "Mythic"
    }
    tech = "Desconocida"
    for k, v in techs.items():
        if k in combined:
            tech = v; break
    return {
        "tipo_ataque": tipo, "cve": sig["cve"] or "Desconocido",
        "gravedad": gravedad, "tecnologia_objetivo": tech,
        "confidence": "determinista", "motor": "nuclei"
    }

async def analizar_deepseek(session, payload, semaphore, retries=3):
    url = "https://api.deepseek.com/chat/completions"
    prompt = (
        "Eres un experto en ciberseguridad. Analiza este payload HTTP de un honeypot. "
        "Responde ÚNICAMENTE con este JSON exacto: "
        '{"tipo_ataque":"RCE|LFI|SQLi|XSS|SSRF|Path Traversal|Info Disclosure|Fingerprinting|Backdoor|Auth Bypass|Legitimo|Desconocido",'
        '"cve":"CVE-XXXX-XXXXX o Desconocido","gravedad":"Critica|Alta|Media|Baja|Ninguna",'
        '"tecnologia_objetivo":"Software objetivo o Desconocida"}\n\n'
        f"Payload: {payload}"
    )
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {DEEPSEEK_API_KEY}"}
    data = {"model": "deepseek-v4-pro", "messages": [
        {"role": "system", "content": "Responde solo con JSON válido. Sin markdown. Sin explicaciones."},
        {"role": "user", "content": prompt}
    ], "temperature": 0.0}
    async with semaphore:
        for attempt in range(retries):
            try:
                async with session.post(url, headers=headers, json=data, timeout=60) as resp:
                    if resp.status == 429 or resp.status >= 500:
                        await asyncio.sleep(2 ** attempt); continue
                    resp.raise_for_status()
                    result = await resp.json()
                    content = result["choices"][0]["message"]["content"].strip()
                    if content.startswith("```json"): content = content[7:]
                    if content.startswith("```"): content = content[3:]
                    if content.endswith("```"): content = content[:-3]
                    parsed = json.loads(content.strip())
                    parsed["motor"] = "deepseek-v4-pro"
                    parsed["confidence"] = "heuristica"
                    return parsed
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == retries - 1: return None
                await asyncio.sleep(2 ** attempt)
            except (json.JSONDecodeError, Exception):
                return None
        return None

def guardar_alertas_batch(regs):
    if not regs: return
    fecha = datetime.datetime.now().isoformat()
    datos = []
    for ip, payload, d in regs:
        datos.append((fecha, ip, payload,
            d.get('tipo_ataque','Desconocido'), d.get('cve','Desconocido'),
            d.get('gravedad','Desconocida'), d.get('tecnologia_objetivo','Desconocida'),
            d.get('motor','deepseek'), d.get('confidence','heuristica')))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executemany('''INSERT INTO alertas_hibrido
        (fecha, ip_origen, payload, tipo_ataque, cve, gravedad, tecnologia_objetivo, motor_deteccion, confidence)
        VALUES (?,?,?,?,?,?,?,?,?)''', datos)
    conn.commit(); conn.close()

def guardar_metricas(total, nuclei_c, ds_c, ds_f, t_total, inp, out):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO metricas
        (fecha, total_logs, resueltos_nuclei, resueltos_deepseek, fallos_deepseek, tiempo_total_s, coste_estimado_input_tokens, coste_estimado_output_tokens)
        VALUES (?,?,?,?,?,?,?,?)''',
        (datetime.datetime.now().isoformat(), total, nuclei_c, ds_c, ds_f, t_total, inp, out))
    conn.commit(); conn.close()

async def procesar_lote(lote, session, semaphore, procesados):
    payload_a_ip = {}
    for ataque in lote:
        p = ataque["payload"]
        if p not in procesados and p not in payload_a_ip:
            payload_a_ip[p] = ataque["ip"]
    nuclei_hits = 0; ds_hits = 0; ds_fails = 0; inp_t = 0; out_t = 0
    regs = []; ds_tasks = []; ds_payloads = []
    for p, ip in payload_a_ip.items():
        procesados.add(p)
        match = match_nuclei(p)
        if match:
            nuclei_hits += 1
            regs.append((ip, p, match))
        else:
            ds_tasks.append(analizar_deepseek(session, p, semaphore))
            ds_payloads.append((ip, p))
    if ds_tasks:
        results = await asyncio.gather(*ds_tasks)
        for (ip, p), r in zip(ds_payloads, results):
            if r:
                ds_hits += 1
                out_t += len(str(r).split())
                regs.append((ip, p, r))
            else:
                ds_fails += 1
                regs.append((ip, p, {"tipo_ataque":"Desconocido","cve":"Desconocido","gravedad":"Desconocida","tecnologia_objetivo":"Desconocida","motor":"deepseek-v4-pro","confidence":"fallo_api"}))
        inp_t += sum(len(p.split()) + 50 for _, p in ds_payloads)
    guardar_alertas_batch(regs)
    return nuclei_hits, ds_hits, ds_fails, inp_t, out_t

async def main():
    print("[*] Pipeline Híbrido v2: Nuclei (Exacto) + DeepSeek v4-pro")
    inicializar_db()
    logs = extraer_logs(LOG_PATH)
    total = len(logs)
    print(f"[*] Total logs: {total}")
    procesados = obtener_procesados()
    print(f"[*] Ya procesados: {len(procesados)}")
    LOTE_SIZE = 100; MAX_CONC = 25
    semaphore = asyncio.Semaphore(MAX_CONC)
    PRESUPUESTO = 2.00
    COST_IN = 0.435 / 1_000_000; COST_OUT = 0.87 / 1_000_000
    gasto = 0.0
    t_ini = time.time()
    n_tot = ds_tot = f_tot = 0
    async with aiohttp.ClientSession() as session:
        for i in range(0, total, LOTE_SIZE):
            lote = logs[i:i+LOTE_SIZE]
            if all(a["payload"] in procesados for a in lote): continue
            if gasto >= PRESUPUESTO:
                print(f"[!] PRESUPUESTO AGOTADO: ${gasto:.4f} / ${PRESUPUESTO:.2f}"); break
            n, d, f, inp, out = await procesar_lote(lote, session, semaphore, procesados)
            n_tot += n; ds_tot += d; f_tot += f
            gasto += (inp * COST_IN) + (out * COST_OUT)
            prog = min(i + LOTE_SIZE, total)
            t_elap = time.time() - t_ini
            vel = prog / t_elap if t_elap > 0 else 0
            print(f"Prog: {prog}/{total} ({prog/total*100:.1f}%) | Vel: {vel:.1f} req/s | "
                  f"Nuclei: {n_tot} | DeepSeek: {ds_tot} | Fallos: {f_tot} | "
                  f"Gasto: ${gasto:.4f}/${PRESUPUESTO:.2f}")
    t_total = time.time() - t_ini
    guardar_metricas(total, n_tot, ds_tot, f_tot, t_total, 0, 0)
    print(f"\n{'='*60}")
    print(f"[*] Finalizado en {t_total:.1f}s")
    print(f"[*] Nuclei: {n_tot} | DeepSeek: {ds_tot} | Fallos: {f_tot}")
    print(f"[*] Gasto: ${gasto:.4f} | BD: {DB_PATH}")
    print(f"{'='*60}")

if __name__ == "__main__":
    asyncio.run(main())
