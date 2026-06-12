import re

# Nombres de archivos
ARCHIVO_LOG = 'logs_cowrie_60dias.log'
ARCHIVO_SALIDA = 'urls_maliciosas_extraidas.txt'
ARCHIVO_COMANDOS_URL = 'comandos_con_urls.txt'

# Utilizamos un 'set' (conjunto) para almacenar las URLs sin que se repitan
urls_unicas = set()
comandos_descarga = set()

# Expresion regular mejorada para capturar http, https, ftp y tftp
regex_url = re.compile(r"(?:http[s]?|ftp|tftp)://[^\s\"'<>]+")

# Regex para lineas CMD: de Cowrie
re_cmd = re.compile(r'CMD:\s*(?P<cmd>.+)$')

# Keywords de herramientas de descarga
herramientas_descarga = ['wget', 'curl', 'tftp', 'ftp ', 'lwp-download']

print(f"[*] Iniciando extraccion de URLs desde: {ARCHIVO_LOG}")
print("[*] Esto puede tardar unos minutos. Por favor, espera...\n")

lineas_procesadas = 0

try:
    with open(ARCHIVO_LOG, 'r', encoding='utf-8') as archivo:
        for linea in archivo:
            lineas_procesadas += 1
            
            # Indicador de progreso
            if lineas_procesadas % 500000 == 0:
                print(f"... analizadas {lineas_procesadas} lineas ...")

            # METODO 1: El atacante teclea un comando con una URL (wget, curl, tftp)
            m = re_cmd.search(linea)
            if m:
                comando = m.group('cmd')
                if any(h in comando.lower() for h in herramientas_descarga):
                    comandos_descarga.add(comando.strip()[:200])
                    # Extraer todas las URLs que coincidan con la expresion regular
                    encontradas = regex_url.findall(comando)
                    for url in encontradas:
                        urls_unicas.add(url.strip())

            # METODO 2: Buscar URLs en cualquier linea del log
            # (Ej: descargas registradas por Cowrie internamente)
            if 'http://' in linea or 'https://' in linea or 'ftp://' in linea or 'tftp://' in linea:
                encontradas = regex_url.findall(linea)
                for url in encontradas:
                    urls_unicas.add(url.strip())

            # METODO 3: Rutas de descarga en var/lib/cowrie/downloads/
            # Cowrie guarda archivos con el nombre de la URL en el path
            if 'var/lib/cowrie/downloads/' in linea:
                m_path = re.search(r"var/lib/cowrie/downloads/(?P<path>\S+)", linea)
                if m_path:
                    urls_unicas.add(f"[DOWNLOAD_PATH] {m_path.group('path')}")

    # --- GUARDAR RESULTADOS EN EL ARCHIVO DE SALIDA ---
    print(f"\n[*] Analisis finalizado. Total de lineas procesadas: {lineas_procesadas}")
    print(f"[*] Se han encontrado {len(urls_unicas)} URLs/descargas UNICAS de malware.")
    print(f"[*] Comandos de descarga unicos: {len(comandos_descarga)}")

    if len(urls_unicas) > 0:
        with open(ARCHIVO_SALIDA, 'w', encoding='utf-8') as salida:
            for url in sorted(urls_unicas):
                salida.write(f"{url}\n")
        print(f"[+] Las URLs se han guardado exitosamente en: {ARCHIVO_SALIDA}")
    else:
        print("[-] No se encontraron URLs maliciosas en este log.")

    if len(comandos_descarga) > 0:
        with open(ARCHIVO_COMANDOS_URL, 'w', encoding='utf-8') as salida:
            for cmd in sorted(comandos_descarga):
                salida.write(f"{cmd}\n")
        print(f"[+] Comandos de descarga guardados en: {ARCHIVO_COMANDOS_URL}")

except FileNotFoundError:
    print(f"[!] ERROR: No se encuentra el log '{ARCHIVO_LOG}'.")
except Exception as e:
    print(f"[!] ERROR inesperado: {e}")
