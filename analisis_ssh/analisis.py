import re

ARCHIVO_LOG = 'logs_cowrie_60dias.log'
ARCHIVO_COMANDOS = 'todos_los_comandos.txt'
ARCHIVO_ARCHIVOS = 'inventario_malware.txt'

logins_exitosos = 0
logins_fallidos = 0
comandos_unicos = set()
archivos_detectados = []

print(f"[*] Escaneando {ARCHIVO_LOG} en busca de intrusiones reales...")

lineas_procesadas = 0

# Expresiones regulares para el formato de texto de Cowrie
re_login = re.compile(
    r"login attempt \[b'(?P<user>[^']+)'/b'(?P<pwd>[^']+)'\] (?P<status>succeeded|failed)"
)
re_cmd = re.compile(r'CMD:\s*(?P<cmd>.+)$')
re_cmd_found = re.compile(r'Command found:\s*(?P<cmd>.+)$')
re_download = re.compile(
    r"var/lib/cowrie/downloads/(?P<file>\S+)"
)
re_upload = re.compile(
    r"Added file (?P<file>\S+) to SFTP"
)

try:
    with open(ARCHIVO_LOG, 'r', encoding='utf-8') as archivo:
        for linea in archivo:
            lineas_procesadas += 1
            if lineas_procesadas % 500000 == 0:
                print(f"... procesadas {lineas_procesadas} lineas ...")

            # 1. Contar logins exitosos y fallidos
            m = re_login.search(linea)
            if m:
                if m.group('status') == 'succeeded':
                    logins_exitosos += 1
                else:
                    logins_fallidos += 1
                continue

            # 2. Capturar comandos (CMD: formato principal de Cowrie)
            m = re_cmd.search(linea)
            if m:
                cmd = m.group('cmd').strip()
                if cmd:
                    comandos_unicos.add(cmd)
                continue

            # 3. Capturar comandos (Command found: formato secundario)
            m = re_cmd_found.search(linea)
            if m:
                cmd = m.group('cmd').strip()
                if cmd:
                    comandos_unicos.add(cmd)
                continue

            # 4. Capturar archivos descargados (wget/curl)
            if 'var/lib/cowrie/downloads/' in linea:
                m = re_download.search(linea)
                if m:
                    archivos_detectados.append({
                        'tipo': 'Descarga (wget/curl)',
                        'ruta': m.group('file'),
                        'hash': 'N/A'
                    })
                continue

            # 5. Capturar archivos subidos (SFTP/SCP)
            if 'SFTP' in linea and 'Added' in linea:
                archivos_detectados.append({
                    'tipo': 'Subida directa (SFTP/SCP)',
                    'ruta': linea.strip(),
                    'hash': 'N/A'
                })
                continue

    # --- GUARDAR Y MOSTRAR RESULTADOS ---
    print("\n" + "="*50)
    print(" RESULTADOS DE LA INTRUSION")
    print("="*50)
    print(f"[*] Logins EXITOSOS (atacantes que entraron): {logins_exitosos}")
    print(f"[*] Logins FALLIDOS:                    {logins_fallidos}")
    print(f"[*] Total intentos:                     {logins_exitosos + logins_fallidos}")
    print(f"[*] Comandos unicos ejecutados:          {len(comandos_unicos)}")
    print(f"[*] Archivos malware detectados:         {len(archivos_detectados)}\n")

    # Guardar comandos
    if comandos_unicos:
        with open(ARCHIVO_COMANDOS, 'w', encoding='utf-8') as f:
            for cmd in sorted(comandos_unicos):
                f.write(f"{cmd}\n")
        print(f"[+] Comandos guardados en: {ARCHIVO_COMANDOS}")
    else:
        print("[-] No se encontraron comandos.")

    # Guardar inventario de archivos
    if archivos_detectados:
        with open(ARCHIVO_ARCHIVOS, 'w', encoding='utf-8') as f:
            for arch in archivos_detectados:
                f.write(f"[{arch['tipo']}] Ruta: {arch['ruta']}\n")
        print(f"[+] Inventario de malware guardado en: {ARCHIVO_ARCHIVOS}")
    else:
        print("[-] No se encontraron archivos de malware.")

    if logins_exitosos == 0:
        print("\n[!] AVISO IMPORTANTE PARA TU TFG:")
        print("El numero de logins exitosos es 0. Esto significa que nadie adivino tu contrasena.")
        print("Es normal que no tengas comandos ni archivos. Para capturar malware, debes configurar")
        print("Cowrie con contrasenas muy faciles en su archivo userdb.txt (ej. root:123456).")

except FileNotFoundError:
    print(f"[!] ERROR: No se encuentra el log '{ARCHIVO_LOG}'.")
except Exception as e:
    print(f"[!] ERROR inesperado: {e}")
