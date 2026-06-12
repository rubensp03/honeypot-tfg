import os

from pipeline_hibrido_deepseek import (
    inicializar_db, extraer_logs, match_nuclei, parse_payload
)
from config import DB_HONEYPOT_HIBRIDO, LOG_FILE

DB_PATH = str(DB_HONEYPOT_HIBRIDO)
LOG_PATH = str(LOG_FILE)

# Test 1: Verificar BD
def test_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    inicializar_db()
    assert os.path.exists(DB_PATH)
    print("[OK] Base de datos creada correctamente")

# Test 2: Verificar parsing de logs
def test_logs():
    logs = extraer_logs(LOG_PATH)
    assert len(logs) > 0
    print(f"[OK] Logs parseados: {len(logs)} entradas")
    # Mostrar 3 ejemplos
    for i, log in enumerate(logs[:3]):
        print(f"  [{i}] IP: {log['ip']} | Payload: {log['payload'][:80]}")

# Test 3: Verificar matcher Nuclei con payloads conocidos
def test_matcher():
    test_cases = [
        "GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1",
        "GET /cgi-bin/luci/;stok=/locale HTTP/1.1",
        "GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello HTTP/1.1",
        "POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh HTTP/1.1",
        "GET / HTTP/1.1",  # Debe NO matchear (genérico)
        "GET /wp-admin/admin-ajax.php?action=revslider_show_image HTTP/1.1",
    ]
    
    print("[OK] Test Matcher Nuclei:")
    for payload in test_cases:
        method, path, query = parse_payload(payload)
        result = match_nuclei(payload)
        if result:
            print(f"  [MATCH] {payload[:60]}...")
            print(f"    -> CVE: {result['cve']} | Tipo: {result['tipo_ataque']} | Tech: {result['tecnologia_objetivo']}")
        else:
            print(f"  [NO MATCH] {payload[:60]}...")

# Test 4: Verificar API Key
def test_api_key():
    key = obtener_api_key()
    assert key and len(key) > 10
    print(f"[OK] API Key cargada (longitud: {len(key)})")

if __name__ == "__main__":
    print("="*60)
    print("TEST UNITARIOS - Pipeline Híbrido DeepSeek")
    print("="*60)
    test_db()
    test_logs()
    test_matcher()
    test_api_key()
    print("="*60)
    print("[✓] Todos los tests unitarios pasaron")
    print("="*60)
