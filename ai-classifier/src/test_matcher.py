import os
import re
from nuclei_signatures import NUCLEI_SIGNATURES
from urllib.parse import urlparse

from config import LOG_FILE

LOG_PATH = str(LOG_FILE)

def extraer_logs(ruta, limite=200):
    logs = []
    regex_access = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    regex_error = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')
    with open(ruta, 'r', encoding='utf-8') as f:
        for linea in f:
            if limite and len(logs) >= limite:
                break
            m = regex_access.search(linea)
            if m:
                logs.append({"ip": m.group(1), "payload": m.group(2)})
                continue
            m = regex_error.search(linea)
            if m:
                logs.append({"ip": m.group(1), "payload": m.group(2)})
    return logs

def parse_payload(payload):
    parts = payload.split(' ')
    if len(parts) < 2:
        return None, None
    method = parts[0]
    path = parts[1]
    path = re.sub(r'\s+HTTP/\d\.\d$', '', path)
    parsed = urlparse(path)
    return method, parsed.path

def match_test(method, path):
    path_norm = path.lower()
    best = None
    best_score = 0
    for sig in NUCLEI_SIGNATURES.values():
        if sig["method"] != method:
            continue
        sp = sig["path"].lower()
        # Ignorar firmas con path vacío o solo '/'
        sp_clean = sp.strip("/")
        if not sp_clean:
            continue
        score = 0
        if sp == path_norm:
            score = 100
        elif path_norm.startswith(sp) and len(sp) > 3:
            score = 90
        elif sp in path_norm and len(sp) > 5:
            score = 70
        elif path_norm.endswith(sp) and len(sp) > 3:
            score = 80
        if score > best_score:
            best_score = score
            best = sig
    
    # Filtrar matches de paths muy genéricos
    if best and best_score >= 70:
        best_path_clean = best["path"].strip("/")
        if len(best_path_clean) < 4 and best_score < 100:
            return None, 0
    
    return best, best_score

logs = extraer_logs(LOG_PATH, limite=500)
print(f"[*] Testing {len(logs)} log entries against {len(NUCLEI_SIGNATURES)} signatures...")

matches = 0
sample_matches = []
for log in logs:
    m, p = parse_payload(log["payload"])
    if not m:
        continue
    sig, score = match_test(m, p)
    if sig and score >= 70:
        matches += 1
        if len(sample_matches) < 10:
            sample_matches.append({
                "payload": log["payload"],
                "cve": sig["cve"],
                "name": sig["name"],
                "score": score
            })

print(f"[*] Matches found: {matches}/{len(logs)} ({matches/len(logs)*100:.1f}%)")
print("\n=== Sample Matches ===")
for s in sample_matches:
    print(f"Score: {s['score']} | CVE: {s['cve']} | {s['name']}")
    print(f"  Payload: {s['payload'][:120]}")
