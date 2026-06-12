import re
import time

def extraer_logs_count(ruta_archivo):
    logs = 0
    regex_access = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(.*?)"')
    regex_error = re.compile(r'client:\s+(\S+).*?request:\s+"(.*?)"')
    
    with open(ruta_archivo, 'r', encoding='utf-8') as f:
        for i, linea in enumerate(f):
            if i % 5000 == 0:
                print(f"Procesando linea {i}...")
            match_access = regex_access.search(linea)
            if match_access:
                logs += 1
                continue
            
            match_error = regex_error.search(linea)
            if match_error:
                logs += 1
                continue
                
    return logs

from config import LOG_FILE

if __name__ == "__main__":
    t0 = time.time()
    c = extraer_logs_count(str(LOG_FILE))
    print(f"Total extracciones: {c} en {time.time()-t0:.2f}s")
