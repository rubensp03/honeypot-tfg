import sqlite3
import random

from config import DB_HONEYPOT_DEEPSEEK, OUTPUT_CVE_SAMPLE

DB_PATH = str(DB_HONEYPOT_DEEPSEEK)
OUTPUT_FILE = str(OUTPUT_CVE_SAMPLE)

# Sample plan per CVE
PLAN = {
    'CVE-2017-9841': 5,
    'CVE-2020-28076': 3,
    'CVE-2018-20062': 3,
    'CVE-2021-41773': 3,
    'CVE-2019-11043': 3,
    'CVE-2016-6277': 2,
    'CVE-2022-22947': 2,
    'CVE-2017-12149': 2,
    'CVE-2021-3129': 2,
    'CVE-2021-22986': 2,
    'CVE-2020-3452': 2,
    'CVE-2019-5418': 2,
}

QUERY_SQL = """
SELECT payload, cve, tipo_ataque, gravedad
FROM alertas_ia
WHERE cve = ?
ORDER BY RANDOM()
LIMIT ?
"""

def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    rows = []

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("MUESTRA ALEATORIA DE CVEs ESCANEADAS CON DeepSeek\n")
        f.write("=" * 80 + "\n")
        f.write(f"Registros totales solicitados: {sum(PLAN.values())}\n\n")

        i = 1
        for cve, limit in PLAN.items():
            cursor.execute(QUERY_SQL, (cve, limit))
            results = cursor.fetchall()

            if not results:
                print(f"[!] Sin resultados para {cve}")
                continue

            f.write(f"\n{'─' * 80}\n")
            f.write(f"  CVE: {cve}  |  Muestras: {len(results)}/{limit}\n")
            f.write(f"{'─' * 80}\n")

            for payload, cve_val, tipo, gravedad in results:
                f.write(f"\n  [{i}] ─────────────────────────────────────────────\n")
                f.write(f"  CVE:       {cve_val}\n")
                f.write(f"  Tipo:      {tipo}\n")
                f.write(f"  Gravedad:  {gravedad}\n")
                f.write(f"  Payload:   {payload}\n")
                f.write(f"  ────────────────────────────────────────────────\n")
                rows.append((i, cve_val, tipo, gravedad, payload))
                i += 1

        f.write(f"\n\n{'=' * 80}\n")
        f.write(f"TOTAL de registros extraidos: {len(rows)}\n")

    conn.close()

    print(f"[*] Archivo generado: {OUTPUT_FILE}")
    print(f"[*] Total registros extraidos: {len(rows)}")
    print(f"[*] CVEs unicas: {len(set(r[1] for r in rows))}")

    # Print summary
    print("\nResumen por CVE:")
    cve_counts = {}
    for r in rows:
        cve_counts[r[1]] = cve_counts.get(r[1], 0) + 1
    for cve, count in sorted(cve_counts.items(), key=lambda x: -x[1]):
        print(f"  {cve}: {count}")

if __name__ == '__main__':
    main()
