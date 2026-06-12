"""
Configuración centralizada de rutas para el proyecto ai-classifier.
Todos los scripts deben importar desde aquí para evitar rutas hardcodeadas.
"""

from pathlib import Path

# Directorio raíz del proyecto (ai-classifier/)
BASE_DIR = Path(__file__).resolve().parent.parent

# Rutas de datos
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
DB_DIR = DATA_DIR / "databases"
OUTPUTS_DIR = DATA_DIR / "outputs"

# Rutas de configuración
CONFIG_DIR = BASE_DIR / "config"

# Rutas de logs de ejecución
RUN_LOGS_DIR = BASE_DIR / "logs"

# Archivos principales
LOG_FILE = LOGS_DIR / "honeypot_march.log"
LOG_FILE_2026 = LOGS_DIR / "honeypot_2026-02-12_09-06-40.log"
API_KEY_FILE = CONFIG_DIR / "api-deepseek.txt"

# Bases de datos
DB_HONEYPOT_LLAMA = DB_DIR / "honeypot_ataques_llama3.1.db"
DB_HONEYPOT_DEEPSEEK = DB_DIR / "honeypot_ataques_deepseek.db"
DB_HONEYPOT_QWEN = DB_DIR / "honeypot_ataques_qwen.db"
DB_HONEYPOT_HIBRIDO = DB_DIR / "honeypot_hibrido_deepseek.db"
DB_HONEYPOT_HIBRIDO_V2 = DB_DIR / "honeypot_hibrido_v2.db"
DB_HONEYPOT_GENERIC = DB_DIR / "honeypot_ataques.db"

# Outputs
OUTPUT_ANALISIS_MD = OUTPUTS_DIR / "analisis_tfg_hibrido.md"
OUTPUT_RESULTADOS_CSV = OUTPUTS_DIR / "resultados_hibrido.csv"
OUTPUT_INFORME_TXT = OUTPUTS_DIR / "informe_completo.txt"
OUTPUT_RESULTADOS_MARZO = OUTPUTS_DIR / "resultados_marzo.txt"
OUTPUT_MUESTRA_V2 = OUTPUTS_DIR / "muestra_validacion_v2.txt"
OUTPUT_MUESTRA_MANUAL = OUTPUTS_DIR / "muestra_validacion_manual.txt"
OUTPUT_CVE_SAMPLE = OUTPUTS_DIR / "resultado_cves.txt"


def obtener_api_key():
    """Lee la API key de DeepSeek desde archivo de configuración o variable de entorno."""
    import os

    env_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if env_key:
        return env_key

    rutas_posibles = [
        API_KEY_FILE,
        CONFIG_DIR / "api_deepseek.txt",
    ]
    for ruta in rutas_posibles:
        if ruta.exists():
            with open(ruta, "r", encoding="utf-8") as f:
                return f.read().strip().rstrip(".")
    raise RuntimeError(
        "No se encontró la API key de DeepSeek. "
        "Configúrala mediante la variable de entorno DEEPSEEK_API_KEY "
        "o crea el archivo config/api-deepseek.txt"
    )
