"""
Utilidades comunes para la generación de gráficas del TFG.
Paleta colorblind-safe, estilo académico, exportación bilingüe.
"""
import os
import matplotlib.pyplot as plt
import matplotlib as mpl

# --- Paleta colorblind-safe (sin rojo ni verde puros) ---
COLORS = [
    '#0072B2',  # azul
    '#E69F00',  # naranja
    '#CC79A7',  # rosa
    '#F0E442',  # amarillo
    '#D55E00',  # vermillo-anaranjado
    '#56B4E9',  # celeste
    '#999999',  # gris
    '#884EA0',  # púrpura
    '#117A65',  # verde oscuro (daltónico-friendly, no puro)
    '#D68910',  # mostaza
]

# --- Configuración estilo académico ---
def setup_style():
    plt.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['Times New Roman', 'DejaVu Serif', 'Computer Modern'],
        'axes.labelsize': 11,
        'axes.titlesize': 12,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'figure.dpi': 300,
        'savefig.dpi': 300,
        'savefig.bbox': 'tight',
        'savefig.pad_inches': 0.02,
        'axes.grid': True,
        'grid.alpha': 0.3,
        'grid.linestyle': '--',
        'grid.linewidth': 0.5,
        'axes.edgecolor': '#333333',
        'axes.labelcolor': '#333333',
        'xtick.color': '#333333',
        'ytick.color': '#333333',
        'text.color': '#333333',
    })

# --- Rutas ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', '..'))
OUT_ES = os.path.join(BASE_DIR, '..', 'es')
OUT_EN = os.path.join(BASE_DIR, '..', 'en')

# --- Rutas de datos de ai-classifier (reorganizado) ---
AI_CLASSIFIER_DIR = os.path.join(ROOT_DIR, 'ai-classifier')
AI_CLASSIFIER_DATA_DIR = os.path.join(AI_CLASSIFIER_DIR, 'data')
AI_CLASSIFIER_DB_DIR = os.path.join(AI_CLASSIFIER_DATA_DIR, 'databases')
AI_CLASSIFIER_LOG_DIR = os.path.join(AI_CLASSIFIER_DATA_DIR, 'logs')
AI_CLASSIFIER_OUTPUT_DIR = os.path.join(AI_CLASSIFIER_DATA_DIR, 'outputs')

# --- Rutas de bases de datos ---
DB_HIBRIDO = os.path.join(AI_CLASSIFIER_DB_DIR, 'honeypot_hibrido_deepseek.db')
DB_HIBRIDO_V2 = os.path.join(AI_CLASSIFIER_DB_DIR, 'honeypot_hibrido_v2.db')
DB_DEEPSEEK = os.path.join(AI_CLASSIFIER_DB_DIR, 'honeypot_ataques_deepseek.db')
DB_QWEN = os.path.join(AI_CLASSIFIER_DB_DIR, 'honeypot_ataques_qwen.db')
DB_LLAMA = os.path.join(AI_CLASSIFIER_DB_DIR, 'honeypot_ataques_llama3.1.db')
DB_BLACKLIST = os.path.join(ROOT_DIR, 'blacklisting', 'blacklist.db')

# --- Rutas de logs ---
LOG_WEB = os.path.join(AI_CLASSIFIER_LOG_DIR, 'honeypot_march.log')
LOG_SSH = os.path.join(ROOT_DIR, 'analisis_ssh', 'logs_cowrie_60dias.log')
LOG_TCPDUMP = os.path.join(ROOT_DIR, 'data.txt')

def ensure_dirs():
    os.makedirs(OUT_ES, exist_ok=True)
    os.makedirs(OUT_EN, exist_ok=True)

def save_fig(fig, base_name, lang):
    """Guarda figura en es/ o en/ como PDF y PNG."""
    out_dir = OUT_ES if lang == 'es' else OUT_EN
    pdf_path = os.path.join(out_dir, f"{base_name}_{lang}.pdf")
    png_path = os.path.join(out_dir, f"{base_name}_{lang}.png")
    fig.savefig(pdf_path, format='pdf')
    fig.savefig(png_path, format='png')

# --- Traducciones para reutilizar ---
TRANSLATIONS = {
    'fig_5_1': {
        'title': {
            'es': 'Volumen de Paquetes TCP Entrantes',
            'en': 'Incoming TCP Packet Volume'
        },
        'xlabel': {
            'es': 'Hora de Captura',
            'en': 'Capture Time'
        },
        'ylabel': {
            'es': 'Paquetes por minuto',
            'en': 'Packets per minute'
        },
        'ylabel2': {
            'es': 'Paquetes por intervalo de 10 s',
            'en': 'Packets per 10 s interval'
        }
    },
    'fig_5_2': {
        'title': {
            'es': 'Top 15 Puertos TCP más Escaneados',
            'en': 'Top 15 Most Scanned TCP Ports'
        },
        'xlabel': {
            'es': 'Frecuencia de sondas',
            'en': 'Probe frequency'
        },
        'ylabel': {
            'es': 'Puerto de destino',
            'en': 'Destination port'
        }
    },
    'fig_5_3': {
        'title': {
            'es': 'Tipología de Ataques en Honeypot Web',
            'en': 'Web Honeypot Attack Typology'
        },
        'xlabel': {
            'es': 'Número de peticiones',
            'en': 'Number of requests'
        },
        'ylabel': {
            'es': 'Tipo de ataque',
            'en': 'Attack type'
        }
    },
    'fig_5_4': {
        'title': {
            'es': 'Top 10 Vulnerabilidades (CVE) Explotadas',
            'en': 'Top 10 Exploited Vulnerabilities (CVE)'
        },
        'xlabel': {
            'es': 'Intentos detectados',
            'en': 'Detected attempts'
        },
        'ylabel': {
            'es': 'Identificador CVE',
            'en': 'CVE identifier'
        }
    },
    'fig_5_5': {
        'title': {
            'es': 'Comparativa de Rendimiento entre Modelos LLM',
            'en': 'LLM Model Performance Comparison'
        },
        'subtitle_a': {
            'es': '(a) Volumen procesado y tasa de fallo en extracción de CVEs',
            'en': '(a) Processed volume and CVE extraction failure rate'
        },
        'subtitle_b': {
            'es': '(b) Distribución de tipos de ataque principales por modelo',
            'en': '(b) Distribution of main attack types per model'
        },
        'xlabel_vol': {
            'es': 'Volumen procesado',
            'en': 'Processed volume'
        },
        'ylabel_fail': {
            'es': 'Tasa de fallo CVE (%)',
            'en': 'CVE failure rate (%)'
        },
        'legend_vol': {
            'es': 'Volumen',
            'en': 'Volume'
        },
        'legend_fail': {
            'es': 'Tasa fallo CVE',
            'en': 'CVE failure rate'
        }
    },
    'fig_5_6': {
        'title': {
            'es': 'Top 15 Datacenters / ISPs por IPs Únicas Atacantes',
            'en': 'Top 15 Datacenters / ISPs by Unique Attacker IPs'
        },
        'xlabel': {
            'es': 'Número de IPs únicas',
            'en': 'Unique IPs'
        },
        'ylabel': {
            'es': 'Proveedor / ISP',
            'en': 'Provider / ISP'
        }
    },
    'fig_5_7': {
        'title': {
            'es': 'Categorización de Proveedores de Origen del Tráfico Malicioso',
            'en': 'Categorization of Malicious Traffic Origin Providers'
        },
        'labels': {
            'es': ['Hyperscalers / CDNs', 'Escáneres OSINT', 'Offshore / Bulletproof', 'Otros / Desconocidos'],
            'en': ['Hyperscalers / CDNs', 'OSINT Scanners', 'Offshore / Bulletproof', 'Others / Unknown']
        }
    },
    'fig_5_8': {
        'title': {
            'es': 'Distribución de Severidad de Ataques Web (DeepSeek)',
            'en': 'Web Attack Severity Distribution (DeepSeek)'
        },
        'xlabel': {
            'es': 'Nivel de severidad',
            'en': 'Severity level'
        },
        'ylabel': {
            'es': 'Número de peticiones',
            'en': 'Number of requests'
        }
    },
    'fig_5_9': {
        'title': {
            'es': 'Evolución Temporal de Ataques Web por Día',
            'en': 'Temporal Evolution of Web Attacks by Day'
        },
        'xlabel': {
            'es': 'Fecha',
            'en': 'Date'
        },
        'ylabel': {
            'es': 'Número de peticiones',
            'en': 'Number of requests'
        }
    },
    'fig_5_10': {
        'title': {
            'es': 'Mapa de Calor de Actividad Maliciosa (Día vs Hora)',
            'en': 'Heatmap of Malicious Activity (Day vs Hour)'
        },
        'xlabel': {
            'es': 'Hora del día',
            'en': 'Hour of day'
        },
        'ylabel': {
            'es': 'Día de la semana',
            'en': 'Day of week'
        }
    },
    'fig_4_1': {
        'title': {
            'es': 'Análisis de Intentos de Login SSH',
            'en': 'SSH Login Attempts Analysis'
        },
        'subtitle_a': {
            'es': '(a) Serie temporal de intentos de login',
            'en': '(a) Time series of login attempts'
        },
        'subtitle_b': {
            'es': '(b) Top 10 combinaciones usuario/contraseña',
            'en': '(b) Top 10 username/password combinations'
        },
        'xlabel': {
            'es': 'Fecha',
            'en': 'Date'
        },
        'ylabel': {
            'es': 'Intentos de login',
            'en': 'Login attempts'
        }
    },
    'fig_4_2': {
        'title': {
            'es': 'Top Credenciales en Ataques de Fuerza Bruta SSH',
            'en': 'Top Credentials in SSH Brute-Force Attacks'
        },
        'subtitle_a': {
            'es': '(a) Top 10 nombres de usuario',
            'en': '(a) Top 10 usernames'
        },
        'subtitle_b': {
            'es': '(b) Top 10 contraseñas',
            'en': '(b) Top 10 passwords'
        },
        'xlabel': {
            'es': 'Frecuencia',
            'en': 'Frequency'
        },
        'ylabel': {
            'es': 'Credencial',
            'en': 'Credential'
        }
    },
    'fig_5_11': {
        'title': {
            'es': 'Top 15 Países de Origen del Tráfico Malicioso',
            'en': 'Top 15 Countries of Origin for Malicious Traffic'
        },
        'xlabel': {
            'es': 'Número de IPs únicas',
            'en': 'Unique IPs'
        },
        'ylabel': {
            'es': 'País',
            'en': 'Country'
        }
    },
    'fig_5_12': {
        'title': {
            'es': 'Evolución Acumulada de IPs Únicas Atacantes',
            'en': 'Cumulative Evolution of Unique Attacker IPs'
        },
        'xlabel': {
            'es': 'Tiempo',
            'en': 'Time'
        },
        'ylabel': {
            'es': 'IPs únicas acumuladas',
            'en': 'Cumulative unique IPs'
        }
    },
    'fig_5_13': {
        'title': {
            'es': 'Diagrama de Pareto: Distribución de Puertos Escaneados',
            'en': 'Pareto Chart: Distribution of Scanned Ports'
        },
        'xlabel': {
            'es': 'Puerto TCP',
            'en': 'TCP Port'
        },
        'ylabel_left': {
            'es': 'Frecuencia',
            'en': 'Frequency'
        },
        'ylabel_right': {
            'es': 'Porcentaje acumulado',
            'en': 'Cumulative percentage'
        }
    },
    'fig_5_14': {
        'title': {
            'es': 'Distribución de Tiempos Inter-llegada de Paquetes',
            'en': 'Inter-Arrival Time Distribution of Packets'
        },
        'xlabel': {
            'es': 'Tiempo entre paquetes (s)',
            'en': 'Inter-arrival time (s)'
        },
        'ylabel': {
            'es': 'Densidad',
            'en': 'Density'
        }
    },
    'fig_4_3': {
        'title': {
            'es': 'Histograma Horario de Intentos de Login SSH',
            'en': 'Hourly Histogram of SSH Login Attempts'
        },
        'xlabel': {
            'es': 'Hora del día (UTC)',
            'en': 'Hour of day (UTC)'
        },
        'ylabel': {
            'es': 'Intentos de login',
            'en': 'Login attempts'
        }
    },
    'fig_4_4': {
        'title': {
            'es': 'Top 15 IPs Origen más Persistentes en Ataques SSH',
            'en': 'Top 15 Most Persistent Source IPs in SSH Attacks'
        },
        'xlabel': {
            'es': 'Total de intentos de login',
            'en': 'Total login attempts'
        },
        'ylabel': {
            'es': 'IP origen',
            'en': 'Source IP'
        }
    },
    'fig_4_5': {
        'title': {
            'es': 'Duración de Sesiones SSH',
            'en': 'SSH Session Duration'
        },
        'xlabel': {
            'es': 'Duración (s)',
            'en': 'Duration (s)'
        },
        'ylabel': {
            'es': 'Frecuencia',
            'en': 'Frequency'
        }
    },
    'fig_4_6': {
        'title': {
            'es': 'Matriz de Calor: Usuario vs Contraseña (Top 10x10)',
            'en': 'Heatmap: Username vs Password (Top 10x10)'
        },
        'xlabel': {
            'es': 'Contraseña',
            'en': 'Password'
        },
        'ylabel': {
            'es': 'Usuario',
            'en': 'Username'
        }
    },
    'fig_5_15': {
        'title': {
            'es': 'Top 10 User-Agents en Peticiones al Honeypot Web',
            'en': 'Top 10 User-Agents in Web Honeypot Requests'
        },
        'xlabel': {
            'es': 'Frecuencia',
            'en': 'Frequency'
        },
        'ylabel': {
            'es': 'User-Agent',
            'en': 'User-Agent'
        }
    },
    'fig_5_16': {
        'title': {
            'es': 'Top 10 Rutas (Paths) más Solicitadas en el Honeypot Web',
            'en': 'Top 10 Most Requested Paths in the Web Honeypot'
        },
        'xlabel': {
            'es': 'Frecuencia',
            'en': 'Frequency'
        },
        'ylabel': {
            'es': 'Ruta',
            'en': 'Path'
        }
    },
    'fig_5_17': {
        'title': {
            'es': 'Distribución de Códigos de Respuesta HTTP',
            'en': 'HTTP Response Code Distribution'
        },
        'xlabel': {
            'es': 'Código HTTP',
            'en': 'HTTP Code'
        },
        'ylabel': {
            'es': 'Número de respuestas',
            'en': 'Number of responses'
        }
    },
    'fig_5_18': {
        'title': {
            'es': 'Matriz de Correlación: Tipo de Ataque vs Severidad (DeepSeek)',
            'en': 'Correlation Matrix: Attack Type vs Severity (DeepSeek)'
        }
    },
    'fig_5_19': {
        'title': {
            'es': 'Top 10 IPs Atacantes Web y Tipos de Ataque Asociados',
            'en': 'Top 10 Web Attacker IPs and Associated Attack Types'
        },
        'xlabel': {
            'es': 'Número de peticiones',
            'en': 'Number of requests'
        },
        'ylabel': {
            'es': 'IP origen',
            'en': 'Source IP'
        }
    },
    'fig_5_20': {
        'title': {
            'es': 'Mapa de Origen Geográfico del Tráfico Malicioso',
            'en': 'Geographic Origin Map of Malicious Traffic'
        },
        'subtitle_map': {
            'es': '(a) Distribución mundial de IPs atacantes únicas (escala logarítmica)',
            'en': '(a) Global distribution of unique attacker IPs (logarithmic scale)'
        },
        'subtitle_bars': {
            'es': '(b) Top 15 países por número de IPs únicas',
            'en': '(b) Top 15 countries by unique IPs'
        },
        'cbar_label': {
            'es': 'IPs únicas (log10)',
            'en': 'Unique IPs (log10)'
        },
        'xlabel_bars': {
            'es': 'IPs únicas',
            'en': 'Unique IPs'
        },
        'ylabel_bars': {
            'es': 'País',
            'en': 'Country'
        }
    },
    'fig_hibrido_1': {
        'title': {
            'es': 'Volumen General del Pipeline Híbrido de Detección',
            'en': 'Overall Volume of the Hybrid Detection Pipeline'
        },
        'subtitle': {
            'es': 'Distribución de logs procesados entre motores de detección',
            'en': 'Distribution of processed logs across detection engines'
        },
        'xlabel': {
            'es': 'Motor de detección',
            'en': 'Detection engine'
        },
        'ylabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        },
        'labels': {
            'es': ['Nuclei (Determinista)', 'DeepSeek v4-pro (Heurística)', 'Sin clasificar'],
            'en': ['Nuclei (Deterministic)', 'DeepSeek v4-pro (Heuristic)', 'Unclassified']
        }
    },
    'fig_hibrido_2': {
        'title': {
            'es': 'Proporción del Pipeline Híbrido de Detección',
            'en': 'Proportion of the Hybrid Detection Pipeline'
        },
        'labels': {
            'es': ['Nuclei (Determinista)', 'DeepSeek v4-pro (Heurística)', 'Sin clasificar'],
            'en': ['Nuclei (Deterministic)', 'DeepSeek v4-pro (Heuristic)', 'Unclassified']
        }
    },
    'fig_hibrido_3': {
        'title': {
            'es': 'Top 15 CVEs Detectados: Comparativa Nuclei vs DeepSeek',
            'en': 'Top 15 Detected CVEs: Nuclei vs DeepSeek Comparison'
        },
        'subtitle': {
            'es': 'Cantidad de detecciones por motor y CVE',
            'en': 'Detection count by engine and CVE'
        },
        'xlabel': {
            'es': 'Detecciones',
            'en': 'Detections'
        },
        'ylabel': {
            'es': 'Identificador CVE',
            'en': 'CVE identifier'
        }
    },
    'fig_hibrido_4': {
        'title': {
            'es': 'Tipos de Ataque por Motor de Detección',
            'en': 'Attack Types by Detection Engine'
        },
        'subtitle': {
            'es': 'Distribución de categorías de ataque según motor resolutor',
            'en': 'Distribution of attack categories by resolving engine'
        },
        'xlabel': {
            'es': 'Tipo de ataque',
            'en': 'Attack type'
        },
        'ylabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        }
    },
    'fig_hibrido_5': {
        'title': {
            'es': 'Distribución de Severidad por Motor de Detección',
            'en': 'Severity Distribution by Detection Engine'
        },
        'subtitle': {
            'es': 'Comparativa de niveles de gravedad entre Nuclei y DeepSeek',
            'en': 'Comparison of severity levels between Nuclei and DeepSeek'
        },
        'xlabel': {
            'es': 'Nivel de severidad',
            'en': 'Severity level'
        },
        'ylabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        }
    },
    'fig_hibrido_6': {
        'title': {
            'es': 'Top 10 Tecnologías Objetivo más Atacadas',
            'en': 'Top 10 Most Targeted Technologies'
        },
        'xlabel': {
            'es': 'Número de ataques',
            'en': 'Number of attacks'
        },
        'ylabel': {
            'es': 'Tecnología',
            'en': 'Technology'
        }
    },
    'fig_hibrido_7': {
        'title': {
            'es': 'Eficiencia Económica del Pipeline Híbrido',
            'en': 'Economic Efficiency of the Hybrid Pipeline'
        },
        'subtitle': {
            'es': 'Coste estimado de procesamiento vs estrategia pura de DeepSeek',
            'en': 'Estimated processing cost vs pure DeepSeek strategy'
        },
        'xlabel': {
            'es': 'Estrategia',
            'en': 'Strategy'
        },
        'ylabel': {
            'es': 'Coste estimado (USD)',
            'en': 'Estimated cost (USD)'
        },
        'labels': {
            'es': ['Todo a DeepSeek', 'Pipeline Híbrido (Real)'],
            'en': ['All DeepSeek', 'Hybrid Pipeline (Actual)']
        }
    },
    'fig_hibrido_8': {
        'title': {
            'es': 'Volumen del Pipeline Híbrido (Matching Exacto)',
            'en': 'Hybrid Pipeline Volume (Exact Matching)'
        },
        'subtitle': {
            'es': 'Distribución de logs procesados con matching exacto de Nuclei',
            'en': 'Distribution of logs processed with exact Nuclei matching'
        },
        'xlabel': {
            'es': 'Motor de detección',
            'en': 'Detection engine'
        },
        'ylabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        },
        'labels': {
            'es': ['Nuclei (Exacto)', 'DeepSeek v4-pro (Heurística)', 'Sin clasificar'],
            'en': ['Nuclei (Exact)', 'DeepSeek v4-pro (Heuristic)', 'Unclassified']
        }
    },
    'fig_hibrido_9': {
        'title': {
            'es': 'Precisión del Matching de Nuclei: Fuzzy vs Exacto',
            'en': 'Nuclei Matching Precision: Fuzzy vs Exact'
        },
        'subtitle': {
            'es': 'Comparación de detecciones entre estrategia de matching fuzzy (v1) y exacto (v2)',
            'en': 'Comparison of detections between fuzzy (v1) and exact (v2) matching strategies'
        },
        'xlabel': {
            'es': 'Estrategia de matching',
            'en': 'Matching strategy'
        },
        'ylabel': {
            'es': 'Detecciones Nuclei',
            'en': 'Nuclei detections'
        },
        'labels': {
            'es': ['Fuzzy (v1)', 'Exacto (v2)'],
            'en': ['Fuzzy (v1)', 'Exact (v2)']
        }
    },
    'fig_hibrido_10': {
        'title': {
            'es': 'Top 10 CVEs con Matching Exacto (Pipeline v2)',
            'en': 'Top 10 CVEs with Exact Matching (Pipeline v2)'
        },
        'subtitle': {
            'es': 'Vulnerabilidades confirmadas mediante matching exacto de firmas Nuclei',
            'en': 'Vulnerabilities confirmed via exact Nuclei signature matching'
        },
        'xlabel': {
            'es': 'Detecciones',
            'en': 'Detections'
        },
        'ylabel': {
            'es': 'Identificador CVE',
            'en': 'CVE identifier'
        }
    },
    'fig_hibrido_11': {
        'title': {
            'es': 'Tipos de Ataque en Pipeline v2 (Matching Exacto)',
            'en': 'Attack Types in Pipeline v2 (Exact Matching)'
        },
        'subtitle': {
            'es': 'Distribución de categorías de ataque con matching exacto',
            'en': 'Attack category distribution with exact matching'
        },
        'xlabel': {
            'es': 'Tipo de ataque',
            'en': 'Attack type'
        },
        'ylabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        }
    },
    'fig_hibrido_12': {
        'title': {
            'es': 'Eficiencia Económica del Pipeline v2 (Exacto)',
            'en': 'Economic Efficiency of Pipeline v2 (Exact)'
        },
        'subtitle': {
            'es': 'Coste real vs coste hipotético con matching exacto de Nuclei',
            'en': 'Actual cost vs hypothetical cost with exact Nuclei matching'
        },
        'xlabel': {
            'es': 'Estrategia',
            'en': 'Strategy'
        },
        'ylabel': {
            'es': 'Coste estimado (USD)',
            'en': 'Estimated cost (USD)'
        },
        'labels': {
            'es': ['Todo a DeepSeek', 'Pipeline v2 (Exacto)'],
            'en': ['All DeepSeek', 'Pipeline v2 (Exact)']
        }
    },
    'fig_hibrido_13': {
        'title': {
            'es': 'Tipos de Ataque por Motor de Detección (v2)',
            'en': 'Attack Types by Detection Engine (v2)'
        },
        'subtitle': {
            'es': 'Distribución de categorías de ataque según motor resolutor con matching exacto de Nuclei',
            'en': 'Attack category distribution by resolving engine with exact Nuclei matching'
        },
        'xlabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        },
        'ylabel': {
            'es': 'Tipo de ataque',
            'en': 'Attack type'
        },
        'legend_nuclei': {
            'es': 'Nuclei (Determinista)',
            'en': 'Nuclei (Deterministic)'
        },
        'legend_deepseek': {
            'es': 'DeepSeek v4 Pro (Heurístico)',
            'en': 'DeepSeek v4 Pro (Heuristic)'
        }
    },
    'fig_hibrido_14': {
        'title': {
            'es': 'Distribución de Severidad por Motor de Detección (v2)',
            'en': 'Severity Distribution by Detection Engine (v2)'
        },
        'subtitle': {
            'es': 'Niveles de gravedad asignados por Nuclei (exacto) y DeepSeek v4 Pro',
            'en': 'Severity levels assigned by Nuclei (exact) and DeepSeek v4 Pro'
        },
        'xlabel': {
            'es': 'Número de logs',
            'en': 'Number of logs'
        },
        'ylabel': {
            'es': 'Nivel de severidad',
            'en': 'Severity level'
        },
        'legend_nuclei': {
            'es': 'Nuclei (Determinista)',
            'en': 'Nuclei (Deterministic)'
        },
        'legend_deepseek': {
            'es': 'DeepSeek v4 Pro (Heurístico)',
            'en': 'DeepSeek v4 Pro (Heuristic)'
        }
    },
    'fig_hibrido_15': {
        'title': {
            'es': 'Tecnologías Objetivo por Motor de Detección (v2)',
            'en': 'Target Technologies by Detection Engine (v2)'
        },
        'subtitle': {
            'es': 'Stacks tecnológicos más atacados según el motor que los detectó',
            'en': 'Most targeted tech stacks by detecting engine'
        },
        'xlabel': {
            'es': 'Número de detecciones',
            'en': 'Number of detections'
        },
        'ylabel': {
            'es': 'Tecnología',
            'en': 'Technology'
        },
        'legend_nuclei': {
            'es': 'Nuclei (Determinista)',
            'en': 'Nuclei (Deterministic)'
        },
        'legend_deepseek': {
            'es': 'DeepSeek v4 Pro (Heurístico)',
            'en': 'DeepSeek v4 Pro (Heuristic)'
        }
    },
    'fig_hibrido_16': {
        'title': {
            'es': 'Top CVEs Detectados por Motor (v2)',
            'en': 'Top Detected CVEs by Engine (v2)'
        },
        'subtitle': {
            'es': 'Solo CVE-2017-9841 fue detectado por ambos motores, evidenciando complementariedad',
            'en': 'Only CVE-2017-9841 was detected by both engines, showing complementarity'
        },
        'xlabel': {
            'es': 'Detecciones',
            'en': 'Detections'
        },
        'ylabel': {
            'es': 'Identificador CVE',
            'en': 'CVE identifier'
        },
        'legend_nuclei': {
            'es': 'Nuclei (Determinista)',
            'en': 'Nuclei (Deterministic)'
        },
        'legend_deepseek': {
            'es': 'DeepSeek v4 Pro (Heurístico)',
            'en': 'DeepSeek v4 Pro (Heuristic)'
        }
    },
    'fig_hibrido_17': {
        'title': {
            'es': 'Correlación Tipo de Ataque vs Severidad - DeepSeek v4 Pro (v2)',
            'en': 'Attack Type vs Severity Correlation - DeepSeek v4 Pro (v2)'
        },
        'subtitle': {
            'es': 'Mapa de calor: frecuencia de cada combinación tipo-severidad en clasificaciones heurísticas',
            'en': 'Heatmap: frequency of each type-severity combination in heuristic classifications'
        },
        'xlabel': {
            'es': 'Severidad',
            'en': 'Severity'
        },
        'ylabel': {
            'es': 'Tipo de ataque',
            'en': 'Attack type'
        },
        'cbar_label': {
            'es': 'Número de\nregistros',
            'en': 'Number of\nrecords'
        }
    },
    'fig_hibrido_18': {
        'title': {
            'es': 'Top 10 IPs Atacantes con Desglose por Tipo de Ataque (v2)',
            'en': 'Top 10 Attacker IPs by Attack Type (v2)'
        },
        'subtitle': {
            'es': 'Patrones de comportamiento: escáneres masivos vs atacantes dirigidos',
            'en': 'Behavior patterns: mass scanners vs targeted attackers'
        },
        'xlabel': {
            'es': 'Número de peticiones',
            'en': 'Number of requests'
        },
        'ylabel': {
            'es': 'IP origen',
            'en': 'Source IP'
        }
    },
    'fig_hibrido_19': {
        'title': {
            'es': 'Visión Global del Pipeline Híbrido v2',
            'en': 'Global Overview of Hybrid Pipeline v2'
        },
        'subtitle': {
            'es': 'Resumen de distribución de motor, severidad, tipo de ataque y top tecnologías',
            'en': 'Summary of engine distribution, severity, attack type, and top technologies'
        },
        'subtitle_a': {
            'es': '(a) Proporción por motor de detección',
            'en': '(a) Proportion by detection engine'
        },
        'subtitle_b': {
            'es': '(b) Distribución de severidad por motor',
            'en': '(b) Severity distribution by engine'
        },
        'subtitle_c': {
            'es': '(c) Top tipos de ataque',
            'en': '(c) Top attack types'
        },
        'subtitle_d': {
            'es': '(d) Tecnologías más atacadas',
            'en': '(d) Most targeted technologies'
        },
        'labels': {
            'es': ['Nuclei (Exacto)', 'DeepSeek v4 Pro'],
            'en': ['Nuclei (Exact)', 'DeepSeek v4 Pro']
        }
    }
}
