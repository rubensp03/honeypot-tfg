# TFG — Honeypot para el estudio estadístico de amenazas informáticas

Trabajo de Fin de Grado en Ingeniería Informática — Universidad de Cantabria

**Autor:** Rubén San Pedro Barquín  
**Tutor:** Esteban Stafford  
**Curso:** 2025–2026  

---

## Resumen

Este proyecto investiga los ataques cibernéticos automatizados que operan en Internet mediante el despliegue de una arquitectura de **honeypots** (SSH/Cowrie + Web/Nginx) expuestos en infraestructura cloud (DigitalOcean). Durante el periodo de exposición se registraron **más de 320.000 intentos de autenticación SSH**, miles de peticiones web maliciosas y el compromiso efectivo del señuelo con la familia de malware **Prometei**.

El análisis incluye estadísticas sobre tipología de ataques, puertos más escaneados, credenciales SSH más probadas, CVEs explotadas sistemáticamente y una **evaluación crítica del uso de modelos de lenguaje (LLMs)** para la clasificación automatizada de ataques, contrastada contra una verdad terreno manual. Se incluye además la generación de **listas negras perimetrales** de infraestructuras de *offshore hosting*.

---

## Estructura del repositorio

```
├── README.md
├── requirements.txt                 ← Dependencias globales del proyecto
├── .gitignore
│
├── ai-classifier/                   ← Motor de clasificación de ataques con IA
│   ├── requirements.txt
│   └── src/                         ← Pipelines híbridos, clasificadores LLM, análisis
│
├── analisis_ssh/                    ← Análisis de logs Cowrie (fuerza bruta SSH)
│
├── analisis_tcp/                    ← Análisis tcpdump + generación de blacklists
│   └── requirements.txt
│
├── graficas/                        ← Generación de todas las figuras de la memoria
│   ├── requirements.txt
│   ├── README.md                    ← Mapa de inserción en el documento
│   └── src/                         ← 45+ scripts Python (matplotlib/seaborn/geopandas)
│
├── honeypot-dashboard/              ← Dashboard web React (Vite + TypeScript + Tailwind)
│
├── web-panel-honeypot/              ← Panel de login falso (HTML/CSS/JS)
│
└── random-forests/                  ← Intento inicial con ML clásico (placeholder)
```

---

## Componentes principales

### 1. AI Classifier — Clasificación de ataques con LLMs

Clasifica los *payloads* HTTP capturados por el honeypot web usando una arquitectura híbrida:

| Motor | Tipo | Descripción |
|-------|------|-------------|
| **Nuclei** | Determinista | *Matching* de firmas YAML contra 4.325 plantillas de exploits |
| **DeepSeek v4-pro** | Heurístico (API) | Clasificación via API comercial con *Chain of Thought* |
| **Qwen 2.5 (7B)** | Heurístico (local) | Inferencia local con Ollama (GPU NVIDIA) |
| **LLaMA 3.1** | Heurístico (local) | Inferencia local con Ollama |

**Pipeline híbrido:** Primero se intenta el *matching* determinista con Nuclei. Si no hay coincidencia exacta, el *payload* se envía al LLM para clasificación heurística. Esto reduce el coste económico un ~35% frente a usar solo el LLM.

**Scripts principales:**
- `pipeline_hibrido_v2.py` — Pipeline híbrido determinista + LLM (versión final con *matching* exacto)
- `clasificador_deepseek.py` — Clasificador exclusivo con DeepSeek API
- `clasificador_qwen.py` / `clasificador_llama.py` — Clasificadores locales vía Ollama
- `nuclei_template_parser.py` — Parser de templates YAML de Nuclei → firmas Python
- `analisis_profundo.py` — Análisis comparativo Nuclei vs DeepSeek (informe + CSV)

### 2. Análisis SSH (Cowrie)

Procesa logs del honeypot SSH Cowrie para extraer:
- Intentos de login (exitosos/fallidos)
- Comandos ejecutados post-intrusión
- URLs y binarios de malware descargados (wget/curl)
- Inventario de artefactos maliciosos

**Scripts:**
- `analisis.py` — Estadísticas de intrusión, comandos únicos, inventario de malware
- `analisis_ssh.py` — Extracción de URLs maliciosas y comandos de descarga

### 3. Análisis TCP dump + Blacklisting

Procesa la captura de tráfico de `tcpdump` para:
- Identificar puertos más escaneados y volumen de tráfico
- Geolocalizar IPs atacantes via ip-api.com
- Categorizar proveedores: *Hyperscalers*, *Scanners OSINT*, *Offshore/Bulletproof*
- Generar reglas de firewall (iptables/ufw) por rangos CIDR de ASN maliciosos

**Scripts:**
- `generar_graficas.py` — Volumen TCP + top puertos
- `process_ips.py` — Extracción y geolocalización de IPs → SQLite
- `generate_blacklist.py` — Blacklist por ASN con rangos CIDR (RIPE API)
- `show_datacenters.py` — Distribución de ISPs/datacenters

### 4. Gráficas de la memoria

Más de 45 scripts Python que generan todas las figuras de la tesis en formato PDF vectorial + PNG (300 DPI), tanto en español como en inglés. Ver `graficas/README.md` para el mapa de inserción de cada figura en el documento.

### 5. Dashboard Web

Dashboard interactivo desarrollado con React 19, Vite 7, TypeScript y Tailwind CSS 4. Muestra estadísticas en tiempo real del tráfico TCP capturado: conexiones, puertos escaneados y distribución geográfica (recharts).

### 6. Web Panel Honeypot

Panel de administración falso (*fake login*) diseñado para atraer atacantes. Simula un backend corporativo con credenciales de acceso. HTML + CSS + JavaScript vanilla, sin dependencias.

---

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/rubensp03/honeypot-tfg.git
cd honeypot-tfg

# Instalar dependencias Python (todos los módulos)
pip install -r requirements.txt

# O por módulo individual
pip install -r ai-classifier/requirements.txt
pip install -r analisis_tcp/requirements.txt
pip install -r graficas/requirements.txt
```

### Dashboard

```bash
cd honeypot-dashboard
npm install
npm run dev
```

---

## Requisitos

- Python 3.10+
- Node.js 20+ (solo para el dashboard)
- [Ollama](https://ollama.ai) + modelos Qwen 2.5 / LLaMA 3.1 (opcional, para inferencia local)
- GPU NVIDIA con al menos 6 GB VRAM (recomendado para inferencia local)
- API key de [DeepSeek](https://deepseek.com) (opcional, para clasificación por API)

---

## Configuración

1. **AI Classifier:** Colocar la API key de DeepSeek en `ai-classifier/config/api-deepseek.txt`
2. **Datos de entrada:** Colocar los archivos de log en las rutas esperadas por `config.py`:
   - Logs web: `ai-classifier/data/logs/`
   - Logs SSH: `analisis_ssh/logs_cowrie_60dias.log`
   - TCP dump: `data.txt` (raíz del proyecto)

---

## Resultados destacados

| Métrica | Valor |
|---------|-------|
| Intento de autenticaciones SSH | > 320.000 |
| CVEs detectadas explotadas activamente | > 140 únicas |
| CVE más explotada | CVE-2017-9841 (PHPUnit RCE) |
| Precisión LLM (DeepSeek v4-pro) | Evaluada contra *ground truth* manual |
| Ahorro pipeline híbrido vs todo-LLM | ~35% |
| ISPs identificados | Cientos de ASNs de *offshore hosting* |

---

## Tecnologías utilizadas

- **Infraestructura:** Debian 13, Docker, DigitalOcean (AMS3)
- **Honeypots:** Cowrie (SSH), Nginx + Alpine (Web)
- **Captura de red:** tcpdump
- **Análisis de datos:** Python, Pandas, SQLite
- **IA/LLM:** DeepSeek v4-pro (API), Qwen 2.5, LLaMA 3.1 (Ollama)
- **Matching de firmas:** Nuclei (4.325 plantillas YAML)
- **Visualización:** Matplotlib, Seaborn, Geopandas, Recharts
- **Dashboard:** React 19, Vite 7, TypeScript, Tailwind CSS 4
- **Análisis de malware:** Any.Run (sandbox dinámico)

---

## Licencia

Este proyecto es de uso académico. Consultar con el autor para otros usos.
