# Graficas del TFG - Mapa de Insercion

Este directorio contiene 33 figuras generadas con Python y Matplotlib para el TFG
**"Estudio practico de los ataques ciberneticos automatizados mediante honeypots"**.

## Estructura de archivos

```
graficas/
├── venv/          # Entorno virtual Python 3
├── src/           # Scripts generadores (.py)
│   └── run_all.py # Ejecuta todos los scripts
├── es/            # Version en espanol (PDF + PNG 300 DPI)
└── en/            # Version en ingles (PDF + PNG 300 DPI)
```

## Paleta y estilo

- **Colorblind-safe**: sin rojo ni verde puros. Paleta adaptada de ColorBrewer/Wong.
- **Estilo academico**: fuente serif, grids sutiles, fondo blanco.
- **Formato dual**: PDF vectorial (ideal para LaTeX) + PNG 300 DPI.

---

## Mapa de insercion en el documento

### Seccion 5: Resultados y Pruebas

| # | Archivo base | Punto de insercion | Descripcion |
|---|--------------|--------------------|-------------|
| 1 | `fig_5_1_trafico_tcp_volumen` | **5.1** | Serie temporal del volumen de paquetes TCP entrantes (raw + media movil 1 h). |
| 2 | `fig_5_2_top_puertos_tcp` | **5.1** | Top 15 puertos TCP destino mas escaneados con porcentajes. |
| 3 | `fig_5_3_tipos_ataque_web` | **5.2.3** | Distribucion de tipos de ataque en honeypot web. **Visual de la Tabla 5.1.** |
| 4 | `fig_5_4_top_cves` | **5.2.4** | Top 10 CVEs mas escaneados + "Ataques Genericos". **Visual de la Tabla 5.2.** |
| 5 | `fig_5_5_comparativa_llms` | **5.2.5** | Comparativa DeepSeek vs Qwen vs LLaMA 3.1. **Visual de la Tabla 5.3.** |
| 6 | `fig_5_6_top_datacenters` | **5.4.4** | Top 15 proveedores/ISPs por numero de IPs unicas atacantes. |
| 7 | `fig_5_7_categorizacion_proveedores` | **5.4.5 / 5.4.7** | Donut chart: Hyperscalers, Escanners OSINT, Offshore/Bulletproof y Otros. |
| 8 | `fig_5_8_distribucion_gravedad` | **5.2.3** | Distribucion de severidad (Baja, Media, Alta, Critica) de ataques web. |
| 9 | `fig_5_9_evolucion_ataques_web_tiempo` | **5.2** | Evolucion diaria del numero de peticiones maliciosas web. |
| 10 | `fig_5_10_mapa_calor_dia_hora` | **5.1 / 5.2** | Heatmap dia de la semana vs hora (24 h x 7 dias). |
| 11 | `fig_5_11_top_asns` | **5.4.4 / 5.4.6** | Top 15 Sistemas Autonomos (ASN) por IPs unicas atacantes. |
| 12 | `fig_5_12_evolucion_ips_acumulada` | **5.1 / 5.4** | Curva de acumulacion de IPs unicas a lo largo del tiempo de captura. |
| 13 | `fig_5_13_pareto_puertos` | **5.1** | Diagrama de Pareto: que puertos concentran el 80 % del trafico escaneado. |
| 14 | `fig_5_14_interarrival_times` | **5.1** | Distribucion de tiempos entre paquetes consecutivos (inter-arrival). |
| 15 | `fig_5_15_user_agents_web` | **5.2** | Top 10 User-Agents en peticiones al honeypot web (detecta bots/scanners). |
| 16 | `fig_5_16_rutas_web` | **5.2.3 / 5.2.4** | Top 10 rutas/paths mas solicitados (/.env, /wp-admin, exploits PHPUnit, etc.). |
| 17 | `fig_5_17_codigos_http_web` | **5.2** | Distribucion de codigos de respuesta HTTP (200, 404, 405, 400). |
| 18 | `fig_5_18_correlacion_tipo_severidad` | **5.2.3** | Matriz de calor: tipo de ataque vs nivel de severidad (DeepSeek). |
| 19 | `fig_5_19_ips_web_tipos` | **5.2.3** | Top 10 IPs atacantes web con desglose por tipo de ataque (barras apiladas). |
| 20 | `fig_5_20_mapa_mundial_paises` | **5.4** | **(a)** Mapa coropletico mundial de IPs atacantes unicas (escala logaritmica). **(b)** Top 15 paises por IPs unicas. |

### Seccion 5.X: Analisis Hibrido Nuclei + DeepSeek

| # | Archivo base | Punto de insercion | Descripcion |
|---|--------------|--------------------|-------------|
| 21 | `fig_hibrido_1_volumen_general` | **5.2** / **5.2.5** | Volumen general del pipeline: 4.402 logs procesados (Nuclei 1.582, DeepSeek 2.820). |
| 22 | `fig_hibrido_2_proporcion_pipeline` | **5.2** | Proporcion del pipeline: 35.9% Nuclei (determinista) vs 64.1% DeepSeek (heuristica). |
| 23 | `fig_hibrido_3_cves_comparativa` | **5.2.4** | Top 15 CVEs detectados comparando Nuclei (firma YAML) vs DeepSeek (razonamiento). |
| 24 | `fig_hibrido_4_tipos_ataque` | **5.2.3** | Distribucion de tipos de ataque por motor: Fingerprinting, Info Disclosure, RCE, XSS, SSRF. |
| 25 | `fig_hibrido_5_severidad` | **5.2.3 / 5.2.5** | Comparativa de niveles de severidad entre motor determinista y heuristica. |
| 26 | `fig_hibrido_6_tecnologias` | **5.2.4** | Top 10 tecnologias objetivo mas atacadas (PHP, WordPress, Laravel, Git, etc.). |
| 27 | `fig_hibrido_7_eficiencia_economica` | **5.2.5** | Eficiencia economica: coste hipotetico todo-DeepSeek ($3.12) vs pipeline real ($2.00, ahorro $1.12). |

### Seccion 4: Desarrollo del Proyecto (SSH)

| # | Archivo base | Punto de insercion | Descripcion |
|---|--------------|--------------------|-------------|
| 28 | `fig_4_1_ssh_intentos_login` | **4.4.1** | Serie temporal de intentos SSH (exitosos vs fallidos) + top combinaciones credenciales. |
| 29 | `fig_4_2_ssh_top_credenciales` | **4.4.1** | Top 10 usuarios y top 10 contrasenas mas probados en fuerza bruta. |
| 30 | `fig_4_3_horario_ssh` | **4.4.1** | Histograma horario (24 barras) de intentos de login SSH por hora UTC. |
| 31 | `fig_4_4_ips_persistentes_ssh` | **4.4.1** | Top 15 IPs origen mas persistentes (mayor numero de intentos totales). |
| 32 | `fig_4_5_duracion_sesiones_ssh` | **4.4.1** | Distribucion de la duracion de sesiones SSH (filtrado < 300 s). |
| 33 | `fig_4_6_matriz_usuario_password` | **4.4.1** | Matriz de calor 10x10: frecuencia de combinaciones usuario-contrasena. |

---

## Instrucciones de uso

### Reproducir todas las graficas

```bash
cd /Users/ruben/Documents/tfg/graficas
venv/bin/python src/run_all.py
```

### Ejecutar una grafica individual

```bash
cd /Users/ruben/Documents/tfg/graficas
venv/bin/python src/fig_5_3_tipos_ataque_web.py
```

### Regenerar tras actualizar datos

Si actualizas `logs_cowrie_60dias.log` (JSON) o las bases de datos SQLite, simplemente
vuelve a ejecutar `run_all.py` y las figuras se regeneraran automaticamente.

---

## Notas tecnicas

- Los scripts de SSH (`fig_4_1` a `fig_4_6`) soportan **dos formatos de log**:
  1. **JSON** (formato nativo `cowrie.json`): eventid `cowrie.login.success` / `cowrie.login.failed`.
  2. **Texto** (formato Twisted de tu log actual): parsing por expresion regular.
  
  Si actualizas el log a formato JSON, los scripts funcionaran sin modificaciones.

- El entorno virtual (`venv`) contiene:
  - `matplotlib`
  - `seaborn`
  - `pandas`
  - `numpy`

---

## Autor
Generado automaticamente para el TFG de Ruben San Pedro Barquin (2026).
