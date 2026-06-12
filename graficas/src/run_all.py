"""
Script maestro: ejecuta todos los generadores de figuras.
Uso: python run_all.py
"""
import sys
import os
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

scripts = [
    'fig_5_1_trafico_tcp_volumen.py',
    'fig_5_2_top_puertos_tcp.py',
    'fig_5_3_tipos_ataque_web.py',
    'fig_5_4_top_cves.py',
    'fig_5_5_comparativa_llms.py',
    'fig_5_6_top_datacenters.py',
    'fig_5_7_categorizacion_proveedores.py',
    'fig_5_8_distribucion_gravedad.py',
    'fig_5_9_evolucion_ataques_web_tiempo.py',
    'fig_5_10_mapa_calor_dia_hora.py',
    'fig_5_11_top_asns.py',
    'fig_5_12_evolucion_ips_acumulada.py',
    'fig_5_13_pareto_puertos.py',
    'fig_5_14_interarrival_times.py',
    'fig_5_15_user_agents_web.py',
    'fig_5_16_rutas_web.py',
    'fig_5_17_codigos_http_web.py',
    'fig_5_18_correlacion_tipo_severidad.py',
    'fig_5_19_ips_web_tipos.py',
    'fig_5_20_mapa_mundial_paises.py',
    'fig_hibrido_1_volumen_general.py',
    'fig_hibrido_2_proporcion_pipeline.py',
    'fig_hibrido_3_cves_comparativa.py',
    'fig_hibrido_4_tipos_ataque.py',
    'fig_hibrido_5_severidad.py',
    'fig_hibrido_6_tecnologias.py',
    'fig_hibrido_7_eficiencia_economica.py',
    'fig_hibrido_8_v2_volumen.py',
    'fig_hibrido_9_comparativa_v1_v2_nuclei.py',
    'fig_hibrido_10_v2_cves_exactos.py',
    'fig_hibrido_11_v2_tipos_ataque.py',
    'fig_hibrido_12_v2_eficiencia.py',
    'fig_4_1_ssh_intentos_login.py',
    'fig_4_2_ssh_top_credenciales.py',
    'fig_4_3_horario_ssh.py',
    'fig_4_4_ips_persistentes_ssh.py',
    'fig_4_5_duracion_sesiones_ssh.py',
    'fig_4_6_matriz_usuario_password.py',
]

def run_script(path):
    name = os.path.basename(path).replace('.py', '')
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    if hasattr(mod, 'main'):
        mod.main()

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # Paso previo: enriquecer países
    enrich_path = os.path.join(base_dir, 'enrich_countries.py')
    if os.path.exists(enrich_path):
        print("\n=== Ejecutando enrich_countries.py (paso previo) ===")
        try:
            run_script(enrich_path)
        except Exception as e:
            print(f"[ERROR] enrich_countries.py: {e}")
    
    for s in scripts:
        p = os.path.join(base_dir, s)
        print(f"\n=== Ejecutando {s} ===")
        try:
            run_script(p)
        except Exception as e:
            print(f"[ERROR] {s}: {e}")
    print("\n=== Proceso completado ===")
