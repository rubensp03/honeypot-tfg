"""
Diagrama 04 - Pipeline Híbrido de Clasificación IA
2 fases: Nuclei (determinista, 35.9%) + DeepSeek v4 Pro CoT (heurística, 58.5%)
"""
import os
from diagrams import Diagram, Edge, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.logging import FluentBit
from diagrams.onprem.analytics import Beam
from diagrams.programming.language import Python
from diagrams.custom import Custom

ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')


def make(name_es, name_en, filename_base):
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'en', 'diagrams')
    os.makedirs(out_path, exist_ok=True)

    with Diagram(
        name_en,
        show=False,
        outformat="png",
        filename=os.path.join(out_path, f"{filename_base}_en"),
        direction="TB",
    ):
        with Cluster("Input"):
            web_logs = FluentBit("Nginx Access/Error Logs\n(honeypot_march.log)")
            nuclei_templates = FluentBit("Nuclei YAML Templates\n4,325 signatures")

        with Cluster("Phase 1: Deterministic Engine (Free)"):
            parser = Python("parse_payload()\nMethod + Path + Query")
            nuclei = Beam("Nuclei Matching\n100% Exact Match\n(method + path)")
            nuclei_result = FluentBit("35.9% resolved\n(1,582 records)")

        with Cluster("Phase 2: Heuristic Engine (API)"):
            with Cluster("DeepSeek v4 Pro (Chain of Thought)"):
                cot = Server("CoT Reasoning\nStep-by-step analysis")
            unmatched = FluentBit("Unmatched payloads")
            batch = Python("Batch Processing\n25 concurrent\n(asyncio semaphore)")
            deepseek_result = FluentBit("58.5% resolved\n(2,576 records)")

        with Cluster("Output - Persistence"):
            db = PostgreSQL("honeypot_hibrido_v2.db\n\nalertas_hibrido\ntipo_ataque, cve, gravedad\nmotor_deteccion, confianza\nrazonamiento\n\nmetricas\n(cost, tokens, time)")
            failures = FluentBit("5.5% API failures\n(244 records)")

        with Cluster("Post-Processing & Visualization"):
            reports = Server("Reports & Graphs\nPDF / CSV / MD")
            dashboard = Server("Web Dashboard\nReact + Recharts")

        web_logs >> parser >> nuclei
        nuclei_templates >> nuclei
        nuclei >> Edge(label="Match found") >> nuclei_result >> db
        nuclei >> Edge(label="No match") >> unmatched >> batch >> cot
        cot >> deepseek_result >> db
        batch >> Edge(label="API errors\n429 / 5xx") >> failures >> db
        db >> [reports, dashboard]

    out_path_es = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'es', 'diagrams')
    os.makedirs(out_path_es, exist_ok=True)

    with Diagram(
        name_es,
        show=False,
        outformat="png",
        filename=os.path.join(out_path_es, f"{filename_base}_es"),
        direction="TB",
    ):
        with Cluster("Entrada"):
            web_logs = FluentBit("Logs Nginx Acceso/Error\n(honeypot_march.log)")
            nuclei_templates = FluentBit("Plantillas YAML Nuclei\n4.325 firmas")

        with Cluster("Fase 1: Motor Determinista (Gratuito)"):
            parser = Python("parse_payload()\nMétodo + Ruta + Query")
            nuclei = Beam("Matching Nuclei\n100% Coincidencia Exacta\n(método + ruta)")
            nuclei_result = FluentBit("35.9% resuelto\n(1.582 registros)")

        with Cluster("Fase 2: Motor Heurístico (API)"):
            with Cluster("DeepSeek v4 Pro (Chain of Thought)"):
                cot = Server("Razonamiento CoT\nAnálisis paso a paso")
            unmatched = FluentBit("Payloads no\nemparejados")
            batch = Python("Procesamiento por Lotes\n25 concurrentes\n(asyncio semáforo)")
            deepseek_result = FluentBit("58.5% resuelto\n(2.576 registros)")

        with Cluster("Salida - Persistencia"):
            db = PostgreSQL("honeypot_hibrido_v2.db\n\nalertas_hibrido\ntipo_ataque, cve, gravedad\nmotor_deteccion, confianza\nrazonamiento\n\nmetricas\n(coste, tokens, tiempo)")
            failures = FluentBit("5.5% fallos API\n(244 registros)")

        with Cluster("Post-Procesado y Visualización"):
            reports = Server("Informes y Gráficos\nPDF / CSV / MD")
            dashboard = Server("Dashboard Web\nReact + Recharts")

        web_logs >> parser >> nuclei
        nuclei_templates >> nuclei
        nuclei >> Edge(label="Coincidencia") >> nuclei_result >> db
        nuclei >> Edge(label="Sin coincidencia") >> unmatched >> batch >> cot
        cot >> deepseek_result >> db
        batch >> Edge(label="Errores API\n429 / 5xx") >> failures >> db
        db >> [reports, dashboard]


if __name__ == "__main__":
    make(
        "Pipeline Híbrido de Clasificación IA",
        "Hybrid AI Classification Pipeline",
        "diagrama_04_pipeline_hibrido",
    )
