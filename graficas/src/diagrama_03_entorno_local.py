"""
Diagrama 03 - Entorno Local (Análisis)
GPU Workstation, WireGuard VPN, Ollama, SQLite, Python scripts
"""
import os
from diagrams import Diagram, Edge, Cluster
from diagrams.onprem.compute import Server
from diagrams.generic.compute import Rack
from diagrams.generic.network import VPN
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.client import User
from diagrams.programming.language import Python
from diagrams.onprem.logging import FluentBit

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
        researcher = User("Researcher\n(University city)")

        with Cluster("Home LAN - Edge Router"):
            mikrotik = VPN("MikroTik Router\nWireGuard Server")

        with Cluster("Analysis Server (On-Premise)\nDebian 13 Headless"):
            with Cluster("GPU Acceleration"):
                gpu = Rack("NVIDIA GTX 1660\n8 GB VRAM")
                with Cluster("Ollama Engine"):
                    qwen = Server("Qwen 2.5:7b\nLocal LLM")

            with Cluster("Async Inference Engine\nPython asyncio + aiohttp"):
                semaphore = Python("Semaphore\n(25 concurrent)")
                cache = Redis("Dedup Cache\nIn-memory")
                backoff = Python("Exponential\nBackoff")
                budget = Python("Budget Control\n($1.30 USD max)")

            with Cluster("Data Processing & Persistence"):
                scripts = Python("ETL Scripts\nPandas / Regex")
                db = PostgreSQL("SQLite3\nRelational DBs")
                reports = FluentBit("Reports\nCSV / MD / TXT")

            with Cluster("External APIs"):
                deepseek_api = Server("DeepSeek v4 Pro\nAPI (CoT)")

        researcher >> Edge(label="SSH\n(Ed25519)") >> mikrotik
        mikrotik >> Edge(label="WireGuard Tunnel\n(End-to-End Encrypted)") >> gpu
        gpu >> qwen >> semaphore
        semaphore >> [cache, backoff, budget]
        semaphore >> Edge(label="Local inference") >> db
        semaphore >> Edge(label="API inference") >> deepseek_api >> db
        scripts >> db >> reports

    out_path_es = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'es', 'diagrams')
    os.makedirs(out_path_es, exist_ok=True)

    with Diagram(
        name_es,
        show=False,
        outformat="png",
        filename=os.path.join(out_path_es, f"{filename_base}_es"),
        direction="TB",
    ):
        researcher = User("Investigador\n(Ciudad universitaria)")

        with Cluster("LAN Familiar - Router de Frontera"):
            mikrotik = VPN("Router MikroTik\nServidor WireGuard")

        with Cluster("Servidor de Análisis (On-Premise)\nDebian 13 Headless"):
            with Cluster("Aceleración GPU"):
                gpu = Rack("NVIDIA GTX 1660\n8 GB VRAM")
                with Cluster("Motor Ollama"):
                    qwen = Server("Qwen 2.5:7b\nLLM Local")

            with Cluster("Motor de Inferencia Asíncrono\nPython asyncio + aiohttp"):
                semaphore = Python("Semáforo\n(25 concurrente)")
                cache = Redis("Caché Dedup\nEn memoria")
                backoff = Python("Backoff\nExponencial")
                budget = Python("Control\nPresupuesto ($1.30)")

            with Cluster("Procesamiento y Persistencia"):
                scripts = Python("Scripts ETL\nPandas / Regex")
                db = PostgreSQL("SQLite3\nBases de datos")
                reports = FluentBit("Informes\nCSV / MD / TXT")

            with Cluster("APIs Externas"):
                deepseek_api = Server("DeepSeek v4 Pro\nAPI (CoT)")

        researcher >> Edge(label="SSH\n(Ed25519)") >> mikrotik
        mikrotik >> Edge(label="Túnel WireGuard\n(Cifrado extremo a extremo)") >> gpu
        gpu >> qwen >> semaphore
        semaphore >> [cache, backoff, budget]
        semaphore >> Edge(label="Inferencia local") >> db
        semaphore >> Edge(label="Inferencia API") >> deepseek_api >> db
        scripts >> db >> reports


if __name__ == "__main__":
    make(
        "Entorno Local - Infraestructura de Análisis",
        "Local Environment - Analysis Infrastructure",
        "diagrama_03_entorno_local",
    )
