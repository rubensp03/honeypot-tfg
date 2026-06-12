"""
Diagrama 01 - Arquitectura General del Sistema
Vista global: Internet atacantes -> Entorno Cloud (DigitalOcean AMS3) -> Entorno Local (GPU + VPN)
"""
import os
from diagrams import Diagram, Edge, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.container import Docker
from diagrams.generic.compute import Rack
from diagrams.generic.network import VPN
from diagrams.onprem.database import PostgreSQL
from diagrams.custom import Custom
from diagrams.onprem.network import Internet

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
        internet = Internet("Internet\nAtacantes / Botnets")

        with Cluster("DigitalOcean AMS3\nEntorno de Exposición (Cloud)"):
            with Cluster("VPS Droplet Debian 13\n1 vCPU / 2 GB / 70 GB SSD"):
                droplet = Server("Host Debian 13\nDocker Engine")
                with Cluster("Docker (bridge honey_net)"):
                    cowrie = Docker("Cowrie\nSSH :22")
                    nginx_hp = Docker("Nginx Honeypot\nWeb :80/:443")
                tcpdump = Server("tcpdump\nCaptura pasiva")

        with Cluster("Entorno Local (On-Premise)\nAnálisis y Clasificación"):
            with Cluster("Red Privada Segura"):
                vpn = VPN("WireGuard VPN\nMikroTik")
            gpu = Rack("GPU GTX 1660\nOllama / Qwen 2.5:7b")
            scripts = Server("Python (asyncio)\nPipelines ETL / IA")
            db = PostgreSQL("SQLite\nBases de datos")

        internet >> Edge(label="Tráfico hostil") >> droplet
        droplet >> [cowrie, nginx_hp, tcpdump]
        droplet >> Edge(label="Exportación\nde logs") >> vpn
        vpn >> Edge(label="SSH (Ed25519)") >> gpu
        vpn >> scripts
        gpu >> scripts >> db

    out_path_es = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'es', 'diagrams')
    os.makedirs(out_path_es, exist_ok=True)

    with Diagram(
        name_es,
        show=False,
        outformat="png",
        filename=os.path.join(out_path_es, f"{filename_base}_es"),
        direction="TB",
    ):
        internet = Internet("Internet\nAtacantes / Botnets")

        with Cluster("DigitalOcean AMS3\nEntorno de Exposición (Cloud)"):
            with Cluster("VPS Droplet Debian 13\n1 vCPU / 2 GB / 70 GB SSD"):
                droplet = Server("Host Debian 13\nDocker Engine")
                with Cluster("Docker (bridge honey_net)"):
                    cowrie = Docker("Cowrie\nSSH :22")
                    nginx_hp = Docker("Nginx Honeypot\nWeb :80/:443")
                tcpdump = Server("tcpdump\nCaptura pasiva")

        with Cluster("Entorno Local (On-Premise)\nAnálisis y Clasificación"):
            with Cluster("Red Privada Segura"):
                vpn = VPN("WireGuard VPN\nMikroTik")
            gpu = Rack("GPU GTX 1660\nOllama / Qwen 2.5:7b")
            scripts = Server("Python (asyncio)\nPipelines ETL / IA")
            db = PostgreSQL("SQLite\nBases de datos")

        internet >> Edge(label="Tráfico hostil") >> droplet
        droplet >> [cowrie, nginx_hp, tcpdump]
        droplet >> Edge(label="Exportación\nde logs") >> vpn
        vpn >> Edge(label="SSH (Ed25519)") >> gpu
        vpn >> scripts
        gpu >> scripts >> db


if __name__ == "__main__":
    make(
        "Arquitectura General del Sistema",
        "System Architecture Overview",
        "diagrama_01_arquitectura_general",
    )
