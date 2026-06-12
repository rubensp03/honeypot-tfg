"""
Diagrama 02 - Entorno Cloud (Exposición)
Detalle: Droplet DO AMS3, Debian host, Docker bridge network, honeypots
"""
import os
from diagrams import Diagram, Edge, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.container import Docker
from diagrams.onprem.network import Internet
from diagrams.onprem.logging import FluentBit
from diagrams.generic.os import Debian

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
        internet = Internet("Internet\nAtacantes globales")

        with Cluster("DigitalOcean - AMS3 (Amsterdam)"):
            with Cluster("VPS Droplet - Debian 13 x64\n1 vCPU / 2 GB / 70 GB SSD"):
                with Cluster("Host Debian 13\nSSH Real reubicado :HIGH-PORT\nAutenticación Ed25519"):
                    host_ssh = Server("SSH Admin\n(no estándar)")
                    host_fw = Server("iptables\nFirewall")

                with Cluster("Docker Engine\nBridge Network: honey_net"):
                    with Cluster("Cowrie (Honeypot SSH)"):
                        cowrie_container = Docker("Alpine + Cowrie\n:22 expuesto")
                        cowrie_fs = FluentBit("FS Emulado\nUNIX shell")

                    with Cluster("Nginx (Honeypot Web)"):
                        nginx_container = Docker("Alpine + Nginx\n:80 / :443")
                        login_panel = FluentBit("Fake Login Panel\nHTML/CSS/JS\nSin backend real")

                tcpdump = Server("tcpdump\nCaptura pasiva TCP\n+Todos los puertos")

                with Cluster("Exportación de Datos"):
                    logs = FluentBit("Logs Raw\nnginx + cowrie\n+ tcpdump traces")

        internet >> Edge(label="SSH :22 - fuerza bruta") >> cowrie_container
        internet >> Edge(label="HTTP :80/:443 - exploits web") >> nginx_container
        internet >> Edge(label="Todos los puertos\n(sondeo masivo)") >> tcpdump

        cowrie_container >> cowrie_fs >> logs
        nginx_container >> login_panel >> logs
        tcpdump >> logs
        host_ssh >> logs

    out_path_es = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'es', 'diagrams')
    os.makedirs(out_path_es, exist_ok=True)

    with Diagram(
        name_es,
        show=False,
        outformat="png",
        filename=os.path.join(out_path_es, f"{filename_base}_es"),
        direction="TB",
    ):
        internet = Internet("Internet\nAtacantes globales")

        with Cluster("DigitalOcean - AMS3 (Amsterdam)"):
            with Cluster("VPS Droplet - Debian 13 x64\n1 vCPU / 2 GB / 70 GB SSD"):
                with Cluster("Host Debian 13\nSSH Real reubicado :HIGH-PORT\nAutenticación Ed25519"):
                    host_ssh = Server("SSH Admin\n(no estándar)")
                    host_fw = Server("iptables\nFirewall")

                with Cluster("Docker Engine\nBridge Network: honey_net"):
                    with Cluster("Cowrie (Honeypot SSH)"):
                        cowrie_container = Docker("Alpine + Cowrie\n:22 expuesto")
                        cowrie_fs = FluentBit("FS Emulado\nUNIX shell")

                    with Cluster("Nginx (Honeypot Web)"):
                        nginx_container = Docker("Alpine + Nginx\n:80 / :443")
                        login_panel = FluentBit("Panel Login Falso\nHTML/CSS/JS\nSin backend real")

                tcpdump = Server("tcpdump\nCaptura pasiva TCP\n+Todos los puertos")

                with Cluster("Exportación de Datos"):
                    logs = FluentBit("Logs Raw\nnginx + cowrie\n+ tcpdump traces")

        internet >> Edge(label="SSH :22 - fuerza bruta") >> cowrie_container
        internet >> Edge(label="HTTP :80/:443 - exploits web") >> nginx_container
        internet >> Edge(label="Todos los puertos\n(sondeo masivo)") >> tcpdump

        cowrie_container >> cowrie_fs >> logs
        nginx_container >> login_panel >> logs
        tcpdump >> logs
        host_ssh >> logs


if __name__ == "__main__":
    make(
        "Entorno Cloud - Infraestructura de Exposición",
        "Cloud Environment - Exposure Infrastructure",
        "diagrama_02_entorno_cloud",
    )
