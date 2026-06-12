"""
Diagrama 06 - Flujo de Datos Completo (End-to-End)
Desde los honeypots hasta los productos finales: informes, dashboard, blacklists, gráficas
"""
import os
from diagrams import Diagram, Edge, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.container import Docker
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.logging import FluentBit
from diagrams.onprem.network import Internet, Nginx
from diagrams.programming.language import Python
from diagrams.generic.compute import Rack
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
        with Cluster("Data Sources - Cloud (DO AMS3)"):
            cowrie = Docker("Cowrie\nSSH Logs\n(JSON)")
            nginx = FluentBit("Nginx Honeypot\nWeb Logs\n(Access/Error)")
            tcpdump = FluentBit("tcpdump\ndata.txt\n(Raw traces)")

        with Cluster("ETL - Extraction & Transformation\n(Python / Pandas)"):
            etl = Python("ETL Scripts\n- Timestamp normalization (UTC)\n- Deduplication\n- IP / session / payload extraction")
            normalization = Python("Regex Parsing\n- SSH: credentials, commands\n- Web: method, path, query\n- TCP: source IP, dest port")

        with Cluster("Data Storage - SQLite"):
            db_cowrie = PostgreSQL("SSH DB\n(analisis)")

            with Cluster("ai-classifier Databases"):
                db_web = PostgreSQL("honeypot_hibrido_v2.db\nalertas_hibrido\nmetricas")
                db_deepseek = PostgreSQL("honeypot_ataques_deepseek.db")
                db_qwen = PostgreSQL("honeypot_ataques_qwen.db")
                db_llama = PostgreSQL("honeypot_ataques_llama3.1.db")

            db_blacklist = PostgreSQL("blacklist.db\nmalicious_ips")

        with Cluster("AI Classification Pipelines\n(Local + External)"):
            with Cluster("Local LLM"):
                ollama = Rack("Ollama + Qwen 2.5:7b\nGPU GTX 1660")
            with Cluster("External APIs"):
                deepseek = Server("DeepSeek v4 Pro\nAPI (CoT)")
            nuclei = Server("Nuclei\n(4,325 templates)")

        with Cluster("External Intelligence APIs"):
            ip_api = Server("ip-api.com\nBatch API (ISP/ASN)")
            radb = Server("whois.radb.net\nASN -> CIDR")
            shodan = Server("Shodan\nPassive OSINT")
            virustotal = Server("VirusTotal\nMalware hash lookup")
            anyrun = Server("Any.Run\nCloud Sandbox")

        with Cluster("Post-Processing & Reports"):
            reports = Python("Analysis Scripts\nanalisis_profundo.py\ninforme_hibrido.py")
            ssh_analysis = Python("SSH Analysis\nanalisis.py\nanalisis_ssh.py")
            blacklist_gen = Python("generate_blacklist.py\nprocess_ips.py\nshow_datacenters.py")

        with Cluster("Final Products"):
            graphics = FluentBit("33+ Figures\n(graficas/)\nPDF + PNG 300 DPI")
            dashboard = Server("Web Dashboard\n(React + Recharts)")
            blacklist = FluentBit("firewall_blacklist.txt\nCIDR ranges")
            reports_md = FluentBit("Markdown Reports\nAnalysis + Comparison")

        cowrie >> etl >> db_cowrie
        nginx >> etl >> normalization
        tcpdump >> etl >> normalization

        normalization >> [db_web, db_deepseek, db_qwen, db_llama, db_blacklist]

        ollama >> Edge(label="Local\nZero-Shot") >> [db_qwen, db_llama]
        deepseek >> Edge(label="API\nCoT") >> [db_deepseek, db_web]
        nuclei >> Edge(label="100% exact\nmatch") >> db_web

        ip_api >> db_blacklist
        radb >> blacklist_gen >> blacklist

        db_web >> [reports, graphics]
        db_cowrie >> ssh_analysis >> graphics
        db_blacklist >> blacklist_gen >> blacklist
        db_cowrie >> virustotal >> anyrun >> reports_md
        reports >> reports_md
        db_web >> dashboard

    out_path_es = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'es', 'diagrams')
    os.makedirs(out_path_es, exist_ok=True)

    with Diagram(
        name_es,
        show=False,
        outformat="png",
        filename=os.path.join(out_path_es, f"{filename_base}_es"),
        direction="TB",
    ):
        with Cluster("Fuentes de Datos - Cloud (DO AMS3)"):
            cowrie = Docker("Cowrie\nLogs SSH\n(JSON)")
            nginx = FluentBit("Nginx Honeypot\nLogs Web\n(Access/Error)")
            tcpdump = FluentBit("tcpdump\ndata.txt\n(Trazas crudas)")

        with Cluster("ETL - Extracción y Transformación\n(Python / Pandas)"):
            etl = Python("Scripts ETL\n- Normalización timestamps (UTC)\n- Deduplicación\n- Extracción IP/sesión/payload")
            normalization = Python("Parsing Regex\n- SSH: credenciales, comandos\n- Web: método, ruta, query\n- TCP: IP origen, puerto destino")

        with Cluster("Almacenamiento - SQLite"):
            db_cowrie = PostgreSQL("BD SSH\n(análisis)")

            with Cluster("Bases de datos ai-classifier"):
                db_web = PostgreSQL("honeypot_hibrido_v2.db\nalertas_hibrido\nmétricas")
                db_deepseek = PostgreSQL("honeypot_ataques_deepseek.db")
                db_qwen = PostgreSQL("honeypot_ataques_qwen.db")
                db_llama = PostgreSQL("honeypot_ataques_llama3.1.db")

            db_blacklist = PostgreSQL("blacklist.db\nmalicious_ips")

        with Cluster("Pipelines de Clasificación IA\n(Local + Externo)"):
            with Cluster("LLM Local"):
                ollama = Rack("Ollama + Qwen 2.5:7b\nGPU GTX 1660")
            with Cluster("APIs Externas"):
                deepseek = Server("DeepSeek v4 Pro\nAPI (CoT)")
            nuclei = Server("Nuclei\n(4.325 plantillas)")

        with Cluster("APIs de Inteligencia Externas"):
            ip_api = Server("ip-api.com\nBatch API (ISP/ASN)")
            radb = Server("whois.radb.net\nASN -> CIDR")
            shodan = Server("Shodan\nOSINT Pasivo")
            virustotal = Server("VirusTotal\nConsulta hash malware")
            anyrun = Server("Any.Run\nSandbox Cloud")

        with Cluster("Post-Procesado e Informes"):
            reports = Python("Scripts de Análisis\nanalisis_profundo.py\ninforme_hibrido.py")
            ssh_analysis = Python("Análisis SSH\nanalisis.py\nanalisis_ssh.py")
            blacklist_gen = Python("generate_blacklist.py\nprocess_ips.py\nshow_datacenters.py")

        with Cluster("Productos Finales"):
            graphics = FluentBit("33+ Figuras\n(gráficas/)\nPDF + PNG 300 DPI")
            dashboard = Server("Dashboard Web\n(React + Recharts)")
            blacklist = FluentBit("firewall_blacklist.txt\nRangos CIDR")
            reports_md = FluentBit("Informes Markdown\nAnálisis + Comparativa")

        cowrie >> etl >> db_cowrie
        nginx >> etl >> normalization
        tcpdump >> etl >> normalization

        normalization >> [db_web, db_deepseek, db_qwen, db_llama, db_blacklist]

        ollama >> Edge(label="Local\nZero-Shot") >> [db_qwen, db_llama]
        deepseek >> Edge(label="API\nCoT") >> [db_deepseek, db_web]
        nuclei >> Edge(label="Match\n100% exacto") >> db_web

        ip_api >> db_blacklist
        radb >> blacklist_gen >> blacklist

        db_web >> [reports, graphics]
        db_cowrie >> ssh_analysis >> graphics
        db_blacklist >> blacklist_gen >> blacklist
        db_cowrie >> virustotal >> anyrun >> reports_md
        reports >> reports_md
        db_web >> dashboard


if __name__ == "__main__":
    make(
        "Flujo de Datos Completo del Sistema",
        "Complete System Data Flow",
        "diagrama_06_flujo_datos_completo",
    )
