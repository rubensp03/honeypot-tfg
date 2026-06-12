"""
Diagrama 05 - Pipeline de Blacklisting e Inteligencia de IPs
Flujo: data.txt -> IP extraction -> ip-api.com -> ASN -> RADB/WHOIS -> firewall_blacklist.txt
"""
import os
from diagrams import Diagram, Edge, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.network import Internet
from diagrams.onprem.logging import FluentBit
from diagrams.generic.storage import Storage
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
        with Cluster("Phase 1: Extraction & Normalization\n(process_ips.py)"):
            tcpdump = Storage("data.txt\n(tcpdump raw traces)")
            regex = Python("Regex Parser\nIP extraction")
            filtering = Python("Filters\n- Exclude honeypot IP\n- Exclude link-local\n- Dedup via set()")
            db_ips = PostgreSQL("blacklist.db\nmalicious_ips\n(IP PRIMARY KEY)")

        with Cluster("Phase 2: Enrichment\n(ip-api.com Batch API)"):
            ip_api = Server("ip-api.com\nBatch API\n100 IPs/request\n15 req/min\nfields: isp, org")
            enriched = FluentBit("ISP / Org / ASN\nfor each IP")

        with Cluster("Phase 3: Aggregation & Whitelisting\n(show_datacenters.py / generate_blacklist.py)"):
            aggregation = Python("SQL Aggregation\nGROUP BY datacenter\nCOUNT(ip)")
            whitelist = FluentBit("Whitelist Filter\n- Hyperscalers (AWS, GCP,\n  Azure, CF, DO, Akamai)\n- OSINT scanners\n  (Shodan, Censys)")
            hostile = FluentBit("Hostile Providers\n(Bulletproof Hostings)")

        with Cluster("Phase 4: ASN Expansion\n(RADB / WHOIS)"):
            asn_lookup = Server("whois.radb.net\nASN -> CIDR prefixes\n(IPv4 + IPv6)")
            expansion = Python("CIDR dedup\nUnique set of ranges")

        with Cluster("Phase 5: Output"):
            blacklist = FluentBit("firewall_blacklist.txt\nActionable perimeter rules\nfor iptables / pfSense / NGFW")

        tcpdump >> regex >> filtering >> db_ips
        db_ips >> ip_api >> enriched
        enriched >> db_ips >> aggregation >> whitelist >> hostile
        hostile >> asn_lookup >> expansion >> blacklist

    out_path_es = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'es', 'diagrams')
    os.makedirs(out_path_es, exist_ok=True)

    with Diagram(
        name_es,
        show=False,
        outformat="png",
        filename=os.path.join(out_path_es, f"{filename_base}_es"),
        direction="TB",
    ):
        with Cluster("Fase 1: Extracción y Normalización\n(process_ips.py)"):
            tcpdump = Storage("data.txt\n(trazas tcpdump crudas)")
            regex = Python("Parser Regex\nExtracción IPs")
            filtering = Python("Filtros\n- Excluir IP honeypot\n- Excluir link-local\n- Dedup via set()")
            db_ips = PostgreSQL("blacklist.db\nmalicious_ips\n(IP PRIMARY KEY)")

        with Cluster("Fase 2: Enriquecimiento\n(ip-api.com Batch API)"):
            ip_api = Server("ip-api.com\nBatch API\n100 IPs/petición\n15 req/min\ncampos: isp, org")
            enriched = FluentBit("ISP / Org / ASN\npara cada IP")

        with Cluster("Fase 3: Agregación y Whitelisting\n(show_datacenters.py / generate_blacklist.py)"):
            aggregation = Python("Agregación SQL\nGROUP BY datacenter\nCOUNT(ip)")
            whitelist = FluentBit("Filtro Whitelist\n- Hyperscalers (AWS, GCP,\n  Azure, CF, DO, Akamai)\n- Escáneres OSINT\n  (Shodan, Censys)")
            hostile = FluentBit("Proveedores Hostiles\n(Bulletproof Hostings)")

        with Cluster("Fase 4: Expansión ASN\n(RADB / WHOIS)"):
            asn_lookup = Server("whois.radb.net\nASN -> Prefijos CIDR\n(IPv4 + IPv6)")
            expansion = Python("Dedup CIDR\nConjunto único\nde rangos")

        with Cluster("Fase 5: Salida"):
            blacklist = FluentBit("firewall_blacklist.txt\nReglas perimetrales accionables\npara iptables / pfSense / NGFW")

        tcpdump >> regex >> filtering >> db_ips
        db_ips >> ip_api >> enriched
        enriched >> db_ips >> aggregation >> whitelist >> hostile
        hostile >> asn_lookup >> expansion >> blacklist


if __name__ == "__main__":
    make(
        "Pipeline de Blacklisting e Inteligencia de IPs",
        "Blacklisting and IP Intelligence Pipeline",
        "diagrama_05_blacklisting",
    )
