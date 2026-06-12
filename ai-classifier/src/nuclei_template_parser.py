import yaml
import os
import re
from pathlib import Path

from config import BASE_DIR

NUCLEI_TEMPLATES_PATH = os.path.expanduser("~/nuclei-templates/http")
SIGNATURES_DB = str(BASE_DIR / "src" / "nuclei_signatures.py")

# Paths de RECONOCIMIENTO genérico que NUNCA deben clasificarse como exploit confirmado
RECONOCIMIENTO_GENERICO = {
    "/.env", "/.env.production", "/.env.local", "/.env.development",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/wp-login.php", "/wp-admin", "/wp-admin/", "/wp-json/wp/v2/users",
    "/admin", "/admin/", "/admin/login", "/admin/config.php",
    "/login", "/login/", "/login/index.php",
    "/license.txt", "/readme.html", "/robots.txt", "/sitemap.xml",
    "/phpinfo.php", "/info.php", "/_profiler", "/_profiler/",
    "/actuator", "/actuator/", "/actuator/env", "/actuator/health",
    "/node_modules", "/package.json", "/composer.json",
    "/config.php", "/configuration.php", "/settings.php",
    "/api", "/api/", "/api/v1", "/api/v2",
    "/setup.php", "/install.php", "/wizard.php",
    "/debug", "/debug/", "/test", "/test/",
    "/console", "/console/", "/shell", "/shell/",
}


def is_exploit_path(path):
    path_lower = path.lower()
    path_only = path_lower.split("?")[0]
    
    if path_only in RECONOCIMIENTO_GENERICO:
        return False
    
    if len(path_only) < 15:
        exploit_keywords = [
            "eval-stdin", "invokefunction", "call_user_func",
            "setup.cgi", "jmx-console", "cmd.jsp", "shell.jsp",
            "gponform", "diag_form", "stok=", "syscmd",
            "auto_prepend_file", "allow_url_include",
            "password.txt", "id_rsa", ".aws/credentials",
            "%%32", "%2e", "..;/", "....//",
            "sqlmap", "union select", "sleep(", "benchmark(",
            "<script", "javascript:", "onerror=", "onload=",
            "$(", "${", "|", ";", "&&", "||",
            "php://input", "php://filter", "data:", "expect:",
            "file:///", "ftp://", "http://", "https://",
            "cmd.exe", "powershell", "bash -c", "wget ", "curl ",
            "nc ", "netcat", "python -c", "perl -e",
        ]
        if not any(kw in path_lower for kw in exploit_keywords):
            return False
    
    return True


def extract_request_signatures(template_data):
    signatures = []
    http_block = template_data.get("http", [])
    if not http_block:
        return signatures

    info = template_data.get("info", {})
    cve_id = None
    classification = info.get("classification", {})
    if classification:
        cve_id = classification.get("cve-id", "")
    
    severity = info.get("severity", "unknown")
    tags = info.get("tags", "")
    name = info.get("name", "")
    description = info.get("description", "")

    for req in http_block:
        raw_requests = req.get("raw", [])
        for raw in raw_requests:
            lines = raw.strip().split("\n")
            if not lines:
                continue
            first_line = lines[0].strip()
            match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", first_line)
            if match:
                method = match.group(1)
                path = match.group(2)
                path_clean = re.sub(r"\{\{.*?:.*?\}\}", "", path)
                path_clean = re.sub(r"\{\{.*?\}\}", "", path_clean)
                path_clean = re.sub(r"/+", "/", path_clean)
                
                if not is_exploit_path(path_clean):
                    continue
                    
                signatures.append({
                    "method": method,
                    "path": path_clean,
                    "cve": cve_id,
                    "severity": severity,
                    "tags": tags,
                    "name": name,
                    "description": description
                })

        method = req.get("method", "GET")
        paths = req.get("path", [])
        for path in paths:
            path_clean = re.sub(r"\{\{.*?:.*?\}\}", "", path)
            path_clean = re.sub(r"\{\{.*?\}\}", "", path_clean)
            path_clean = re.sub(r"/+", "/", path_clean)
            path_clean = path_clean.replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
            if path_clean.startswith("?"):
                path_clean = "/" + path_clean
            if not path_clean.startswith("/"):
                path_clean = "/" + path_clean
            
            if not is_exploit_path(path_clean):
                continue
                
            signatures.append({
                "method": method,
                "path": path_clean,
                "cve": cve_id,
                "severity": severity,
                "tags": tags,
                "name": name,
                "description": description
            })
    return signatures


def compile_templates():
    all_signatures = []
    total_templates = 0
    skipped_exploit_filter = 0
    
    search_dirs = ["cves", "vulnerabilities"]
    
    for subdir in search_dirs:
        base_path = os.path.join(NUCLEI_TEMPLATES_PATH, subdir)
        if not os.path.exists(base_path):
            print(f"[!] Directorio no encontrado: {base_path}")
            continue
            
        yaml_files = list(Path(base_path).rglob("*.yaml"))
        print(f"[*] Escaneando {len(yaml_files)} templates en {subdir}...")
        
        for yfile in yaml_files:
            try:
                with open(yfile, "r", encoding="utf-8") as f:
                    template = yaml.safe_load(f)
                if not template:
                    continue
                total_templates += 1
                sigs = extract_request_signatures(template)
                if not sigs:
                    skipped_exploit_filter += 1
                all_signatures.extend(sigs)
            except Exception as e:
                continue
    
    print(f"[*] Total templates parseados: {total_templates}")
    print(f"[*] Templates descartados (reconocimiento genérico): {skipped_exploit_filter}")
    print(f"[*] Firmas EXPLOIT extraídas: {len(all_signatures)}")
    
    sig_dict = {}
    for sig in all_signatures:
        key = (sig["method"], sig["path"])
        if key not in sig_dict:
            sig_dict[key] = sig
    
    print(f"[*] Firmas únicas: {len(sig_dict)}")
    
    with open(SIGNATURES_DB, "w", encoding="utf-8") as f:
        f.write("# Auto-generated from Nuclei templates - SOLO EXPLOITS (no reconocimiento)\n")
        f.write(f"# Total firmas únicas: {len(sig_dict)}\n\n")
        f.write("NUCLEI_SIGNATURES = {\n")
        for (method, path), sig in sig_dict.items():
            f.write(f"    ({repr(method)}, {repr(path)}): {repr(sig)},\n")
        f.write("}\n")
    
    print(f"[*] Firmas guardadas en {SIGNATURES_DB}")
    return sig_dict


if __name__ == "__main__":
    compile_templates()
