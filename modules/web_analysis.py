import os
import json
import subprocess
from datetime import datetime

WEB_ENUM_DIR = "results/web_enum"
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

def discover_directories(target_url):
    print(f"[*] Buscando directorios en {target_url} con FFUF...")

    os.makedirs(WEB_ENUM_DIR, exist_ok=True)
    temp_output = os.path.join(WEB_ENUM_DIR, "temp_dirs.json")

    cmd = [
        "ffuf", "-u", f"{target_url}/FUZZ",
        "-w", WORDLIST,
        "-mc", "200,403,301,302",
        "-of", "json",
        "-o", temp_output
    ]

    subprocess.run(cmd, stdout=subprocess.DEVNULL)

    rutas = []
    if os.path.exists(temp_output):
        with open(temp_output, "r") as f:
            try:
                data = json.load(f)
                for result in data.get("results", []):
                    url = result.get("url")
                    if url:
                        rutas.append(url)
            except json.JSONDecodeError:
                print("[!] Error al leer el JSON generado por FFUF.")
        os.remove(temp_output)

    return rutas


def run_ffuf(target_url, ruta_relativa):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(WEB_ENUM_DIR, f"{ruta_relativa}_{timestamp}_ffuf.json")

    cmd = [
        "ffuf",
        "-u", f"{target_url}/{ruta_relativa}/FUZZ",
        "-w", WORDLIST,
        "-mc", "200,403,301,302",
        "-of", "json",
        "-o", output_file
    ]

    print(f"[*] Ejecutando FFUF en {target_url}/{ruta_relativa}/")
    subprocess.run(cmd, stdout=subprocess.DEVNULL)
    print(f"[+] Guardado en {output_file}")


def run_nikto(ip, port, root_path=""):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(WEB_ENUM_DIR, f"{ip}_{port}_{root_path.strip('/').replace('/', '_')}_{timestamp}_nikto.txt")

    cmd = [
        "nikto", "-host", ip, "-port", str(port),
        "-output", output_file
    ]

    if root_path:
        cmd.extend(["-root", root_path])

    print(f"[*] Ejecutando Nikto en {ip}:{port}{root_path}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL)
    print(f"[+] Guardado en {output_file}")


def analizar_servicios_web(scan_results_file="results/scan_results.json"):
    if not os.path.exists(scan_results_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_results_file}")
        return

    with open(scan_results_file, "r") as f:
        data = json.load(f)

    for host in data.get("hosts", []):
        ip = host.get("ip")
        for port_info in host.get("open_ports", []):
            port = port_info.get("port")
            service = port_info.get("service")

            if service in ["http", "https"] or port in [80, 443, 8080, 8000]:
                protocol = "https" if port == 443 or service == "https" else "http"
                base_url = f"{protocol}://{ip}:{port}"

                print(f"\n[+] Analizando servicio web en {base_url}")

                directorios = discover_directories(base_url)
                for url in directorios:
                    ruta_relativa = url.replace(base_url, "").strip("/")
                    run_ffuf(base_url, ruta_relativa)
                    run_nikto(ip, port, root_path=f"/{ruta_relativa}")


def run_web_analysis():
    analizar_servicios_web()
