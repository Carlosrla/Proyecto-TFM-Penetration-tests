import os
import json
import subprocess
from datetime import datetime

WEB_ENUM_DIR = "results/web_enum"
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
DIRECTORIOS_INTERES = [
    "DVWA", "admin", "dashboard", "phpmyadmin", "cms", "panel", "login"
]

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

def run_ffuf(target_url, dir_name, output_path):
    ffuf_cmd = [
        "ffuf", "-u", f"{target_url}/{dir_name}/FUZZ",
        "-w", WORDLIST,
        "-mc", "200,403,301,302",
        "-of", "json",
        "-o", output_path
    ]
    print(f"[*] Ejecutando FFUF contra {target_url}/{dir_name}...")
    subprocess.run(ffuf_cmd, stdout=subprocess.DEVNULL)
    print(f"[+] Guardado en {output_path}")

def run_nuclei(target_url, output_path):
    cmd = ["nuclei", "-u", target_url, "-o", output_path]
    print(f"[*] Ejecutando Nuclei contra {target_url}...")
    subprocess.run(cmd, stdout=subprocess.DEVNULL)
    print(f"[+] Resultado Nuclei guardado en {output_path}")

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

                    if ruta_relativa.lower() in [d.lower() for d in DIRECTORIOS_INTERES]:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        ffuf_out = os.path.join(WEB_ENUM_DIR, f"{ruta_relativa}_{timestamp}_ffuf.json")
                        nuclei_out = os.path.join(WEB_ENUM_DIR, f"{ruta_relativa}_{timestamp}_nuclei.txt")

                        run_ffuf(base_url, ruta_relativa, ffuf_out)
                        run_nuclei(url, nuclei_out)

                        generar_analisis_web_final(ip, port, ruta_relativa, ffuf_out, nuclei_out)

                        if os.path.exists(ffuf_out):
                            os.remove(ffuf_out)
                        if os.path.exists(nuclei_out):
                            os.remove(nuclei_out)
                    else:
                        print(f"[-] Ignorando directorio irrelevante: {ruta_relativa}")

def run_web_analysis():
    analizar_servicios_web()

def generar_analisis_web_final(ip, port, ruta_relativa, ffuf_json, nuclei_json):
    salida_final = os.path.join(
        WEB_ENUM_DIR,
        f"{ip}_{port}_{ruta_relativa}_analisis.txt"
    )

    with open(salida_final, "w") as out:
        out.write(f"# Análisis Web - {ip}:{port}/{ruta_relativa}\n\n")

        out.write("== Rutas encontradas (FFUF) ==\n")
        if os.path.exists(ffuf_json):
            try:
                with open(ffuf_json, "r") as f:
                    data = json.load(f)
                    for r in data.get("results", []):
                        path = r.get("input", {}).get("FUZZ", "")
                        status = r.get("status")
                        out.write(f"- {path} [{status}]\n")
            except Exception:
                out.write("[!] Error al leer resultados FFUF.\n")
        else:
            out.write("[!] No se encontró el archivo FFUF.\n")

        out.write("\n== Hallazgos Nuclei ==\n")
        if os.path.exists(nuclei_txt):
            try:
                with open(nuclei_txt, "r") as f:
                    for line in f:
                        out.write(line)
            except Exception:
                out.write("[!] Error al leer resultados de Nuclei.\n")
        else:
            out.write("[!] No se encontró el archivo de Nuclei.\n")

        out.write("\n" + "="*50 + "\n")

    print(f"[+] Análisis combinado guardado en {salida_final}")
