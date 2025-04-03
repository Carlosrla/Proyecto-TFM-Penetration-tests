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
    wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    ffuf_cmd = [
        "ffuf", "-u", f"{target_url}/{dir_name}/FUZZ",
        "-w", wordlist,
        "-mc", "200,403,301,302",
        "-of", "json",
        "-o", output_path
    ]
    print(f"[*] Ejecutando FFUF contra {target_url}/{dir_name}...")
    subprocess.run(ffuf_cmd, stdout=subprocess.DEVNULL)
    print(f"[+] Guardado en {output_path}")


def run_nikto(ip, port, output_path, root_path=""):
    """
    Ejecuta Nikto correctamente desde shell, como si fuera en terminal.
    """
    base_cmd = f"nikto -host {ip} -port {port} -output {output_path}"
    

    print(f"[*] Ejecutando Nikto en {ip}:{port}...")
    result = subprocess.run(base_cmd, shell=True, capture_output=True, text=True)

    print("[DEBUG] STDOUT:")
    print(result.stdout)
    print("[DEBUG] STDERR:")
    print(result.stderr)
    print(f"[DEBUG] Código de salida: {result.returncode}")

    print(f"[+] Guardado en {output_path}")

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
                        nikto_out = os.path.join(WEB_ENUM_DIR, f"{ruta_relativa}_{timestamp}_nikto.txt")

                        run_ffuf(base_url, ruta_relativa, ffuf_out)
                        run_nikto(ip, port, nikto_out)

                        generar_analisis_web_final(ip, port, ruta_relativa, ffuf_out, nikto_out)

                        # Opcional: borrar los archivos temporales
                        if os.path.exists(ffuf_out):
                            os.remove(ffuf_out)
                        if os.path.exists(nikto_out):
                            os.remove(nikto_out)
                    else:
                        print(f"[-] Ignorando directorio irrelevante: {ruta_relativa}")


def run_web_analysis():
    analizar_servicios_web()


def generar_analisis_web_final(ip, port, ruta_relativa, ffuf_json, nikto_txt):
    salida_final = os.path.join(
        WEB_ENUM_DIR,
        f"{ip}_{port}_{ruta_relativa}_analisis.txt"
    )

    with open(salida_final, "w") as out:

        out.write(f"# Análisis Web - {ip}:{port}/{ruta_relativa}\n\n")

        # FFUF
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

        out.write("\n== Hallazgos Nikto ==\n")
        if os.path.exists(nikto_txt):
            with open(nikto_txt, "r") as f:
                for line in f:
                    if line.strip().startswith("+") and "Nikto" not in line:
                        out.write(line)
        else:
            out.write("[!] No se encontró el archivo Nikto.\n")
            out.write("\n" + "="*50 + "\n")

    print(f"[+] Análisis combinado guardado en {salida_final}")
