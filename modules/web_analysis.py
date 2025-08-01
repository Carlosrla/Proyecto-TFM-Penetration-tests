import os  # Para manejar rutas y directorios
import json  # Para leer y guardar datos en formato JSON
import subprocess  # Para ejecutar comandos externos (ffuf y nuclei)
from datetime import datetime  # Para generar marcas de tiempo en los nombres de archivos

# Directorio donde se guardarán los resultados del análisis web
WEB_ENUM_DIR = "results/web_enum"

# Wordlist usada para el descubrimiento de directorios
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

# Lista de directorios de interés (solo estos serán analizados a fondo)
DIRECTORIOS_INTERES = [
    "DVWA", "admin", "dashboard", "phpmyadmin", "cms", "panel", "login"
]

def discover_directories(target_url):
    """
    Ejecuta FFUF para detectar directorios accesibles en un servicio web.
    Retorna una lista de URLs descubiertas.
    """
    print(f"[*] Buscando directorios en {target_url} con FFUF...")

    os.makedirs(WEB_ENUM_DIR, exist_ok=True)
    temp_output = os.path.join(WEB_ENUM_DIR, "temp_dirs.json")

    # Comando FFUF para detectar rutas válidas
    cmd = [
        "ffuf", "-u", f"{target_url}/FUZZ",
        "-w", WORDLIST,
        "-mc", "200,403,301,302",
        "-of", "json",
        "-o", temp_output
    ]

    # Ejecuta FFUF y descarta la salida de consola
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
        os.remove(temp_output)  # Elimina archivo temporal

    return rutas  # Devuelve las rutas encontradas

def run_ffuf(target_url, dir_name, output_path):
    """
    Ejecuta FFUF sobre un subdirectorio específico para análisis más profundo.
    """
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
    """
    Ejecuta Nuclei para detectar vulnerabilidades conocidas en la URL objetivo.
    """
    cmd = ["nuclei", "-u", target_url, "-o", output_path]
    print(f"[*] Ejecutando Nuclei contra {target_url}...")
    subprocess.run(cmd, stdout=subprocess.DEVNULL)
    print(f"[+] Resultado Nuclei guardado en {output_path}")

def analizar_servicios_web(scan_results_file="results/scan_results.json"):
    """
    Analiza los servicios web detectados en el escaneo inicial,
    ejecutando FFUF y Nuclei en rutas de interés.
    """
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

            # Detecta si es un servicio web por nombre o número de puerto
            if service in ["http", "https"] or port in [80, 443, 8080, 8000]:
                protocol = "https" if port == 443 or service == "https" else "http"
                base_url = f"{protocol}://{ip}:{port}"

                print(f"\n[+] Analizando servicio web en {base_url}")

                # Detectar directorios con FFUF
                directorios = discover_directories(base_url)
                for url in directorios:
                    ruta_relativa = url.replace(base_url, "").strip("/")

                    # Solo analiza si el directorio está en la lista de interés
                    if ruta_relativa.lower() in [d.lower() for d in DIRECTORIOS_INTERES]:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        subdir = os.path.join(WEB_ENUM_DIR, ruta_relativa)
                        os.makedirs(subdir, exist_ok=True)

                        ffuf_out = os.path.join(subdir, f"{ruta_relativa}_{timestamp}_ffuf.json")
                        nuclei_out = os.path.join(subdir, f"{ruta_relativa}_{timestamp}_nuclei.txt")

                        # Ejecuta FFUF y Nuclei
                        run_ffuf(base_url, ruta_relativa, ffuf_out)
                        run_nuclei(url, nuclei_out)

                        # Genera un archivo resumen combinado
                        generar_analisis_web_final(ip, port, ruta_relativa, ffuf_out, nuclei_out, subdir)

                        # Limpia archivos temporales
                        if os.path.exists(ffuf_out):
                            os.remove(ffuf_out)
                        if os.path.exists(nuclei_out):
                            os.remove(nuclei_out)
                    else:
                        print(f"[-] Ignorando directorio irrelevante: {ruta_relativa}")

def run_web_analysis():
    """
    Punto de entrada para lanzar el análisis web completo desde otros scripts.
    """
    analizar_servicios_web()

def generar_analisis_web_final(ip, port, ruta_relativa, ffuf_json, nuclei_json, output_dir):
    """
    Genera un archivo .txt con los hallazgos combinados de FFUF y Nuclei para un directorio específico.
    """
    salida_final = os.path.join(
        output_dir,
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
        if os.path.exists(nuclei_json):
            try:
                with open(nuclei_json, "r") as f:
                    for line in f:
                        out.write(line)
            except Exception:
                out.write("[!] Error al leer resultados de Nuclei.\n")
        else:
            out.write("[!] No se encontró el archivo de Nuclei.\n")

        out.write("\n" + "="*50 + "\n")

    print(f"[+] Análisis combinado guardado en {salida_final}")
