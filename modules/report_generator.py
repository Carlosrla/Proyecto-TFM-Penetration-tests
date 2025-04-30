import os
import json
from datetime import datetime

RESULTS_DIR = "results"
EXPLOITS_FILE = os.path.join(RESULTS_DIR, "exploit_results.json")
SCAN_RESULTS_FILE = os.path.join(RESULTS_DIR, "scan_results.json")
INFORME_FINAL = os.path.join(RESULTS_DIR, "informe_final.txt")

def detectar_modulos_usados():
    modulos = {}
    for modulo in ["web_enum", "mysql", "rdp", "smb", "ftp"]:
        ruta = os.path.join(RESULTS_DIR, modulo)
        if os.path.exists(ruta) and any(f.endswith((".json", ".txt")) for f in os.listdir(ruta)):
            modulos[modulo] = [os.path.join(ruta, f) for f in os.listdir(ruta) if f.endswith((".json", ".txt"))]
    return modulos

def cargar_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def incluir_scan_general(out):
    out.write("# INFORME DE PENTEST\n")
    out.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    out.write("## Información general del escaneo\n")
    scan = cargar_json(SCAN_RESULTS_FILE)
    for host in scan.get("hosts", []):
        ip = host.get("ip")
        os_detected = host.get("os", "No detectado")
        out.write(f"- Host: {ip} ({os_detected})\n")
        for port in host.get("open_ports", []):
            svc = port.get("service", "")
            version = port.get("version", "")
            out.write(f"  - {port['port']}/tcp  {svc} {version}\n")
    out.write("\n")

def incluir_exploits(out):
    out.write("## Exploits encontrados\n")
    exploits = cargar_json(EXPLOITS_FILE)
    if not exploits:
        out.write("No se encontraron exploits relevantes.\n\n")
        return

    for host in exploits.get("hosts", []):
        out.write(f"- {host['ip']}:\n")
        for e in host.get("exploits", []):
            out.write(f"  - {e}\n")
    out.write("\n")

def incluir_modulo(modulo, archivos, out):
    out.write(f"## Resultados del módulo {modulo}\n")
    for archivo in archivos:
        out.write(f"[Archivo: {archivo}]\n")
        try:
            with open(archivo, "r") as f:
                contenido = f.read()
                out.write(contenido + "\n")
        except Exception:
            out.write("[!] Error al leer el archivo.\n")
    out.write("\n")

def generar_informe_final():
    modulos = detectar_modulos_usados()
    with open(INFORME_FINAL, "w") as out:
        incluir_scan_general(out)
        incluir_exploits(out)
        for modulo, archivos in modulos.items():
            incluir_modulo(modulo, archivos, out)

    print(f"[+] Informe generado en: {INFORME_FINAL}")

if __name__ == "__main__":
    generar_informe_final()
