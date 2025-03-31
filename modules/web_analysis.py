import os
import subprocess
import json

def analizar_servicios_web(scan_results_file="results/scan_results.json", output_dir="results/web_enum", wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"):
    """
    Analiza servicios web detectados (HTTP/HTTPS) con herramientas como ffuf y nikto.
    """
    if not os.path.exists(scan_results_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_results_file}")
        return

    with open(scan_results_file, "r") as f:
        data = json.load(f)

    hosts = data.get("hosts", [])
    os.makedirs(output_dir, exist_ok=True)

    for host in hosts:
        ip = host.get("ip")
        for port_info in host.get("open_ports", []):
            port = port_info.get("port")
            service = port_info.get("service")

            if service in ["http", "https"] or port in [80, 443, 8080, 8000]:
                url = f"http://{ip}:{port}"
                if port == 443 or service == "https":
                    url = f"https://{ip}:{port}"

                print(f"[*] Analizando servicio web en {url}")

                ejecutar_ffuf(url, ip, port, output_dir, wordlist)
                ejecutar_nikto(ip, port, output_dir)

def ejecutar_ffuf(url, ip, port, output_dir, wordlist):
    output_file = os.path.join(output_dir, f"{ip}_{port}_ffuf.json")
    print(f"[*] Ejecutando ffuf contra {url}...")
    try:
        subprocess.run([
            "ffuf", "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-mc", "200,403",
            "-of", "json",
            "-o", output_file
        ], check=True)
        print(f"[+] Resultado ffuf guardado en {output_file}")
    except subprocess.CalledProcessError:
        print(f"[!] Error ejecutando ffuf sobre {url}")

def ejecutar_nikto(ip, port, output_dir):
    output_file = os.path.join(output_dir, f"{ip}_{port}_nikto.txt")
    print(f"[*] Ejecutando Nikto contra {ip}:{port}...")
    try:
        subprocess.run([
            "nikto", "-host", ip, "-port", str(port), "-output", output_file
        ], check=True)
        print(f"[+] Resultado nikto guardado en {output_file}")
    except subprocess.CalledProcessError:
        print(f"[!] Error ejecutando nikto sobre {ip}:{port}")

def run_web_analysis():
    analizar_servicios_web()