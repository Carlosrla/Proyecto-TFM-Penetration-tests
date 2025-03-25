import json
import subprocess
import os

def enumerate_with_credentials(creds, scan_results_file="results/scan_results.json", log_file="results/smb_enum.log"):
    """
    Usa CrackMapExec para enumerar hosts SMB según su rol (DC o máquina normal) y privilegios.
    """

    if not os.path.exists(scan_results_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_results_file}")
        return

    with open(scan_results_file, "r") as f:
        data = json.load(f)

    hosts = data.get("hosts", [])
    dc_ip = None
    objetivos = []

    for host in hosts:
        ip = host.get("ip")
        puertos = [p["port"] for p in host.get("open_ports", [])]

        if 389 in puertos or 88 in puertos:
            dc_ip = ip

        if 445 in puertos:
            objetivos.append(ip)

    if not objetivos:
        print("[!] No se encontraron objetivos SMB.")
        return

    os.makedirs("results", exist_ok=True)
    with open(log_file, "w") as log:
        for cred in creds:
            user = cred.get("usuario")
            passwd = cred.get("password")

            # Acciones generales (aplicables a todos los hosts)
            acciones_generales = ["--shares", "--sessions", "--disks"]

            for ip in objetivos:
                for accion in acciones_generales:
                    log.write(f"[{ip}] {user}:{passwd} {accion}\n")
                    try:
                        result = subprocess.run(
                            ["crackmapexec", "smb", ip, "-u", user, "-p", passwd, accion],
                            capture_output=True, text=True, timeout=20
                        )
                        log.write(result.stdout + "\n---\n")
                    except Exception as e:
                        log.write(f"[!] Error en {ip} con {accion}: {e}\n---\n")

            # Acciones especiales para el DC
            if dc_ip:
                acciones_dc = ["--users", "--groups", "--pass-pol", "--computers", "--rid-brute"]

                for accion in acciones_dc:
                    log.write(f"[DC {dc_ip}] {user}:{passwd} {accion}\n")
                    try:
                        result = subprocess.run(
                            ["crackmapexec", "smb", dc_ip, "-u", user, "-p", passwd, accion],
                            capture_output=True, text=True, timeout=30
                        )
                        log.write(result.stdout + "\n---\n")
                    except Exception as e:
                        log.write(f"[!] Error en DC {dc_ip} con {accion}: {e}\n---\n")

    print(f"[+] Enumeración completada. Log guardado en {log_file}")