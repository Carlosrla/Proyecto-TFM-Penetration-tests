import json
import subprocess
import os

def enumerate_with_credentials(creds, scan_results_file="results/scan_results.json", log_file="results/smb_enum.log"):
    """
    Usa CrackMapExec para enumerar hosts SMB con privilegios válidos.
    Ejecuta tanto acciones generales como avanzadas, incluyendo detección de DC.
    """

    if not os.path.exists(scan_results_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_results_file}")
        return

    with open(scan_results_file, "r") as f:
        data = json.load(f)

    hosts = data.get("hosts", [])
    if not hosts:
        print("[!] No hay hosts en el archivo de escaneo.")
        return

    os.makedirs("results", exist_ok=True)

    with open(log_file, "w") as log:
        for cred in creds:
            user = cred.get("usuario")
            passwd = cred.get("password")

            for host in hosts:
                ip = host.get("ip")
                puertos = [p["port"] for p in host.get("open_ports", [])]

                if 445 not in puertos:
                    continue  # Saltar si no hay SMB

                # Detectar si es un DC por los puertos 88 o 389
                es_dc = 389 in puertos or 88 in puertos

                acciones_generales = ["--shares", "--sessions", "--disks"]
                acciones_avanzadas = ["--users", "--groups", "--pass-pol", "--computers", "--rid-brute"]

                log.write(f"[{ip}] {user}:{passwd}\n")

                for accion in acciones_generales:
                    log.write(f"[{ip}] Ejecutando {accion}\n")
                    try:
                        result = subprocess.run(
                            ["crackmapexec", "smb", ip, "-u", user, "-p", passwd, accion],
                            capture_output=True, text=True, timeout=30
                        )
                        log.write(result.stdout + "\n---\n")
                    except Exception as e:
                        log.write(f"[!] Error en {ip} con {accion}: {e}\n---\n")

                if es_dc:
                    log.write(f"[{ip}] Detectado como DC, ejecutando acciones avanzadas\n")
                    for accion in acciones_avanzadas:
                        log.write(f"[{ip}] Ejecutando {accion}\n")
                        try:
                            result = subprocess.run(
                                ["crackmapexec", "smb", ip, "-u", user, "-p", passwd, accion],
                                capture_output=True, text=True, timeout=40
                            )
                            log.write(result.stdout + "\n---\n")
                        except Exception as e:
                            log.write(f"[!] Error en {ip} con {accion}: {e}\n---\n")

    print(f"[+] Enumeración completada. Log guardado en {log_file}")
