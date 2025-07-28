import json  # Módulo para trabajar con archivos JSON
import subprocess  # Módulo para ejecutar comandos del sistema
import os  # Módulo para interactuar con el sistema de archivos

def enumerate_with_credentials(creds, scan_results_file="results/scan_results.json", log_file="results/smb/smb_enum.log"):
    """
    Usa CrackMapExec para enumerar hosts SMB con privilegios válidos.
    Ejecuta tanto acciones generales como avanzadas, incluyendo detección de DC.
    """

    # Verifica si existe el archivo de resultados del escaneo
    if not os.path.exists(scan_results_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_results_file}")
        return

    # Carga el contenido del archivo JSON con los datos del escaneo
    with open(scan_results_file, "r") as f:
        data = json.load(f)

    # Extrae la lista de hosts desde los datos cargados
    hosts = data.get("hosts", [])
    if not hosts:
        print("[!] No hay hosts en el archivo de escaneo.")
        return

    # Crea el directorio "results" si no existe
    os.makedirs("results", exist_ok=True)

    # Abre el archivo de log en modo escritura
    with open(log_file, "w") as log:
        # Itera sobre cada credencial proporcionada
        for cred in creds:
            user = cred.get("usuario")
            passwd = cred.get("password")

            # Itera sobre cada host del archivo de resultados
            for host in hosts:
                ip = host.get("ip")
                # Obtiene la lista de puertos abiertos del host
                puertos = [p["port"] for p in host.get("open_ports", [])]

                # Si no tiene el puerto 445 abierto (SMB), se omite
                if 445 not in puertos:
                    continue  # Saltar si no hay SMB

                # Determina si el host es un Domain Controller (puertos 88 o 389)
                es_dc = 389 in puertos or 88 in puertos

                # Acciones básicas a ejecutar con CrackMapExec
                acciones_generales = ["--shares", "--sessions", "--disks"]

                # Acciones avanzadas si se detecta un DC
                acciones_avanzadas = ["--users", "--groups", "--pass-pol", "--computers", "--rid-brute"]

                # Escribe en el log la IP y credenciales usadas
                log.write(f"[{ip}] {user}:{passwd}\n")

                # Ejecuta cada acción general contra el host
                for accion in acciones_generales:
                    log.write(f"[{ip}] Ejecutando {accion}\n")
                    try:
                        # Ejecuta el comando de CrackMapExec con los parámetros dados
                        result = subprocess.run(
                            ["crackmapexec", "smb", ip, "-u", user, "-p", passwd, accion],
                            capture_output=True, text=True, timeout=30
                        )
                        # Escribe la salida del comando en el log
                        log.write(result.stdout + "\n---\n")
                    except Exception as e:
                        # En caso de error, lo escribe en el log
                        log.write(f"[!] Error en {ip} con {accion}: {e}\n---\n")

                # Si es un DC, ejecuta también las acciones avanzadas
                if es_dc:
                    log.write(f"[{ip}] Detectado como DC, ejecutando acciones avanzadas\n")
                    for accion in acciones_avanzadas:
                        log.write(f"[{ip}] Ejecutando {accion}\n")
                        try:
                            # Ejecuta el comando de CrackMapExec con acción avanzada
                            result = subprocess.run(
                                ["crackmapexec", "smb", ip, "-u", user, "-p", passwd, accion],
                                capture_output=True, text=True, timeout=40
                            )
                            # Escribe la salida en el log
                            log.write(result.stdout + "\n---\n")
                        except Exception as e:
                            # Escribe el error en el log
                            log.write(f"[!] Error en {ip} con {accion}: {e}\n---\n")

    # Informa que la enumeración ha terminado y dónde se encuentra el log
    print(f"[+] Enumeración completada. Log guardado en {log_file}")
