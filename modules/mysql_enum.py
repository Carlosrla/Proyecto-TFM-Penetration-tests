import subprocess  # Para ejecutar comandos del sistema (cliente mysql)
import os  # Para gestionar rutas y creación de carpetas
import json  # Para guardar los resultados en formato JSON

# Carpeta donde se guardarán los resultados
MYSQL_RESULTS_DIR = "results"

def probar_login_mysql(ip, usuario, contrasena=""):
    """
    Intenta conectarse a MySQL con un usuario y contraseña dados.
    Retorna True si la conexión es válida, False si se deniega o hay error.
    """
    try:
        resultado = subprocess.run(
            ["mysql", "-h", ip, "-u", usuario, f"-p{contrasena}", "--ssl=0", "-e", "SHOW DATABASES;"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        # Si la salida indica "Access denied", se retorna False
        if "Access denied" in resultado.stderr.decode():
            return False
        return True  # Credenciales válidas
    except Exception:
        return False  # Cualquier fallo también se considera denegado

def obtener_banner_mysql(ip):
    """
    Intenta conectarse al servidor MySQL para obtener el banner de versión.
    Retorna la línea donde aparece la versión, si está disponible.
    """
    try:
        resultado = subprocess.run(["mysql", "-h", ip, "-P", "3306", "--ssl=0"], capture_output=True, timeout=5)
        salida = resultado.stdout.decode() + resultado.stderr.decode()
        for linea in salida.splitlines():
            # Busca líneas que puedan indicar la versión de MySQL
            if "Ver" in linea or "Distrib" in linea:
                return linea
        return "Desconocido"  # Si no se detecta versión
    except Exception:
        return "No accesible"  # Error al conectar

def enumerar_mysql(ip, credenciales=[], output_file="results/mysql/mysql_enum.json"):
    """
    Ejecuta pruebas de login y enumera bases de datos y usuarios si las credenciales funcionan.
    Guarda los resultados en un archivo JSON estructurado.
    """

    # Asegura que el directorio destino existe
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Diccionario de resultados a guardar
    resultados = {
        "host": ip,
        "port": 3306,
        "version": "Desconocido",
        "login_test": {},  # Resultado de cada intento de login
        "databases": [],   # Lista de bases de datos visibles
        "users": []        # Lista de usuarios extraídos
    }

    # Lista por defecto de usuarios a probar sin contraseña
    usuarios_a_probar = ["root", "admin", "mysql", "user"]
    credenciales_default = [(u, "") for u in usuarios_a_probar]

    # Se combinan las credenciales por defecto con las externas recibidas por parámetro
    pruebas = credenciales_default + [
        (c.get("user", ""), c.get("password", "")) for c in credenciales
    ]

    # Se prueba cada par usuario:contraseña
    for usuario, password in pruebas:
        clave = f"{usuario}:{password}"

        try:
            # Ejecuta el comando para listar bases de datos con ese login
            proc = subprocess.Popen(
                ["mysql", "-h", ip, "-u", usuario, f"-p{password}", "-e", "SHOW DATABASES;", "--ssl=0"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(timeout=10)
            salida = stdout.decode() + stderr.decode()

            # Si contiene error o denegación, se registra como fallo
            if "ERROR" in salida or "denied" in salida.lower():
                resultados["login_test"][clave] = "access_denied"
                continue

            # Credenciales válidas, se registra acceso
            resultados["login_test"][clave] = "access_granted"
            # Se extraen las bases de datos, ignorando la cabecera
            resultados["databases"] = [
                db.strip() for db in salida.splitlines()[1:] if db.strip()
            ]

            # Intenta extraer usuarios de la tabla mysql.user
            proc_users = subprocess.Popen(
                ["mysql", "-h", ip, "-u", usuario, f"-p{password}", "-e", "SELECT user, host FROM mysql.user;", "--ssl=0"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            stdout_users, _ = proc_users.communicate(timeout=10)

            # Añade cada línea del resultado (sin la cabecera) a la lista de usuarios
            for linea in stdout_users.decode().splitlines()[1:]:
                resultados["users"].append(linea.strip())

            break  # Si se ha logrado acceso, no se sigue probando más credenciales

        except subprocess.TimeoutExpired:
            # Si el comando tarda demasiado, se marca como "timeout"
            resultados["login_test"][clave] = "timeout"
        except Exception:
            # Cualquier otro fallo se marca como acceso denegado
            resultados["login_test"][clave] = "access_denied"

    # Guarda todos los resultados en el archivo JSON de salida
    with open(output_file, "w") as f:
        json.dump(resultados, f, indent=4)

    # Informa que los resultados se han guardado
    print(f"[+] Resultados de MySQL guardados en {output_file}")
    return resultados  # Devuelve el diccionario para uso posterior
