
import subprocess
import os
import json

def probar_login_mysql(ip, usuario, contrasena=""):
    """
    Intenta conectarse a MySQL en el host objetivo con las credenciales proporcionadas.
    Retorna True si la conexión fue exitosa, False si fue denegada.
    """
    try:
        resultado = subprocess.run(
            ["mysql", "-h", ip, "-u", usuario, f"-p{contrasena}", "--ssl=0", "-e", "SHOW DATABASES;"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        if "Access denied" in resultado.stderr.decode():
            return False
        return True
    except Exception:
        return False

def obtener_banner_mysql(ip):
    """
    Obtiene información de versión de MySQL usando el banner.
    """
    try:
        resultado = subprocess.run(["mysql", "-h", ip, "-P", "3306", "--ssl=0"], capture_output=True, timeout=5)
        salida = resultado.stdout.decode() + resultado.stderr.decode()
        for linea in salida.splitlines():
            if "Ver" in linea or "Distrib" in linea:
                return linea
        return "Desconocido"
    except Exception:
        return "No accesible"

def enumerar_mysql(ip, credenciales=[], output_file="results/mysql_enum.json"):
    """
    Analiza el servicio MySQL del host dado.
    Intenta logins, recoge versión y lista bases de datos y usuarios si accede.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    resultados = {
        "host": ip,
        "port": 3306,
        "version": obtener_banner_mysql(ip),
        "login_test": {},
        "databases": [],
        "users": []
    }

    usuarios_a_probar = ["root", "admin", "mysql", "user"]
    credenciales_default = [(u, "") for u in usuarios_a_probar]

    # Unir credenciales por defecto + capturadas
    pruebas = credenciales_default + [(c["usuario"], c["password"]) for c in credenciales]

    for usuario, password in pruebas:
        clave = f"{usuario}:{password}"
        acceso = probar_login_mysql(ip, usuario, password)
        resultados["login_test"][clave] = "access_granted" if acceso else "access_denied"

        if acceso:
            try:
                salida = subprocess.check_output([
                    "mysql", "-h", ip, "-u", usuario, f"-p{password}", "--ssl=0",
                    "-e", "SHOW DATABASES;"
                ]).decode()
                resultados["databases"] = [db.strip() for db in salida.splitlines()[1:] if db.strip()]

                salida_usuarios = subprocess.check_output([
                    "mysql", "-h", ip, "-u", usuario, f"-p{password}", "--ssl=0",
                    "-e", "SELECT user, host FROM mysql.user;"
                ]).decode()

                for linea in salida_usuarios.splitlines()[1:]:
                    resultados["users"].append(linea.strip())
            except Exception:
                pass
            break

    with open(output_file, "w") as f:
        json.dump(resultados, f, indent=4)

    print(f"[+] Resultados de MySQL guardados en {output_file}")
    return resultados