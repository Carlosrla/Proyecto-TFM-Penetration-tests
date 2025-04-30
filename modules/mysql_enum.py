import subprocess
import os
import json

MYSQL_RESULTS_DIR = "results"

def probar_login_mysql(ip, usuario, contrasena=""):
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
    import os
    import json
    import subprocess

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    resultados = {
        "host": ip,
        "port": 3306,
        "version": "Desconocido",
        "login_test": {},
        "databases": [],
        "users": []
    }

    usuarios_a_probar = ["root", "admin", "mysql", "user"]
    credenciales_default = [(u, "") for u in usuarios_a_probar]
    pruebas = credenciales_default + [(c["usuario"], c["password"]) for c in credenciales]

    for usuario, password in pruebas:
        clave = f"{usuario}:{password}"

        try:
            resultado = subprocess.run(
                ["mysql", "-h", ip, "-u", usuario, f"-p{password}", "-e", "SHOW DATABASES;"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
            )
            salida = resultado.stdout.decode() + resultado.stderr.decode()

            if "ERROR" in salida or "denied" in salida.lower():
                resultados["login_test"][clave] = "access_denied"
                continue

            resultados["login_test"][clave] = "access_granted"
            resultados["databases"] = [
                db.strip() for db in salida.splitlines()[1:] if db.strip()
            ]

            resultado_users = subprocess.run(
                ["mysql", "-h", ip, "-u", usuario, f"-p{password}", "-e", "SELECT user, host FROM mysql.user;"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5
            )

            salida_users = resultado_users.stdout.decode()
            for linea in salida_users.splitlines()[1:]:
                resultados["users"].append(linea.strip())

            break  # No hace falta seguir probando si ya accedimos
        except Exception:
            resultados["login_test"][clave] = "access_denied"

    with open(output_file, "w") as f:
        json.dump(resultados, f, indent=4)

    print(f"[+] Resultados de MySQL guardados en {output_file}")
    return resultados