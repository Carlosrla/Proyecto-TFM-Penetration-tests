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

def enumerar_mysql(ip, credenciales=[], output_file="results/mysql/mysql_enum.json"):

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
    pruebas = credenciales_default + [
        (c.get("user", ""), c.get("password", "")) for c in credenciales
    ]

    for usuario, password in pruebas:
        clave = f"{usuario}:{password}"

        try:
            proc = subprocess.Popen(
                ["mysql", "-h", ip, "-u", usuario, f"-p{password}", "-e", "SHOW DATABASES;", "--ssl=0"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(timeout=10)
            salida = stdout.decode() + stderr.decode()

            if "ERROR" in salida or "denied" in salida.lower():
                resultados["login_test"][clave] = "access_denied"
                continue

            resultados["login_test"][clave] = "access_granted"
            resultados["databases"] = [
                db.strip() for db in salida.splitlines()[1:] if db.strip()
            ]

            proc_users = subprocess.Popen(
                ["mysql", "-h", ip, "-u", usuario, f"-p{password}", "-e", "SELECT user, host FROM mysql.user;", "--ssl=0"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            stdout_users, _ = proc_users.communicate(timeout=10)

            for linea in stdout_users.decode().splitlines()[1:]:
                resultados["users"].append(linea.strip())

            break  # Con una credencial válida es suficiente
        except subprocess.TimeoutExpired:
            resultados["login_test"][clave] = "timeout"
        except Exception:
            resultados["login_test"][clave] = "access_denied"

    with open(output_file, "w") as f:
        json.dump(resultados, f, indent=4)

    print(f"[+] Resultados de MySQL guardados en {output_file}")
    return resultados