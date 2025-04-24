import subprocess
import os
import json
from datetime import datetime

RESULTS_DIR = "results"
MYSQL_RESULTS_DIR = os.path.join(RESULTS_DIR, "mysql")
os.makedirs(MYSQL_RESULTS_DIR, exist_ok=True)

CREDENCIALES_COMUNES = [
    ("root", ""),
    ("root", "root"),
    ("root", "admin"),
    ("root", "1234"),
    ("root", "toor"),
    ("admin", ""),
    ("admin", "root")
]

def probar_login_mysql(ip, usuario, contrasena=""):
    try:
        resultado = subprocess.run(
            ["mysql", "-h", ip, "-u", usuario, f"-p{contrasena}", "--ssl=0", "-e", "SHOW DATABASES;"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        if b"Access denied" in resultado.stderr:
            return False
        return True
    except Exception:
        return False

def obtener_banner_mysql(ip):
    try:
        resultado = subprocess.run(["mysql", "-h", ip, "--ssl=0"], capture_output=True, timeout=5)
        salida = resultado.stdout.decode() + resultado.stderr.decode()
        for linea in salida.splitlines():
            if "Ver" in linea or "Distrib" in linea:
                return linea
        return "Desconocido"
    except Exception:
        return "No accesible"

def enumerar_mysql(ip):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_output_file = os.path.join(MYSQL_RESULTS_DIR, f"mysql_{ip}_enum.json")
    txt_output_file = os.path.join(MYSQL_RESULTS_DIR, f"mysql_{ip}_analisis.txt")

    resultados = {
        "host": ip,
        "port": 3306,
        "version": obtener_banner_mysql(ip),
        "login_test": {},
        "databases": [],
        "users": []
    }

    for usuario, password in CREDENCIALES_COMUNES:
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

    with open(json_output_file, "w") as f:
        json.dump(resultados, f, indent=4)

    with open(txt_output_file, "w") as out:
        out.write(f"# Análisis MySQL - {ip}:3306\n\n")
        out.write("== Pruebas de acceso ==\n")
        for k, v in resultados["login_test"].items():
            simbolo = "✅" if v == "access_granted" else "  "
            out.write(f"- {k:<20} → {simbolo} {v}\n")

        out.write("\n== Bases de datos detectadas ==\n")
        for db in resultados["databases"]:
            out.write(f"- {db}\n")

        out.write("\n== Usuarios detectados ==\n")
        for usr in resultados["users"]:
            out.write(f"- {usr}\n")

        out.write("\n" + "="*50 + "\n")

    print(f"[+] Resultados de MySQL guardados en {json_output_file}")
    print(f"[+] Análisis formateado guardado en {txt_output_file}")