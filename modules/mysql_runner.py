import sys
import os
import json

# Añadir el path raíz del proyecto para permitir imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from mysql_enum import enumerar_mysql

def cargar_credenciales():
    users_path = os.path.join(ROOT_DIR, "wordlists", "users.txt")
    passwords_path = os.path.join(ROOT_DIR, "wordlists", "passwords.txt")

    if not os.path.exists(users_path) or not os.path.exists(passwords_path):
        print("[!] Archivos de usuarios o contraseñas no encontrados en 'wordlists/'")
        return []

    try:
        with open(users_path, "r") as f:
            usuarios = [line.strip() for line in f if line.strip()]
        with open(passwords_path, "r") as f:
            contrasenas = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error al leer wordlists: {e}")
        return []

    credenciales = [{"user": u, "password": p} for u in usuarios for p in contrasenas]
    return credenciales

def ejecutar_mysql_desde_args():
    if len(sys.argv) != 3:
        print("Uso: python3 mysql_runner.py <IP> <output_file>")
        sys.exit(1)

    ip = sys.argv[1]
    output_file = sys.argv[2]

    credenciales = cargar_credenciales()
    if not credenciales:
        print("[!] No se generaron credenciales. Abortando.")
        sys.exit(1)

    print(f"[*] Iniciando análisis MySQL en {ip}...")

    try:
        enumerar_mysql(ip, credenciales, output_file)
        print(f"[+] Enumeración MySQL completada. Resultados guardados en {output_file}")
    except Exception as e:
        print(f"[!] Error durante la enumeración de MySQL: {e}")
        sys.exit(1)

if __name__ == "__main__":
    ejecutar_mysql_desde_args()