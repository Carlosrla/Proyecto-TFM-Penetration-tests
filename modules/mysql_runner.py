import sys
import os
import json

# Añadir el path raíz del proyecto para permitir imports desde 'modules'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mysql.mysql_enum import enumerar_mysql

def ejecutar_mysql_desde_args():
    """
    Ejecuta la enumeración MySQL usando argumentos pasados desde la línea de comandos.
    Uso: python3 modules/mysql_runner.py <IP> <output_file> <creds_file>
    """
    if len(sys.argv) != 4:
        print("Uso: python3 modules/mysql_runner.py <IP> <output_file> <creds_file>")
        sys.exit(1)

    ip = sys.argv[1]
    output_file = sys.argv[2]
    creds_file = sys.argv[3]

    # Cargar credenciales
    credenciales = []
    if os.path.exists(creds_file):
        try:
            with open(creds_file, "r") as f:
                credenciales = json.load(f)
        except Exception as e:
            print(f"[!] Error al leer el archivo de credenciales: {e}")
            credenciales = []

    print(f"[*] Iniciando análisis MySQL en {ip}...")

    try:
        enumerar_mysql(ip, credenciales, output_file)
        print(f"[+] Enumeración MySQL completada. Resultados guardados en {output_file}")
    except Exception as e:
        print(f"[!] Error durante la enumeración de MySQL: {e}")
        sys.exit(1)

if __name__ == "__main__":
    ejecutar_mysql_desde_args()