import sys  # Para acceder a los argumentos pasados por consola y terminar el programa
import os  # Para manipular rutas de archivos y carpetas
import json  # No se utiliza en este script, pero comúnmente empleado para resultados

# Añadir el path raíz del proyecto al sys.path para permitir importar módulos propios
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # Carpeta actual (donde está este script)
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))  # Carpeta raíz del proyecto (un nivel arriba)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)  # Se añade al path para que se puedan importar módulos personalizados

# Importa la función de enumeración desde el módulo mysql_enum.py
from mysql_enum import enumerar_mysql

def cargar_credenciales():
    """
    Lee las wordlists de usuarios y contraseñas, y genera combinaciones.
    Devuelve una lista de diccionarios con pares usuario/contraseña.
    """
    users_path = os.path.join(ROOT_DIR, "wordlists", "users.txt")
    passwords_path = os.path.join(ROOT_DIR, "wordlists", "passwords.txt")

    # Verifica si existen los archivos de wordlist
    if not os.path.exists(users_path) or not os.path.exists(passwords_path):
        print("[!] Archivos de usuarios o contraseñas no encontrados en 'wordlists/'")
        return []

    try:
        # Lee usuarios y contraseñas, eliminando espacios en blanco y líneas vacías
        with open(users_path, "r") as f:
            usuarios = [line.strip() for line in f if line.strip()]
        with open(passwords_path, "r") as f:
            contrasenas = [line.strip() for line in f if line.strip()]
    except Exception as e:
        # Si hay error leyendo los archivos, lo muestra y retorna lista vacía
        print(f"[!] Error al leer wordlists: {e}")
        return []

    # Crea todas las combinaciones posibles entre usuarios y contraseñas
    credenciales = [{"user": u, "password": p} for u in usuarios for p in contrasenas]
    return credenciales

def ejecutar_mysql_desde_args():
    """
    Ejecuta el análisis de MySQL usando parámetros pasados por línea de comandos.
    Uso: python3 mysql_runner.py <IP> <output_file>
    """
    if len(sys.argv) != 3:
        # Muestra el formato correcto si faltan argumentos
        print("Uso: python3 mysql_runner.py <IP> <output_file>")
        sys.exit(1)

    # Extrae los argumentos pasados por consola
    ip = sys.argv[1]
    output_file = sys.argv[2]

    # Carga las credenciales desde las wordlists
    credenciales = cargar_credenciales()
    if not credenciales:
        print("[!] No se generaron credenciales. Abortando.")
        sys.exit(1)

    print(f"[*] Iniciando análisis MySQL en {ip}...")

    try:
        # Ejecuta el módulo de enumeración de MySQL con las credenciales generadas
        enumerar_mysql(ip, credenciales, output_file)
        print(f"[+] Enumeración MySQL completada. Resultados guardados en {output_file}")
    except Exception as e:
        # Muestra el error si algo falla durante la ejecución
        print(f"[!] Error durante la enumeración de MySQL: {e}")
        sys.exit(1)

# Punto de entrada del script si se ejecuta directamente
if __name__ == "__main__":
    ejecutar_mysql_desde_args()
