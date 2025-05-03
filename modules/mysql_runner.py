import json
import os
from modules.mysql.mysql_enum import enumerar_mysql

def ejecutar_mysql_standalone(scan_file="results/scan_results.json", creds_file="results/creds.json"):
    if not os.path.exists(scan_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_file}")
        return

    try:
        with open(scan_file, "r") as f:
            datos = json.load(f)
    except Exception as e:
        print(f"[!] Error leyendo el archivo de escaneo: {e}")
        return

    credenciales = []
    if os.path.exists(creds_file):
        try:
            with open(creds_file, "r") as f:
                credenciales = json.load(f)
        except:
            print("[!] Error al cargar las credenciales, se usará una lista vacía.")

    for host in datos.get("hosts", []):
        ip = host.get("ip")
        puertos = [p["port"] for p in host.get("open_ports", [])]
        if 3306 in puertos:
            print(f"[*] MySQL detectado en {ip}. Iniciando enumeración...")
            enumerar_mysql(ip, credenciales, output_file=f"results/mysql/mysql_{ip}.json")

    print("[+] Enumeración MySQL finalizada.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 4:
        ip = sys.argv[1]
        output_file = sys.argv[2]
        creds_file = sys.argv[3]

        from modules.mysql.mysql_enum import enumerar_mysql
        try:
            with open(creds_file, "r") as f:
                credenciales = json.load(f)
        except:
            credenciales = []

        enumerar_mysql(ip, credenciales, output_file)
    else:
        print("Uso: python3 mysql_runner.py <IP> <output_file> <creds_file>")