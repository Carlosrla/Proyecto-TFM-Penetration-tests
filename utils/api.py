import os
import time
import json
import subprocess

from modules.reconnaissance import Reconnaissance
from modules.service_analysis import analyze_services
from modules.credential_capture import run_responder
from modules.hash_cracking import crack_hashes
from modules.advanced_enumeration import enumerate_with_credentials
from utils.config import load_config as base_load_config
from modules.web_analysis import run_web_analysis
from modules.mysql_enum import enumerar_mysql
from modules.rdp_attack import run_rdp_attack
from modules.ftp_attack import run_ftp_attack
from utils.common import restaurar_stdin

class PentestAPI:
    def __init__(self):
        self.recon = Reconnaissance()  # Inicializa el módulo de reconocimiento

    def load_config(self):
        return base_load_config()
    
    def scan_network(self, target, output_file="scan_results.json", scan_type="critical"):
        """
        Escanea la red usando el módulo de reconocimiento.
        :param target: Rango de IP, IP única o dominio.
        :param output_file: Ruta para guardar los resultados.
        :param scan_type: Tipo de escaneo ("full" o "critical").
        :return: Resultados del escaneo en formato JSON.
        """
        return self.recon.run_nmap_scan(target, output_file, scan_type)
    
    def run_service_analysis(self, scan_results_path):
        return analyze_services(scan_results_path)
    
    def ejecutar_ataque_smb(self, interface, dictionary_path):
        print("[*] Lanzando ataque SMB: Responder + Hashcat + Enumeración")

        # Paso 1: Ejecutar Responder y capturar hashes
        success = run_responder(interface)

        if not success:
            print("[-] No se capturaron hashes. Abortando módulo SMB.")
            return

        credenciales = crack_hashes("results/hashes.txt", dictionary_path)

        if not credenciales:
            print("[!] No se pudo crackear ningún hash.")
            return

        if not credenciales:
            print("[!] No se pudo crackear ningún hash.")
            return

        # Paso 3: Enumeración avanzada
        enumerate_with_credentials(credenciales)
        restaurar_stdin()
        # Al finalizar, matar procesos peligrosos si siguen vivos
        try:
            subprocess.run(["pkill", "-f", "Responder"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al finalizar Responder: {e}")

    def ejecutar_analisis_web(self):
        """
        Lanza el análisis web completo (descubrimiento de directorios + FFUF + Nikto).
        """
        print("[*] Iniciando análisis web...")
        run_web_analysis()
        restaurar_stdin()
        try:
            subprocess.run(["pkill", "-f", "ffuf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "nikto"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al limpiar procesos web: {e}")

    def run_mysql_analysis(self, scan_file="results/scan_results.json", creds_file="results/creds.json"):
    if not os.path.exists(scan_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_file}")
        return

    try:
        with open(scan_file, "r") as f:
            datos = json.load(f)
    except Exception as e:
        print(f"[!] Error leyendo el archivo de escaneo: {e}")
        return

    for host in datos.get("hosts", []):
        ip = host.get("ip")
        puertos = [p["port"] for p in host.get("open_ports", [])]
        if 3306 in puertos:
            print(f"[*] MySQL detectado en {ip}. Iniciando análisis...")

            output_path = f"results/mysql/mysql_{ip}.json"
            os.makedirs("results/mysql", exist_ok=True)

            # Lanza en nueva terminal (Gnome)
            cmd = [
                "gnome-terminal",
                "--",
                "python3",
                "modules/mysql_runner.py",
                ip,
                output_path,
                creds_file
            ]
            try:
                subprocess.Popen(cmd)
                print("[+] Módulo MySQL ejecutándose en una nueva terminal.")
            except Exception as e:
                print(f"[!] Error al lanzar nueva terminal: {e}")

    def run_rdp_bruteforce(self):
        run_rdp_attack()
        restaurar_stdin()
        try:
            subprocess.run(["pkill", "-f", "xfreerdp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al limpiar procesos RDP: {e}")

    def run_ftp_bruteforce(self):
        run_ftp_attack()
        restaurar_stdin()
        try:
            subprocess.run(["pkill", "-f", "hydra"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al limpiar procesos FTP: {e}")