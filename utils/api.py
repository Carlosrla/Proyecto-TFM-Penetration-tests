import os
import time
from modules.reconnaissance import Reconnaissance
from modules.service_analysis import analyze_services
from modules.credential_capture import run_responder
from modules.hash_cracking import crack_hashes
from modules.advanced_enumeration import enumerate_with_credentials
from utils.config import load_config as base_load_config
from modules.web_analysis import run_web_analysis
from modules.mysql_enum import enumerar_mysql
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

    def ejecutar_analisis_web(self):
        """
        Lanza el análisis web completo (descubrimiento de directorios + FFUF + Nikto).
        """
        print("[*] Iniciando análisis web...")
        run_web_analysis()
    
    def run_mysql_analysis(self, scan_file="results/scan_results.json", creds_file="results/creds.json"):
    """
    Detecta si hay MySQL activo en los hosts y lanza el análisis correspondiente.
    """
    if not os.path.exists(scan_file):
        print(f"[!] Archivo de escaneo no encontrado: {scan_file}")
        return None

    try:
        with open(scan_file, "r") as f:
            datos = json.load(f)
    except Exception as e:
        print(f"[!] Error leyendo el archivo de escaneo: {e}")
        return None

    # Leer credenciales crackeadas si existen
    credenciales = []
    if os.path.exists(creds_file):
        with open(creds_file, "r") as f:
            try:
                credenciales = json.load(f)
            except:
                pass

    for host in datos.get("hosts", []):
        ip = host.get("ip")
        puertos = [p["port"] for p in host.get("open_ports", [])]
        if 3306 in puertos:
            print(f"[*] MySQL detectado en {ip}. Iniciando análisis...")
            enumerar_mysql(ip, credenciales, output_file=f"results/mysql_{ip}_enum.json")
