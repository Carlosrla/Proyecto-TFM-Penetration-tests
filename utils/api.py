import os  # Para manejar rutas y archivos
import time  # (No se usa directamente aquí, puede eliminarse si no es necesario)
import json  # Para leer y escribir datos en formato JSON
import subprocess  # Para ejecutar módulos como scripts externos en nuevas terminales

# Importaciones de módulos del framework
from modules.reconnaissance import Reconnaissance  # Escaneo y parsing de Nmap
from modules.service_analysis import analyze_services  # Análisis de servicios detectados
from modules.credential_capture import run_responder  # Captura de hashes SMB
from modules.hash_cracking import crack_hashes  # Crackeo de hashes con Hashcat
from modules.advanced_enumeration import enumerate_with_credentials  # Enumeración SMB con credenciales
from utils.config import load_config as base_load_config  # Carga de configuración
from modules.web_analysis import run_web_analysis  # Módulo de análisis web automatizado
from modules.mysql_enum import enumerar_mysql  # Análisis de MySQL
from modules.rdp_attack import run_rdp_attack  # Fuerza bruta RDP
from modules.ftp_attack import run_ftp_attack  # Fuerza bruta FTP
from utils.common import restaurar_stdin  # Restaurar estado de la entrada estándar

class PentestAPI:
    def __init__(self):
        # Inicializa el módulo de reconocimiento al crear una instancia de la clase
        self.recon = Reconnaissance()

    def load_config(self):
        # Carga configuración desde un archivo externo si es necesario
        return base_load_config()
    
    def scan_network(self, target, output_file="scan_results.json", scan_type="critical"):
        """
        Ejecuta un escaneo de red usando Nmap a través del módulo Reconnaissance.
        :param target: IP, rango de IPs o dominio.
        :param output_file: Archivo JSON donde guardar los resultados.
        :param scan_type: "critical" o "full", define los puertos escaneados.
        """
        return self.recon.run_nmap_scan(target, output_file, scan_type)
    
    def run_service_analysis(self, scan_results_path):
        # Analiza los servicios detectados para determinar qué módulos lanzar después
        return analyze_services(scan_results_path)
    
    def ejecutar_ataque_smb(self, interface, dictionary_path):
        """
        Ejecuta el flujo SMB completo (Responder + Crackeo + Enumeración)
        en una nueva terminal para evitar bloquear la interfaz principal.
        """
        print("[*] Ejecutando ataque SMB en nueva terminal...")

        runner_path = os.path.abspath("modules/smb_runner.py")  # Ruta al script

        cmd = [
            "gnome-terminal",
            "--",
            "bash",
            "-c",
            f"python3 {runner_path} {interface} {dictionary_path}"
        ]

        try:
            subprocess.run(cmd, check=True)  # Espera hasta que la terminal termine
            print("[+] Módulo SMB finalizado.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error al ejecutar el módulo SMB: {e}")

    def ejecutar_analisis_web(self):
        """
        Ejecuta el módulo de análisis web completo:
        - Detecta directorios interesantes
        - Lanza FFUF y Nuclei
        - Genera informes por cada subdirectorio encontrado
        """
        print("[*] Iniciando análisis web...")
        run_web_analysis()
        restaurar_stdin()
        try:
            # Finaliza procesos residuales de FFUF y Nikto si siguen activos
            subprocess.run(["pkill", "-f", "ffuf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "nikto"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al limpiar procesos web: {e}")

    def run_mysql_analysis(self, scan_file="results/scan_results.json"):
        """
        Ejecuta el módulo de análisis MySQL si se detecta el puerto 3306 en el escaneo.
        Abre una nueva terminal para lanzar el script con su propia lógica.
        """
        if not os.path.exists(scan_file):
            print(f"[!] Archivo de escaneo no encontrado: {scan_file}")
            return

        try:
            with open(scan_file, "r") as f:
                datos = json.load(f)
        except Exception as e:
            print(f"[!] Error leyendo el archivo de escaneo: {e}")
            return

        # Itera sobre los hosts y busca si alguno tiene MySQL (puerto 3306)
        for host in datos.get("hosts", []):
            ip = host.get("ip")
            puertos = [p["port"] for p in host.get("open_ports", [])]
            if 3306 in puertos:
                print(f"[*] MySQL detectado en {ip}. Iniciando análisis...")

                output_path = f"results/mysql/mysql_{ip}.json"
                os.makedirs("results/mysql", exist_ok=True)

                # Ejecuta mysql_runner en una nueva terminal
                cmd = [
                    "gnome-terminal",
                    "--",
                    "bash",
                    "-c",
                    f"python3 modules/mysql_runner.py {ip} {output_path}"
                ]
                try:
                    subprocess.run(cmd, check=True)
                    print("[+] Módulo MySQL finalizado correctamente.")
                except subprocess.CalledProcessError as e:
                    print(f"[!] Error al lanzar terminal o ejecutar módulo: {e}")

    def run_rdp_bruteforce(self):
        """
        Lanza el ataque de fuerza bruta RDP directamente.
        Luego intenta cerrar cualquier proceso residual de xfreerdp.
        """
        run_rdp_attack()
        restaurar_stdin()
        try:
            subprocess.run(["pkill", "-f", "xfreerdp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al limpiar procesos RDP: {e}")

    def run_ftp_bruteforce(self):
        """
        Lanza el ataque de fuerza bruta FTP.
        Luego intenta cerrar procesos residuales de herramientas como hydra.
        """
        run_ftp_attack()
        restaurar_stdin()
        try:
            subprocess.run(["pkill", "-f", "hydra"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Error al limpiar procesos FTP: {e}")
