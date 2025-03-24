from modules.reconnaissance import Reconnaissance
from modules.service_analysis import analyze_services

class PentestAPI:
    def __init__(self):
        self.recon = Reconnaissance()  # Inicializa el módulo de reconocimiento

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