import subprocess
import json
import xml.etree.ElementTree as ET
from tqdm import tqdm
import time
from modules.exploit_search import search_exploits  # Importar el módulo de búsqueda de exploits

class Reconnaissance:
    def __init__(self):
        self.stop_spinner = False
        self.CRITICAL_PORTS = "21,22,25,53,80,110,139,143,443,445,1433,2049,3306,3389,5432,5900,6379,8080"

    def parse_nmap_output(self, xml_output):
        """
        Parsea la salida XML de Nmap y la convierte en un diccionario.
        """
        root = ET.fromstring(xml_output)
        scan_results = {"hosts": []}
        for host in root.findall(".//host"):
            ip = host.find("address").get("addr")
            hostname = host.find("hostnames/hostname")
            hostname = hostname.get("name") if hostname is not None else "N/A"
            ports = []
            unknown_ports = []
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"
                service_version = service.get("version") if service is not None else "N/A"
                ports.append({"port": int(port_id), "service": service_name, "version": service_version})
                if service_name == "unknown":
                    unknown_ports.append(port_id)
            os_element = host.find("os/osmatch")
            os_name = os_element.get("name") if os_element is not None else "Unknown"
            scan_results["hosts"].append({
                "ip": ip,
                "hostname": hostname,
                "open_ports": ports,
                "os": os_name
            })
            if unknown_ports:
                banner_results = self.run_banner_scan(ip, unknown_ports)
                print(f"[+] Información adicional obtenida: {banner_results}")
        
        # Buscar exploits para los servicios detectados
        self.search_exploits_for_services(scan_results)
        return scan_results

    def search_exploits_for_services(self, scan_results):
        """
        Busca exploits para los servicios y versiones detectados.
        """
        for host in scan_results["hosts"]:
            print(f"[+] Buscando exploits para {host['ip']}...")
            for port in host["open_ports"]:
                if port["service"] != "unknown" and port["version"] != "N/A":
                    print(f"  - Servicio: {port['service']} {port['version']}")
                    search_exploits(port["service"], port["version"])

    def run_banner_scan(self, ip, ports):
        """
        Ejecuta un escaneo de banners en puertos desconocidos.
        """
        port_str = ",".join(ports)
        print(f"[+] Ejecutando escaneo adicional en puertos desconocidos: {port_str}")
        nmap_command = ["nmap", "-sV", "--script=banner", "-p", port_str, "-oX", "-", ip]
        try:
            nmap_output = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
            return nmap_output.stdout
        except subprocess.CalledProcessError as e:
            print(f"[-] Error en el escaneo de banners: {e}")
            return None

    def run_nmap_scan(self, target, output_file="scan_results.json", scan_type="critical"):
        """
        Ejecuta un escaneo de Nmap con una barra de progreso.
        :param target: IP o rango de IPs a escanear.
        :param output_file: Ruta para guardar los resultados.
        :param scan_type: Tipo de escaneo ("full" para todos los puertos, "critical" para puertos críticos).
        """
        print(f"[+] Escaneando la red: {target}")
        
        # Definir el comando de Nmap según el tipo de escaneo
        if scan_type == "full":
            nmap_command = ["nmap", "-sV", "-p-", "-O", "--open", "--script=banner", "-oX", "-", target]
        elif scan_type == "critical":
            nmap_command = ["nmap", "-sV", "-p", self.CRITICAL_PORTS, "-O", "--open", "--script=banner", "-oX", "-", target]
        else:
            print("[-] Tipo de escaneo no válido.")
            return None

        # Ejecutar Nmap en segundo plano
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Barra de progreso
        with tqdm(total=100, desc="Progreso del escaneo", unit="%") as pbar:
            while process.poll() is None:  # Mientras el proceso esté en ejecución
                time.sleep(1)  # Actualizar la barra cada segundo
                pbar.update(1)  # Incrementar la barra en 1%
            pbar.n = 100  # Forzar la barra a 100% cuando el escaneo termine
            pbar.refresh()

        # Obtener la salida de Nmap
        nmap_output, _ = process.communicate()

        if process.returncode == 0:
            print("\n[+] Escaneo completado.")
            parsed_results = self.parse_nmap_output(nmap_output)
            parsed_results["target"] = target
            with open(output_file, "w") as json_file:
                json.dump(parsed_results, json_file, indent=4)
            print(f"[+] Resultados guardados en {output_file}")
            return parsed_results
        else:
            print("\n[-] Error ejecutando Nmap.")
            return None