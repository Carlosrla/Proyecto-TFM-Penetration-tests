import subprocess  # Para ejecutar comandos externos (como Nmap)
import json  # Para guardar los resultados en formato JSON
import xml.etree.ElementTree as ET  # Para parsear la salida XML de Nmap
from tqdm import tqdm  # Para mostrar la barra de progreso durante el escaneo
import time  # Para controlar el tiempo de espera en la barra de progreso
from modules.exploit_search import search_exploits  # Función para buscar exploits en los servicios detectados

class Reconnaissance:
    def __init__(self):
        # Bandera para controlar el spinner de carga (no se usa en este código)
        self.stop_spinner = False
        # Puertos considerados críticos para escaneo rápido
        self.CRITICAL_PORTS = "21,22,25,53,80,110,139,143,443,445,1433,2049,3306,3389,5432,5900,6379,8080"

    def parse_nmap_output(self, xml_output):
        """
        Parsea la salida XML de Nmap y la convierte en un diccionario.
        Extrae información de IPs, puertos abiertos, sistema operativo y servicios.
        """
        root = ET.fromstring(xml_output)  # Convierte la cadena XML en árbol de elementos
        scan_results = {"hosts": []}

        # Itera por cada host detectado en el escaneo
        for host in root.findall(".//host"):
            ip = host.find("address").get("addr")  # IP del host
            hostname = host.find("hostnames/hostname")
            hostname = hostname.get("name") if hostname is not None else "N/A"  # Nombre del host (si existe)
            
            ports = []  # Lista de puertos abiertos
            unknown_ports = []  # Lista de puertos con servicio desconocido

            # Recorre los puertos detectados
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"
                service_version = service.get("version") if service is not None else "N/A"
                ports.append({
                    "port": int(port_id),
                    "service": service_name,
                    "version": service_version
                })
                if service_name == "unknown":
                    unknown_ports.append(port_id)

            # Intentar identificar el sistema operativo
            os_element = host.find("os/osmatch")
            os_name = os_element.get("name") if os_element is not None else "Unknown"

            # Guardar la información del host
            scan_results["hosts"].append({
                "ip": ip,
                "hostname": hostname,
                "open_ports": ports,
                "os": os_name
            })

            # Si hay puertos con servicios desconocidos, se ejecuta un escaneo adicional de banners
            if unknown_ports:
                banner_results = self.run_banner_scan(ip, unknown_ports)
                print(f"[+] Información adicional obtenida: {banner_results}")
        
        # Llama a la función que busca exploits para los servicios detectados
        self.search_exploits_for_services(scan_results)

        return scan_results

    def search_exploits_for_services(self, scan_results):
        """
        Busca exploits para los servicios y versiones detectados en cada host.
        Utiliza la función search_exploits para cada servicio identificado.
        """
        for host in scan_results["hosts"]:
            print(f"[+] Buscando exploits para {host['ip']}...")
            for port in host["open_ports"]:
                if port["service"] != "unknown" and port["version"] != "N/A" and port["version"] is not None:
                    print(f"  - Servicio: {port['service']} {port['version']}")
                    search_exploits(port["service"], port["version"], "results/exploits.json")
                else:
                    print(f"  - Servicio: {port['service']} (versión no disponible, omitiendo búsqueda de exploits)")

    def run_banner_scan(self, ip, ports):
        """
        Ejecuta un escaneo de banners para obtener más información sobre puertos desconocidos.
        Utiliza el script `banner` de Nmap.
        """
        port_str = ",".join(ports)  # Convierte la lista de puertos en una cadena separada por comas
        print(f"[+] Ejecutando escaneo adicional en puertos desconocidos: {port_str}")
        nmap_command = ["nmap", "-sV", "--script=banner", "-p", port_str, "-oX", "-", ip]
        try:
            nmap_output = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
            return nmap_output.stdout  # Devuelve la salida XML
        except subprocess.CalledProcessError as e:
            print(f"[-] Error en el escaneo de banners: {e}")
            return None

    def run_nmap_scan(self, target, output_file="results/scan_results.json", scan_type="critical"):
        """
        Ejecuta un escaneo de Nmap mostrando una barra de progreso.
        :param target: IP o rango de IPs a escanear.
        :param output_file: Ruta del archivo donde guardar los resultados.
        :param scan_type: "critical" para puertos comunes, "full" para escaneo completo.
        """
        print(f"[+] Escaneando la red: {target}")
        
        # Selecciona el tipo de escaneo según el parámetro
        if scan_type == "full":
            nmap_command = ["nmap", "-sV", "-p-", "-O", "--open", "--script=banner", "-oX", "-", target]
        elif scan_type == "critical":
            # Si se pasan múltiples objetivos separados por espacios, se añade cada uno por separado
            nmap_command = ["nmap"] + target.split() + ["-sV", "-sS", "-Pn", "-T4", "-p", self.CRITICAL_PORTS, "-O", "--open", "--script=banner", "-oX", "-"]
        else:
            print("[-] Tipo de escaneo no válido.")
            return None

        # Inicia el proceso de escaneo en segundo plano
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Barra de progreso durante el escaneo
        with tqdm(total=100, desc="Progreso del escaneo", unit="%") as pbar:
            while process.poll() is None:  # Mientras el escaneo esté en ejecución
                time.sleep(1)
                pbar.update(1)  # Incrementa el progreso
            pbar.n = 100  # Forzar a 100% al terminar
            pbar.refresh()

        # Captura la salida del comando Nmap
        nmap_output, _ = process.communicate()

        # Si el escaneo fue exitoso y hay salida
        if process.returncode == 0 and nmap_output:
            print("\n[+] Escaneo completado.")
            parsed_results = self.parse_nmap_output(nmap_output)
            parsed_results["target"] = target
            # Guarda los resultados en un archivo JSON
            with open(output_file, "w") as json_file:
                json.dump(parsed_results, json_file, indent=4)
            print(f"[+] Resultados guardados en {output_file}")
            return parsed_results
        else:
            # Si hubo error o la salida está vacía
            print("\n[-] Error ejecutando Nmap o salida vacía.")
            return None
