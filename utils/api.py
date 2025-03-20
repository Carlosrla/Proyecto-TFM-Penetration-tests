import nmap
import json
from utils.logger import setup_logger

logger = setup_logger()

def scan_network(ip_range, arguments):
    logger.info(f"Iniciando escaneo de red en rango {ip_range}")
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments=arguments)
    
    hosts_list = []
    for host in nm.all_hosts():
        host_info = {
            "ip": host,
            "open_ports": []
        }
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]['name']
                state = nm[host][proto][port]['state']
                version = nm[host][proto][port]['version']
                host_info["open_ports"] = host_info.get("open_ports", []) + [
                    {"port": port, "service": service, "state": state, "version": version}]
        logger.info(f"Host escaneado: {host_info}")
        
    with open('results/scan_results.json', 'w') as json_file:
        json.dump(nm.all_hosts(), json_file, indent=4)
    logger.info("Resultados de escaneo guardados en scan_results.json")
    return nm.all_hosts()
