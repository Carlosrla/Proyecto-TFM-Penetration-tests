import subprocess
import json
import argparse
import xml.etree.ElementTree as ET

def parse_nmap_output(xml_output):
    root = ET.fromstring(xml_output)
    scan_results = {"hosts": []}

    for host in root.findall(".//host"):
        ip = host.find("address").get("addr")
        hostname = host.find("hostnames/hostname")
        hostname = hostname.get("name") if hostname else "N/A"

        ports = []
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name") if service else "unknown"
            ports.append({"port": int(port_id), "service": service_name})

        os_element = host.find("os/osmatch")
        os_name = os_element.get("name") if os_element else "Unknown"

        scan_results["hosts"].append({
            "ip": ip,
            "hostname": hostname,
            "open_ports": ports,
            "os": os_name
        })

    return scan_results


def run_nmap_scan(target, output_file):
    print(f"[+] Escaneando la red: {target}")
    
    nmap_command = ["nmap", "-sV", "-p-", "-O", "--open", "-oX", "-", target]
    
    try:
        nmap_output = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
        parsed_results = parse_nmap_output(nmap_output.stdout)
        parsed_results["target"] = target
        
        with open(output_file, "w") as json_file:
            json.dump(parsed_results, json_file, indent=4)
        
        print(f"[+] Resultados guardados en {output_file}")
    
    except subprocess.CalledProcessError as e:
        print(f"[-] Error ejecutando Nmap: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Módulo de Reconocimiento de Red con Nmap")
    parser.add_argument("--target", required=True, help="Objetivo a escanear (IP o rango de red)")
    parser.add_argument("--output", default="scan_results.json", help="Archivo de salida para guardar resultados")
    args = parser.parse_args()
    
    run_nmap_scan(args.target, args.output)
