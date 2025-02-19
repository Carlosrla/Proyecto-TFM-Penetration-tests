import subprocess
import json
import argparse

def run_nmap_scan(target, output_file):
    print(f"[+] Escaneando la red: {target}")
    
    # Comando Nmap para escanear puertos y detectar servicios
    nmap_command = ["nmap", "-sV", "-p-", "--open", "-oX", "-", target]
    
    try:
        # Ejecutar Nmap y capturar la salida
        nmap_output = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
        
        # Guardar salida en JSON
        result = {"target": target, "scan_output": nmap_output.stdout}
        
        with open(output_file, "w") as json_file:
            json.dump(result, json_file, indent=4)
        
        print(f"[+] Resultados guardados en {output_file}")
    
    except subprocess.CalledProcessError as e:
        print(f"[-] Error ejecutando Nmap: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Módulo de Reconocimiento de Red con Nmap")
    parser.add_argument("--target", required=True, help="Objetivo a escanear (IP o rango de red)")
    parser.add_argument("--output", default="scan_results.json", help="Archivo de salida para guardar resultados")
    args = parser.parse_args()
    
    run_nmap_scan(args.target, args.output)