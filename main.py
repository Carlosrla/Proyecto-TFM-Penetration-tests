from utils.api import PentestAPI

def main():
    target = "192.168.1.0/24"  # Define el objetivo (rango de IP, IP única o dominio)
    output_file = "results/scan_results.json"  # Ruta para guardar los resultados del escaneo

    # Inicializar el API
    api = PentestAPI()

    # Elegir el tipo de escaneo
    scan_type = input("Selecciona el tipo de escaneo (full/critical): ").strip().lower()

    # Fase 1: Reconocimiento
    print("[*] Iniciando fase de reconocimiento...")
    scan_results = api.scan_network(target, output_file, scan_type)
    
    if scan_results:
        print("[+] Resultados del escaneo:")
        for host in scan_results["hosts"]:
            print(f"  - {host['ip']}: {host['open_ports']}")
    else:
        print("[-] No se encontraron hosts o hubo un error en el escaneo.")

if __name__ == "__main__":
    main()