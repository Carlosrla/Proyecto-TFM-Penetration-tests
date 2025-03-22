from utils.api import PentestAPI
from modules.reporting import generate_report

def main():
    target = "192.168.1.0/24"
    output_file = "results/scan_results.json"
    exploits_file = "results/exploits.json"
    report_file = "results/report.html"

    # Inicializar el API
    api = PentestAPI()

    # Fase 1: Reconocimiento
    print("[*] Iniciando fase de reconocimiento...")
    scan_results = api.scan_network(target, output_file, scan_type="critical")
    
    if scan_results:
        print("[+] Resultados del escaneo:")
        for host in scan_results["hosts"]:
            print(f"  - {host['ip']}: {host['open_ports']}")

        # Fase 2: Generación del informe
        print("[*] Generando informe...")
        generate_report(scan_results, exploits_file, report_file)
    else:
        print("[-] No se encontraron hosts o hubo un error en el escaneo.")

if __name__ == "__main__":
    main()