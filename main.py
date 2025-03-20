from utils.api import PentestAPI

def main():
    target = "192.168.1.0/24"
    output_file = "results/scan_results.json"

    # Inicializar el API
    api = PentestAPI()

    # Fase 1: Reconocimiento
    scan_results = api.scan_network(target, output_file)
    if scan_results:
        print("[+] Resultados del escaneo:")
        for host in scan_results["hosts"]:
            print(f"  - {host['ip']}: {host['open_ports']}")

if __name__ == "__main__":
    main()