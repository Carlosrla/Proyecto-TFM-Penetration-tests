from utils.api import PentestAPI
from modules.reporting import generate_report
import os

def main():
    target = "192.168.1.80"
    output_file = "results/scan_results.json"
    exploits_file = "results/exploits.json"
    report_file = "results/report.html"

    # Asegurarse de que el directorio "results" exista
    os.makedirs("results", exist_ok=True)

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

    # Después del reconocimiento
    
    if api.run_service_analysis:
        print("\n[+] Servicios críticos detectados:\n")
        for ip, puertos in api.run_service_analysis.items():
            print(f"Host: {ip}")
            for puerto, acciones in puertos.items():
                print(f"  - Puerto {puerto}: Acciones sugeridas -> {', '.join(acciones)}")
        print("\n[*] ¿Cómo deseas proceder?\n")
        
        opciones = [
            "1. Ejecutar ataques web (HTTP - Fuzzing)",
            "2. Ejecutar ataque SMB (Responder + Crackeo)",
            "3. Ejecutar enumeración avanzada",
            "4. Ejecutar todo automáticamente",
            "5. Salir"
        ]
        
        for opcion in opciones:
            print(opcion)

        eleccion = input("\nSelecciona una opción (1-5): ")

        if eleccion == "1":
            print("[*] Ejecutando ataques web (fuzzing)...")
            # Aquí llamarías a tu módulo web_fuzzing.py en el futuro

        elif eleccion == "2":
            print("[*] Ejecutando Responder y Crackeo de hashes...")
            # Aquí llamarías a credential_capture + hash_cracking

        elif eleccion == "3":
            print("[*] Ejecutando enumeración avanzada...")
            # Aquí invocarías advanced_enumeration.py

        elif eleccion == "4":
            print("[*] Ejecutando todo automáticamente...")
            # Aquí irías ejecutando todo en cadena según lo detectado

        elif eleccion == "5":
            print("[*] Saliendo.")
            exit(0)

        else:
            print("[!] Opción no válida. Terminando.")
    else:
        print("[*] No se detectaron servicios sensibles para analizar.")

if __name__ == "__main__":
    main()