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
    recommendations = api.run_service_analysis(output_file)

    if recommendations:
        print("\n[+] Servicios críticos detectados:\n")
        for ip, puertos in recommendations.items():
            print(f"Host: {ip}")
            for puerto, acciones in puertos.items():
                print(f"  - Puerto {puerto}: Acciones sugeridas -> {', '.join(acciones)}")

        # Generar menú dinámico basado en acciones detectadas
        acciones_detectadas = set()
        for ip, puertos in recommendations.items():
            for acciones in puertos.values():
                acciones_detectadas.update(acciones)

        # Descripciones legibles para el usuario
        descripciones = {
            "fuzzing_directorios": "Ejecutar fuzzing web (ffuf, gobuster)",
            "escaneo_nikto": "Escanear vulnerabilidades web (Nikto)",
            "responder": "Capturar hashes con Responder (SMB)",
            "crackeo_hashes": "Crackear hashes con Hashcat",
            "enumeracion_avanzada": "Enumerar usuarios, shares, permisos (SMB)",
            "analisis_rdp": "Analizar configuración RDP (Bluekeep, NLA)",
            "fuerza_bruta": "Fuerza bruta contra servicios detectados (RDP/SSH/FTP)",
            "login_anonimo": "Probar acceso anónimo en FTP",
            "conexion_sin_password": "Intentar conexión MySQL sin contraseña",
            "recoleccion_banner": "Recolectar banners SSH/FTP",
            "analisis_ssl": "Analizar configuración de SSL/TLS"
        }

        acciones_lista = sorted(list(acciones_detectadas))
        print("\n[*] ¿Cómo deseas proceder?\n")
        for idx, accion in enumerate(acciones_lista, start=1):
            desc = descripciones.get(accion, accion)
            print(f"{idx}. {desc}")

        print(f"{len(acciones_lista) + 1}. Ejecutar todo automáticamente")
        print(f"{len(acciones_lista) + 2}. Salir")

        # Entrada del usuario
        try:
            eleccion = int(input("\nSelecciona una opción (número): "))
        except ValueError:
            print("[!] Entrada no válida.")
            return

        if 1 <= eleccion <= len(acciones_lista):
            accion_seleccionada = acciones_lista[eleccion - 1]
            print(f"[*] Ejecutando acción seleccionada: {accion_seleccionada}")
            # Aquí puedes enlazar con los módulos que correspondan según el nombre técnico
            if accion_seleccionada == "fuzzing_directorios":
                print("[!] (Aquí se llamaría al módulo web_fuzzing.py)")
            elif accion_seleccionada == "responder":
                print("[!] (Aquí se llamaría a credential_capture.py)")
            elif accion_seleccionada == "crackeo_hashes":
                print("[!] (Aquí se llamaría a hash_cracking.py)")
            elif accion_seleccionada == "analisis_rdp":
                print("[!] (Aquí se llamaría a rdp_analysis.py)")
            elif accion_seleccionada == "enumeracion_avanzada":
                print("[!] (Aquí se llamaría a advanced_enumeration.py)")
            elif accion_seleccionada == "fuerza_bruta":
                print("[!] (Aquí se lanzaría Hydra, Medusa u otra herramienta)")

        elif eleccion == len(acciones_lista) + 1:
            print("[*] Ejecutando todo automáticamente...")
            # Aquí lanzarías en cadena todas las acciones detectadas

        elif eleccion == len(acciones_lista) + 2:
            print("[*] Saliendo.")
            exit(0)
        else:
            print("[!] Opción fuera de rango. Terminando.")
    else:
        print("[*] No se detectaron servicios sensibles para analizar.")

if __name__ == "__main__":
    main()