from utils.api import PentestAPI
from modules.reporting import generate_report
import os

def main():
    config = api.load_config()
    target = config.get("ip_range")
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

         # Agrupación de servicios por módulo lógico
        modulos_disponibles = {}

        for ip, puertos in recommendations.items():
            for puerto, acciones in puertos.items():
                for accion in acciones:
                    if accion in ["responder", "crackeo_hashes", "enumeracion_avanzada"]:
                        modulos_disponibles["smb"] = True
                    elif accion in ["fuzzing_directorios", "escaneo_nikto"]:
                        modulos_disponibles["web"] = True
                    elif accion in ["analisis_rdp", "fuerza_bruta"] and int(puerto) == 3389:
                        modulos_disponibles["rdp"] = True
                    elif accion in ["login_anonimo", "fuerza_bruta"] and int(puerto) == 21:
                        modulos_disponibles["ftp"] = True
                    elif accion in ["conexion_sin_password", "fuerza_bruta"] and int(puerto) == 3306:
                        modulos_disponibles["mysql"] = True

        # Menú agrupado por módulo
        print("\n[*] ¿Qué módulo deseas ejecutar?\n")
        menu_modulos = []
        if "smb" in modulos_disponibles:
            menu_modulos.append("1. Ataques SMB (Responder + Crackeo + Enumeración)")
        if "web" in modulos_disponibles:
            menu_modulos.append("2. Análisis Web (Fuzzing + Nikto)")
        if "rdp" in modulos_disponibles:
            menu_modulos.append("3. Análisis RDP (BlueKeep, fuerza bruta)")
        if "ftp" in modulos_disponibles:
            menu_modulos.append("4. Ataques FTP (Login anónimo, fuerza bruta)")
        if "mysql" in modulos_disponibles:
            menu_modulos.append("5. Ataques MySQL (Sin password, fuerza bruta)")

        menu_modulos.append(f"{len(menu_modulos)+1}. Ejecutar todo automáticamente")
        menu_modulos.append(f"{len(menu_modulos)+2}. Salir")

        for opcion in menu_modulos:
            print(opcion)

        try:
            eleccion = int(input("\nSelecciona una opción (número): "))
        except ValueError:
            print("[!] Entrada no válida.")
            return

        if eleccion == 1 and "smb" in modulos_disponibles:
            print("[*] Ejecutando Ataques SMB...")

            # Leer parámetros desde config.json
            config = api.load_config()
            interface = config.get("interface", "eth0")
            dictionary = config.get("dictionary", "/usr/share/wordlists/rockyou.txt")

            # Ejecutar el módulo SMB
            api.ejecutar_ataque_smb(interface=interface, dictionary_path=dictionary)

        elif eleccion == 2 and "web" in modulos_disponibles:
            print("[*] Ejecutando Fuzzing y análisis web...")
            # Aquí: fuzzing_directorios → escaneo_nikto

        elif eleccion == 3 and "rdp" in modulos_disponibles:
            print("[*] Ejecutando análisis de RDP...")
            # Aquí: analisis_rdp → fuerza_bruta

        elif eleccion == 4 and "ftp" in modulos_disponibles:
            print("[*] Ejecutando ataques FTP...")
            # Aquí: login_anonimo → fuerza_bruta

        elif eleccion == 5 and "mysql" in modulos_disponibles:
            print("[*] Ejecutando ataques MySQL...")
            # Aquí: conexion_sin_password → fuerza_bruta

        elif eleccion == len(menu_modulos) - 1:
            print("[*] Ejecutando todo automáticamente...")
            # Ejecutar todos los módulos disponibles

        elif eleccion == len(menu_modulos):
            print("[*] Saliendo.")
            exit(0)
        else:
            print("[!] Opción fuera de rango o módulo no disponible.")

if __name__ == "__main__":
    main()