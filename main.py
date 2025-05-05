from utils.api import PentestAPI
from modules.reporting import generate_report
from modules.report_generator import ReportGenerator
import os

def main():

    # Inicializar el API
    api = PentestAPI()

    # Cargar la configuración      
    config = api.load_config()
    target = config.get("ip_range", "192.168.1.0/24")
    output_file = "results/scan_results.json"
    exploits_file = "results/exploits.json"
    report_file = "results/report.html"

    # Asegurarse de que el directorio "results" exista
    os.makedirs("results", exist_ok=True)

    

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
    while True:
        print("\n[*] ¿Qué módulo deseas ejecutar?\n")
        menu_modulos = []
        opciones_menu = {}
        idx = 1

        if "smb" in modulos_disponibles:
            menu_modulos.append(f"{idx}. Ataques SMB (Responder + Crackeo + Enumeración)")
            opciones_menu[idx] = "smb"
            idx += 1

        if "web" in modulos_disponibles:
            menu_modulos.append(f"{idx}. Análisis Web (Fuzzing + Nuclei)")
            opciones_menu[idx] = "web"
            idx += 1

        if "rdp" in modulos_disponibles:
            menu_modulos.append(f"{idx}. Análisis RDP (BlueKeep, fuerza bruta)")
            opciones_menu[idx] = "rdp"
            idx += 1

        if "ftp" in modulos_disponibles:
            menu_modulos.append(f"{idx}. Ataques FTP (Login anónimo, fuerza bruta)")
            opciones_menu[idx] = "ftp"
            idx += 1

        if "mysql" in modulos_disponibles:
            menu_modulos.append(f"{idx}. Ataques MySQL (Sin password, fuerza bruta)")
            opciones_menu[idx] = "mysql"
            idx += 1

        menu_modulos.append(f"{idx}. Ejecutar todo automáticamente")
        opciones_menu[idx] = "auto"
        idx += 1

        menu_modulos.append(f"{idx}. Generar informe final")
        opciones_menu[idx] = "informe"
        idx += 1

        menu_modulos.append(f"{idx}. Salir")
        opciones_menu[idx] = "salir"

        for opcion in menu_modulos:
            print(opcion)

        try:
            eleccion = int(input("\nSelecciona una opción (número): "))
        except EOFError:
            print("\n[!] No se pudo leer entrada. Finalizando ejecución.")
            break
        except ValueError:
            print("[!] Entrada no válida.")
            continue

        accion = opciones_menu.get(eleccion)
        if not accion:
            print("[!] Opción fuera de rango o módulo no disponible.")
            continue

        if accion == "smb":
            print("[*] Ejecutando Ataques SMB...")
            config = api.load_config()
            interface = config.get("interface", "eth0")
            dictionary = config.get("dictionary", "/usr/share/wordlists/rockyou.txt")
            api.ejecutar_ataque_smb(interface=interface, dictionary_path=dictionary)

        elif accion == "web":
            print("[*] Ejecutando Fuzzing y análisis web...")
            api.ejecutar_analisis_web()

        elif accion == "rdp":
            print("[*] Ejecutando análisis de RDP...")
            api.run_rdp_bruteforce()

        elif accion == "ftp":
            print("[*] Ejecutando ataques FTP...")
            api.run_ftp_bruteforce()

        elif accion == "mysql":
            print("[*] Ejecutando ataques MySQL...")
            api.run_mysql_analysis()

        elif accion == "auto":
            print("[*] Ejecutando todos los módulos disponibles...")
            config = api.load_config()
            interface = config.get("interface", "eth0")
            dictionary = config.get("dictionary", "/usr/share/wordlists/rockyou.txt")
            if "smb" in modulos_disponibles:
                api.ejecutar_ataque_smb(interface=interface, dictionary_path=dictionary)
            if "web" in modulos_disponibles:
                api.ejecutar_analisis_web()
            if "rdp" in modulos_disponibles:
                api.run_rdp_bruteforce()
            if "ftp" in modulos_disponibles:
                api.run_ftp_bruteforce()
            if "mysql" in modulos_disponibles:
                api.run_mysql_analysis()
            break

        elif accion == "informe":
            print("[*] Generando informe final...")
            report = ReportGenerator()
            report.generar()

        elif accion == "salir":
            print("[*] Saliendo.")
            break


if __name__ == "__main__":
    main()