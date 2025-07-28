import json  # Para cargar los resultados del escaneo desde un archivo JSON

# Diccionario que mapea servicios sensibles a las acciones recomendadas para pentesting
SERVICE_ACTIONS = {
    "http": ["fuzzing_directorios", "escaneo_nikto"],
    "https": ["analisis_ssl", "fuzzing_directorios"],
    "ssh": ["fuerza_bruta", "recoleccion_banner"],
    "ftp": ["login_anonimo", "fuerza_bruta"],
    "smb": ["responder", "crackeo_hashes", "enumeracion_avanzada"],
    "microsoft-ds": ["responder", "crackeo_hashes", "enumeracion_avanzada"],
    "netbios-ssn": ["enumeracion_samba"],
    "ms-wbt-server": ["analisis_rdp", "fuerza_bruta"],
    "mysql": ["conexion_sin_password", "fuerza_bruta"]
}

def analyze_services(scan_results_path="results/scan_results.json"):
    """
    Analiza los servicios detectados en el archivo de resultados del escaneo
    y sugiere acciones recomendadas para cada puerto según el tipo de servicio.
    """
    # Carga el archivo JSON con los resultados del escaneo
    with open(scan_results_path, "r") as file:
        scan_data = json.load(file)

    analysis = {}  # Diccionario que almacenará las recomendaciones por host

    # Recorre cada host detectado en el escaneo
    for host in scan_data.get("hosts", []):
        ip = host.get("ip")  # IP del host
        services = host.get("open_ports", [])  # Puertos abiertos con información de servicio
        service_recommendations = {}  # Acciones sugeridas por puerto

        for svc in services:
            port = svc.get("port")  # Número de puerto
            name = svc.get("service", "").lower()  # Nombre del servicio en minúsculas

            # Normaliza nombres relacionados con SMB
            if name in ["microsoft-ds", "netbios-ssn", "smb"]:
                name = "smb"

            # Si el servicio tiene acciones definidas, se asignan
            if name in SERVICE_ACTIONS:
                service_recommendations[str(port)] = SERVICE_ACTIONS[name]

        # Si hay recomendaciones para algún puerto del host, se añaden al análisis
        if service_recommendations:
            analysis[ip] = service_recommendations

    return analysis  # Devuelve el diccionario con recomendaciones por host y puerto

# Permite ejecutar el análisis de forma independiente
if __name__ == "__main__":
    resultados = analyze_services()
    print("[+] Recomendaciones basadas en los servicios detectados:")
    for ip, puertos in resultados.items():
        print(f"Host: {ip}")
        for puerto, acciones in puertos.items():
            print(f"  - Puerto {puerto}: Acciones sugeridas -> {', '.join(acciones)}")
