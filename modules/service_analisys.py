import json

# Servicios sensibles mapeados con acciones recomendadas
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
    with open(scan_results_path, "r") as file:
        scan_data = json.load(file)

    analysis = {}
    for host in scan_data.get("hosts", []):
        ip = host.get("ip")
        services = host.get("open_ports", [])
        service_recommendations = {}

        for svc in services:
            port = svc.get("port")
            name = svc.get("service", "").lower()
            # Normalización de nombres (microsoft-ds, smb, etc.)
            if name in ["microsoft-ds", "netbios-ssn", "smb"]:
                name = "smb"
            if name in SERVICE_ACTIONS:
                service_recommendations[str(port)] = SERVICE_ACTIONS[name]

        if service_recommendations:
            analysis[ip] = service_recommendations

    return analysis

# Prueba rápida si ejecutas este módulo directamente
if __name__ == "__main__":
    resultados = analyze_services()
    print("[+] Recomendaciones basadas en los servicios detectados:")
    for ip, puertos in resultados.items():
        print(f"Host: {ip}")
        for puerto, acciones in puertos.items():
            print(f"  - Puerto {puerto}: Acciones sugeridas -> {', '.join(acciones)}")
