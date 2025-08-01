import os  # Para trabajar con rutas de archivos y directorios
import json  # Para cargar y guardar información en formato JSON

class ReportGenerator:
    def __init__(self, results_dir="results"):
        # Directorio donde se encuentran todos los resultados del pentesting
        self.results_dir = results_dir

    def modulo_existe(self, path):
        # Comprueba si el archivo existe y no está vacío
        return os.path.exists(path) and os.path.getsize(path) > 0

    def generar(self):
        # Lista que contiene las líneas HTML que formarán el informe final
        html = [
            "<html lang='es'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "<title>Informe de Pentest</title>",
            "<link rel='icon' href='https://www.svgrepo.com/show/475695/bug.svg'>",
            "<style>",  # Estilos del informe en CSS
            "body { background-color: #121212; color: #ffffff; font-family: 'Segoe UI', sans-serif; padding: 20px; }",
            "h1, h2, h3 { color: #00e676; }",
            "pre { background: #1e1e1e; padding: 10px; overflow-x: auto; border-left: 4px solid #00e676; }",
            ".ok { color: #00e676; font-weight: bold; }",
            ".bad { color: #ff5252; font-weight: bold; }",
            ".medium { color: #ffc107; font-weight: bold; }",
            ".box { background: #1e1e1e; padding: 15px; margin: 10px 0; border-radius: 5px; overflow-x: auto; word-wrap: break-word; overflow-wrap: break-word; white-space: pre-wrap; }",
            "table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }",
            "th, td { border: 1px solid #555; padding: 8px; text-align: left; }",
            "th { background-color: #2e7d32; color: white; }",
            ".critical { background-color: #ff1744; color: white; }",
            ".high { background-color: #ff9100; color: black; }",
            ".medium { background-color: #ffee58; color: black; }",
            ".low { background-color: #69f0ae; color: black; }",
            "details summary { cursor: pointer; padding: 4px; margin: 5px 0; font-weight: bold; }",
            "</style></head><body>",
            "<h1>Informe Final de Pentesting</h1>",
            self.tabla_resumen_ejecutiva()  # Sección de resumen ejecutivo
        ]

        # Añadir secciones dinámicamente según módulos encontrados
        scan = os.path.join(self.results_dir, "scan_results.json")
        if self.modulo_existe(scan):
            html.append(self.seccion_scan(scan))

        exploits = os.path.join(self.results_dir, "exploits.json")
        if self.modulo_existe(exploits):
            html.append(self.seccion_exploits(exploits))

        mysql_dir = os.path.join(self.results_dir, "mysql")
        if os.path.isdir(mysql_dir):
            html.append(self.seccion_mysql(mysql_dir))

        # Módulo SMB
        smb_hashes = os.path.join(self.results_dir, "smb", "hashes.txt")
        smb_creds = os.path.join(self.results_dir, "smb", "creds.json")
        smb_enum = os.path.join(self.results_dir, "smb", "smb_enum.log")
        if self.modulo_existe(smb_hashes) or self.modulo_existe(smb_creds):
            html.append(self.seccion_smb(smb_hashes, smb_creds, smb_enum))

        # Módulo Web
        web_dir = os.path.join(self.results_dir, "web_enum")
        if os.path.isdir(web_dir):
            html.append(self.seccion_web(web_dir))

        # Módulo FTP
        ftp_dir = os.path.join(self.results_dir, "ftp")
        if os.path.isdir(ftp_dir):
            for fname in os.listdir(ftp_dir):
                if fname.endswith(".json"):
                    ftp_path = os.path.join(ftp_dir, fname)
                    if self.modulo_existe(ftp_path):
                        html.append(self.seccion_ftp(ftp_path))

        # Módulo RDP
        rdp_dir = os.path.join(self.results_dir, "rdp")
        if os.path.isdir(rdp_dir):
            for fname in os.listdir(rdp_dir):
                if fname.endswith(".json"):
                    rdp_path = os.path.join(rdp_dir, fname)
                    if self.modulo_existe(rdp_path):
                        html.append(self.seccion_rdp(rdp_path))

        # Cierre del HTML
        html.append("</body></html>")

        # Escribe el HTML final en un archivo
        with open("results/report.html", "w") as f:
            f.write("\n".join(html))
        print("[+] Informe generado como results/report.html")

    def tabla_resumen_ejecutiva(self):
        """
        Genera una tabla resumen de servicios comprometidos con su severidad y credenciales.
        """
        filas = []

        # Detectar IP con SMB activo
        scan_file = os.path.join(self.results_dir, "scan_results.json")
        ip_smb = "IP no especificada"
        if self.modulo_existe(scan_file):
            with open(scan_file) as f:
                scan_data = json.load(f)
                for h in scan_data.get("hosts", []):
                    for p in h.get("open_ports", []):
                        if p.get("port") == 445:
                            ip_smb = h.get("ip")
                            break

        # Añadir credenciales SMB crackeadas
        smb_creds_path = os.path.join(self.results_dir, "smb", "creds.json")
        if self.modulo_existe(smb_creds_path):
            with open(smb_creds_path) as f:
                creds = json.load(f)
                for c in creds:
                    filas.append([ip_smb, "SMB", "Credencial crackeada", "Alta", f"{c['usuario']}:{c['password']}"])

        # Añadir credenciales FTP válidas
        ftp_dir = os.path.join(self.results_dir, "ftp")
        for fname in os.listdir(ftp_dir):
            if fname.endswith(".json"):
                ftp_path = os.path.join(ftp_dir, fname)
                if self.modulo_existe(ftp_path):
                    with open(ftp_path) as f:
                        data = json.load(f)
                        ip = data.get("host")
                        for cred in data.get("valid_credentials", []):
                            if ip:
                                filas.append([ip, "FTP", "Credencial válida", "Media", f"{cred['usuario']}:{cred['password']}"])

        # Añadir credenciales RDP válidas
        rdp_dir = os.path.join(self.results_dir, "rdp")
        for fname in os.listdir(rdp_dir):
            if fname.endswith(".json"):
                rdp_path = os.path.join(rdp_dir, fname)
                if self.modulo_existe(rdp_path):
                    with open(rdp_path) as f:
                        data = json.load(f)
                        ip = data.get("host")
                        for cred in data.get("valid_credentials", []):
                            if ip:
                                filas.append([ip, "RDP", "Credencial válida", "Alta", f"{cred['usuario']}:{cred['password']}"])

        # Construcción de tabla HTML
        html = ["<h2>Resumen Ejecutivo</h2>", "<table>",
                "<tr><th>IP</th><th>Servicio</th><th>Tipo</th><th>Severidad</th><th>Credenciales</th></tr>"]
        for fila in filas:
            ip, servicio, tipo, sev, cred = fila
            sev_class = sev.lower()  # Clase CSS según severidad
            html.append(f"<tr class='{sev_class}'><td>{ip}</td><td>{servicio}</td><td>{tipo}</td><td>{sev}</td><td>{cred}</td></tr>")
        html.append("</table>")
        return "\n".join(html)

    # Todas las funciones siguientes agregan secciones por módulo específico
    def seccion_scan(self, path):
        with open(path) as f:
            data = json.load(f)
        html = ["<h2>Mapa de red detectado</h2>", "<div class='box'><ul>"]
        for host in data.get("hosts", []):
            ip = host.get("ip")
            puertos = ", ".join(str(p["port"]) for p in host.get("open_ports", []))
            html.append(f"<li><strong>{ip}</strong> - Puertos: {puertos}</li>")
        html.append("</ul></div>")
        return "\n".join(html)

    def seccion_exploits(self, path):
        html = ["<h2>Exploits detectados</h2>"]
        html.append(f"<p>El análisis de exploits se encuentra en: <code>{path}</code></p>")
        return "\n".join(html)

    def seccion_mysql(self, dir_path):
        html = ["<h2>Análisis MySQL</h2>"]
        for fname in os.listdir(dir_path):
            if not fname.endswith(".json"): continue
            with open(os.path.join(dir_path, fname)) as f:
                data = json.load(f)
            html.append(f"<div class='box'><strong>Host:</strong> {data.get('host')}<br>")
            html.append(f"<strong>Versión:</strong> {data.get('version')}<br>")
            html.append("<strong>Bases de datos encontradas:</strong><ul>")
            for db in data.get("databases", []):
                html.append(f"<li>{db}</li>")
            html.append("</ul><strong>Usuarios encontrados:</strong><ul>")
            for user in data.get("users", []):
                html.append(f"<li>{user}</li>")
            html.append("</ul></div>")
        return "\n".join(html)

    def seccion_smb(self, hashes_path, creds_path, enum_log):
        html = ["<h2>Resultado SMB</h2><div class='box'>"]
        if self.modulo_existe(hashes_path):
            with open(hashes_path) as f:
                hashes = f.read().strip().splitlines()
            html.append(f"<strong>Hashes capturados:</strong> {len(hashes)}<ul>")
            for h in hashes:
                html.append(f"<li>{h}</li>")
            html.append("</ul>")
        if self.modulo_existe(creds_path):
            with open(creds_path) as f:
                creds = json.load(f)
            html.append(f"<strong>Credenciales crackeadas:</strong> {len(creds)}<ul>")
            for c in creds:
                html.append(f"<li class='ok'>{c['usuario']}:{c['password']}</li>")
            html.append("</ul>")
        if self.modulo_existe(enum_log):
            html.append("<details><summary><strong>Log de enumeración SMB</strong></summary><pre>")
            with open(enum_log) as f:
                html.append(f.read())
            html.append("</pre></details>")
        html.append("</div>")
        return "\n".join(html)

    def seccion_web(self, dir_path):
        html = ["<h2>Análisis Web</h2>"]
        for carpeta in os.listdir(dir_path):
            subdir = os.path.join(dir_path, carpeta)
            if not os.path.isdir(subdir):
                continue
            html.append(f"<details><summary><strong>{carpeta}</strong></summary><div class='box'>")
            for archivo in os.listdir(subdir):
                path_archivo = os.path.join(subdir, archivo)
                if not self.modulo_existe(path_archivo):
                    continue
                html.append(f"<h4>{archivo}</h4><pre>")
                with open(path_archivo, "r", errors="ignore") as f:
                    html.append(f.read())
                html.append("</pre>")
            html.append("</div></details>")
        return "\n".join(html)

    def seccion_ftp(self, path):
        with open(path) as f:
            data = json.load(f)
        html = ["<h2>Resultado FTP</h2><div class='box'>"]
        html.append(f"<strong>Acceso anónimo:</strong> {'Sí' if data.get('anonymous_access') else 'No'}<br>")
        if 'valid_credentials' in data:
            html.append("<strong>Credenciales encontradas:</strong><ul>")
            for c in data['valid_credentials']:
                html.append(f"<li class='ok'>{c['usuario']}:{c['password']}</li>")
            html.append("</ul>")
        html.append("</div>")
        return "\n".join(html)

    def seccion_rdp(self, path):
        with open(path) as f:
            data = json.load(f)
        html = ["<h2>Resultado RDP</h2><div class='box'>"]
        if 'valid_credentials' in data:
            html.append("<strong>Credenciales encontradas:</strong><ul>")
            for c in data['valid_credentials']:
                html.append(f"<li class='ok'>{c['usuario']}:{c['password']}</li>")
            html.append("</ul>")
        else:
            html.append("<p>No se encontraron credenciales válidas.</p>")
        html.append("</div>")
        return "\n".join(html)

# Punto de entrada para generar el informe si se ejecuta directamente
if __name__ == "__main__":
    gen = ReportGenerator()
    gen.generar()
