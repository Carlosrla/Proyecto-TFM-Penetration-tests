import json
from jinja2 import Template

def generate_report(scan_results, exploits_file="exploits.json", output_file="report.html"):
    """
    Genera un informe en formato HTML con los resultados del escaneo y los exploits encontrados.
    :param scan_results: Resultados del escaneo de Nmap.
    :param exploits_file: Ruta del archivo JSON con los exploits encontrados.
    :param output_file: Ruta para guardar el informe.
    """
    # Cargar los exploits encontrados
    with open(exploits_file, "r") as f:
        exploits = json.load(f)

    # Crear el informe usando una plantilla HTML
    template = Template("""
    <h1>Informe de Pentesting</h1>
    <h2>Hosts Escaneados</h2>
    <ul>
        {% for host in scan_results.hosts %}
        <li>
            <strong>{{ host.ip }}</strong> ({{ host.hostname }})
            <ul>
                {% for port in host.open_ports %}
                <li>
                    Puerto {{ port.port }}: {{ port.service }} {{ port.version }}
                    {% if port.service in exploits %}
                    <ul>
                        {% for exploit in exploits[port.service] %}
                        <li>{{ exploit.title }} - <a href="{{ exploit.url }}">Enlace</a></li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </li>
                {% endfor %}
            </ul>
        </li>
        {% endfor %}
    </ul>
    """)
    html = template.render(scan_results=scan_results, exploits=exploits)
    with open(output_file, "w") as f:
        f.write(html)
    print(f"[+] Informe generado en {output_file}")