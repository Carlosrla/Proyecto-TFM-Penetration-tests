README - Framework de Pentesting Automatizado
Autor: Carlos Ramos López
TFM - Curso 2024/2025

===========================================
Descripción general del proyecto
===========================================

Este proyecto es un framework automatizado para realizar auditorías de seguridad en redes y sistemas Windows. Automatiza las fases clave de un pentest técnico: escaneo, análisis de servicios, explotación basada en credenciales, enumeración avanzada y generación de informes en HTML.

El sistema detecta servicios como SMB, RDP, FTP, Web y MySQL, adaptando su ejecución a los servicios identificados mediante un menú dinámico.

===========================================
Estructura de carpetas
===========================================

- main.py                     → Menú principal y lógica de control
- report_generator.py         → Módulo de generación de informes HTML
- modules/                    → Módulos de ataque y análisis por servicio
- runners/                    → Coordinadores de flujos SMB y MySQL
- utils/                      → Funciones auxiliares, API y configuración
- results/                    → Carpeta de salida (vacía por defecto)
- wordlists/                  → Listas de usuarios y contraseñas

===========================================
Requisitos
===========================================

Sistema operativo: Linux (recomendado Kali Linux)

Python: Versión 3.8 o superior

Dependencias Python (instalar con `pip install -r requirements.txt` si se crea un fichero):

- python-nmap
- impacket
- scapy
- jinja2
- reportlab
- argparse

Dependencias externas (instalar por sistema operativo o gestor de paquetes):

- Nmap
- ffuf
- nuclei
- Responder
- Hashcat
- CrackMapExec
- xfreerdp

Nota: Algunas herramientas deben ejecutarse con permisos de administrador (ej. Responder, Nmap con -sS, CrackMapExec).

===========================================
Instrucciones de uso
===========================================

1. Ejecutar el archivo principal:

    ```bash
    sudo python3 main.py
    ```

2. Seleccionar una opción del menú:

    - Escanear una red
    - Ejecutar módulos por servicio detectado
    - Ejecutar análisis completo
    - Generar informe final

3. Los resultados se almacenarán automáticamente en la carpeta `results/`.

4. El informe se guardará en `results/report.html` y puede abrirse desde el navegador.

===========================================
Advertencia de uso ético
===========================================

Este framework está diseñado para fines educativos y de auditoría autorizada. El uso de estas herramientas en redes no autorizadas puede violar leyes nacionales e internacionales.

Utiliza este software únicamente en entornos de laboratorio, redes de pruebas o bajo consentimiento expreso del propietario del sistema.

===========================================
Contacto
===========================================

Carlos Ramos López  