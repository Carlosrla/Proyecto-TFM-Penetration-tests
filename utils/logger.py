import logging  # Módulo estándar para manejo de logs en Python

def setup_logger():
    """
    Configura un logger global que guarda mensajes en el archivo 'logs/pentest.log'.
    - Nivel por defecto: INFO
    - Formato: [timestamp] [nivel]: mensaje
    :return: Instancia del logger configurado.
    """
    # Configura el sistema de logging:
    # - filename: ruta del archivo donde se almacenarán los logs
    # - level: nivel mínimo de mensajes que se van a registrar
    # - format: formato de cada línea en el log (fecha, nivel, mensaje)
    logging.basicConfig(
        filename='logs/pentest.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    # Devuelve el logger raíz configurado
    return logging.getLogger()
