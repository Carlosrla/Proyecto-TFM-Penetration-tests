import json  # Para cargar configuraciones desde archivos JSON

def load_config(config_file="config.json"):
    """
    Carga un archivo de configuración en formato JSON.
    :param config_file: Ruta al archivo de configuración (por defecto: config.json)
    :return: Diccionario con los datos de configuración cargados.
    """
    # Abre el archivo especificado y lo interpreta como JSON
    with open(config_file, "r") as file:
        config = json.load(file)
    return config  # Devuelve el contenido del archivo como diccionario
