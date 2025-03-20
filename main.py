from utils.config import load_config
from utils.logger import setup_logger
from modules.reconnaissance import scan_network

def main():
    logger = setup_logger()
    config = load_config()

    ip_range = input("Introduce el rango IP a escanear (ENTER para usar por defecto): ")
    if not ip_range:
        ip_range = config["ip_range"]

    scan_results = scan_network(ip_range, config["scan_options"])
    logger.info(f"Resultados del escaneo: {scan_network}")

if __name__ == "__main__":
    main()