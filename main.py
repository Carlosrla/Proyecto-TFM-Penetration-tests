from api import scan_network
import argparse

def main():
    parser = argparse.ArgumentParser(description="Herramienta de Pentesting - Reconocimiento")
    parser.add_argument("--target", required=True, help="Objetivo a escanear (IP o rango)")
    parser.add_argument("--output", default="scan_results.json", help="Archivo para resultados")
    args = parser.parse_args()

    scan_network(args.target, args.output)

if __name__ == "__main__":
    main()
